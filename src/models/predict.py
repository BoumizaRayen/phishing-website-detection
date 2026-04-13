"""
src/models/predict.py
=====================
Loads the serialised LightGBM pipeline and exposes a clean prediction API.

The artefacts expected on disk:
  artifacts/phishing_model.joblib  — sklearn Pipeline
  artifacts/input_features.joblib  — list[str] of feature column names
  artifacts/metadata.json          — training metadata (for introspection)

Public surface
--------------
  PhishingPredictor          — singleton-friendly predictor class
  get_predictor()            — returns the module-level singleton instance
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import shap

from src.config import FEATURES_PATH, METADATA_PATH, MODEL_PATH

logger = logging.getLogger(__name__)


# ── Result dataclass ──────────────────────────────────────────────────────

@dataclass
class PredictionResult:
    """Structured output of a single URL prediction."""

    # Core verdict
    is_phishing: bool
    confidence: float          # probability of being phishing (0-1)
    label: str                 # "phishing" | "legitimate"

    # Top contributing features (name → importance score)
    top_features: list[dict[str, Any]] = field(default_factory=list)

    # Raw feature vector sent to the model (for debugging / explainability)
    features_used: dict[str, Any] = field(default_factory=dict)


# ── Predictor class ───────────────────────────────────────────────────────

class PhishingPredictor:
    """
    Wraps the serialised LightGBM pipeline and provides a predict() method.

    Usage
    -----
        predictor = PhishingPredictor()
        result = predictor.predict(features_dict)
    """

    def __init__(
        self,
        model_path: Path = MODEL_PATH,
        features_path: Path = FEATURES_PATH,
        metadata_path: Path = METADATA_PATH,
    ) -> None:
        self._model_path = model_path
        self._features_path = features_path
        self._metadata_path = metadata_path

        self._pipeline = None          # lazy-loaded
        self._explainer = None         # lazy-loaded SHAP explainer
        self._feature_names: list[str] = []
        self._metadata: dict = {}
        self._loaded = False

    # ── Loading ───────────────────────────────────────────────────────────

    def _load(self) -> None:
        """Load artefacts from disk (called once on first use)."""
        if self._loaded:
            return

        if not self._model_path.exists():
            raise FileNotFoundError(
                f"Model artefact not found: {self._model_path}\n"
                "Run `python export_model.py` first."
            )

        logger.info("Loading model from %s", self._model_path)
        self._pipeline = joblib.load(self._model_path)

        logger.info("Loading feature list from %s", self._features_path)
        self._feature_names = joblib.load(self._features_path)

        if self._metadata_path.exists():
            with open(self._metadata_path, encoding="utf-8") as f:
                self._metadata = json.load(f)
            logger.info(
                "Model trained at %s — %d features",
                self._metadata.get("trained_at", "?"),
                len(self._feature_names),
            )

        self._loaded = True
        logger.info("PhishingPredictor ready.")

    # ── Feature validation ────────────────────────────────────────────────

    def _build_dataframe(self, features: dict[str, Any]) -> pd.DataFrame:
        """
        Build a single-row DataFrame aligned with the training feature set.

        - Columns present in features but not in the training set are ignored.
        - Columns missing from features are filled with 0 (numeric) or
          empty string (object / TLD), matching the dataset's convention.
        """
        row: dict[str, Any] = {}
        for col in self._feature_names:
            if col in features:
                row[col] = features[col]
            else:
                # Use 0 for numeric, "" for categorical (TLD)
                row[col] = "" if col == "TLD" else 0
                logger.debug("Feature '%s' missing — using default value.", col)

        df = pd.DataFrame([row], columns=self._feature_names)

        # Verify column alignment (critical guard against mismatch)
        assert list(df.columns) == self._feature_names, (
            "Column order mismatch between extracted features and model input!"
        )
        return df

    # ── Top features (global importance) ─────────────────────────────────

    def _get_top_features(
        self,
        df_row: pd.DataFrame,
        n: int = 8,
    ) -> list[dict[str, Any]]:
        """
        Return the top-N most important features for this prediction.
        Uses the LightGBM global feature importance (gain), filtered to
        features that are actually non-zero for this sample.
        """
        try:
            lgbm_model = self._pipeline.named_steps["model"]
            preprocessor = self._pipeline.named_steps["preprocessor"]

            # Get feature names after OHE
            transformed_feature_names = preprocessor.get_feature_names_out()
            # Init SHAP explainer if needed (we use it on transformed data)
            if self._explainer is None:
                self._explainer = shap.TreeExplainer(lgbm_model)

            X_transformed = preprocessor.transform(df_row)
            shap_values_raw = self._explainer.shap_values(X_transformed)
            
            # For LGBM in binary mode, shap_values can be a list [P(0), P(1)] or just P(1)
            # Since we care about P(0) (phishing impact), if it's a list we take [0] or flip [1].
            # Actually, by default local TreeExplainer on LGBM binary gives log-odds for positive class (which is Legitimate=1).
            # So shap_values > 0 means pushes towards Legitimate. shap_values < 0 means pushes towards Phishing.
            sv_arr = shap_values_raw.toarray()[0] if hasattr(shap_values_raw, "toarray") else shap_values_raw[0] if isinstance(shap_values_raw, list) else shap_values_raw[0] if len(shap_values_raw.shape) > 1 else shap_values_raw
            
            # Map SHAP values back to original feature names
            shap_map: dict[str, float] = {}
            for fname, sv in zip(transformed_feature_names, sv_arr):
                # e.g. "num__IsHTTPS" → "IsHTTPS"
                if fname.startswith("num__"):
                    orig = fname[len("num__"):]
                elif fname.startswith("cat__"):
                    orig = fname[len("cat__"):].rsplit("_", 1)[0]
                else:
                    orig = fname
                # We sum the SHAP values for one-hot encoded groups
                # We invert it: now positive SHAP means "pushes towards Phishing"
                shap_map[orig] = shap_map.get(orig, 0.0) - float(sv)

            # Sort by absolute SHAP value impact
            sorted_by_impact = sorted(
                shap_map.items(), key=lambda x: abs(x[1]), reverse=True
            )[:n]

            results = []
            for name, shap_val in sorted_by_impact:
                val = df_row[name].iloc[0] if name in df_row.columns else None
                if hasattr(val, "item"):
                    val = val.item()
                results.append({
                    "feature": name,
                    "importance": int(abs(shap_val) * 100), # pseudo importance for backwards compat
                    "value": val,
                    "shap_value": round(shap_val, 4),
                })
            return results
        except Exception as exc:
            logger.warning("Could not compute feature importances: %s", exc)
            return []

    # ── Public predict API ────────────────────────────────────────────────

    def predict(self, features: dict[str, Any]) -> PredictionResult:
        """
        Run inference on a feature dictionary.

        Parameters
        ----------
        features : dict[str, Any]
            Keys = feature names (matching the training set, 45 columns).
            Missing keys are filled with defaults automatically.

        Returns
        -------
        PredictionResult
        """
        self._load()

        df_row = self._build_dataframe(features)
        proba = self._pipeline.predict_proba(df_row)[0]   # [P(phish=0), P(legit=1)]
        phish_prob = float(proba[0])
        is_phishing = phish_prob >= 0.40  # Seuil ajusté à 0.40 pour être plus sensible
        label = "phishing" if is_phishing else "legitimate"

        top_features = self._get_top_features(df_row)

        logger.info(
            "Prediction: %s (confidence=%.4f)", label, phish_prob
        )

        return PredictionResult(
            is_phishing=is_phishing,
            confidence=round(phish_prob, 4),
            label=label,
            top_features=top_features,
            features_used={k: (v.item() if hasattr(v, "item") else v) for k, v in zip(self._feature_names, df_row.iloc[0])},
        )

    # ── Introspection ─────────────────────────────────────────────────────

    @property
    def feature_names(self) -> list[str]:
        self._load()
        return self._feature_names

    @property
    def metadata(self) -> dict:
        self._load()
        return self._metadata

    @property
    def n_features(self) -> int:
        self._load()
        return len(self._feature_names)


# ── Module-level singleton ────────────────────────────────────────────────

_predictor: PhishingPredictor | None = None


def get_predictor() -> PhishingPredictor:
    """Return the module-level singleton predictor (lazy init)."""
    global _predictor
    if _predictor is None:
        _predictor = PhishingPredictor()
    return _predictor
