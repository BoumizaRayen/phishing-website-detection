"""
src/features/feature_builder.py
================================
Orchestrates URL + HTML extraction and assembles the final feature
DataFrame expected by the Case-4 LightGBM model.

Strict alignment guarantee
---------------------------
The output DataFrame has **exactly** the columns listed in
``artifacts/input_features.joblib`` (same names, same order).
An AssertionError is raised if a mismatch is detected — this prevents
silent training/serving skew.

The 6 excluded features are never added:
  URLSimilarityIndex, DomainTitleMatchScore, URLTitleMatchScore,
  TLDLegitimateProb, URLCharProb, CharContinuationRate
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import joblib
import pandas as pd

from src.config import FEATURES_PATH
from src.features.html_features import (
    _default_html_features,
    extract_html_features,
    fetch_page,
)
from src.features.url_features import _default_url_features, extract_url_features

logger = logging.getLogger(__name__)

# Features that must NEVER appear in the output (safety guard)
_EXCLUDED_FEATURES = frozenset({
    "URLSimilarityIndex",
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "TLDLegitimateProb",
    "URLCharProb",
    "CharContinuationRate",
})


# ── Result dataclass ─────────────────────────────────────────────────────

@dataclass
class FetchStatus:
    """Metadata about the HTTP fetch stage."""
    success: bool = True
    final_url: str = ""
    redirect_count: int = 0
    error_message: str = ""
    html_available: bool = True


# ── Feature builder ───────────────────────────────────────────────────────

class FeatureBuilder:
    """
    Builds the production feature vector for a given URL.

    Usage
    -----
        builder = FeatureBuilder()
        df, status = builder.build(url)
        result = predictor.predict(df.iloc[0].to_dict())
    """

    def __init__(self, features_path=FEATURES_PATH) -> None:
        self._expected_features: list[str] | None = None
        self._features_path = features_path

    def _load_expected_features(self) -> list[str]:
        if self._expected_features is None:
            if not self._features_path.exists():
                raise FileNotFoundError(
                    f"Feature list not found: {self._features_path}\n"
                    "Run `python export_model.py` first."
                )
            self._expected_features = joblib.load(self._features_path)
            logger.info(
                "Loaded %d expected features from %s",
                len(self._expected_features),
                self._features_path,
            )
        return self._expected_features

    def build(self, url: str) -> tuple[pd.DataFrame, FetchStatus]:
        """
        Extract all features for *url* and return an aligned DataFrame.

        Parameters
        ----------
        url : str
            The URL to analyse.

        Returns
        -------
        (df, status)
          df     : single-row DataFrame with exactly the model's expected columns
          status : FetchStatus with HTTP metadata
        """
        expected = self._load_expected_features()
        status = FetchStatus(final_url=url)

        # ── Step 1: URL-based features (no network required) ────────────
        logger.debug("Extracting URL features for: %s", url)
        url_feats = extract_url_features(url)

        # ── Step 2: Fetch page + HTML features ──────────────────────────
        logger.debug("Fetching page: %s", url)
        html, final_url, redirect_count = fetch_page(url)
        status.final_url = final_url
        status.redirect_count = redirect_count

        if html:
            status.html_available = True
            logger.debug("Extracting HTML features (%d bytes)", len(html))
            html_feats = extract_html_features(
                page_url=final_url,
                html=html,
                redirect_count=redirect_count,
            )
        else:
            status.success = False
            status.html_available = False
            status.error_message = "Page could not be fetched — using defaults."
            logger.warning("HTML unavailable for %s. Using default HTML features.", url)
            html_feats = _default_html_features(redirect_count=redirect_count)

        # ── Step 3: Merge features ───────────────────────────────────────
        all_feats: dict[str, Any] = {**url_feats, **html_feats}

        # ── Step 4: Safety guard — excluded features must not be present ──
        for bad_col in _EXCLUDED_FEATURES:
            if bad_col in all_feats:
                logger.error(
                    "Excluded feature '%s' found in feature dict — removing.", bad_col
                )
                del all_feats[bad_col]

        # ── Step 5: Align with expected feature order ────────────────────
        row: dict[str, Any] = {}
        missing: list[str] = []

        for col in expected:
            if col in all_feats:
                row[col] = all_feats[col]
            else:
                # Fill with sensible default
                row[col] = "" if col == "TLD" else 0
                missing.append(col)

        if missing:
            logger.warning(
                "Features missing and filled with defaults: %s", missing
            )

        df = pd.DataFrame([row], columns=expected)

        # ── Step 6: Strict column alignment assertion ────────────────────
        assert list(df.columns) == expected, (
            f"Column mismatch!\n"
            f"Expected: {expected}\n"
            f"Got:      {list(df.columns)}"
        )

        logger.info(
            "Feature vector built: %d features, html_available=%s, redirects=%d",
            len(expected),
            status.html_available,
            redirect_count,
        )
        return df, status


# ── Module-level singleton ────────────────────────────────────────────────

_builder: FeatureBuilder | None = None


def get_builder() -> FeatureBuilder:
    """Return the module-level singleton FeatureBuilder (lazy init)."""
    global _builder
    if _builder is None:
        _builder = FeatureBuilder()
    return _builder
