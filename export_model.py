"""
export_model.py
===============
Re-trains the final LightGBM pipeline (Case 4 — strict group split by
domain, suspect features removed) and serialises the artefacts needed
by the inference pipeline.

Artefacts produced
------------------
artifacts/phishing_model.joblib  — sklearn Pipeline (preprocessor + LightGBM)
artifacts/input_features.joblib  — ordered list of feature column names
artifacts/metadata.json          — training metrics, hyperparameters, date

Usage
-----
    python export_model.py --dataset "C:/PhiUSIIL_Phishing_URL_Dataset.csv"

The dataset path can also be set via the DATASET_PATH environment variable.
"""

import argparse
import json
import os
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from lightgbm import LGBMClassifier

# ── Constants (must mirror the notebook exactly) ───────────────────────────
TARGET_COL = "label"

# Columns that are textual identifiers — dropped before training
TEXT_COLS = ["FILENAME", "URL", "Domain", "Title"]
BASE_DROP_COLS = TEXT_COLS + [TARGET_COL]

# The 6 "suspect" features excluded in Case 4
SUSPECT_COLS = [
    "URLSimilarityIndex",
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "TLDLegitimateProb",
    "URLCharProb",
    "CharContinuationRate",
]

# Best hyperparameters found by RandomizedSearchCV in the notebook
BEST_PARAMS = {
    "model__subsample": 0.8,
    "model__num_leaves": 15,
    "model__n_estimators": 200,
    "model__min_child_samples": 30,
    "model__max_depth": 10,
    "model__learning_rate": 0.1,
    "model__colsample_bytree": 1.0,
}

ARTIFACTS_DIR = Path(__file__).parent / "artifacts"


def load_and_clean(dataset_path: str) -> pd.DataFrame:
    """Load the PhiUSIIL dataset and apply the same cleaning as the notebook."""
    print(f"[1/5] Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path, encoding="latin1")

    # Fix BOM in column names (notebook: str.replace("ï»¿", ""))
    df.columns = df.columns.str.replace("ï»¿", "", regex=False).str.strip()

    print(f"      Shape: {df.shape}")
    # Drop exact duplicates (notebook showed 0, but keep it safe)
    df = df.drop_duplicates().reset_index(drop=True)
    print(f"      Shape after dedup: {df.shape}")
    return df


def build_pipeline(X_train: pd.DataFrame) -> Pipeline:
    """Construct the sklearn Pipeline with the same preprocessor as Case 4."""
    num_cols = X_train.select_dtypes(include=["int64", "float64"]).columns.tolist()
    cat_cols = X_train.select_dtypes(include=["object"]).columns.tolist()

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", "passthrough", num_cols),
            ("cat", OneHotEncoder(handle_unknown="ignore"), cat_cols),
        ]
    )

    model = LGBMClassifier(
        n_estimators=BEST_PARAMS["model__n_estimators"],
        learning_rate=BEST_PARAMS["model__learning_rate"],
        num_leaves=BEST_PARAMS["model__num_leaves"],
        max_depth=BEST_PARAMS["model__max_depth"],
        min_child_samples=BEST_PARAMS["model__min_child_samples"],
        subsample=BEST_PARAMS["model__subsample"],
        colsample_bytree=BEST_PARAMS["model__colsample_bytree"],
        random_state=42,
        n_jobs=-1,
    )

    return Pipeline(steps=[("preprocessor", preprocessor), ("model", model)])


def train_and_evaluate(df: pd.DataFrame) -> tuple[Pipeline, list[str], dict]:
    """
    Reproduce Case 4:
      - Drop BASE_DROP_COLS + SUSPECT_COLS
      - Group split by Domain (test_size=0.2, random_state=42)
      - Fit pipeline on train split
      - Evaluate on test split
    Returns the fitted pipeline, feature names, and metrics dict.
    """
    drop_cols = BASE_DROP_COLS + SUSPECT_COLS
    X = df.drop(columns=drop_cols, errors="ignore")
    y = df[TARGET_COL]
    groups = df["Domain"]

    print(f"[2/5] Feature matrix shape: {X.shape}")
    print(f"      Features used ({len(X.columns)}): {X.columns.tolist()}")

    # Group split — same seed as notebook
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups=groups))

    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

    # Sanity check: no domain overlap
    train_domains = set(groups.iloc[train_idx])
    test_domains = set(groups.iloc[test_idx])
    assert len(train_domains & test_domains) == 0, "Domain overlap detected!"

    print(f"      Train: {X_train.shape}, Test: {X_test.shape}")

    print("[3/5] Training LightGBM pipeline (tuned hyperparameters)...")
    pipeline = build_pipeline(X_train)
    pipeline.fit(X_train, y_train)

    print("[4/5] Evaluating on strict test split...")
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 6),
        "precision": round(float(precision_score(y_test, y_pred)), 6),
        "recall": round(float(recall_score(y_test, y_pred)), 6),
        "f1_score": round(float(f1_score(y_test, y_pred)), 6),
        "roc_auc": round(float(roc_auc_score(y_test, y_prob)), 6),
        "pr_auc": round(float(average_precision_score(y_test, y_prob)), 6),
        "n_train": len(X_train),
        "n_test": len(X_test),
    }

    print("      Metrics:")
    for k, v in metrics.items():
        print(f"        {k}: {v}")

    return pipeline, X.columns.tolist(), metrics


def save_artefacts(
    pipeline: Pipeline,
    feature_names: list[str],
    metrics: dict,
) -> None:
    """Persist the three artefact files."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    model_path = ARTIFACTS_DIR / "phishing_model.joblib"
    features_path = ARTIFACTS_DIR / "input_features.joblib"
    metadata_path = ARTIFACTS_DIR / "metadata.json"

    print("[5/5] Saving artefacts...")

    joblib.dump(pipeline, model_path)
    print(f"      OK Model  -> {model_path}")

    joblib.dump(feature_names, features_path)
    print(f"      OK Features ({len(feature_names)}) -> {features_path}")

    metadata = {
        "trained_at": datetime.utcnow().isoformat() + "Z",
        "scenario": "Case 4 — group split by domain, suspect features removed",
        "model": "LightGBM",
        "hyperparameters": BEST_PARAMS,
        "n_features": len(feature_names),
        "feature_names": feature_names,
        "excluded_features": SUSPECT_COLS,
        "metrics": metrics,
        "dataset": "PhiUSIIL_Phishing_URL_Dataset",
        "label_encoding": {"0": "legitimate", "1": "phishing"},
    }
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    print(f"      OK Metadata -> {metadata_path}")

    print("\nOK Export complete.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Export the phishing detection model.")
    parser.add_argument(
        "--dataset",
        default=os.getenv("DATASET_PATH", r"C:\PhiUSIIL_Phishing_URL_Dataset.csv"),
        help="Path to the PhiUSIIL CSV dataset.",
    )
    args = parser.parse_args()

    df = load_and_clean(args.dataset)
    pipeline, feature_names, metrics = train_and_evaluate(df)
    save_artefacts(pipeline, feature_names, metrics)


if __name__ == "__main__":
    main()
