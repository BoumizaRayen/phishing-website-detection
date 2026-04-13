"""
Centralised configuration for the Phishing Detection project.

All settings are read from environment variables (or a .env file loaded
by python-dotenv).  Defaults are provided for local development.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# ── Load .env file if present ──────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent   # project root
load_dotenv(BASE_DIR / ".env")

# ── Paths ──────────────────────────────────────────────────────────────────
ARTIFACTS_DIR: Path = Path(
    os.getenv("ARTIFACTS_DIR", str(BASE_DIR / "artifacts"))
)
MODEL_PATH: Path = ARTIFACTS_DIR / "phishing_model.joblib"
FEATURES_PATH: Path = ARTIFACTS_DIR / "input_features.joblib"
METADATA_PATH: Path = ARTIFACTS_DIR / "metadata.json"

# ── HTTP fetch settings ────────────────────────────────────────────────────
FETCH_TIMEOUT: int = int(os.getenv("FETCH_TIMEOUT", "10"))          # seconds
FETCH_RETRIES: int = int(os.getenv("FETCH_RETRIES", "2"))
FETCH_USER_AGENT: str = os.getenv(
    "FETCH_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
)

# ── Risk thresholds ────────────────────────────────────────────────────────
# Confidence score (0–1) boundaries for the four risk levels
RISK_LOW_MAX: float = float(os.getenv("RISK_LOW_MAX", "0.3"))
RISK_MEDIUM_MAX: float = float(os.getenv("RISK_MEDIUM_MAX", "0.6"))
RISK_HIGH_MAX: float = float(os.getenv("RISK_HIGH_MAX", "0.85"))
# Above RISK_HIGH_MAX → "critical"

# ── API settings ───────────────────────────────────────────────────────────
API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
API_PORT: int = int(os.getenv("API_PORT", "8000"))
API_RELOAD: bool = os.getenv("API_RELOAD", "true").lower() == "true"
CORS_ORIGINS: list[str] = os.getenv("CORS_ORIGINS", "*").split(",")

# ── Optional external services ─────────────────────────────────────────────
VIRUSTOTAL_API_KEY: str | None = os.getenv("VIRUSTOTAL_API_KEY")
