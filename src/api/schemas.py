"""
src/api/schemas.py
==================
Pydantic models for the Phishing Detection API.

Provides strict input validation and a structured JSON response shape.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import AnyHttpUrl, BaseModel, Field, field_validator


# ── Enums ─────────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    PHISHING = "phishing"
    LEGITIMATE = "legitimate"


# ── Request ───────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    """Body of POST /api/v1/analyze"""

    url: str = Field(
        ...,
        description="The URL to analyse for phishing indicators.",
        examples=["https://www.google.com", "http://paypa1-secure.net/login"],
        min_length=4,
        max_length=2048,
    )

    @field_validator("url")
    @classmethod
    def normalise_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://", "ftp://")):
            v = "https://" + v
        return v


# ── Response sub-models ───────────────────────────────────────────────────

class FeatureContribution(BaseModel):
    """A single top-contributing feature."""
    feature: str = Field(..., description="Technical feature name.")
    label: str = Field(..., description="Human-readable label.")
    value: Any = Field(None, description="Actual value extracted for this URL.")
    importance: int = Field(0, description="LightGBM gain importance score or generic scale.")
    shap_value: float = Field(0.0, description="SHAP value (positive = phishing, negative = legitimate).")


class VirusTotalReport(BaseModel):
    """VirusTotal integration response."""
    positives: int
    total: int
    scan_id: str = ""
    malicious_votes: int = 0
    permalink: str = ""



class FetchInfo(BaseModel):
    """HTTP fetch metadata."""
    html_available: bool
    final_url: str
    redirect_count: int
    error_message: str = ""


# ── Main response ─────────────────────────────────────────────────────────

class AnalyzeResponse(BaseModel):
    """Full response of POST /api/v1/analyze"""

    # Input echo
    url: str = Field(..., description="The URL that was analysed.")

    # Core verdict
    verdict: Verdict = Field(..., description="'phishing' or 'legitimate'.")
    is_phishing: bool
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Model probability of the URL being phishing (0–1).",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Qualitative risk level derived from confidence score.",
    )

    # Explainability
    top_features: list[FeatureContribution] = Field(
        default_factory=list,
        description="Top features that most influenced this prediction.",
    )

    # Fetch metadata
    fetch_info: FetchInfo
    
    # Optional VirusTotal integration
    virustotal_report: VirusTotalReport | None = None

    # Analysis timing
    analysis_duration_ms: float = Field(
        ...,
        description="Total server-side analysis time in milliseconds.",
    )


# ── Health check ──────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    model_loaded: bool
    n_features: int
    model_trained_at: str = ""
