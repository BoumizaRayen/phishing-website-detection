"""
src/api/services.py
====================
Business logic layer: orchestrates feature extraction → prediction →
risk scoring → response assembly.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from src.api.schemas import (
    AnalyzeResponse,
    FeatureContribution,
    FetchInfo,
    RiskLevel,
    Verdict,
)
from src.config import RISK_HIGH_MAX, RISK_LOW_MAX, RISK_MEDIUM_MAX
from src.features.feature_builder import get_builder
from src.models.predict import get_predictor

logger = logging.getLogger(__name__)

# ── Trusted domains (Allowlist) ───────────────────────────────────────────
_TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "amazon.com", "wikipedia.org",
    "facebook.com", "twitter.com", "x.com", "instagram.com", 
    "linkedin.com", "microsoft.com", "apple.com", "github.com", 
    "netflix.com", "yahoo.com", "reddit.com", "bing.com", "whatsapp.com"
}

import os
from pathlib import Path
_TOP_DOMAINS_PATH = Path(__file__).parent / "top_domains.txt"
if _TOP_DOMAINS_PATH.exists():
    try:
        with open(_TOP_DOMAINS_PATH, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
            _TRUSTED_DOMAINS.update(d.strip().lower() for d in lines if d.strip())
        logger.info(f"Loaded {len(_TRUSTED_DOMAINS)} trusted domains allowlist.")
    except Exception as e:
        logger.error(f"Could not load top_domains.txt: {e}")

# ── Human-readable labels for the top features ────────────────────────────
_FEATURE_LABELS: dict[str, str] = {
    # URL features
    "URLLength": "URL length",
    "DomainLength": "Domain length",
    "IsDomainIP": "Domain is an IP address",
    "TLD": "Top-level domain",
    "TLDLength": "TLD length",
    "NoOfSubDomain": "Number of subdomains",
    "HasObfuscation": "URL contains obfuscation (%xx)",
    "NoOfObfuscatedChar": "Number of obfuscated characters",
    "ObfuscationRatio": "Obfuscation ratio in URL",
    "NoOfLettersInURL": "Number of letters in URL",
    "LetterRatioInURL": "Letter ratio in URL",
    "NoOfDegitsInURL": "Number of digits in URL",
    "DegitRatioInURL": "Digit ratio in URL",
    "NoOfEqualsInURL": "Number of '=' signs in URL",
    "NoOfQMarkInURL": "Number of '?' in URL",
    "NoOfAmpersandInURL": "Number of '&' in URL",
    "NoOfOtherSpecialCharsInURL": "Number of other special characters",
    "SpacialCharRatioInURL": "Special character ratio in URL",
    "IsHTTPS": "Uses HTTPS",
    # HTML features
    "LineOfCode": "Lines of HTML code",
    "LargestLineLength": "Longest HTML line",
    "HasTitle": "Page has a title",
    "HasFavicon": "Page has a favicon",
    "Robots": "Has robots meta tag",
    "IsResponsive": "Page is responsive",
    "NoOfURLRedirect": "Number of HTTP redirects",
    "NoOfSelfRedirect": "Self-redirects",
    "HasDescription": "Has meta description",
    "NoOfPopup": "Number of popups (window.open)",
    "NoOfiFrame": "Number of iframes",
    "HasExternalFormSubmit": "Form submits to external domain",
    "HasSocialNet": "Links to social networks",
    "HasSubmitButton": "Has a submit button",
    "HasHiddenFields": "Has hidden form fields",
    "HasPasswordField": "Has a password field",
    "Bank": "Contains banking keywords",
    "Pay": "Contains payment keywords",
    "Crypto": "Contains crypto keywords",
    "HasCopyrightInfo": "Has copyright notice",
    "NoOfImage": "Number of images",
    "NoOfCSS": "Number of CSS stylesheets",
    "NoOfJS": "Number of JS scripts",
    "NoOfSelfRef": "Number of internal links",
    "NoOfEmptyRef": "Number of empty/# links",
    "NoOfExternalRef": "Number of external links",
}


def _compute_risk_level(confidence: float, is_phishing: bool) -> RiskLevel:
    """Map the model confidence score to a human-readable risk level."""
    if not is_phishing:
        # Legitimate prediction — confidence = P(phishing) is low
        if confidence <= RISK_LOW_MAX:
            return RiskLevel.LOW
        return RiskLevel.MEDIUM   # uncertain legitimate
    else:
        # Phishing prediction
        if confidence <= RISK_MEDIUM_MAX:
            return RiskLevel.MEDIUM
        if confidence <= RISK_HIGH_MAX:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL


def _enrich_top_features(
    raw_features: list[dict[str, Any]],
) -> list[FeatureContribution]:
    """Add human-readable labels to the raw top-feature list."""
    return [
        FeatureContribution(
            feature=f["feature"],
            label=_FEATURE_LABELS.get(f["feature"], f["feature"]),
            value=f.get("value"),
            importance=f.get("importance", 0),
            shap_value=f.get("shap_value", 0.0),
        )
        for f in raw_features
    ]

import httpx
import base64
from src.config import VIRUSTOTAL_API_KEY
from src.api.schemas import VirusTotalReport
from src.api.db import log_scan

async def check_virustotal(url: str) -> VirusTotalReport | None:
    """Async wrapper for VirusTotal URL report."""
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        async with httpx.AsyncClient(timeout=4.0) as client:
            headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
            response = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers
            )
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return VirusTotalReport(
                    positives=stats.get("malicious", 0) + stats.get("suspicious", 0),
                    total=sum(stats.values()),
                    scan_id=data.get("data", {}).get("id", ""),
                    malicious_votes=stats.get("malicious", 0),
                    permalink=f"https://www.virustotal.com/gui/url/{url_id}",
                )
    except Exception as exc:
        logger.warning("VirusTotal API check failed: %s", exc)
    return None

async def analyze_url(url: str) -> AnalyzeResponse:
    """
    Full analysis pipeline for a single URL.
    """
    t0 = time.perf_counter()
    logger.info("Analysing URL: %s", url)

    # ── Feature extraction ────────────────────────────────────────────────
    builder = get_builder()
    df, fetch_status = builder.build(url)

    # ── Model inference ───────────────────────────────────────────────────
    predictor = get_predictor()
    result = predictor.predict(df.iloc[0].to_dict())

    # ── External integrations (VT is fast and transparent) ─────────────────
    vt_report = await check_virustotal(url)

    # ── Trusted Domain & VirusTotal Override ──────────────────────────────
    from urllib.parse import urlparse
    netloc = urlparse(url).netloc.lower()
    base_domain = netloc[4:] if netloc.startswith("www.") else netloc
    
    is_trusted = base_domain in _TRUSTED_DOMAINS or any(base_domain.endswith("." + d) for d in _TRUSTED_DOMAINS)
    
    if is_trusted:
        logger.info("URL %s matches trusted domain list. Overriding to legitimate.", url)
        result.is_phishing = False
        result.confidence = 0.0
        result.label = "legitimate"
    elif vt_report and vt_report.positives > 0:
        logger.info("VirusTotal override: %d engines flagged URL %s", vt_report.positives, url)
        result.is_phishing = True
        result.label = "phishing"
        # Force high confidence so Risk Level becomes CRITICAL or HIGH
        result.confidence = max(result.confidence, 0.99 if vt_report.positives >= 3 else 0.85)

    # ── Risk level ────────────────────────────────────────────────────────
    risk_level = _compute_risk_level(result.confidence, result.is_phishing)

    # ── Assemble response ─────────────────────────────────────────────────
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

    logger.info(
        "Analysis done: verdict=%s confidence=%.4f risk=%s duration=%.1fms",
        result.label,
        result.confidence,
        risk_level.value,
        elapsed_ms,
    )
    
    enriched_features = _enrich_top_features(result.top_features)
    
    # Log to SQLite monitoring database
    log_scan(
        url=url, 
        verdict=result.label, 
        confidence=result.confidence, 
        risk_level=risk_level.value, 
        duration_ms=elapsed_ms,
        shap_features=[f.model_dump() for f in enriched_features]
    )

    return AnalyzeResponse(
        url=url,
        verdict=Verdict(result.label),
        is_phishing=result.is_phishing,
        confidence=result.confidence,
        risk_level=risk_level,
        top_features=enriched_features,
        fetch_info=FetchInfo(
            html_available=fetch_status.html_available,
            final_url=fetch_status.final_url,
            redirect_count=fetch_status.redirect_count,
            error_message=fetch_status.error_message,
        ),
        virustotal_report=vt_report,
        analysis_duration_ms=elapsed_ms,
    )
