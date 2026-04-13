"""
Tests for url_features.py
"""
import pytest
from src.features.url_features import extract_url_features

def test_extract_url_features():
    features = extract_url_features("https://www.google.com")
    assert "URLLength" in features
    assert "IsHTTPS" in features
    assert features["IsHTTPS"] == 1
    assert "TLD" in features
    assert features["TLD"] == "com"

    # Excluded features should not be present
    excluded = [
        "URLSimilarityIndex",
        "TLDLegitimateProb",
        "URLCharProb",
        "CharContinuationRate"
    ]
    for ext in excluded:
        assert ext not in features

def test_extract_url_features_no_scheme():
    features = extract_url_features("google.com")
    assert features["TLD"] == "com"
    # Given _parse_url adds http:// if no scheme
    assert features["IsHTTPS"] == 0
