"""
Tests for html_features.py
"""
import pytest
from src.features.html_features import extract_html_features

def test_extract_html_features():
    html = '''<html><head><title>Test Title</title></head><body><h1>Hello World</h1><script>window.open()</script></body></html>'''
    features = extract_html_features("https://www.google.com", html, 0, 0)
    assert features["HasTitle"] == 1
    assert features["NoOfPopup"] == 1
    # LineOfCode = 1 because no newlines above
    assert features["LineOfCode"] == 1

    excluded = [
        "DomainTitleMatchScore",
        "URLTitleMatchScore"
    ]
    for ext in excluded:
        assert ext not in features

def test_extract_html_empty():
    features = extract_html_features("https://empty.com", "", 0, 0)
    assert features["HasTitle"] == 0
    assert features["LineOfCode"] == 0
