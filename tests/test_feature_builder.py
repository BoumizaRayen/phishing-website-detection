"""
Tests for feature_builder.py
"""
import pytest
import pandas as pd
from unittest.mock import patch, MagicMock
from src.features.feature_builder import FeatureBuilder

@patch('src.features.feature_builder.joblib.load')
@patch('src.features.feature_builder.fetch_page')
def test_feature_builder(mock_fetch, mock_joblib):
    expected_cols = ["URLLength", "DomainLength", "IsHTTPS", "TLD", "HasTitle", "LineOfCode"]
    mock_joblib.return_value = expected_cols

    mock_fetch.return_value = ("<html><title>Hi</title></html>", "https://example.com", 0)

    builder = FeatureBuilder(features_path=MagicMock()) # Mock path
    df, status = builder.build("https://example.com")
    
    assert list(df.columns) == expected_cols
    assert df["HasTitle"].iloc[0] == 1
    assert df["TLD"].iloc[0] == "com"
    assert status.success is True
