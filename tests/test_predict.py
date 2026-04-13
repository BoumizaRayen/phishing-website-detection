"""
Tests for predict.py
"""
import pytest
from unittest.mock import patch, MagicMock
import pandas as pd
from src.models.predict import PhishingPredictor

@patch('src.models.predict.joblib.load')
@patch('src.models.predict.Path.exists')
@patch('builtins.open', new_callable=MagicMock)
@patch('src.models.predict.json.load')
def test_predictor(mock_json_load, mock_open, mock_exists, mock_joblib):
    mock_exists.return_value = True
    
    # Mock model and features list
    # Expected features
    mock_joblib.side_effect = [
        MagicMock(predict_proba=MagicMock(return_value=[[0.9, 0.1]])), # Model
        ["F1", "F2", "TLD"] # Features list
    ]
    
    predictor = PhishingPredictor()
    
    with patch.object(predictor, '_get_top_features', return_value=[]):
        result = predictor.predict({"F1": 10})
        
        assert result.is_phishing is True
        assert result.confidence == 0.9
        assert result.features_used["F1"] == 10
        assert result.features_used["F2"] == 0
        assert result.features_used["TLD"] == ""
