"""
Tests for API
"""
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from src.api.app import app

client = TestClient(app)

@patch('src.api.app.get_predictor')
def test_health_check(mock_get_predictor):
    mock_predictor = MagicMock()
    mock_predictor._load = MagicMock()
    mock_predictor.n_features = 45
    mock_predictor.metadata = {"trained_at": "now"}
    mock_get_predictor.return_value = mock_predictor

    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["model_loaded"] is True
