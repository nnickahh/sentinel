"""
Unit & Integration tests for Sentinel FastAPI REST API
"""
import pytest
from starlette.testclient import TestClient
from backend.app import app

client = TestClient(app)

def test_api_stats():
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert "privacy_score" in data
    assert "total_connections" in data
    assert "trackers_detected" in data
    assert "blocked_count" in data
    assert "high_risk_count" in data

def test_api_connections():
    res = client.get("/api/connections")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) > 0
    # Check structure
    ev = data[0]
    assert "domain" in ev
    assert "application" in ev
    assert "risk_level" in ev
    assert "status" in ev

def test_api_connections_filtering():
    res = client.get("/api/connections?filter=high")
    assert res.status_code == 200
    data = res.json()
    for ev in data:
        assert ev["risk_level"] == "high"

def test_api_investigate():
    res = client.post("/api/investigate", json={
        "domain": "adservice.google.com",
        "application": "chrome"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["risk"] in ["high", "medium"]
    assert "recommendation" in data
    assert "explanation" in data
    assert "possible_consequences" in data

def test_api_quick_decision():
    res = client.post("/api/decision", json={
        "domain": "fingerprint.device-id.net",
        "application": "chrome",
        "decision": "block",
        "reason": "Test block"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"

    # Verify rule is listed
    res_rules = client.get("/api/rules")
    assert res_rules.status_code == 200
    rules = res_rules.json()
    assert any(r["domain"] == "fingerprint.device-id.net" for r in rules)

def test_api_explain_privacy():
    res = client.get("/api/explain-privacy")
    assert res.status_code == 200
    data = res.json()
    assert "score" in data
    assert "narrative_report" in data
    assert len(data["narrative_report"]) > 50
