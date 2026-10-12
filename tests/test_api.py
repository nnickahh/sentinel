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

def test_api_warn_decision():
    res = client.post("/api/decision", json={
        "domain": "spclient.wg.spotify.com",
        "application": "spotify",
        "decision": "warn",
        "reason": "Warn on background telemetry"
    })
    assert res.status_code == 200
    assert res.json()["status"] == "ok"

def test_api_timeline():
    res = client.get("/api/timeline")
    assert res.status_code == 200
    data = res.json()
    assert "labels" in data
    assert "detected_series" in data
    assert "events" in data
    assert len(data["events"]) > 0

def test_api_ask_question():
    res = client.post("/api/ask", json={
        "question": "What did this application collect today?",
        "application": "chrome"
    })
    assert res.status_code == 200
    data = res.json()
    assert "answer" in data
    assert len(data["answer"]) > 20
    assert "recommended_actions" in data

def test_api_privacy_modes():
    for mode in ["normal", "strict", "paranoid"]:
        res = client.post("/api/privacy-mode", json={"mode": mode})
        assert res.status_code == 200
        assert res.json()["privacy_mode"] == mode

def test_api_autopilot():
    res = client.post("/api/autopilot", json={"enabled": True, "run_sweep": True})
    assert res.status_code == 200
    data = res.json()
    assert data["autopilot_enabled"] is True
    assert data["preserved_essential_count"] >= 1
    assert "api.stripe.com" in data["preserved_domains"]

def test_api_browser_status():
    res = client.get("/api/browser/status")
    assert res.status_code == 200
    data = res.json()
    assert "edge" in data
    assert "chrome" in data
    assert "opera" in data
    assert data["edge"]["browser"] == "Microsoft Edge"
    assert data["chrome"]["browser"] == "Google Chrome"
    assert data["opera"]["browser"] == "Opera Browser"

def test_api_browser_sync():
    res = client.post("/api/browser/sync")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "browser_status" in data

def test_api_browser_ingest():
    res = client.post("/api/browser/ingest", json={
        "browser": "opera",
        "domain": "opera-telemetry.opera.com",
        "url": "https://opera-telemetry.opera.com/collect",
        "ip": "34.233.253.76",
        "tab_title": "Opera Speed Dial"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["event"]["application"] == "opera"
    assert data["event"]["domain"] == "opera-telemetry.opera.com"

def test_api_system_telemetry():
    res = client.get("/api/system-telemetry")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "edge" in data
    assert "chrome" in data
    assert "opera" in data
    assert "other_apps" in data
    assert "live_sockets" in data
    assert "attack_sources" in data
    countries = [c["country"] for c in data["attack_sources"]]
    assert countries == ["United States", "China", "Russia", "Germany", "Other"]


def test_app_country_classification():
    from backend.app import live_monitor

    assert live_monitor.classify_app_and_ip_country("valorant", "104.18.41.99", "gaming-sdk.com")[:2] == ("United States", "United States")
    assert live_monitor.classify_app_and_ip_country("discord", "162.159.129.235", "")[:2] == ("United States", "United States")
    assert live_monitor.classify_app_and_ip_country("tiktok live studio", "104.18.0.1", "")[:2] == ("China", "China")
    assert live_monitor.classify_app_and_ip_country("wuthering waves", "43.130.0.1", "")[:2] == ("China", "China")
    assert live_monitor.classify_app_and_ip_country("kaspersky", "87.250.250.1", "")[:2] == ("Russia", "Russia")
    assert live_monitor.classify_app_and_ip_country("anydesk", "85.214.0.1", "")[:2] == ("Germany", "Germany")
    assert live_monitor.classify_app_and_ip_country("overwolf", "34.36.216.150", "")[:2] == ("Other", "Israel")
    assert live_monitor.classify_app_and_ip_country("opera", "34.1.1.1", "")[:2] == ("Other", "Norway")
    assert live_monitor.classify_app_and_ip_country("arduino ide", "104.18.1.1", "")[:2] == ("Other", "Italy")
    assert live_monitor.classify_app_and_ip_country("mobaxterm", "104.18.1.1", "")[:2] == ("Other", "France")
    assert live_monitor.classify_app_and_ip_country("vncviewer", "104.18.1.1", "")[:2] == ("Other", "United Kingdom")
    assert live_monitor.classify_app_and_ip_country("spotify", "35.186.224.25", "")[:2] == ("Other", "Sweden")
    assert live_monitor.classify_app_and_ip_country("razer", "104.18.1.1", "")[:2] == ("Other", "Singapore")



