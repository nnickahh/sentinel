"""
Unit tests for Sentinel SQLite Policy Store
Verifies persistent policy rules, decision memory, and event history logging.
"""
import pytest
from backend.models import ActionDecision, ConnectionStatus
from database.policy_store import PolicyStore
from privacy_engine.detector import PrivacyDetector

@pytest.fixture
def temp_store():
    # Use in-memory SQLite database for isolated test execution
    store = PolicyStore(db_path=":memory:")
    yield store
    store.clear_all()

def test_save_and_retrieve_decision(temp_store):
    temp_store.save_decision(
        domain="analytics.example.com",
        application="chrome",
        decision=ActionDecision.BLOCK,
        reason="User requested block"
    )

    rec = temp_store.get_decision("analytics.example.com", "chrome")
    assert rec is not None
    assert rec.domain == "analytics.example.com"
    assert rec.decision == ActionDecision.BLOCK
    assert rec.application == "chrome"

def test_wildcard_application_policy(temp_store):
    # Rule applied globally across all apps
    temp_store.save_decision(
        domain="doubleclick.net",
        application="*",
        decision=ActionDecision.BLOCK
    )

    rec = temp_store.get_decision("doubleclick.net", "firefox")
    assert rec is not None
    assert rec.decision == ActionDecision.BLOCK

def test_delete_rule(temp_store):
    temp_store.save_decision(
        domain="spclient.wg.spotify.com",
        application="spotify",
        decision=ActionDecision.BLOCK
    )

    assert temp_store.get_decision("spclient.wg.spotify.com", "spotify") is not None
    
    deleted = temp_store.delete_rule("spclient.wg.spotify.com", "spotify")
    assert deleted is True
    assert temp_store.get_decision("spclient.wg.spotify.com", "spotify") is None

def test_record_events_and_top_offenders(temp_store):
    detector = PrivacyDetector()
    ev1 = detector.create_event("chrome", "adservice.google.com")
    ev2 = detector.create_event("chrome", "fingerprint.device-id.net")
    ev3 = detector.create_event("discord", "analytics.discord.com")
    
    temp_store.record_events([ev1, ev2, ev3])
    
    top_apps = temp_store.get_top_offenders()
    assert len(top_apps) >= 2
    # Chrome has 2 trackers, should be first
    assert top_apps[0]["application"] == "chrome"
    assert top_apps[0]["tracker_count"] == 2
