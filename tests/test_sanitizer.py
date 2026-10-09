"""
Unit tests for Sentinel Privacy Sanitizer
Verifies PII stripping, query parameter removal, and structured payload generation for Nemotron.
"""
from backend.models import ConnectionStatus
from privacy_engine.detector import PrivacyDetector
from privacy_engine.sanitizer import PrivacySanitizer

def test_clean_domain_stripping():
    # Test path and query string removal
    dirty = "https://analytics.example.com/v1/track?user_id=12345&token=secret"
    clean = PrivacySanitizer.clean_domain(dirty)
    assert clean == "analytics.example.com"
    assert "token" not in clean
    assert "12345" not in clean

    # Test port removal
    with_port = "telemetry.zoom.us:8443"
    assert PrivacySanitizer.clean_domain(with_port) == "telemetry.zoom.us"

def test_sanitization_for_nemotron():
    detector = PrivacyDetector()
    ev = detector.create_event(
        application="Chrome.exe",
        domain="adservice.google.com",
        connection_count=143,
        status=ConnectionStatus.ACTIVE
    )

    sanitized = PrivacySanitizer.sanitize_for_nemotron(ev)
    
    assert sanitized.application == "chrome"
    assert sanitized.domain == "adservice.google.com"
    assert sanitized.category in ["ad_tracking", "analytics"]
    assert sanitized.frequency == 143
    assert sanitized.known_tracker is True
    assert "known_tracker" in sanitized.risk_signals
    assert "high_frequency" in sanitized.risk_signals
