"""
Unit tests for Sentinel Privacy Detector and Risk Scoring Heuristics
"""
import pytest
from backend.models import RiskLevel, Category, ConnectionStatus
from privacy_engine.detector import PrivacyDetector

def test_known_ad_tracker_detection():
    detector = PrivacyDetector()
    cat, risk, score, is_tracker, vendor, consequences = detector.classify_domain("adservice.google.com")
    
    assert cat == Category.AD_TRACKING
    assert risk == RiskLevel.HIGH
    assert score >= 85
    assert is_tracker is True
    assert vendor == "Google"

def test_fingerprinting_detection():
    detector = PrivacyDetector()
    cat, risk, score, is_tracker, vendor, consequences = detector.classify_domain("fingerprint.device-id.net")
    
    assert cat == Category.FINGERPRINTING
    assert risk == RiskLevel.HIGH
    assert score >= 90
    assert is_tracker is True

def test_telemetry_detection():
    detector = PrivacyDetector()
    cat, risk, score, is_tracker, vendor, consequences = detector.classify_domain("spclient.wg.spotify.com")
    
    assert cat == Category.TELEMETRY
    assert risk == RiskLevel.MEDIUM
    assert is_tracker is True
    assert vendor == "Spotify"

def test_cdn_safe_detection():
    detector = PrivacyDetector()
    cat, risk, score, is_tracker, vendor, consequences = detector.classify_domain("cdn.cloudflare.net")
    
    assert cat == Category.CDN_CONTENT
    assert risk == RiskLevel.SAFE
    assert is_tracker is False

def test_essential_api_safe_detection():
    detector = PrivacyDetector()
    cat, risk, score, is_tracker, vendor, consequences = detector.classify_domain("api.stripe.com")
    
    assert cat == Category.ESSENTIAL_API
    assert risk == RiskLevel.SAFE
    assert is_tracker is False

def test_privacy_score_calculation():
    detector = PrivacyDetector()
    
    # Clean state
    assert detector.calculate_privacy_score([]) == 98
    
    # Add high risk active tracker
    ev1 = detector.create_event("chrome", "adservice.google.com", status=ConnectionStatus.ACTIVE)
    ev2 = detector.create_event("chrome", "fingerprint.device-id.net", status=ConnectionStatus.ACTIVE)
    score_unprotected = detector.calculate_privacy_score([ev1, ev2])
    
    # Block one tracker
    ev1.status = ConnectionStatus.BLOCKED
    score_protected = detector.calculate_privacy_score([ev1, ev2])
    
    assert score_protected > score_unprotected
