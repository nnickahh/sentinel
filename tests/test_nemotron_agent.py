"""
Unit tests for NVIDIA Nemotron Agent & Fallback Engine
Verifies structured JSON parsing, prompt formatting, error recovery, and consequence deduction.
"""
import pytest
from backend.models import RiskLevel, ActionDecision, ConnectionStatus
from agent.nemotron_agent import NemotronPrivacyAgent
from agent.fallback_engine import FallbackPrivacyEngine
from privacy_engine.detector import PrivacyDetector

def test_extract_json_from_raw():
    raw = '{"risk": "high", "category": "ad_tracking", "recommendation": "block", "confidence": 0.95, "explanation": "Ad tracker", "possible_consequences": ["Ads stopped"]}'
    data = NemotronPrivacyAgent._extract_json(raw)
    assert data["risk"] == "high"
    assert data["recommendation"] == "block"

def test_extract_json_from_markdown_fences():
    fenced = """```json
{
  "risk": "medium",
  "category": "telemetry",
  "recommendation": "block",
  "confidence": 0.88,
  "explanation": "Telemetry",
  "possible_consequences": ["Metrics stopped"]
}
```"""
    data = NemotronPrivacyAgent._extract_json(fenced)
    assert data["risk"] == "medium"
    assert data["category"] == "telemetry"

def test_fallback_engine_investigate():
    analysis = FallbackPrivacyEngine.investigate(
        domain="adservice.google.com",
        application="chrome",
        category="ad_tracking",
        frequency=120
    )

    assert analysis.risk == RiskLevel.HIGH
    assert analysis.recommendation == ActionDecision.BLOCK
    assert len(analysis.possible_consequences) > 0
    assert "Google" in analysis.explanation or "Google" in (analysis.vendor_profile or "")

def test_fallback_engine_essential_api():
    analysis = FallbackPrivacyEngine.investigate(
        domain="api.stripe.com",
        application="browser",
        category="essential_api",
        frequency=5
    )

    assert analysis.risk == RiskLevel.SAFE
    assert analysis.recommendation in [ActionDecision.ALLOW, ActionDecision.ALWAYS_ALLOW]
    assert any("Payment" in c or "break" in c.lower() for c in analysis.possible_consequences)

@pytest.mark.asyncio
async def test_agent_investigate_offline_resilience():
    # Agent should gracefully use fallback when Nebius is not configured
    agent = NemotronPrivacyAgent()
    detector = PrivacyDetector()
    ev = detector.create_event("spotify", "spclient.wg.spotify.com")
    
    result = await agent.investigate_connection(ev)
    assert result is not None
    assert result.risk in [RiskLevel.MEDIUM, RiskLevel.HIGH]
    assert len(result.possible_consequences) > 0
