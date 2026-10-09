"""
Unit & Integration tests for Sentinel 'Protect Me' 10-step agent workflow
"""
import pytest
from backend.models import RiskLevel, ActionDecision, ConnectionStatus
from privacy_engine.detector import PrivacyDetector
from database.policy_store import PolicyStore
from monitor.demo_traffic import DemoTrafficGenerator
from agent.nemotron_agent import NemotronPrivacyAgent

@pytest.mark.asyncio
async def test_protect_me_workflow():
    detector = PrivacyDetector()
    store = PolicyStore(":memory:")
    demo = DemoTrafficGenerator(detector, store)
    agent = NemotronPrivacyAgent()

    # Step 1 & 2: Check recent activity and find suspicious connections
    events = demo.get_events()
    assert len(events) > 0
    
    initial_score = detector.calculate_privacy_score(events)
    assert initial_score < 100

    # Step 3 & 4: Send to Nemotron / Agent for assessment
    past_rules = {r.domain: r for r in store.list_active_rules()}
    plan = await agent.evaluate_protect_me_batch(events, past_rules)

    # Step 5 & 6: Verify recommendations
    assert plan.analyzed_count == len(events)
    assert plan.recommended_block_count > 0
    assert plan.recommended_keep_count > 0

    # Step 7 & 8: Apply selected rules
    for item in plan.items:
        if item.recommended_action == ActionDecision.BLOCK:
            store.save_decision(
                domain=item.domain,
                application=item.application,
                decision=ActionDecision.BLOCK,
                reason="Applied via test Protect Me"
            )
            demo.update_event_status(item.domain, ConnectionStatus.BLOCKED)

    # Step 9 & 10: Verify action worked and score improved
    events_after = demo.get_events()
    new_score = detector.calculate_privacy_score(events_after)

    assert new_score > initial_score
    # Verify that essential APIs were NOT blocked
    stripe_rec = store.get_decision("api.stripe.com", "browser")
    assert stripe_rec is None or stripe_rec.decision != ActionDecision.BLOCK
