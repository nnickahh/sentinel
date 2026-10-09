"""
Sentinel Local Fallback Intelligence Engine
Guarantees reliable, instant responses even when offline or when Nebius Token Factory
API keys are not yet configured. Provides realistic, domain-tailored privacy decisions.
"""
from typing import List, Dict, Any, Optional
from backend.models import (
    NemotronAnalysis,
    ProtectMeBatchResponse,
    ProtectMeBatchItem,
    RiskLevel,
    ActionDecision,
    ConnectionEvent,
    UserDecisionRecord
)
from privacy_engine.blocklist import lookup_domain

class FallbackPrivacyEngine:
    @classmethod
    def investigate(
        cls,
        domain: str,
        application: str,
        category: str,
        frequency: int,
        past_decision: Optional[UserDecisionRecord] = None
    ) -> NemotronAnalysis:
        """Generate structured privacy analysis locally when Nebius is unavailable."""
        db_match = lookup_domain(domain)
        
        # Vendor profiling
        vendor = db_match["vendor"] if db_match else "Third-Party Service"
        risk_str = db_match["risk_level"] if db_match else ("high" if "track" in domain or "ad" in domain else "medium")
        risk_level = RiskLevel(risk_str) if risk_str in RiskLevel._value2member_map_ else RiskLevel.MEDIUM
        
        # Past decision memory
        memory_suffix = ""
        if past_decision:
            memory_suffix = f" (Note: You previously chose to '{past_decision.decision.value}' connections to this domain)."

        if risk_level == RiskLevel.HIGH:
            rec = ActionDecision.BLOCK
            explanation = (
                f"{application.capitalize()} is connecting to {domain}, operated by {vendor}. "
                f"This endpoint is actively used for behavioral ad tracking or device fingerprinting.{memory_suffix}"
            )
            consequences = [
                "Targeted ad tracking and cross-site user profiling will be halted.",
                "Application core features will continue to function normally."
            ]
        elif risk_level == RiskLevel.MEDIUM:
            rec = ActionDecision.BLOCK if "telemetry" in domain or "analytics" in domain else ActionDecision.ALLOW
            explanation = (
                f"{application.capitalize()} contacted {domain} for background telemetry and usage metrics.{memory_suffix}"
            )
            consequences = [
                "Usage analytics logs will not be uploaded to remote telemetry servers.",
                "Main application playback or communications remain operational."
            ]
        elif risk_level == RiskLevel.LOW:
            rec = ActionDecision.ALLOW
            explanation = (
                f"Diagnostic or crash reporting traffic from {application.capitalize()} to {domain}."
            )
            consequences = [
                "Automated bug logs will not be transmitted if blocked."
            ]
        else: # SAFE
            rec = ActionDecision.ALWAYS_ALLOW
            explanation = (
                f"Essential CDN or secure infrastructure endpoint for {application.capitalize()}."
            )
            consequences = [
                "WARNING: Blocking this connection may break user interface assets or login functions."
            ]

        return NemotronAnalysis(
            risk=risk_level,
            category=category,
            recommendation=rec,
            confidence=0.93,
            explanation=explanation,
            possible_consequences=consequences,
            vendor_profile=f"{vendor} infrastructure endpoint",
            source_model="Local Heuristic Fallback (Nebius Offline/Unset)"
        )

    @classmethod
    def evaluate_protect_me(
        cls,
        events: List[ConnectionEvent],
        past_decisions: Dict[str, UserDecisionRecord]
    ) -> ProtectMeBatchResponse:
        """Batch evaluate connections for the 'Protect Me' agent flow."""
        items: List[ProtectMeBatchItem] = []
        block_count = 0
        keep_count = 0

        for ev in events:
            analysis = cls.investigate(
                domain=ev.domain,
                application=ev.application,
                category=ev.category.value,
                frequency=ev.connection_count,
                past_decision=past_decisions.get(ev.domain)
            )

            # Recommend block for trackers/telemetry/fingerprinters, keep for essential/CDN
            should_block = analysis.risk in [RiskLevel.HIGH, RiskLevel.MEDIUM] and analysis.category not in ["cdn_content", "essential_api"]
            
            action = ActionDecision.BLOCK if should_block else ActionDecision.ALLOW
            if should_block:
                block_count += 1
            else:
                keep_count += 1

            items.append(
                ProtectMeBatchItem(
                    domain=ev.domain,
                    application=ev.application,
                    category=ev.category.value,
                    risk=analysis.risk,
                    recommended_action=action,
                    confidence=analysis.confidence,
                    explanation=analysis.explanation,
                    consequences=analysis.possible_consequences,
                    selected=should_block
                )
            )

        narrative = (
            f"I found {len(items)} connections evaluated across your active applications. "
            f"I recommend blocking {block_count} trackers and telemetry beacons to protect your privacy, "
            f"while keeping {keep_count} connection{'s' if keep_count != 1 else ''} required for essential app operations."
        )

        return ProtectMeBatchResponse(
            analyzed_count=len(items),
            recommended_block_count=block_count,
            recommended_keep_count=keep_count,
            narrative=narrative,
            items=items
        )

    @classmethod
    def generate_report_narrative(
        cls,
        privacy_score: int,
        total_connections: int,
        trackers_detected: int,
        blocked_count: int,
        high_risk_count: int,
        top_apps: List[Dict[str, Any]]
    ) -> str:
        """Generate high-level privacy audit narrative."""
        top_apps_str = ", ".join([f"{a.get('application', 'app')} ({a.get('tracker_count', 0)} trackers)" for a in top_apps[:3]]) or "None"
        
        return (
            f"### Executive Privacy Assessment\n"
            f"Your current desktop privacy score is **{privacy_score}/100**. Sentinel inspected {total_connections} outbound network connections, "
            f"identifying {trackers_detected} telemetry and advertising trackers. A total of **{blocked_count} tracking endpoints are actively blocked**, "
            f"neutralizing {high_risk_count} high-severity profiling vectors.\n\n"
            f"### Top Offending Applications\n"
            f"The applications generating the highest volume of third-party telemetry are: **{top_apps_str}**. "
            f"These applications regularly beacon usage statistics, behavioral telemetry, and hardware device fingerprints in the background.\n\n"
            f"### Telemetry vs Functionality Impact\n"
            f"Sentinel's local privacy engine distinguishes between intrusive background beacons (e.g. ad networks, analytics funnels) "
            f"and critical application infrastructure (e.g. CDNs, secure authentication gateways). By blocking non-essential trackers while preserving "
            f"core application APIs, your desktop apps maintain full speed and functionality without sacrificing your personal privacy.\n\n"
            f"### Recommended Actions\n"
            f"1. Run the **Protect Me** sweep whenever launching new desktop software.\n"
            f"2. Keep high-risk fingerprinting domains blocked to prevent cross-session device tracking.\n"
            f"3. Review telemetry permissions in browser and communication apps."
        )
