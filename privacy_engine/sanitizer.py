"""
Sentinel Privacy Sanitizer
Enforces strict local privacy guardrails before any data leaves the host machine.
Extracts only domain, app identifier, frequency, category, and risk signals.
Never forwards query parameters, full URLs, auth headers, passwords, or personal content.
"""
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from backend.models import SanitizedTelemetry, ConnectionEvent

class PrivacySanitizer:
    @staticmethod
    def clean_domain(raw_target: str) -> str:
        """
        Extract clean hostname/domain, stripping paths, query parameters,
        passwords, and ports.
        """
        if not raw_target:
            return "unknown"
            
        clean = raw_target.strip().lower()
        if "://" in clean:
            parsed = urlparse(clean)
            clean = parsed.hostname or clean
        else:
            # Strip port or path if any
            clean = clean.split("/")[0].split(":")[0]
            
        # Remove any illegal characters
        clean = re.sub(r"[^a-z0-9.-]", "", clean)
        return clean.strip(".")

    @staticmethod
    def extract_risk_signals(event: ConnectionEvent) -> List[str]:
        """Compute structured risk signals based on connection characteristics."""
        signals: List[str] = []
        
        if event.known_tracker:
            signals.append("known_tracker")
            
        category_name = event.category.value if hasattr(event.category, "value") else str(event.category)
        
        if category_name in ["ad_tracking", "tracking"]:
            signals.append("ad_tracking_network")
        elif category_name == "analytics":
            signals.append("third_party_analytics")
        elif category_name == "telemetry":
            signals.append("background_telemetry")
        elif category_name == "fingerprinting":
            signals.append("fingerprinting_vector")
            signals.append("device_profiling")
            
        if event.connection_count > 50:
            signals.append("high_frequency")
        elif event.connection_count > 15:
            signals.append("frequent_beaconing")
            
        # Check cross-context / unexpected connection
        app_clean = event.application.lower()
        if "spotify" in app_clean and "doubleclick" in event.domain:
            signals.append("cross_context_ad_tracker")
        if "calculator" in app_clean or "notepad" in app_clean:
            signals.append("unexpected_network_activity_for_offline_tool")
            
        return signals

    @classmethod
    def sanitize_for_nemotron(cls, event: ConnectionEvent) -> SanitizedTelemetry:
        """
        Produce a minimal, structured, privacy-preserving object
        for NVIDIA Nemotron analysis.
        """
        clean_app = re.sub(r"[^a-zA-Z0-9_\-\.]", "", event.application.lower())
        clean_app = re.sub(r"\.exe$", "", clean_app)
        clean_dom = cls.clean_domain(event.domain)
        category_str = event.category.value if hasattr(event.category, "value") else str(event.category)
        
        signals = cls.extract_risk_signals(event)
        
        return SanitizedTelemetry(
            application=clean_app,
            domain=clean_dom,
            category=category_str,
            frequency=event.connection_count,
            known_tracker=event.known_tracker,
            risk_signals=signals
        )
