"""
Sentinel Realistic Demo Traffic Generator
Provides instant out-of-the-box demonstration for hackathon judges and evaluators.
Simulates realistic browser ad-trackers, music telemetry, chat analytics, CDNs, and fingerprinting.
"""
import random
from typing import List, Dict, Any, Optional
from datetime import datetime
from backend.models import ConnectionEvent, ConnectionStatus, ActionDecision
from privacy_engine.detector import PrivacyDetector
from database.policy_store import PolicyStore

# Authentic desktop application telemetry simulation scenarios
DEMO_SCENARIOS = [
    {
        "app": "chrome",
        "domain": "adservice.google.com",
        "ip": "142.250.190.46",
        "port": 443,
        "base_count": 84,
        "country": "United States",
        "description": "Cross-site advertising tracking network beaconing user clicks and queries",
        "ai_explanation": "Nemotron Analysis: Collects cross-site browsing profiles, ad click identifiers, and behavioral conversion signals. High privacy risk; blocking stops targeted ad tracking without affecting web browsing.",
        "breakage_risk": "None — safe to block without breaking websites"
    },
    {
        "app": "spotify",
        "domain": "spclient.wg.spotify.com",
        "ip": "35.186.224.25",
        "port": 443,
        "base_count": 52,
        "country": "Sweden",
        "description": "Background audio listening behavior and playback UI telemetry",
        "ai_explanation": "Nemotron Analysis: Transmits granular playback interaction telemetry, skip rates, and session duration metrics. Medium risk; blocking halts telemetry upload while audio streaming continues.",
        "breakage_risk": "Low — audio streaming unaffected"
    },
    {
        "app": "discord",
        "domain": "analytics.discord.com",
        "ip": "162.159.135.232",
        "port": 443,
        "base_count": 31,
        "country": "United States",
        "description": "Application interaction funnels and UI click metrics",
        "ai_explanation": "Nemotron Analysis: Captures client UI click events, server navigation funnels, and active window focus state. Safe to block; voice and chat channels remain 100% functional.",
        "breakage_risk": "None — voice and chat work normally"
    },
    {
        "app": "chrome",
        "domain": "fingerprint.device-id.net",
        "ip": "155.31.171.33",
        "port": 443,
        "base_count": 19,
        "country": "China",
        "description": "Malware signature & aggressive canvas/hardware device fingerprinting probe",
        "ai_explanation": "Nemotron Critical Alert: Probes WebGL, AudioContext, and GPU rendering signatures from 155.31.171.33 to construct a permanent hardware fingerprint across sessions. Immediate block recommended.",
        "breakage_risk": "None — malicious tracker only"
    },
    {
        "app": "zoom",
        "domain": "telemetry.zoom.us",
        "ip": "170.114.10.88",
        "port": 443,
        "base_count": 27,
        "country": "United States",
        "description": "Call quality telemetry and device diagnostic ping",
        "ai_explanation": "Nemotron Analysis: Periodically beacons microphone/camera hardware metadata and network jitter statistics. Medium risk; blocking prevents background diagnostics while video calls work normally.",
        "breakage_risk": "None — meetings and video unaffected"
    },
    {
        "app": "slack",
        "domain": "cdn.slack-edge.com",
        "ip": "151.101.65.140",
        "port": 443,
        "base_count": 115,
        "country": "United States",
        "description": "Essential static UI styling and avatar delivery (safe)",
        "ai_explanation": "Nemotron Analysis: Essential content delivery network serving workspace icons, attachments, and stylesheets. No behavioral tracking detected. AI Autopilot preserves this connection.",
        "breakage_risk": "High — blocking will break Slack images & UI"
    },
    {
        "app": "browser",
        "domain": "api.stripe.com",
        "ip": "54.187.174.169",
        "port": 443,
        "base_count": 8,
        "country": "United States",
        "description": "Encrypted payment processor gateway (safe essential API)",
        "ai_explanation": "Nemotron Analysis: Verified PCI-DSS encrypted payment API gateway. Required for checkout and billing flows. AI Autopilot whitelists this connection to prevent breaking transactions.",
        "breakage_risk": "High — blocking will break checkout flows"
    },
    {
        "app": "edge",
        "domain": "edge.activity.windows.com",
        "ip": "20.190.159.2",
        "port": 443,
        "base_count": 46,
        "country": "Russia",
        "description": "Microsoft Windows timeline sync and browsing history telemetry",
        "ai_explanation": "Nemotron Analysis: Synchronizes local application launch timestamps and browser tab history to cloud telemetry endpoints. High privacy exposure; safe to block.",
        "breakage_risk": "None — local browser works normally"
    },
    {
        "app": "vscode",
        "domain": "vortex.data.microsoft.com",
        "ip": "20.42.72.100",
        "port": 443,
        "base_count": 38,
        "country": "Brazil",
        "description": "Code editor command usage and extension telemetry",
        "ai_explanation": "Nemotron Analysis: Uploads workspace extension invocation counts, crash dumps, and editor performance metrics. Safe to block without impacting coding or extensions.",
        "breakage_risk": "None — editor and extensions unaffected"
    }
]

class DemoTrafficGenerator:
    def __init__(self, detector: PrivacyDetector, policy_store: PolicyStore):
        self.detector = detector
        self.policy_store = policy_store
        self._events: Dict[str, ConnectionEvent] = {}
        self._init_demo_state()

    def _init_demo_state(self):
        """Build initial realistic pool of events."""
        for scenario in DEMO_SCENARIOS:
            dom = scenario["domain"]
            app = scenario["app"]
            
            # Check if user already has an active policy
            decision_rec = self.policy_store.get_decision(dom, app)
            status = ConnectionStatus.ACTIVE
            if decision_rec:
                if decision_rec.decision in [ActionDecision.BLOCK]:
                    status = ConnectionStatus.BLOCKED
                elif decision_rec.decision in [ActionDecision.WARN]:
                    status = ConnectionStatus.WARNED
                elif decision_rec.decision in [ActionDecision.ALLOW, ActionDecision.ALWAYS_ALLOW]:
                    status = ConnectionStatus.ALLOWED

            ev = self.detector.create_event(
                application=app,
                domain=dom,
                ip=scenario["ip"],
                port=scenario["port"],
                connection_count=scenario["base_count"],
                status=status
            )
            if scenario.get("description"):
                ev.details = scenario["description"]
            ev.country = scenario.get("country", "United States")
            ev.ai_explanation = scenario.get("ai_explanation")
            ev.breakage_risk = scenario.get("breakage_risk", "None — safe to block")
            self._events[ev.domain] = ev

    def get_events(self) -> List[ConnectionEvent]:
        """
        Return the current state of simulated connections,
        applying slight dynamic jitter to connection counters.
        """
        for dom, ev in self._events.items():
            # Refresh status against policy store
            rec = self.policy_store.get_decision(ev.domain, ev.application)
            if rec:
                if rec.decision == ActionDecision.BLOCK:
                    ev.status = ConnectionStatus.BLOCKED
                elif rec.decision == ActionDecision.WARN:
                    ev.status = ConnectionStatus.WARNED
                else:
                    ev.status = ConnectionStatus.ALLOWED
            else:
                # Still active
                if ev.status not in [ConnectionStatus.BLOCKED, ConnectionStatus.WARNED]:
                    ev.status = ConnectionStatus.ACTIVE

            # If active, randomly increment counter slightly to simulate live traffic
            if ev.status == ConnectionStatus.ACTIVE and random.random() < 0.35:
                ev.connection_count += random.randint(1, 3)

        return list(self._events.values())

    def update_event_status(self, domain: str, status: ConnectionStatus):
        """Update status of a simulated domain (e.g. when blocked)."""
        if domain in self._events:
            self._events[domain].status = status

    def reset(self):
        """Reset demo dataset."""
        self._events.clear()
        self._init_demo_state()
