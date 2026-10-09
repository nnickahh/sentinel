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
        "description": "Cross-site advertising tracking network beaconing user clicks and queries"
    },
    {
        "app": "spotify",
        "domain": "spclient.wg.spotify.com",
        "ip": "35.186.224.25",
        "port": 443,
        "base_count": 52,
        "description": "Background audio listening behavior and playback UI telemetry"
    },
    {
        "app": "discord",
        "domain": "analytics.discord.com",
        "ip": "162.159.135.232",
        "port": 443,
        "base_count": 31,
        "description": "Application interaction funnels and UI click metrics"
    },
    {
        "app": "chrome",
        "domain": "fingerprint.device-id.net",
        "ip": "104.21.65.112",
        "port": 443,
        "base_count": 19,
        "description": "Aggressive canvas and hardware font device fingerprinting probe"
    },
    {
        "app": "zoom",
        "domain": "telemetry.zoom.us",
        "ip": "170.114.10.88",
        "port": 443,
        "base_count": 27,
        "description": "Call quality telemetry and bandwidth telemetry ping"
    },
    {
        "app": "slack",
        "domain": "cdn.slack-edge.com",
        "ip": "151.101.65.140",
        "port": 443,
        "base_count": 115,
        "description": "Essential static UI styling and avatar delivery (safe)"
    },
    {
        "app": "browser",
        "domain": "api.stripe.com",
        "ip": "54.187.174.169",
        "port": 443,
        "base_count": 8,
        "description": "Encrypted payment processor gateway (safe essential API)"
    },
    {
        "app": "edge",
        "domain": "edge.activity.windows.com",
        "ip": "20.190.159.2",
        "port": 443,
        "base_count": 46,
        "description": "Microsoft Windows timeline sync and browsing history telemetry"
    },
    {
        "app": "vscode",
        "domain": "vortex.data.microsoft.com",
        "ip": "20.42.72.100",
        "port": 443,
        "base_count": 38,
        "description": "Code editor command usage and crash telemetry"
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
                else:
                    ev.status = ConnectionStatus.ALLOWED
            else:
                # Still active
                if ev.status != ConnectionStatus.BLOCKED:
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
