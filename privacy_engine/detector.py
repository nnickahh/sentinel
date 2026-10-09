"""
Sentinel Local Privacy Detector
Classifies connections, evaluates risk heuristics, and calculates local privacy scores.
First line of defense before consulting NVIDIA Nemotron.
"""
import uuid
import re
from typing import List, Dict, Any, Tuple
from datetime import datetime, timezone

from backend.models import ConnectionEvent, RiskLevel, Category, ConnectionStatus
from privacy_engine.blocklist import lookup_domain

# Heuristic keyword matchers for domains not in static blocklist
HEURISTIC_PATTERNS = [
    (r"(?:adservice|doubleclick|adserver|pagead|adnxs|advertising|popads)", Category.AD_TRACKING, RiskLevel.HIGH, 88),
    (r"(?:fingerprint|canvas-id|device-id|webgl-id|audiocontext)", Category.FINGERPRINTING, RiskLevel.HIGH, 94),
    (r"(?:analytics|segment|mixpanel|amplitude|kissmetrics|statcounter)", Category.ANALYTICS, RiskLevel.MEDIUM, 70),
    (r"(?:telemetry|vortex|diag|beacon|heartbeat|usage-stats|metrics)", Category.TELEMETRY, RiskLevel.MEDIUM, 65),
    (r"(?:crashlytics|bugsnag|sentry|rollbar|appcenter|error-log)", Category.CRASH_REPORTING, RiskLevel.LOW, 35),
    (r"(?:cdn|akamai|fastly|cloudfront|cloudflare|static|assets)", Category.CDN_CONTENT, RiskLevel.SAFE, 10),
    (r"(?:api|auth|login|gateway|stripe|paypal|oauth)", Category.ESSENTIAL_API, RiskLevel.SAFE, 12),
]

class PrivacyDetector:
    def __init__(self):
        pass

    def classify_domain(self, domain: str) -> Tuple[Category, RiskLevel, int, bool, str, List[str]]:
        """
        Classifies domain using database lookup first, then regex heuristics.
        Returns: (category, risk_level, risk_score, known_tracker, vendor, consequences)
        """
        clean_dom = domain.lower().strip().rstrip(".")
        
        # 1. Exact or suffix lookup in database
        db_match = lookup_domain(clean_dom)
        if db_match:
            cat = Category(db_match["category"]) if db_match["category"] in Category._value2member_map_ else Category.UNKNOWN
            risk = RiskLevel(db_match["risk_level"])
            return (
                cat,
                risk,
                db_match["risk_score"],
                db_match["known_tracker"],
                db_match["vendor"],
                db_match.get("consequences", ["Tracking will be disabled"])
            )
            
        # 2. Heuristic regex pattern matching
        for pattern, cat, risk, score in HEURISTIC_PATTERNS:
            if re.search(pattern, clean_dom):
                is_tracker = risk in [RiskLevel.HIGH, RiskLevel.MEDIUM]
                return (
                    cat,
                    risk,
                    score,
                    is_tracker,
                    "Automated Classification",
                    [f"Suspected {cat.value} activity"]
                )
                
        # 3. Default safe/unknown
        return (Category.UNKNOWN, RiskLevel.LOW, 25, False, "General Domain", ["Standard network connection"])

    def create_event(
        self,
        application: str,
        domain: str,
        ip: str = "127.0.0.1",
        port: int = 443,
        connection_count: int = 1,
        status: ConnectionStatus = ConnectionStatus.ACTIVE
    ) -> ConnectionEvent:
        """Create and score a structured ConnectionEvent."""
        category, risk, score, is_tracker, vendor, consequences = self.classify_domain(domain)
        
        # Adjust risk score for high connection frequency
        if connection_count > 100:
            score = min(100, score + 15)
        elif connection_count > 30:
            score = min(100, score + 8)

        event_id = f"evt_{uuid.uuid4().hex[:10]}"
        
        return ConnectionEvent(
            id=event_id,
            application=application.lower(),
            domain=domain.lower(),
            ip=ip,
            port=port,
            protocol="TCP",
            timestamp=datetime.now(timezone.utc).isoformat(),
            connection_count=connection_count,
            category=category,
            known_tracker=is_tracker,
            risk_level=risk,
            risk_score=score,
            status=status,
            vendor=vendor,
            details=", ".join(consequences)
        )

    @staticmethod
    def calculate_privacy_score(events: List[ConnectionEvent]) -> int:
        """
        Calculate overall system privacy score (0 - 100).
        High-risk active trackers deduct points.
        Blocked trackers recover points.
        """
        if not events:
            return 98
            
        score = 100.0
        
        for ev in events:
            if ev.status == ConnectionStatus.BLOCKED:
                # Blocked items recover privacy health
                continue
                
            if ev.risk_level == RiskLevel.HIGH:
                score -= 4.0
            elif ev.risk_level == RiskLevel.MEDIUM:
                score -= 1.8
            elif ev.risk_level == RiskLevel.LOW and ev.known_tracker:
                score -= 0.5
                
        return max(20, min(100, int(round(score))))
