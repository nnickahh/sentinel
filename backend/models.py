from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class RiskLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"

class Category(str, Enum):
    AD_TRACKING = "ad_tracking"
    ANALYTICS = "analytics"
    TELEMETRY = "telemetry"
    FINGERPRINTING = "fingerprinting"
    CRASH_REPORTING = "crash_reporting"
    CDN_CONTENT = "cdn_content"
    ESSENTIAL_API = "essential_api"
    UNKNOWN = "unknown"

class ActionDecision(str, Enum):
    BLOCK = "block"
    ALLOW = "allow"
    ALWAYS_ALLOW = "always_allow"
    ASK_LATER = "ask_later"

class ConnectionStatus(str, Enum):
    ACTIVE = "active"
    BLOCKED = "blocked"
    ALLOWED = "allowed"

class ConnectionEvent(BaseModel):
    id: str
    application: str
    domain: str
    ip: Optional[str] = None
    port: Optional[int] = 443
    protocol: str = "TCP"
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    connection_count: int = 1
    category: Category = Category.UNKNOWN
    known_tracker: bool = False
    risk_level: RiskLevel = RiskLevel.LOW
    risk_score: int = 20  # 0 to 100
    status: ConnectionStatus = ConnectionStatus.ACTIVE
    vendor: Optional[str] = "Unknown"
    details: Optional[str] = None

class SanitizedTelemetry(BaseModel):
    application: str
    domain: str
    category: str
    frequency: int
    known_tracker: bool
    risk_signals: List[str]

class NemotronAnalysis(BaseModel):
    risk: RiskLevel
    category: str
    recommendation: ActionDecision
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    possible_consequences: List[str]
    vendor_profile: Optional[str] = None
    source_model: Optional[str] = "NVIDIA Nemotron"

class UserDecisionRecord(BaseModel):
    domain: str
    application: str
    decision: ActionDecision
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    reason: Optional[str] = None
    active: bool = True

class ProtectMeBatchItem(BaseModel):
    domain: str
    application: str
    category: str
    risk: RiskLevel
    recommended_action: ActionDecision
    confidence: float
    explanation: str
    consequences: List[str]
    selected: bool = True  # user can toggle in UI

class ProtectMeBatchResponse(BaseModel):
    analyzed_count: int
    recommended_block_count: int
    recommended_keep_count: int
    narrative: str
    items: List[ProtectMeBatchItem]

class ApplyPolicyItem(BaseModel):
    domain: str
    application: str
    action: ActionDecision

class ApplyPolicyRequest(BaseModel):
    decisions: List[ApplyPolicyItem]

class ApplyPolicyResponse(BaseModel):
    applied_count: int
    blocked_domains: List[str]
    allowed_domains: List[str]
    previous_score: int
    new_score: int
    summary: str

class DashboardStats(BaseModel):
    privacy_score: int
    total_connections: int
    trackers_detected: int
    blocked_count: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    demo_mode: bool
    nebius_connected: bool
    model_name: str

class PrivacyReport(BaseModel):
    score: int
    timestamp: str
    total_connections: int
    trackers_detected: int
    blocked_count: int
    high_risk_count: int
    top_offending_apps: List[Dict[str, Any]]
    category_breakdown: Dict[str, int]
    key_findings: List[str]
    recommended_actions: List[str]
    narrative_report: str
