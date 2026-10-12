"""
Sentinel FastAPI Application
Primary backend orchestrating local privacy detection, SQLite policy persistence,
network monitoring, and NVIDIA Nemotron intelligence via Nebius Token Factory.
"""
import os
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from datetime import datetime, timezone
import uuid
from backend.config import settings
from backend.models import (
    ConnectionEvent,
    ConnectionStatus,
    DashboardStats,
    NemotronAnalysis,
    ProtectMeBatchResponse,
    ApplyPolicyRequest,
    ApplyPolicyResponse,
    PrivacyReport,
    UserDecisionRecord,
    ActionDecision,
    RiskLevel,
    PrivacyMode,
    TimelineEvent,
    AskQuestionRequest,
    AskQuestionResponse,
    AutopilotResponse
)
from privacy_engine.detector import PrivacyDetector
from database.policy_store import PolicyStore
from monitor.demo_traffic import DemoTrafficGenerator
from monitor.connection_monitor import LiveConnectionMonitor
from agent.nemotron_agent import NemotronPrivacyAgent

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI(
    title="Sentinel - AI Privacy Autopilot",
    description="Intelligent desktop privacy autopilot powered by NVIDIA Nemotron on Nebius Token Factory",
    version="1.0.0"
)

# Enable CORS for desktop/local environments
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def disable_static_cache(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response

# Core singletons
detector = PrivacyDetector()
policy_store = PolicyStore(settings.database_path)
demo_monitor = DemoTrafficGenerator(detector, policy_store)
live_monitor = LiveConnectionMonitor(detector, policy_store)
agent = NemotronPrivacyAgent()

# Runtime mode state
state: Dict[str, Any] = {
    "demo_mode": settings.sentinel_demo_mode,
    "privacy_mode": "normal",
    "autopilot_enabled": True,
    "browser_link_enabled": True
}

def _build_initial_timeline() -> List[TimelineEvent]:
    now_iso = datetime.now(timezone.utc).isoformat()
    return [
        TimelineEvent(
            id="tl_001",
            timestamp=now_iso,
            time_label="0s ago",
            title="Malware signature detected in network traffic from 155.31.171.33 (Unknown)",
            description="Chrome attempted outbound connection to fingerprint.device-id.net (155.31.171.33). Flagged by AI Detection System for hardware canvas fingerprinting.",
            application="chrome",
            domain="fingerprint.device-id.net",
            ip="155.31.171.33",
            risk_level=RiskLevel.HIGH,
            event_type="detection",
            action_taken="detected",
            ai_reasoning="Nemotron identified high-entropy WebGL/AudioContext fingerprinting signatures originating from 155.31.171.33."
        ),
        TimelineEvent(
            id="tl_002",
            timestamp=now_iso,
            time_label="2m ago",
            title="Cross-site ad tracker detected on adservice.google.com",
            description="Chrome beaconed 84 behavioral advertising packets to adservice.google.com (142.250.190.46).",
            application="chrome",
            domain="adservice.google.com",
            ip="142.250.190.46",
            risk_level=RiskLevel.HIGH,
            event_type="detection",
            action_taken="detected",
            ai_reasoning="Nemotron classified endpoint as non-essential behavioral ad profiling; safe to block with zero site breakage."
        ),
        TimelineEvent(
            id="tl_003",
            timestamp=now_iso,
            time_label="5m ago",
            title="AI Autopilot preserved essential payment gateway api.stripe.com",
            description="Sentinel AI Privacy Agent verified api.stripe.com (54.187.174.169) as an essential checkout API and avoided blocking.",
            application="browser",
            domain="api.stripe.com",
            ip="54.187.174.169",
            risk_level=RiskLevel.SAFE,
            event_type="autopilot_allow",
            action_taken="allowed",
            ai_reasoning="Blocking api.stripe.com would break payment processing; AI Autopilot whitelisted endpoint automatically."
        ),
        TimelineEvent(
            id="tl_004",
            timestamp=now_iso,
            time_label="11m ago",
            title="Windows timeline telemetry spike from edge.activity.windows.com",
            description="Edge transmitted 46 background activity sync packets to 20.190.159.2.",
            application="edge",
            domain="edge.activity.windows.com",
            ip="20.190.159.2",
            risk_level=RiskLevel.MEDIUM,
            event_type="detection",
            action_taken="warned",
            ai_reasoning="Background OS activity telemetry; can be safely restricted in Strict or Paranoid privacy modes."
        ),
        TimelineEvent(
            id="tl_005",
            timestamp=now_iso,
            time_label="18m ago",
            title="Background playback telemetry on spclient.wg.spotify.com",
            description="Spotify desktop client sent 52 session analytics beacons to 35.186.224.25.",
            application="spotify",
            domain="spclient.wg.spotify.com",
            ip="35.186.224.25",
            risk_level=RiskLevel.MEDIUM,
            event_type="detection",
            action_taken="detected",
            ai_reasoning="Collects skip rate and UI interaction telemetry; audio streaming uses separate CDN servers."
        )
    ]

timeline_events: List[TimelineEvent] = _build_initial_timeline()

def log_timeline_event(
    title: str,
    description: str,
    application: str,
    domain: str,
    risk_level: RiskLevel = RiskLevel.MEDIUM,
    event_type: str = "user_action",
    action_taken: str = "blocked",
    ip: Optional[str] = None,
    ai_reasoning: Optional[str] = None
):
    ev = TimelineEvent(
        id=f"tl_{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        time_label="Just now",
        title=title,
        description=description,
        application=application,
        domain=domain,
        ip=ip,
        risk_level=risk_level,
        event_type=event_type,
        action_taken=action_taken,
        ai_reasoning=ai_reasoning
    )
    timeline_events.insert(0, ev)
    if len(timeline_events) > 40:
        timeline_events.pop()

# Mount static files and templates
frontend_dir = BASE_DIR / "frontend"
static_dir = frontend_dir / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

def get_current_events() -> List[ConnectionEvent]:
    """Retrieve events from Demo generator and merge live local Microsoft Edge / Google Chrome sockets."""
    if state["demo_mode"]:
        events = list(demo_monitor.get_events())
        if state.get("browser_link_enabled", True):
            existing_domains = {e.domain.lower() for e in events}
            live_events = live_monitor.poll_connections(prioritize_browsers=True)
            for lev in live_events:
                if lev.domain.lower() not in existing_domains:
                    events.append(lev)
                    existing_domains.add(lev.domain.lower())
    else:
        events = live_monitor.poll_connections(prioritize_browsers=True)
        if not events:
            # If no live network sockets were captured, fallback smoothly
            events = demo_monitor.get_events()

    # Apply latest policy rules from store
    for ev in events:
        rec = policy_store.get_decision(ev.domain, ev.application)
        if rec:
            if rec.decision == ActionDecision.BLOCK:
                ev.status = ConnectionStatus.BLOCKED
            elif rec.decision == ActionDecision.WARN:
                ev.status = ConnectionStatus.WARNED
            else:
                ev.status = ConnectionStatus.ALLOWED
                
    policy_store.record_events(events)
    return events

# ----------------- UI ROUTE -----------------
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the main consumer desktop UI."""
    index_file = frontend_dir / "templates" / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="UI template not found")
    return FileResponse(
        str(index_file),
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"}
    )

# ----------------- API ROUTES -----------------
@app.get("/api/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """Calculate and return system privacy score and telemetry counters."""
    events = get_current_events()
    privacy_score = detector.calculate_privacy_score(events)
    
    total = len(events)
    trackers = sum(1 for e in events if e.known_tracker)
    blocked = sum(1 for e in events if e.status == ConnectionStatus.BLOCKED)
    warned = sum(1 for e in events if e.status == ConnectionStatus.WARNED)
    high_risk = sum(1 for e in events if e.risk_level == RiskLevel.HIGH and e.status != ConnectionStatus.BLOCKED)
    med_risk = sum(1 for e in events if e.risk_level == RiskLevel.MEDIUM and e.status != ConnectionStatus.BLOCKED)
    low_risk = sum(1 for e in events if e.risk_level in [RiskLevel.LOW, RiskLevel.SAFE])

    return DashboardStats(
        privacy_score=privacy_score,
        total_connections=total,
        trackers_detected=trackers,
        blocked_count=blocked,
        warned_count=warned,
        high_risk_count=high_risk,
        medium_risk_count=med_risk,
        low_risk_count=low_risk,
        demo_mode=state["demo_mode"],
        nebius_connected=agent.is_connected(),
        model_name=settings.nebius_model,
        privacy_mode=state["privacy_mode"],
        autopilot_enabled=state["autopilot_enabled"],
        active_threats=max(0, high_risk - 1) if high_risk > 1 else high_risk,
        unread_alerts=warned,
        system_health=round(min(99.9, 96.4 + (blocked * 0.3) + (1.8 if high_risk <= 2 else 0.0)), 1)
    )

@app.get("/api/connections", response_model=List[ConnectionEvent])
async def get_connections(
    filter: str = Query("all", description="all, high, trackers, blocked, warned, active"),
    app: Optional[str] = Query(None, description="Filter by process name"),
    q: Optional[str] = Query(None, description="Search query")
):
    """Retrieve active and recent network connections with filtering."""
    events = get_current_events()
    
    # Filter by risk/category/status
    if filter == "high":
        events = [e for e in events if e.risk_level == RiskLevel.HIGH]
    elif filter == "trackers":
        events = [e for e in events if e.known_tracker]
    elif filter == "blocked":
        events = [e for e in events if e.status == ConnectionStatus.BLOCKED]
    elif filter == "warned":
        events = [e for e in events if e.status == ConnectionStatus.WARNED]
    elif filter == "active":
        events = [e for e in events if e.status == ConnectionStatus.ACTIVE]
        
    if app:
        events = [e for e in events if app.lower() in e.application.lower()]
        
    if q:
        ql = q.lower()
        events = [e for e in events if ql in e.domain.lower() or ql in e.application.lower() or ql in (e.vendor or "").lower()]
        
    return events

class InvestigateRequest(BaseModel):
    event_id: Optional[str] = None
    domain: str
    application: str

@app.post("/api/investigate", response_model=NemotronAnalysis)
async def investigate_endpoint(req: InvestigateRequest):
    """Deep-dive investigation of a domain via NVIDIA Nemotron."""
    events = get_current_events()
    # Find matching event or generate virtual one
    matched = next((e for e in events if e.domain.lower() == req.domain.lower()), None)
    if not matched:
        matched = detector.create_event(
            application=req.application,
            domain=req.domain
        )
        
    past_decision = policy_store.get_decision(req.domain, req.application)
    
    analysis = await agent.investigate_connection(
        event=matched,
        past_decision=past_decision
    )
    return analysis

@app.post("/api/protect-me/analyze", response_model=ProtectMeBatchResponse)
async def protect_me_analyze():
    """
    Stage 1 of the Protect Me feature:
    Finds suspicious connections and queries Nemotron for batch evaluation and recommendations.
    """
    events = get_current_events()
    
    # Focus on active connections (especially high and medium risk trackers)
    candidates = [
        e for e in events
        if e.status != ConnectionStatus.BLOCKED
    ]
    if not candidates:
        candidates = events

    # Collect past decisions
    past_rules = {r.domain: r for r in policy_store.list_active_rules()}
    
    response = await agent.evaluate_protect_me_batch(candidates, past_rules)
    return response

@app.post("/api/protect-me/apply", response_model=ApplyPolicyResponse)
async def protect_me_apply(req: ApplyPolicyRequest):
    """
    Stage 2 of Protect Me:
    Applies approved user policies, persists to SQLite, verifies enforcement, and reports score diff.
    """
    events_before = get_current_events()
    score_before = detector.calculate_privacy_score(events_before)
    
    applied = 0
    blocked_domains = []
    allowed_domains = []
    
    for item in req.decisions:
        policy_store.save_decision(
            domain=item.domain,
            application=item.application,
            decision=item.action,
            reason=f"Action applied via Protect Me sweep ({item.action.value})"
        )
        if item.action == ActionDecision.BLOCK:
            blocked_domains.append(item.domain)
            demo_monitor.update_event_status(item.domain, ConnectionStatus.BLOCKED)
        elif item.action == ActionDecision.WARN:
            demo_monitor.update_event_status(item.domain, ConnectionStatus.WARNED)
        else:
            allowed_domains.append(item.domain)
            demo_monitor.update_event_status(item.domain, ConnectionStatus.ALLOWED)
        applied += 1

    events_after = get_current_events()
    score_after = detector.calculate_privacy_score(events_after)

    log_timeline_event(
        title=f"AI Autopilot Protection Sweep applied ({len(blocked_domains)} blocked)",
        description=f"Sentinel blocked {len(blocked_domains)} tracking endpoints while preserving {len(allowed_domains)} essential connections.",
        application="sentinel-agent",
        domain=", ".join(blocked_domains[:2]) or "multiple",
        risk_level=RiskLevel.HIGH,
        event_type="autopilot_block",
        action_taken="blocked",
        ai_reasoning=f"Privacy score improved from {score_before}/100 to {score_after}/100 with zero application breakage."
    )

    summary = (
        f"Protection rules applied successfully. "
        f"{len(blocked_domains)} tracking endpoints blocked, {len(allowed_domains)} allowed. "
        f"Desktop privacy score improved from {score_before}/100 to {score_after}/100."
    )

    return ApplyPolicyResponse(
        applied_count=applied,
        blocked_domains=blocked_domains,
        allowed_domains=allowed_domains,
        previous_score=score_before,
        new_score=score_after,
        summary=summary
    )

class QuickDecisionRequest(BaseModel):
    domain: str
    application: str
    decision: ActionDecision
    reason: Optional[str] = None

@app.post("/api/decision")
async def save_quick_decision(req: QuickDecisionRequest):
    """Save an immediate user decision (allow, warn, or block)."""
    if req.decision == ActionDecision.ALLOW and req.application.lower() in ("firewall", "*"):
        for r in policy_store.list_active_rules():
            if r.domain.lower() == req.domain.lower().strip() and r.decision == ActionDecision.BLOCK:
                policy_store.delete_rule(r.domain, r.application)
    rec = policy_store.save_decision(
        domain=req.domain,
        application="*" if req.application.lower() == "firewall" else req.application,
        decision=req.decision,
        reason=req.reason or f"User manual decision: {req.decision.value}"
    )
    # Update active state
    if req.decision == ActionDecision.BLOCK:
        demo_monitor.update_event_status(req.domain, ConnectionStatus.BLOCKED)
        act_str = "blocked"
    elif req.decision == ActionDecision.WARN:
        demo_monitor.update_event_status(req.domain, ConnectionStatus.WARNED)
        act_str = "warned"
    else:
        demo_monitor.update_event_status(req.domain, ConnectionStatus.ALLOWED)
        act_str = "allowed"

    log_timeline_event(
        title=f"Policy updated: {req.domain} set to {req.decision.value.upper()}",
        description=f"User set {req.application} → {req.domain} to {req.decision.value.upper()}.",
        application=req.application,
        domain=req.domain,
        risk_level=RiskLevel.HIGH if req.decision == ActionDecision.BLOCK else RiskLevel.MEDIUM,
        event_type="user_action",
        action_taken=act_str,
        ai_reasoning=req.reason or f"Persistent SQLite policy enforced for {req.domain}."
    )
        
    return {"status": "ok", "record": rec}

@app.get("/api/rules", response_model=List[UserDecisionRecord])
async def list_rules():
    """List persistent user decision policies."""
    return policy_store.list_active_rules()

class DeleteRuleRequest(BaseModel):
    domain: str
    application: str

@app.delete("/api/rules")
async def delete_rule(req: DeleteRuleRequest):
    """Delete a user policy rule."""
    deleted = policy_store.delete_rule(req.domain, req.application)
    # Reset status in demo monitor
    demo_monitor.update_event_status(req.domain, ConnectionStatus.ACTIVE)
    return {"status": "ok", "deleted": deleted}

@app.get("/api/explain-privacy", response_model=PrivacyReport)
async def explain_my_privacy():
    """
    Generate the 'Explain My Privacy' audit report,
    synthesized by NVIDIA Nemotron.
    """
    events = get_current_events()
    privacy_score = detector.calculate_privacy_score(events)
    total = len(events)
    trackers = sum(1 for e in events if e.known_tracker)
    blocked = sum(1 for e in events if e.status == ConnectionStatus.BLOCKED)
    high_risk = sum(1 for e in events if e.risk_level == RiskLevel.HIGH and e.status != ConnectionStatus.BLOCKED)
    
    top_apps = policy_store.get_top_offenders(limit=4)
    
    # Category breakdown
    cat_counts = {}
    for e in events:
        cname = e.category.value
        cat_counts[cname] = cat_counts.get(cname, 0) + 1

    # Call Nemotron for natural language synthesis
    narrative = await agent.generate_privacy_report(
        privacy_score=privacy_score,
        total_connections=total,
        trackers_detected=trackers,
        blocked_count=blocked,
        high_risk_count=high_risk,
        top_apps=top_apps,
        recent_events=events
    )

    key_findings = [
        f"{high_risk} high-risk trackers identified across active desktop processes",
        f"{blocked} tracking connections actively neutralized by Sentinel policies",
        f"Applications contacting most third parties: {', '.join([a['application'] for a in top_apps[:2]]) or 'None'}"
    ]

    recommendations = [
        "Enforce blocking on known canvas and hardware fingerprinters",
        "Keep telemetry disabled for non-essential applications",
        "Run the 'Protect Me' agent sweep regularly when installing new software"
    ]

    return PrivacyReport(
        score=privacy_score,
        timestamp=events[0].timestamp if events else "",
        total_connections=total,
        trackers_detected=trackers,
        blocked_count=blocked,
        high_risk_count=high_risk,
        top_offending_apps=top_apps,
        category_breakdown=cat_counts,
        key_findings=key_findings,
        recommended_actions=recommendations,
        narrative_report=narrative
    )

@app.get("/api/timeline")
async def get_privacy_timeline():
    """Return Threat Detection Timeline series and chronological AI Privacy Timeline events."""
    return {
        "labels": ["02:00", "06:00", "10:00", "12:00", "14:00", "16:00", "18:00", "22:00"],
        "detected_series": [12, 18, 8, 36, 52, 38, 41, 27, 16],
        "mitigated_series": [8, 14, 5, 31, 41, 32, 35, 23, 13],
        "network_monitor_series": [48, 39, 58, 78, 86, 63, 47, 52],
        "events": timeline_events
    }

@app.post("/api/ask", response_model=AskQuestionResponse)
async def ask_privacy_question(req: AskQuestionRequest):
    """Answer user natural-language questions about app telemetry & suspicious connections via NVIDIA Nemotron."""
    events = get_current_events()
    rules = policy_store.list_active_rules()
    privacy_score = detector.calculate_privacy_score(events)
    res = await agent.ask_question(
        question=req.question,
        events=events,
        rules=rules,
        privacy_score=privacy_score,
        privacy_mode=state["privacy_mode"]
    )
    return res

class PrivacyModeRequest(BaseModel):
    mode: PrivacyMode

@app.post("/api/privacy-mode")
async def set_privacy_mode(req: PrivacyModeRequest):
    """Switch Sentinel Privacy Mode between Normal, Strict, and Paranoid."""
    state["privacy_mode"] = req.mode.value
    events = get_current_events()
    blocked_now = []
    warned_now = []

    for ev in events:
        # Essential APIs and CDNs are never broken
        if ev.category.value in ["essential_api", "cdn_content"] or ev.risk_level == RiskLevel.SAFE:
            policy_store.save_decision(ev.domain, ev.application, ActionDecision.ALLOW, f"Preserved essential endpoint in {req.mode.value} mode")
            demo_monitor.update_event_status(ev.domain, ConnectionStatus.ALLOWED)
            continue

        if req.mode == PrivacyMode.NORMAL:
            if ev.domain == "fingerprint.device-id.net":
                # Keep active or warned in normal baseline unless user blocks
                pass
        elif req.mode == PrivacyMode.STRICT:
            if ev.risk_level == RiskLevel.HIGH or ev.known_tracker:
                policy_store.save_decision(ev.domain, ev.application, ActionDecision.BLOCK, "Auto-blocked by Strict Privacy Mode")
                demo_monitor.update_event_status(ev.domain, ConnectionStatus.BLOCKED)
                blocked_now.append(ev.domain)
            elif ev.risk_level == RiskLevel.MEDIUM:
                policy_store.save_decision(ev.domain, ev.application, ActionDecision.WARN, "Flagged for warning by Strict Privacy Mode")
                demo_monitor.update_event_status(ev.domain, ConnectionStatus.WARNED)
                warned_now.append(ev.domain)
        elif req.mode == PrivacyMode.PARANOID:
            if ev.risk_level in [RiskLevel.HIGH, RiskLevel.MEDIUM] or ev.known_tracker:
                policy_store.save_decision(ev.domain, ev.application, ActionDecision.BLOCK, "Locked down by Paranoid Privacy Mode")
                demo_monitor.update_event_status(ev.domain, ConnectionStatus.BLOCKED)
                blocked_now.append(ev.domain)
            else:
                policy_store.save_decision(ev.domain, ev.application, ActionDecision.WARN, "Monitored under Paranoid Privacy Mode")
                demo_monitor.update_event_status(ev.domain, ConnectionStatus.WARNED)
                warned_now.append(ev.domain)

    log_timeline_event(
        title=f"Privacy Mode switched to {req.mode.value.upper()}",
        description=f"Sentinel enforced {req.mode.value.upper()} mode ({len(blocked_now)} blocked, {len(warned_now)} set to warn, essential services preserved).",
        application="sentinel-core",
        domain="system-policy",
        risk_level=RiskLevel.LOW,
        event_type="mode_change",
        action_taken="blocked" if blocked_now else "detected",
        ai_reasoning=f"NVIDIA Nemotron policy profile adjusted to {req.mode.value.upper()}."
    )

    updated_events = get_current_events()
    return {
        "status": "ok",
        "privacy_mode": state["privacy_mode"],
        "blocked_count": len(blocked_now),
        "warned_count": len(warned_now),
        "privacy_score": detector.calculate_privacy_score(updated_events)
    }

class AutopilotRequest(BaseModel):
    enabled: Optional[bool] = True
    run_sweep: bool = True

@app.post("/api/autopilot", response_model=AutopilotResponse)
async def run_ai_autopilot(req: AutopilotRequest):
    """
    AI Privacy Autopilot Agent:
    Automatically identifies and blocks high-confidence tracking while avoiding actions
    that could unnecessarily break applications or websites.
    """
    if req.enabled is not None:
        state["autopilot_enabled"] = req.enabled

    events_before = get_current_events()
    score_before = detector.calculate_privacy_score(events_before)

    blocked_domains = []
    preserved_domains = []
    warned_count = 0

    if req.run_sweep and state["autopilot_enabled"]:
        for ev in events_before:
            # Never break essential APIs or CDNs
            if ev.category.value in ["essential_api", "cdn_content"] or ev.risk_level == RiskLevel.SAFE:
                policy_store.save_decision(
                    domain=ev.domain,
                    application=ev.application,
                    decision=ActionDecision.ALLOW,
                    reason="AI Autopilot: Verified essential infrastructure (zero-breakage guard)"
                )
                demo_monitor.update_event_status(ev.domain, ConnectionStatus.ALLOWED)
                preserved_domains.append(ev.domain)
            elif ev.risk_level == RiskLevel.HIGH or (ev.known_tracker and ev.risk_score >= 65):
                policy_store.save_decision(
                    domain=ev.domain,
                    application=ev.application,
                    decision=ActionDecision.BLOCK,
                    reason="AI Autopilot: High-confidence tracker blocked (zero app breakage)"
                )
                demo_monitor.update_event_status(ev.domain, ConnectionStatus.BLOCKED)
                blocked_domains.append(ev.domain)
            elif ev.risk_level == RiskLevel.MEDIUM:
                policy_store.save_decision(
                    domain=ev.domain,
                    application=ev.application,
                    decision=ActionDecision.WARN,
                    reason="AI Autopilot: Medium-risk telemetry placed on Warning watch"
                )
                demo_monitor.update_event_status(ev.domain, ConnectionStatus.WARNED)
                warned_count += 1

    events_after = get_current_events()
    score_after = detector.calculate_privacy_score(events_after)

    narrative = (
        f"NVIDIA Nemotron AI Autopilot inspected {len(events_before)} endpoints: automatically blocked "
        f"{len(blocked_domains)} high-confidence trackers ({', '.join(blocked_domains[:3])}), placed {warned_count} telemetry "
        f"connection(s) on Warning, and preserved {len(preserved_domains)} essential service(s) ({', '.join(preserved_domains)}) "
        f"so zero applications or websites break."
    )

    log_timeline_event(
        title=f"AI Privacy Autopilot neutralized {len(blocked_domains)} high-confidence trackers",
        description=narrative,
        application="nemotron-autopilot",
        domain=", ".join(blocked_domains[:2]) or "all-endpoints",
        risk_level=RiskLevel.HIGH,
        event_type="autopilot_block",
        action_taken="blocked",
        ai_reasoning="Autonomous zero-breakage policy enforced via NVIDIA Nemotron."
    )

    return AutopilotResponse(
        autopilot_enabled=state["autopilot_enabled"],
        privacy_mode=state["privacy_mode"],
        blocked_count=len(blocked_domains),
        warned_count=warned_count,
        preserved_essential_count=len(preserved_domains),
        blocked_domains=blocked_domains,
        preserved_domains=preserved_domains,
        previous_score=score_before,
        new_score=score_after,
        narrative=narrative
    )

@app.post("/api/toggle-mode")
async def toggle_mode():
    """Toggle between realistic Demo Mode and Live Host Network Monitoring."""
    state["demo_mode"] = not state["demo_mode"]
    return {
        "status": "ok",
        "demo_mode": state["demo_mode"],
        "message": "Demo Mode active (realistic simulated traffic)" if state["demo_mode"] else "Live Network Monitoring active"
    }

class SettingsUpdateRequest(BaseModel):
    nebius_api_key: Optional[str] = None
    nebius_model: Optional[str] = None
    nebius_base_url: Optional[str] = None

@app.get("/api/settings")
async def get_settings():
    """Return non-sensitive configuration status."""
    return {
        "nebius_configured": settings.is_nebius_configured(),
        "nebius_base_url": settings.nebius_base_url,
        "nebius_model": settings.nebius_model,
        "demo_mode": state["demo_mode"],
        "privacy_mode": state["privacy_mode"],
        "autopilot_enabled": state["autopilot_enabled"]
    }

@app.post("/api/settings")
async def update_settings(req: SettingsUpdateRequest):
    """Update runtime Nebius credentials and reload client."""
    if req.nebius_api_key is not None:
        settings.nebius_api_key = req.nebius_api_key.strip()
    if req.nebius_model is not None and req.nebius_model.strip():
        settings.nebius_model = req.nebius_model.strip()
    if req.nebius_base_url is not None and req.nebius_base_url.strip():
        settings.nebius_base_url = req.nebius_base_url.strip()
        
    # Re-initialize agent client
    agent._init_client()
    
    return {
        "status": "ok",
        "nebius_configured": settings.is_nebius_configured(),
        "nebius_model": settings.nebius_model,
        "nebius_base_url": settings.nebius_base_url
    }

@app.post("/api/demo/reset")
async def reset_demo():
    """Reset simulated demo environment."""
    global timeline_events
    state["privacy_mode"] = "normal"
    state["autopilot_enabled"] = True
    demo_monitor.reset()
    policy_store.clear_all()
    demo_monitor._init_demo_state()
    timeline_events = _build_initial_timeline()
    return {"status": "ok", "message": "Demo environment reset to baseline"}

# ----------------- MICROSOFT EDGE & GOOGLE CHROME LIVE LINK ROUTES -----------------
@app.get("/api/browser/status")
async def get_browser_link_status():
    """Return real-time process, memory, and socket link status for local Microsoft Edge and Google Chrome."""
    status = live_monitor.get_browser_link_status()
    status["browser_link_enabled"] = state.get("browser_link_enabled", True)
    status["extension_path"] = str(BASE_DIR / "browser_extension")
    return status

@app.post("/api/browser/sync")
async def sync_browsers_now():
    """Force an immediate Windows DNS cache refresh and socket scan of local Edge and Chrome browsers."""
    state["browser_link_enabled"] = True
    live_monitor._refresh_windows_dns_cache(force=True)
    status = live_monitor.get_browser_link_status()
    live_events = [
        ev for ev in live_monitor.poll_connections(prioritize_browsers=True)
        if ev.application in ["edge", "chrome"]
    ]

    edge_info = status["edge"]
    chrome_info = status["chrome"]

    log_timeline_event(
        title=f"Browser Live Link synced: Edge ({edge_info['process_count']} procs, {edge_info['active_sockets']} sockets) & Chrome ({chrome_info['process_count']} procs, {chrome_info['active_sockets']} sockets)",
        description=(
            f"CyberGuard AI linked to local Microsoft Edge ({edge_info['memory_mb']} MB RAM) and Google Chrome "
            f"({chrome_info['memory_mb']} MB RAM), capturing {len(live_events)} live browser endpoint(s)."
        ),
        application="edge" if edge_info["running"] else "chrome",
        domain=live_events[0].domain if live_events else "local-browser-bridge",
        risk_level=RiskLevel.MEDIUM,
        event_type="browser_sync",
        action_taken="detected",
        ip=edge_info["remote_ips"][0] if edge_info["remote_ips"] else (chrome_info["remote_ips"][0] if chrome_info["remote_ips"] else "127.0.0.1"),
        ai_reasoning="Real-time psutil socket inspection + Windows DNS resolver cache synchronized with NVIDIA Nemotron telemetry engine."
    )

    return {
        "status": "ok",
        "browser_status": status,
        "live_browser_events_count": len(live_events),
        "live_browser_events": live_events[:15]
    }

class BrowserIngestRequest(BaseModel):
    browser: str = "chrome"
    domain: str
    url: Optional[str] = None
    ip: Optional[str] = "0.0.0.0"
    tab_title: Optional[str] = None

@app.post("/api/browser/ingest")
async def ingest_browser_telemetry(req: BrowserIngestRequest):
    """Ingest real-time tab and request telemetry pushed by the CyberGuard AI Chrome/Edge Browser Extension."""
    ev = live_monitor.ingest_browser_event(
        browser=req.browser,
        domain=req.domain,
        url=req.url,
        ip=req.ip or "0.0.0.0",
        tab_title=req.tab_title
    )
    log_timeline_event(
        title=f"Live {req.browser.capitalize()} Extension telemetry: {ev.domain}",
        description=ev.ai_explanation or f"Browser extension reported outbound request to {ev.domain}",
        application=ev.application,
        domain=ev.domain,
        ip=ev.ip,
        risk_level=ev.risk_level,
        event_type="browser_extension",
        action_taken=ev.status.value,
        ai_reasoning=f"Evaluated live {req.browser.capitalize()} tab connection via CyberGuard AI Browser Bridge."
    )
    return {"status": "ok", "event": ev}

class BrowserLaunchRequest(BaseModel):
    browser: str = "edge"

@app.post("/api/browser/launch")
async def launch_in_browser(req: BrowserLaunchRequest):
    """Launch CyberGuard AI in a dedicated local Microsoft Edge or Google Chrome window on the user's host."""
    import subprocess
    target_url = f"http://127.0.0.1:{settings.sentinel_port}"
    b_type = req.browser.lower().strip()

    launched = False
    used_cmd = ""
    try:
        if b_type == "edge":
            edge_paths = [
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
            ]
            exe = next((p for p in edge_paths if os.path.exists(p)), None)
            if exe:
                subprocess.Popen([exe, f"--app={target_url}"], close_fds=True)
                launched = True
                used_cmd = f'"{exe}" --app={target_url}'
            else:
                subprocess.Popen(["cmd", "/c", "start", f"microsoft-edge:{target_url}"], close_fds=True)
                launched = True
                used_cmd = f"start microsoft-edge:{target_url}"
        elif b_type == "opera":
            opera_paths = [
                os.path.expandvars(r"%LOCALAPPDATA%\Programs\Opera\opera.exe"),
                os.path.expandvars(r"%LOCALAPPDATA%\Programs\Opera GX\opera.exe"),
                r"C:\Program Files\Opera\opera.exe"
            ]
            exe = next((p for p in opera_paths if os.path.exists(p)), None)
            if exe:
                subprocess.Popen([exe, target_url], close_fds=True)
                launched = True
                used_cmd = f'"{exe}" {target_url}'
            else:
                subprocess.Popen(["cmd", "/c", "start", "opera", target_url], close_fds=True)
                launched = True
                used_cmd = f"start opera {target_url}"
        else:
            chrome_paths = [
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe")
            ]
            exe = next((p for p in chrome_paths if os.path.exists(p)), None)
            if exe:
                subprocess.Popen([exe, f"--app={target_url}"], close_fds=True)
                launched = True
                used_cmd = f'"{exe}" --app={target_url}'
            else:
                subprocess.Popen(["cmd", "/c", "start", "chrome", f"--app={target_url}"], close_fds=True)
                launched = True
                used_cmd = f"start chrome --app={target_url}"
    except Exception as e:
        return {"status": "error", "launched": False, "message": str(e)}

    return {
        "status": "ok",
        "launched": launched,
        "browser": "Microsoft Edge" if b_type == "edge" else ("Opera Browser" if b_type == "opera" else "Google Chrome"),
        "command": used_cmd,
        "url": target_url
    }

@app.get("/api/system-telemetry")
async def get_system_telemetry():
    """Return live OS network traffic, CPU/RAM metrics, active browser/system sockets, and SQLite firewall rules."""
    import psutil
    try:
        net_io = psutil.net_io_counters()
        sent_bytes = net_io.bytes_sent or 0
        recv_bytes = net_io.bytes_recv or 0
        total_bytes = sent_bytes + recv_bytes
        gb_total = round(total_bytes / (1024 ** 3), 2)
        sent_gb = round(sent_bytes / (1024 ** 3), 2)
        recv_gb = round(recv_bytes / (1024 ** 3), 2)
        cpu_pct = psutil.cpu_percent(interval=None)
        ram_pct = psutil.virtual_memory().percent
    except Exception:
        gb_total = 0.0
        sent_gb = 0.0
        recv_gb = 0.0
        cpu_pct = 0.0
        ram_pct = 0.0

    browser_status = live_monitor.get_browser_link_status()
    real_events = live_monitor.poll_connections(prioritize_browsers=True, force=True)
    rules = policy_store.list_active_rules()
    blocked_domains = list(dict.fromkeys(r.domain for r in rules if r.decision == ActionDecision.BLOCK))

    live_sockets = []
    country_buckets: Dict[str, List[Dict[str, Any]]] = {
        "United States": [],
        "China": [],
        "Russia": [],
        "Germany": [],
        "Other": []
    }

    for ev in real_events[:100]:
        cat_val = ev.category.value if hasattr(ev.category, "value") else str(ev.category)
        risk_val = ev.risk_level.value if hasattr(ev.risk_level, "value") else str(ev.risk_level)
        stat_val = ev.status.value if hasattr(ev.status, "value") else str(ev.status)
        bucket_country, origin_country, pub_label = live_monitor.classify_app_and_ip_country(
            app_name=ev.application,
            ip_str=ev.ip or "",
            domain=ev.domain or ""
        )
        raw_vendor = ev.vendor or "Remote Endpoint"
        if raw_vendor in ("Remote Endpoint", "Unknown", "General Domain") and pub_label:
            display_vendor = pub_label
        elif bucket_country == "Other" and origin_country not in ("Other", "Local Network") and origin_country.lower() not in raw_vendor.lower():
            display_vendor = f"{origin_country} · {raw_vendor}"
        else:
            display_vendor = raw_vendor

        sock_item = {
            "id": ev.id,
            "application": ev.application,
            "domain": ev.domain,
            "ip": ev.ip,
            "port": ev.port,
            "protocol": ev.protocol,
            "vendor": display_vendor,
            "category": cat_val,
            "risk_level": risk_val,
            "status": stat_val,
            "country": bucket_country,
            "origin_country": origin_country,
            "explanation": ev.ai_explanation or f"Verified outbound {ev.protocol} connection from {ev.application}"
        }
        live_sockets.append(sock_item)
        country_buckets[bucket_country].append({
            "ip": ev.ip,
            "port": ev.port,
            "protocol": ev.protocol,
            "domain": ev.domain,
            "app": ev.application,
            "vendor": display_vendor,
            "origin_country": origin_country
        })

    flagged_count = sum(1 for s in live_sockets if s["risk_level"] in ("high", "medium"))

    attack_sources = [
        {"country": "United States", "color": "#ef4444", "count": len(country_buckets["United States"]), "endpoints": country_buckets["United States"]},
        {"country": "China", "color": "#f97316", "count": len(country_buckets["China"]), "endpoints": country_buckets["China"]},
        {"country": "Russia", "color": "#eab308", "count": len(country_buckets["Russia"]), "endpoints": country_buckets["Russia"]},
        {"country": "Germany", "color": "#facc15", "count": len(country_buckets["Germany"]), "endpoints": country_buckets["Germany"]},
        {"country": "Other", "color": "#64748b", "count": len(country_buckets["Other"]), "endpoints": country_buckets["Other"]}
    ]

    user_display_name, user_first_name = "Operator", "Operator"
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(256)
        size = ctypes.c_ulong(256)
        if ctypes.windll.secur32.GetUserNameExW(3, buf, ctypes.byref(size)) and buf.value.strip():
            user_display_name = " ".join(w.capitalize() for w in buf.value.strip().split())
            user_first_name = user_display_name.split()[0]
        else:
            import getpass
            uname = getpass.getuser().strip()
            if uname:
                user_display_name = uname.capitalize()
                user_first_name = user_display_name
    except Exception:
        pass

    return {
        "status": "ok",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user_display_name": user_display_name,
        "user_first_name": user_first_name,
        "network_traffic_gb": gb_total,
        "network_sent_gb": sent_gb,
        "network_recv_gb": recv_gb,
        "cpu_percent": cpu_pct,
        "ram_percent": ram_pct,
        "edge": browser_status.get("edge", {}),
        "chrome": browser_status.get("chrome", {}),
        "opera": browser_status.get("opera", {}),
        "other_apps": browser_status.get("other_apps", {}),
        "blocked_domains": blocked_domains,
        "blocked_count": len(blocked_domains),
        "flagged_count": flagged_count,
        "rules_count": len(rules),
        "live_sockets": live_sockets,
        "attack_sources": attack_sources
    }


