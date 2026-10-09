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
    RiskLevel
)
from privacy_engine.detector import PrivacyDetector
from database.policy_store import PolicyStore
from monitor.demo_traffic import DemoTrafficGenerator
from monitor.connection_monitor import LiveConnectionMonitor
from agent.nemotron_agent import NemotronPrivacyAgent

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI(
    title="Sentinel - AI Privacy Desktop Engine",
    description="Intelligent privacy monitor powered by NVIDIA Nemotron on Nebius Token Factory",
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

# Core singletons
detector = PrivacyDetector()
policy_store = PolicyStore(settings.database_path)
demo_monitor = DemoTrafficGenerator(detector, policy_store)
live_monitor = LiveConnectionMonitor(detector, policy_store)
agent = NemotronPrivacyAgent()

# Runtime mode state
state = {
    "demo_mode": settings.sentinel_demo_mode
}

# Mount static files and templates
frontend_dir = BASE_DIR / "frontend"
static_dir = frontend_dir / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

def get_current_events() -> List[ConnectionEvent]:
    """Retrieve events from either Demo generator or Live system sockets."""
    if state["demo_mode"]:
        events = demo_monitor.get_events()
    else:
        events = live_monitor.poll_connections()
        if not events:
            # If no live network sockets were captured, fallback smoothly
            events = demo_monitor.get_events()

    # Apply latest policy rules from store
    for ev in events:
        rec = policy_store.get_decision(ev.domain, ev.application)
        if rec:
            if rec.decision == ActionDecision.BLOCK:
                ev.status = ConnectionStatus.BLOCKED
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
    return FileResponse(str(index_file))

# ----------------- API ROUTES -----------------
@app.get("/api/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """Calculate and return system privacy score and telemetry counters."""
    events = get_current_events()
    privacy_score = detector.calculate_privacy_score(events)
    
    total = len(events)
    trackers = sum(1 for e in events if e.known_tracker)
    blocked = sum(1 for e in events if e.status == ConnectionStatus.BLOCKED)
    high_risk = sum(1 for e in events if e.risk_level == RiskLevel.HIGH and e.status != ConnectionStatus.BLOCKED)
    med_risk = sum(1 for e in events if e.risk_level == RiskLevel.MEDIUM and e.status != ConnectionStatus.BLOCKED)
    low_risk = sum(1 for e in events if e.risk_level in [RiskLevel.LOW, RiskLevel.SAFE])

    return DashboardStats(
        privacy_score=privacy_score,
        total_connections=total,
        trackers_detected=trackers,
        blocked_count=blocked,
        high_risk_count=high_risk,
        medium_risk_count=med_risk,
        low_risk_count=low_risk,
        demo_mode=state["demo_mode"],
        nebius_connected=agent.is_connected(),
        model_name=settings.nebius_model
    )

@app.get("/api/connections", response_model=List[ConnectionEvent])
async def get_connections(
    filter: str = Query("all", description="all, high, trackers, blocked, active"),
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
        else:
            allowed_domains.append(item.domain)
            demo_monitor.update_event_status(item.domain, ConnectionStatus.ALLOWED)
        applied += 1

    events_after = get_current_events()
    score_after = detector.calculate_privacy_score(events_after)

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
    """Save an immediate user decision (e.g. from connection feed action buttons)."""
    rec = policy_store.save_decision(
        domain=req.domain,
        application=req.application,
        decision=req.decision,
        reason=req.reason or f"User manual decision: {req.decision.value}"
    )
    # Update active state
    if req.decision == ActionDecision.BLOCK:
        demo_monitor.update_event_status(req.domain, ConnectionStatus.BLOCKED)
    else:
        demo_monitor.update_event_status(req.domain, ConnectionStatus.ALLOWED)
        
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
        "demo_mode": state["demo_mode"]
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
    demo_monitor.reset()
    policy_store.clear_all()
    demo_monitor._init_demo_state()
    return {"status": "ok", "message": "Demo environment reset to baseline"}
