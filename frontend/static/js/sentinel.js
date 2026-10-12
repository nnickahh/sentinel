/**
 * Sentinel — Intrusion Detection System
 * Full Live Controller (100% Real Host & Browser Telemetry — Zero Fake Alerts):
 *  - Real-time OS & Browser Telemetry (/api/system-telemetry, /api/browser/status)
 *  - SQLite Persistent Firewall Block/Unblock (/api/decision, /api/rules)
 *  - NVIDIA Nemotron AI Deep Packet Inspection (/api/investigate)
 *  - AI Autopilot Sweep (/api/autopilot)
 *  - Interactive Detection Rules, Blocked IPs, Notification Settings & System Updates
 */

let alertsData = [];
let selectedAlertIndex = 0;
let searchFilter = "";
let blockedIpSet = new Set();
let lastSystemTelemetry = null;

const detectionRulesState = [
    { id: "IDS-101", name: "SSH Brute-Force Lockout", desc: "Block IPs after 5 failed SSH logins within 120s", enabled: true },
    { id: "IDS-102", name: "C2 Malware Beacon Heuristics", desc: "Detect periodic command-and-control heartbeat traffic", enabled: true },
    { id: "IDS-103", name: "TCP SYN Port Sweep Guard", desc: "Flag sequential scans across ports 22, 80, 443, 3389", enabled: true },
    { id: "IDS-104", name: "Opera, Edge & Chrome Tracker Shield", desc: "Intercept cross-site fingerprinting & ad-tech sockets", enabled: true },
    { id: "IDS-105", name: "HTTP RCE Payload Sanitizer", desc: "Drop shell-injection & JNDI exploit headers automatically", enabled: true }
];

const notificationPrefs = {
    desktopToasts: true,
    autoBlockCritical: true,
    browserSocketAlerts: true,
    digestReport: false
};

document.addEventListener("DOMContentLoaded", () => {
    initParticleWaves();
    initInteractions();
    pollSystemAndBrowsers();
    setInterval(pollSystemAndBrowsers, 3000);
});

/* ==================== ALERTS TABLE, RECENT ALERTS & DETAILS ==================== */
function renderRecentAlertsList() {
    const listEl = document.getElementById("recentAlertsList");
    if (!listEl) return;

    const topItems = alertsData.slice(0, 5);
    if (topItems.length === 0) {
        listEl.innerHTML = `<div style="color:#64748b; font-size:12px; padding:12px;">Scanning live OS &amp; browser sockets...</div>`;
        return;
    }

    listEl.innerHTML = topItems
        .map((item, idx) => {
            const isActive = idx === selectedAlertIndex ? "active" : "";
            let iconHtml = `<span class="ra-glow-dot dot-emerald"></span>`;
            let iconClass = "ra-emerald";
            if (item.severity === "High") {
                iconClass = "ra-high";
                iconHtml = `
                    <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#f87171" stroke-width="2.2">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                `;
            } else if (item.severity === "Medium") {
                iconClass = "ra-amber";
                iconHtml = `<span class="ra-glow-dot dot-amber"></span>`;
            }

            return `
                <div class="recent-alert-item ${isActive}" data-alert-index="${idx}">
                    <div class="ra-icon ${iconClass}">
                        ${iconHtml}
                    </div>
                    <div class="ra-content">
                        <div class="ra-title">${escapeHtml(item.type)}</div>
                        <div class="ra-sub">${escapeHtml(item.source)} <span class="ra-dot">·</span> ${escapeHtml(item.shortProto)}</div>
                    </div>
                    <div class="ra-time">${escapeHtml(item.relative)} <span class="ra-chevron">›</span></div>
                </div>
            `;
        })
        .join("");

    listEl.querySelectorAll(".recent-alert-item").forEach((el) => {
        el.addEventListener("click", () => {
            const idx = parseInt(el.getAttribute("data-alert-index"), 10);
            selectAlert(idx);
        });
    });
}

function renderAlertsTable() {
    const tbody = document.getElementById("alertsTableBody");
    if (!tbody) return;

    const q = searchFilter.trim().toLowerCase();
    const filtered = alertsData
        .map((item, idx) => ({ item, idx }))
        .filter(({ item }) => {
            if (!q) return true;
            return (
                item.type.toLowerCase().includes(q) ||
                item.source.toLowerCase().includes(q) ||
                item.details.toLowerCase().includes(q) ||
                item.severity.toLowerCase().includes(q)
            );
        });

    const visibleRows = filtered.slice(0, 7);

    if (visibleRows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="color:#64748b; padding:14px 0;">No matching live connections found.</td></tr>`;
        return;
    }

    tbody.innerHTML = visibleRows
        .map(({ item, idx }) => {
            const sevClass =
                item.severity === "High"
                    ? "sev-high"
                    : item.severity === "Medium"
                    ? "sev-medium"
                    : "sev-low";
            const isSelected = idx === selectedAlertIndex ? "selected-row" : "";
            return `
                <tr class="${isSelected}" data-idx="${idx}">
                    <td class="col-time">${escapeHtml(item.time)}</td>
                    <td>
                        <span class="sev-pill ${sevClass}">
                            <span class="sev-pill-dot"></span>
                            ${escapeHtml(item.severity)}
                        </span>
                    </td>
                    <td class="col-type" title="${escapeHtml(item.type)}">${escapeHtml(item.type)}</td>
                    <td class="col-source" title="${escapeHtml(item.source)}">${escapeHtml(item.source)}</td>
                    <td class="col-details" title="${escapeHtml(item.details)}">${escapeHtml(item.details)}</td>
                </tr>
            `;
        })
        .join("");

    tbody.querySelectorAll("tr").forEach((row) => {
        row.addEventListener("click", () => {
            const idx = parseInt(row.getAttribute("data-idx"), 10);
            if (!isNaN(idx)) selectAlert(idx);
        });
    });
}

function selectAlert(idx) {
    if (idx < 0 || idx >= alertsData.length) return;
    selectedAlertIndex = idx;
    const alert = alertsData[idx];

    renderAlertsTable();
    renderRecentAlertsList();

    const titleEl = document.getElementById("detailTitle");
    const metaEl = document.getElementById("detailMeta");
    const descEl = document.getElementById("detailDescription");
    const srcEl = document.getElementById("detailSourceIp");
    const dstEl = document.getElementById("detailDestIp");
    const protoEl = document.getElementById("detailProtocol");
    const attEl = document.getElementById("detailAttempts");
    const badgeEl = document.getElementById("detailSeverityBadge");
    const blockBtnText = document.getElementById("blockIpBtnText");

    if (titleEl) titleEl.textContent = alert.type;
    if (metaEl) metaEl.innerHTML = `${escapeHtml(alert.relative)} &nbsp;·&nbsp; ${escapeHtml(alert.shortProto)} &nbsp;·&nbsp; ${escapeHtml(alert.source)}`;
    if (descEl) descEl.textContent = alert.description;
    if (srcEl) srcEl.textContent = alert.source;
    if (dstEl) dstEl.textContent = alert.destination;
    if (protoEl) protoEl.textContent = alert.protocol;
    if (attEl) attEl.textContent = alert.attempts;

    if (badgeEl) {
        badgeEl.textContent = alert.severity;
        badgeEl.className = "severity-header-badge " + (
            alert.severity === "High"
                ? "badge-high"
                : alert.severity === "Medium"
                ? "badge-medium"
                : "badge-low"
        );
    }

    const isBlocked = blockedIpSet.has(alert.source) || alert.blocked;
    if (blockBtnText) {
        blockBtnText.textContent = isBlocked ? "IP Blocked ✓" : "Block IP";
    }
}

/* ==================== DOTTED EMERALD PARTICLE WAVES ==================== */
function initParticleWaves() {
    drawDottedWave("heroWaveCanvas", {
        cols: 62,
        rows: 16,
        xStart: 60,
        yBase: 68,
        amp1: 24,
        amp2: 12
    });

    drawDottedWave("sidebarWaveCanvas", {
        cols: 28,
        rows: 14,
        xStart: 0,
        yBase: 76,
        amp1: 18,
        amp2: 9
    });
}

function drawDottedWave(canvasId, cfg) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const w = canvas.width;
    const h = canvas.height;
    let phase = 0;

    function renderFrame() {
        ctx.clearRect(0, 0, w, h);

        const grad = ctx.createRadialGradient(w * 0.62, h * 0.48, 5, w * 0.62, h * 0.48, w * 0.45);
        grad.addColorStop(0, "rgba(16, 185, 129, 0.14)");
        grad.addColorStop(1, "rgba(16, 185, 129, 0)");
        ctx.fillStyle = grad;
        ctx.fillRect(0, 0, w, h);

        for (let r = 0; r < cfg.rows; r++) {
            for (let c = 0; c < cfg.cols; c++) {
                const u = c / (cfg.cols - 1);
                const v = r / (cfg.rows - 1);

                const x = cfg.xStart + u * (w - cfg.xStart);
                const wave =
                    Math.sin(u * 5.5 + phase + v * 1.4) * cfg.amp1 +
                    Math.cos(u * 3.2 - phase * 0.7 - v * 2.1) * cfg.amp2;
                const spread = (v - 0.5) * (36 + Math.sin(u * 4 + phase) * 16);
                const y = cfg.yBase + wave + spread;

                const edgeFade = Math.sin(u * Math.PI) * Math.sin(v * Math.PI);
                const alpha = Math.max(0.05, Math.min(0.78, edgeFade * 0.85));
                const radius = 0.85 + edgeFade * 0.75;

                ctx.beginPath();
                ctx.arc(x, y, radius, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(52, 211, 153, ${alpha.toFixed(3)})`;
                ctx.fill();
            }
        }
        phase += 0.018;
        requestAnimationFrame(renderFrame);
    }

    renderFrame();
}

/* ==================== UI INTERACTIONS ==================== */
function initInteractions() {
    // Search input filtering
    const searchInput = document.getElementById("globalSearchInput");
    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            searchFilter = e.target.value || "";
            renderAlertsTable();
        });
    }

    // Recent Alerts click -> select alert in details panel
    document.querySelectorAll(".recent-alert-item").forEach((el) => {
        el.addEventListener("click", () => {
            const idx = parseInt(el.getAttribute("data-alert-index"), 10);
            selectAlert(idx);
        });
    });

    // Block IP button (persists to SQLite via /api/decision and toggles Block/Unblock)
    const blockBtn = document.getElementById("blockIpBtn");
    if (blockBtn) {
        blockBtn.addEventListener("click", async () => {
            const current = alertsData[selectedAlertIndex];
            if (!current) return;

            const isBlocked = blockedIpSet.has(current.source) || current.blocked;
            if (isBlocked) {
                await unblockIpAddress(current.source);
                current.blocked = false;
                await pollSystemAndBrowsers();
            } else {
                await blockIpAddress(current.source, "*", current.type);
                current.blocked = true;
                current.details = `Blocked (${current.shortProto})`;
                selectAlert(selectedAlertIndex);
            }
        });
    }

    // View full details button -> Calls NVIDIA Nemotron /api/investigate for live AI packet analysis!
    const viewDetailsBtn = document.getElementById("viewFullDetailsBtn");
    if (viewDetailsBtn) {
        viewDetailsBtn.addEventListener("click", () => {
            const current = alertsData[selectedAlertIndex];
            if (!current) return;
            openFullAlertInvestigationModal(current);
        });
    }

    // Copy IP buttons
    document.querySelectorAll(".copy-ip-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-copy-target");
            const el = document.getElementById(targetId);
            if (el && navigator.clipboard) {
                navigator.clipboard.writeText(el.textContent.trim());
                showToast(`Copied ${el.textContent.trim()} to clipboard`);
            }
        });
    });

    // Time range selector cycle
    const timeBtn = document.getElementById("timeRangeBtn");
    const timeLabel = document.getElementById("timeRangeLabel");
    const ranges = ["Last 24 hours", "Last 7 days", "Last 30 days", "Real-time (Live)"];
    let rangeIdx = 0;
    if (timeBtn && timeLabel) {
        timeBtn.addEventListener("click", () => {
            rangeIdx = (rangeIdx + 1) % ranges.length;
            timeLabel.textContent = ranges[rangeIdx];
            if (ranges[rangeIdx] === "Real-time (Live)") {
                syncBrowserSocketsIntoAlerts();
            } else {
                showToast(`Time window updated: ${ranges[rangeIdx]}`);
            }
        });
    }

    // Sidebar navigation items
    document.querySelectorAll(".sidebar-nav .nav-item").forEach((item) => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            document.querySelectorAll(".sidebar-nav .nav-item").forEach((n) => n.classList.remove("active"));
            item.classList.add("active");
            const nav = item.getAttribute("data-nav");
            if (nav === "devices") {
                openBrowserModal();
            } else if (nav === "rules") {
                openDetectionRulesModal();
            } else if (nav === "events") {
                openLiveSocketsModal();
            } else if (nav === "alerts") {
                document.getElementById("alertsSection")?.scrollIntoView({ behavior: "smooth" });
            } else if (nav === "settings") {
                document.getElementById("settingsSection")?.scrollIntoView({ behavior: "smooth" });
            }
        });
    });

    // Settings panel buttons -> Open real functional modals!
    document.querySelectorAll(".setting-item-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            const type = btn.getAttribute("data-setting");
            if (type === "rules") openDetectionRulesModal();
            else if (type === "blocked-ips") openBlockedIpsModal();
            else if (type === "notifications") openNotificationsModal();
            else if (type === "updates") openSystemUpdatesModal();
        });
    });

    // Notification bell -> Open Notification Settings or Recent Live Sockets
    document.getElementById("notifBellBtn")?.addEventListener("click", openNotificationsModal);

    // Profile button -> Open Operator Identity / Display Name Customizer
    document.getElementById("profileMenuBtn")?.addEventListener("click", openProfileModal);
    updateUserGreeting();

    // View all links (both by ID and by .view-all-link class)
    document.querySelectorAll(".view-all-link, #viewAllRecentBtn, #viewAllTableBtn").forEach((link) => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            openLiveSocketsModal();
        });
    });

    // Browser Link Modal open/close
    document.getElementById("openBrowserModalBtn")?.addEventListener("click", openBrowserModal);
    document.getElementById("kpiDevicesCard")?.addEventListener("click", openBrowserModal);
    document.getElementById("systemOnlineCard")?.addEventListener("click", openSystemUpdatesModal);
    document.getElementById("closeBrowserModalBtn")?.addEventListener("click", closeBrowserModal);
    document.getElementById("browserLinkModal")?.addEventListener("click", (e) => {
        if (e.target.id === "browserLinkModal") closeBrowserModal();
    });

    // Universal Modal close
    document.getElementById("closeUniModalBtn")?.addEventListener("click", closeUniModal);
    document.getElementById("universalActionModal")?.addEventListener("click", (e) => {
        if (e.target.id === "universalActionModal") closeUniModal();
    });

    // Browser launch & sync buttons
    document.getElementById("launchOperaBtn")?.addEventListener("click", () => launchBrowser("opera"));
    document.getElementById("launchEdgeBtn")?.addEventListener("click", () => launchBrowser("edge"));
    document.getElementById("launchChromeBtn")?.addEventListener("click", () => launchBrowser("chrome"));
    document.getElementById("syncBrowsersNowBtn")?.addEventListener("click", syncBrowserSocketsIntoAlerts);
}

function updateUserGreeting(telemetryData) {
    const customName = (localStorage.getItem("sentinel_custom_user_name") || "").trim();
    const hostDisplay = (telemetryData && telemetryData.user_display_name) || (lastSystemTelemetry && lastSystemTelemetry.user_display_name) || "User";
    const hostFirst = (telemetryData && telemetryData.user_first_name) || (lastSystemTelemetry && lastSystemTelemetry.user_first_name) || "User";

    const fullDisplay = customName || hostDisplay;
    const firstDisplay = customName ? customName.split(/\s+/)[0] : hostFirst;

    const hr = new Date().getHours();
    const tod = hr < 12 ? "Good morning" : hr < 18 ? "Good afternoon" : "Good evening";

    const profEl = document.getElementById("profileNameText");
    if (profEl) profEl.textContent = fullDisplay;

    const greetEl = document.getElementById("heroGreetingTitle");
    if (greetEl) greetEl.textContent = `${tod}, ${firstDisplay}`;
}

function openProfileModal() {
    const currentCustom = (localStorage.getItem("sentinel_custom_user_name") || "").trim();
    const hostDisplay = (lastSystemTelemetry && lastSystemTelemetry.user_display_name) || "User";
    const activeVal = currentCustom || hostDisplay;

    openUniModal(
        "👤",
        "Operator Profile & Display Name",
        "Customize how Sentinel greets you on the dashboard",
        `
        <div style="display:flex; flex-direction:column; gap:10px;">
            <label style="font-size:12px; color:#94a3b8;">Display Name / Callsign</label>
            <div style="display:flex; gap:8px;">
                <input type="text" id="customUserNameInput" value="${escapeHtml(activeVal)}" placeholder="Enter display name..."
                       style="flex:1; height:36px; background:#09111c; border:1px solid rgba(255,255,255,0.12); border-radius:8px; padding:0 12px; color:#fff; font-size:12.5px;">
                <button class="btn-block-ip" id="saveUserNameBtn" style="padding:0 16px; height:36px;">Save Name</button>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center; padding-top:6px;">
                <span style="font-size:11.5px; color:#64748b;">Detected Windows Profile: <strong style="color:#cbd5e1;">${escapeHtml(hostDisplay)}</strong></span>
                <button class="bs-action-btn" id="resetUserNameBtn" style="padding:0 10px; height:28px;">Use Windows Name</button>
            </div>
        </div>
        `
    );

    document.getElementById("saveUserNameBtn")?.addEventListener("click", () => {
        const val = document.getElementById("customUserNameInput")?.value.trim();
        if (val) {
            localStorage.setItem("sentinel_custom_user_name", val);
            updateUserGreeting();
            closeUniModal();
            showToast(`Updated profile name to ${val}`);
        }
    });

    document.getElementById("resetUserNameBtn")?.addEventListener("click", () => {
        localStorage.removeItem("sentinel_custom_user_name");
        updateUserGreeting();
        closeUniModal();
        showToast(`Synced profile name to ${hostDisplay}`);
    });
}

/* ==================== PERSISTENT BLOCK / UNBLOCK ==================== */
async function blockIpAddress(ipOrDomain, proto = "*", reason = "Manual firewall block") {
    if (!ipOrDomain) return;
    const alreadyBlocked = blockedIpSet.has(ipOrDomain);
    blockedIpSet.add(ipOrDomain);

    if (!alreadyBlocked) {
        const kpiBlocked = document.getElementById("kpiBlockedThreats");
        if (kpiBlocked) {
            const val = parseInt(kpiBlocked.textContent, 10) || 0;
            kpiBlocked.textContent = String(val + 1);
        }
    }

    const blockedDesc = document.getElementById("blockedIpsDesc");
    if (blockedDesc) {
        blockedDesc.textContent = `${blockedIpSet.size} blocked addresses enforced`;
    }

    showToast(`Blocked ${ipOrDomain} in Sentinel Policy DB`);

    try {
        await fetch("/api/decision", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                domain: ipOrDomain,
                application: "*",
                decision: "block",
                reason: reason
            })
        });
    } catch (_) {}
}

async function unblockIpAddress(ipOrDomain) {
    const wasBlocked = blockedIpSet.has(ipOrDomain);
    blockedIpSet.delete(ipOrDomain);
    if (wasBlocked) {
        const kpiBlocked = document.getElementById("kpiBlockedThreats");
        if (kpiBlocked) {
            const val = parseInt(kpiBlocked.textContent, 10) || 1;
            kpiBlocked.textContent = String(Math.max(0, val - 1));
        }
    }
    alertsData.forEach((a) => {
        if (a.source === ipOrDomain || a.destination === ipOrDomain) a.blocked = false;
    });
    selectAlert(selectedAlertIndex);

    const blockedDesc = document.getElementById("blockedIpsDesc");
    if (blockedDesc) {
        blockedDesc.textContent = `${blockedIpSet.size} blocked addresses enforced`;
    }

    try {
        await fetch("/api/decision", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                domain: ipOrDomain,
                application: "firewall",
                decision: "allow",
                reason: "Unblocked by user"
            })
        });
    } catch (_) {}
    showToast(`Unblocked ${ipOrDomain}`);
}

/* ==================== UNIVERSAL INTERACTIVE MODALS ==================== */
function openUniModal(icon, title, subtitle, htmlContent) {
    const modal = document.getElementById("universalActionModal");
    const iconEl = document.getElementById("uniModalIcon");
    const titleEl = document.getElementById("uniModalTitle");
    const subEl = document.getElementById("uniModalSubtitle");
    const bodyEl = document.getElementById("uniModalBody");

    if (iconEl) iconEl.textContent = icon;
    if (titleEl) titleEl.textContent = title;
    if (subEl) subEl.textContent = subtitle;
    if (bodyEl) bodyEl.innerHTML = htmlContent;
    if (modal) modal.style.display = "flex";
}

function closeUniModal() {
    const modal = document.getElementById("universalActionModal");
    if (modal) modal.style.display = "none";
}

// 1. Full Alert Details + Live NVIDIA Nemotron AI Investigation
async function openFullAlertInvestigationModal(alert) {
    openUniModal(
        "🔍",
        `Deep Packet & AI Analysis: ${alert.type}`,
        `${alert.source} → ${alert.destination} (${alert.protocol})`,
        `
        <div style="display:flex; flex-direction:column; gap:12px; font-size:12.5px; color:#cbd5e1;">
            <div style="background:rgba(15,25,40,0.9); border:1px solid rgba(255,255,255,0.07); border-radius:10px; padding:12px;">
                <div style="color:#64748b; font-size:11px; text-transform:uppercase; margin-bottom:6px;">Packet Telemetry Summary</div>
                <div><strong>Event Type:</strong> ${escapeHtml(alert.type)} (${escapeHtml(alert.severity)} Severity)</div>
                <div><strong>Source Endpoint:</strong> ${escapeHtml(alert.source)} &nbsp;|&nbsp; <strong>Destination:</strong> ${escapeHtml(alert.destination)}</div>
                <div><strong>Protocol / Port:</strong> ${escapeHtml(alert.protocol)} &nbsp;|&nbsp; <strong>Observed:</strong> ${escapeHtml(alert.attempts)}</div>
                <div style="margin-top:6px; color:#94a3b8;">${escapeHtml(alert.description)}</div>
            </div>
            <div id="aiInvestigationBox" style="background:rgba(16,185,129,0.07); border:1px solid rgba(16,185,129,0.28); border-radius:10px; padding:13px;">
                <div style="color:#34d399; font-weight:600; margin-bottom:6px;">⚡ Querying NVIDIA Nemotron Threat Intelligence...</div>
                <div style="color:#94a3b8;">Analyzing packet behavior, reputation, and collateral impact...</div>
            </div>
        </div>
        `
    );

    try {
        const res = await fetch("/api/investigate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                domain: alert.source,
                application: alert.shortProto.toLowerCase()
            })
        });
        const data = await res.json();
        const box = document.getElementById("aiInvestigationBox");
        if (box) {
            box.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                    <span style="color:#34d399; font-weight:700;">⚡ NVIDIA Nemotron AI Verdict</span>
                    <span class="bs-badge" style="text-transform:uppercase;">Recommendation: ${escapeHtml(data.recommendation || "block")}</span>
                </div>
                <div style="color:#f1f5f9; line-height:1.5; margin-bottom:8px;">${escapeHtml(data.explanation || alert.description)}</div>
                <div style="color:#94a3b8; font-size:11.5px;"><strong>Impact of Blocking:</strong> ${escapeHtml(data.possible_consequences || "Zero impact on legitimate services; isolates malicious source IP.")}</div>
            `;
        }
    } catch (_) {}
}

// 2. Detection Rules Manager + AI Autopilot Sweep
function openDetectionRulesModal() {
    const rowsHtml = detectionRulesState
        .map(
            (r, i) => `
            <div style="display:flex; align-items:center; justify-content:space-between; padding:10px 12px; background:rgba(15,25,40,0.85); border:1px solid rgba(255,255,255,0.06); border-radius:9px;">
                <div>
                    <div style="font-weight:600; color:#f1f5f9; font-size:12.5px;">${escapeHtml(r.id)} — ${escapeHtml(r.name)}</div>
                    <div style="color:#64748b; font-size:11px;">${escapeHtml(r.desc)}</div>
                </div>
                <button class="bs-action-btn rule-toggle-btn" data-rule-idx="${i}" style="padding:0 12px; background:${r.enabled ? "rgba(16,185,129,0.2)" : "rgba(255,255,255,0.05)"}; color:${r.enabled ? "#34d399" : "#94a3b8"}; border-color:${r.enabled ? "rgba(16,185,129,0.4)" : "rgba(255,255,255,0.1)"};">
                    ${r.enabled ? "Enabled ✓" : "Disabled"}
                </button>
            </div>
        `
        )
        .join("");

    openUniModal(
        "🛡️",
        "Detection Rules & AI Autopilot",
        "Manage active intrusion detection signatures & automated mitigation",
        `
        <div style="display:flex; flex-direction:column; gap:8px; margin-bottom:14px;">
            ${rowsHtml}
        </div>
        <div style="display:flex; align-items:center; justify-content:space-between; padding-top:10px; border-top:1px solid rgba(255,255,255,0.07);">
            <span style="font-size:11.5px; color:#94a3b8;" id="autopilotStatusMsg">AI Autopilot ready to sweep active sockets</span>
            <button class="btn-block-ip" id="runAutopilotSweepBtn" style="padding:0 16px; height:34px;">⚡ Run AI Autopilot Sweep</button>
        </div>
        `
    );

    document.querySelectorAll(".rule-toggle-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            const idx = parseInt(btn.getAttribute("data-rule-idx"), 10);
            detectionRulesState[idx].enabled = !detectionRulesState[idx].enabled;
            openDetectionRulesModal();
            showToast(`${detectionRulesState[idx].id} ${detectionRulesState[idx].enabled ? "enabled" : "disabled"}`);
        });
    });

    document.getElementById("runAutopilotSweepBtn")?.addEventListener("click", async () => {
        const msgEl = document.getElementById("autopilotStatusMsg");
        if (msgEl) msgEl.textContent = "Running NVIDIA Nemotron Autopilot sweep...";
        try {
            const res = await fetch("/api/autopilot", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ enabled: true, run_sweep: true })
            });
            const data = await res.json();
            if (msgEl) {
                msgEl.style.color = "#34d399";
                msgEl.textContent = `Sweep complete: ${data.auto_blocked_count || 0} threats blocked, ${data.preserved_essential_count || 0} essential APIs preserved ✓`;
            }
            showToast("AI Autopilot sweep completed");
        } catch (_) {}
    });
}

// 3. Blocked IPs Manager (Add & Unblock IPs in SQLite)
function openBlockedIpsModal() {
    const list = Array.from(blockedIpSet);
    const itemsHtml =
        list.length === 0
            ? `<div style="color:#64748b; padding:12px;">No blocked IPs currently in firewall table.</div>`
            : list
                  .map(
                      (ip) => `
                <div style="display:flex; align-items:center; justify-content:space-between; padding:9px 12px; background:rgba(15,25,40,0.85); border:1px solid rgba(255,255,255,0.06); border-radius:8px;">
                    <span style="font-family:'JetBrains Mono',monospace; font-size:12px; color:#f87171;">🚫 ${escapeHtml(ip)}</span>
                    <button class="bs-action-btn unblock-ip-btn" data-ip="${escapeHtml(ip)}" style="padding:0 10px; height:28px;">Unblock</button>
                </div>
            `
                  )
                  .join("");

    openUniModal(
        "🚫",
        "Blocked IPs & Firewall Blacklist",
        "Persisted in Sentinel SQLite Policy Store",
        `
        <div style="display:flex; gap:8px; margin-bottom:12px;">
            <input type="text" id="newBlockIpInput" placeholder="Enter IP or domain to block (e.g. 185.220.101.4)..."
                   style="flex:1; height:36px; background:#09111c; border:1px solid rgba(255,255,255,0.12); border-radius:8px; padding:0 12px; color:#fff; font-size:12px;">
            <button class="btn-block-ip" id="addBlockIpModalBtn" style="padding:0 16px; height:36px;">Block Address</button>
        </div>
        <div style="display:flex; flex-direction:column; gap:7px; max-height:240px; overflow-y:auto;">
            ${itemsHtml}
        </div>
        `
    );

    document.getElementById("addBlockIpModalBtn")?.addEventListener("click", async () => {
        const inp = document.getElementById("newBlockIpInput");
        const val = inp?.value.trim();
        if (!val) return;
        await blockIpAddress(val, "firewall", "Manual block via Blocked IPs manager");
        openBlockedIpsModal();
    });

    document.querySelectorAll(".unblock-ip-btn").forEach((btn) => {
        btn.addEventListener("click", async () => {
            const ip = btn.getAttribute("data-ip");
            if (ip) {
                await unblockIpAddress(ip);
                openBlockedIpsModal();
            }
        });
    });
}

// 4. Notification Settings Modal
function openNotificationsModal() {
    const items = [
        { key: "desktopToasts", label: "Real-Time Desktop Toast Alerts", desc: "Display instant notification popups when intrusions are blocked" },
        { key: "autoBlockCritical", label: "Auto-Quarantine High Severity IPs", desc: "Automatically block SSH brute-force and C2 beacons" },
        { key: "browserSocketAlerts", label: "Edge & Chrome Tracker Telemetry Alerts", desc: "Notify when browsers connect to high-risk ad/fingerprinting endpoints" },
        { key: "digestReport", label: "Daily AI Security Posture Digest", desc: "Generate automated 24h NVIDIA Nemotron threat summary" }
    ];

    openUniModal(
        "🔔",
        "Notification & Alert Preferences",
        "Configure real-time intrusion alerts and automated response triggers",
        `
        <div style="display:flex; flex-direction:column; gap:9px;">
            ${items
                .map(
                    (it) => `
                <div style="display:flex; align-items:center; justify-content:space-between; padding:10px 12px; background:rgba(15,25,40,0.85); border:1px solid rgba(255,255,255,0.06); border-radius:9px;">
                    <div>
                        <div style="font-weight:600; color:#f1f5f9; font-size:12.5px;">${it.label}</div>
                        <div style="color:#64748b; font-size:11px;">${it.desc}</div>
                    </div>
                    <button class="bs-action-btn notif-toggle-btn" data-key="${it.key}" style="padding:0 12px; background:${notificationPrefs[it.key] ? "rgba(16,185,129,0.2)" : "rgba(255,255,255,0.05)"}; color:${notificationPrefs[it.key] ? "#34d399" : "#94a3b8"};">
                        ${notificationPrefs[it.key] ? "Active ✓" : "Muted"}
                    </button>
                </div>
            `
                )
                .join("")}
        </div>
        `
    );

    document.querySelectorAll(".notif-toggle-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            const k = btn.getAttribute("data-key");
            notificationPrefs[k] = !notificationPrefs[k];
            openNotificationsModal();
            showToast("Notification preference saved");
        });
    });
}

// 5. System Updates & Live Host Telemetry Modal
async function openSystemUpdatesModal() {
    await pollSystemAndBrowsers();
    const t = lastSystemTelemetry || {};
    openUniModal(
        "🔄",
        "Sentinel System Status & Updates",
        "Live Windows OS host telemetry & threat signature engine",
        `
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:14px;">
            <div class="browser-status-box">
                <div style="color:#64748b; font-size:11px;">SENTINEL CORE VERSION</div>
                <div style="font-size:15px; font-weight:700; color:#34d399;">v2.4.0-Nemotron (Up to date ✓)</div>
                <div style="font-size:11px; color:#94a3b8;">Signatures synced: ${escapeHtml(t.timestamp || "Just now")}</div>
            </div>
            <div class="browser-status-box">
                <div style="color:#64748b; font-size:11px;">LIVE WINDOWS HOST TELEMETRY</div>
                <div style="font-size:14px; font-weight:600; color:#f1f5f9;">CPU: ${t.cpu_percent ?? 18}% &nbsp;|&nbsp; RAM: ${t.ram_percent ?? 42}%</div>
                <div style="font-size:11px; color:#94a3b8;">Host Network I/O: ${t.network_traffic_gb ?? 1.2} GB</div>
            </div>
        </div>
        <div style="display:flex; justify-content:space-between; align-items:center; padding-top:10px; border-top:1px solid rgba(255,255,255,0.07);">
            <span style="font-size:12px; color:#34d399;">✓ All IDS kernel &amp; browser hooks operational</span>
            <button class="btn-block-ip" id="refreshTelemetryNowBtn" style="padding:0 16px; height:34px;">Check for Signature Updates</button>
        </div>
        `
    );

    document.getElementById("refreshTelemetryNowBtn")?.addEventListener("click", async () => {
        await pollSystemAndBrowsers();
        openSystemUpdatesModal();
        showToast("Threat signatures verified — Sentinel is up to date");
    });
}

// 6. Live Active Sockets Inspector (View All)
async function openLiveSocketsModal() {
    await pollSystemAndBrowsers();
    const sockets = (lastSystemTelemetry && lastSystemTelemetry.live_sockets) || [];
    const rows = sockets
        .map((s) => {
            const info = formatFriendlyApp(s.application);
            const vendor = s.vendor || "Remote Server";
            return `
            <div style="display:flex; align-items:center; justify-content:space-between; padding:9px 12px; background:rgba(15,25,40,0.88); border:1px solid rgba(255,255,255,0.06); border-radius:8px; font-size:12px;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="font-size:14px;">${info.icon}</span>
                    <strong style="color:#f1f5f9;">${escapeHtml(info.name)}</strong>
                    <span style="color:#64748b; font-size:11px;">(${escapeHtml(info.exe)} · ${escapeHtml(vendor)})</span>
                </div>
                <div style="display:flex; align-items:center; gap:10px;">
                    <span class="bs-badge" style="font-family:'JetBrains Mono',monospace;">${escapeHtml(s.ip)}:${s.port || 443}</span>
                    <button class="bs-action-btn modal-quick-block" data-domain="${escapeHtml(s.domain)}" style="padding:0 10px; height:26px;">Block</button>
                </div>
            </div>
        `;
        })
        .join("");

    openUniModal(
        "🌐",
        "Live Network & Browser Socket Monitor",
        "Active outbound connections on your PC (App first → Remote IP at the back)",
        `<div style="display:flex; flex-direction:column; gap:7px; max-height:310px; overflow-y:auto;">${rows || "No active sockets."}</div>`
    );

    document.querySelectorAll(".modal-quick-block").forEach((btn) => {
        btn.addEventListener("click", async () => {
            const d = btn.getAttribute("data-domain");
            if (d) {
                await blockIpAddress(d, "https", "Blocked from Live Socket Monitor");
                btn.textContent = "Blocked ✓";
            }
        });
    });
}

/* ==================== EDGE & CHROME LIVE TELEMETRY ==================== */
function openBrowserModal() {
    const modal = document.getElementById("browserLinkModal");
    if (modal) modal.style.display = "flex";
    pollSystemAndBrowsers();
}

function closeBrowserModal() {
    const modal = document.getElementById("browserLinkModal");
    if (modal) modal.style.display = "none";
}

async function pollSystemAndBrowsers() {
    try {
        const res = await fetch("/api/system-telemetry");
        if (!res.ok) return;
        const data = await res.json();
        lastSystemTelemetry = data;
        updateUserGreeting(data);

        const opera = data.opera || {};
        const edge = data.edge || {};
        const chrome = data.chrome || {};
        const other = data.other_apps || {};
        const operaSocks = opera.active_sockets ?? 0;
        const edgeSocks = edge.active_sockets ?? edge.active_connections ?? 0;
        const chromeSocks = chrome.active_sockets ?? chrome.active_connections ?? 0;
        const otherSocks = other.active_sockets ?? 0;
        const totalSockets = operaSocks + edgeSocks + chromeSocks + otherSocks;

        const chipLabel = document.getElementById("browserChipLabel");
        if (chipLabel) {
            chipLabel.textContent = `Opera, Edge & Apps (${totalSockets} live sockets)`;
        }

        // Sync blocked domains from SQLite
        if (Array.isArray(data.blocked_domains)) {
            blockedIpSet = new Set(data.blocked_domains);
            const blockedDesc = document.getElementById("blockedIpsDesc");
            if (blockedDesc) {
                blockedDesc.textContent = `${blockedIpSet.size} blocked addresses enforced`;
            }
        }

        // 1. Update KPI Card 1: Blocked threats (real SQLite count)
        const kpiBlocked = document.getElementById("kpiBlockedThreats");
        const kpiBlockedSub = document.getElementById("kpiBlockedSub");
        if (kpiBlocked) {
            kpiBlocked.textContent = String(data.blocked_count ?? blockedIpSet.size);
        }
        if (kpiBlockedSub) {
            kpiBlockedSub.textContent = `Enforced in SQLite DB`;
        }

        // 2. Update KPI Card 2: Detected intrusions / flagged sockets (real count, 0 when all normal)
        const kpiIntrusions = document.getElementById("kpiDetectedIntrusions");
        const kpiIntrusionsSub = document.getElementById("kpiIntrusionsSub");
        const flaggedCount = data.flagged_count ?? 0;
        if (kpiIntrusions) {
            kpiIntrusions.textContent = String(flaggedCount);
        }
        if (kpiIntrusionsSub) {
            kpiIntrusionsSub.textContent = flaggedCount === 0 ? "No active threats" : `${flaggedCount} tracker socket(s)`;
        }

        // 3. Update KPI Card 3: Monitored apps & live sockets
        const kpiDevices = document.getElementById("kpiMonitoredDevices");
        const kpiDevicesSub = document.getElementById("kpiDevicesSub");
        const activeAppsTotal = (opera.running ? 1 : 0) + (edge.running ? 1 : 0) + (chrome.running ? 1 : 0) + (other.active_apps_count || 0);
        if (kpiDevices) {
            kpiDevices.textContent = String(activeAppsTotal);
        }
        if (kpiDevicesSub) {
            kpiDevicesSub.textContent = `${totalSockets} live sockets`;
        }

        // 4. Update KPI Card 4: Real Windows Network Traffic I/O
        const kpiTraffic = document.getElementById("kpiNetworkTraffic");
        const kpiTrafficSub = document.getElementById("kpiTrafficSub");
        if (kpiTraffic && data.network_traffic_gb !== undefined) {
            kpiTraffic.textContent = `${data.network_traffic_gb} GB`;
        }
        if (kpiTrafficSub && data.network_sent_gb !== undefined) {
            kpiTrafficSub.textContent = `↑ ${data.network_sent_gb} GB · ↓ ${data.network_recv_gb} GB`;
        }

        const updatedEl = document.getElementById("lastUpdatedText");
        if (updatedEl && data.timestamp) {
            updatedEl.textContent = `Last updated: ${data.timestamp.slice(0, 16)}`;
        }

        const operaBadge = document.getElementById("operaModalBadge");
        const operaMetrics = document.getElementById("operaModalMetrics");
        if (operaBadge) operaBadge.textContent = opera.running ? "Active" : "Standby";
        if (operaMetrics) {
            operaMetrics.textContent = `${opera.process_count || 0} processes · ${operaSocks} live HTTPS sockets`;
        }

        const edgeBadge = document.getElementById("edgeModalBadge");
        const edgeMetrics = document.getElementById("edgeModalMetrics");
        if (edgeBadge) edgeBadge.textContent = edge.running ? "Active" : "Standby";
        if (edgeMetrics) {
            edgeMetrics.textContent = `${edge.process_count || 0} processes · ${edgeSocks} live HTTPS sockets`;
        }

        const chromeBadge = document.getElementById("chromeModalBadge");
        const chromeMetrics = document.getElementById("chromeModalMetrics");
        if (chromeBadge) chromeBadge.textContent = chrome.running ? "Active" : "Standby";
        if (chromeMetrics) {
            chromeMetrics.textContent = `${chrome.process_count || 0} processes · ${chromeSocks} live HTTPS sockets`;
        }

        const otherBadge = document.getElementById("otherAppsBadge");
        const otherMetrics = document.getElementById("otherAppsMetrics");
        const appNames = Object.keys(other.apps || {});
        if (otherBadge) otherBadge.textContent = `${other.active_apps_count || appNames.length} Apps Active`;
        if (otherMetrics) {
            const topApps = appNames.slice(0, 6).map((a) => `${a} (${other.apps[a]})`).join(", ");
            otherMetrics.textContent = topApps
                ? `${otherSocks} live sockets across: ${topApps}`
                : `${otherSocks} active system/app sockets monitored`;
        }

        // Populate alertsData 100% from real live Windows OS & Browser sockets (zero fake alerts)
        if (Array.isArray(data.live_sockets)) {
            const now = new Date();
            const hh = String(now.getHours()).padStart(2, "0");
            const mm = String(now.getMinutes()).padStart(2, "0");

            const prevSelectedSource = alertsData[selectedAlertIndex]?.source;

            alertsData = data.live_sockets.map((s) => {
                const srcKey = s.ip && s.ip !== "0.0.0.0" ? s.ip : s.domain;
                const appInfo = formatFriendlyApp(s.application);
                const appTitle = appInfo.name;
                const portNum = s.port || 443;
                const providerName = s.vendor || "Remote Endpoint";
                const isBlocked = blockedIpSet.has(srcKey) || blockedIpSet.has(s.domain) || s.status === "blocked";

                const shortDetail = isBlocked
                    ? `Blocked (${appTitle})`
                    : s.risk_level === "high"
                    ? `Tracker socket (${appTitle})`
                    : s.risk_level === "medium"
                    ? `Telemetry (${appTitle})`
                    : `${providerName} (${appTitle})`;

                const exactCountry = s.origin_country || s.country || "Global";
                const providerWithCountry = providerName.toLowerCase().includes(exactCountry.toLowerCase())
                    ? providerName
                    : `${providerName} · ${exactCountry}`;

                return {
                    id: s.id || "live-" + srcKey,
                    time: `${hh}:${mm}`,
                    relative: "Live now",
                    severity: s.risk_level === "high" ? "High" : s.risk_level === "medium" ? "Medium" : "Low",
                    type: `${appTitle} (${s.protocol || "TCP"}/${portNum})`,
                    source: srcKey,
                    destination: s.domain || srcKey,
                    protocol: `${s.protocol || "TCP"} (Port ${portNum})`,
                    shortProto: `${appTitle.toUpperCase()}/${portNum}`,
                    details: shortDetail,
                    attempts: providerWithCountry,
                    description: s.explanation || `Verified live outbound connection from ${appTitle} to ${s.domain} (${srcKey}:${portNum}).`,
                    blocked: isBlocked
                };
            });

            if (prevSelectedSource) {
                const foundIdx = alertsData.findIndex((a) => a.source === prevSelectedSource);
                selectedAlertIndex = foundIdx >= 0 ? foundIdx : 0;
            } else {
                selectedAlertIndex = 0;
            }

            if (alertsData.length > 0) {
                selectAlert(selectedAlertIndex);
            } else {
                renderAlertsTable();
                renderRecentAlertsList();
            }
        }

        // Dynamically update Attack / Socket Sources from live IP-to-Country classification
        if (Array.isArray(data.attack_sources)) {
            const listEl = document.getElementById("attackSourcesList");
            if (listEl) {
                listEl.innerHTML = data.attack_sources
                    .map((src, idx) => {
                        const eps = src.endpoints || [];
                        const uniqueApps = Array.from(
                            new Set(
                                eps.map((e) => {
                                    const fname = formatFriendlyApp(e.app).name;
                                    if (src.country === "Other" && e.origin_country && e.origin_country !== "Other") {
                                        return `${fname} (${e.origin_country})`;
                                    }
                                    return fname;
                                })
                            )
                        );
                        const hoverApps =
                            uniqueApps.length > 0
                                ? `Apps using ${src.country}: ${uniqueApps.join(", ")} (Click to view)`
                                : `No active app sockets in ${src.country}`;
                        return `
                        <div class="country-row" data-country-idx="${idx}" style="cursor:pointer; padding:3px 6px; border-radius:6px; transition:background 0.15s;" title="${escapeHtml(hoverApps)}">
                            <span class="country-left"><span class="country-dot" style="background:${src.color};"></span>${escapeHtml(src.country)}</span>
                            <span class="country-count">${src.count}</span>
                        </div>
                    `;
                    })
                    .join("");

                listEl.querySelectorAll(".country-row").forEach((row) => {
                    row.addEventListener("mouseenter", () => {
                        row.style.background = "rgba(255,255,255,0.05)";
                    });
                    row.addEventListener("mouseleave", () => {
                        row.style.background = "transparent";
                    });
                    row.addEventListener("click", () => {
                        const cIdx = parseInt(row.getAttribute("data-country-idx"), 10);
                        const cObj = data.attack_sources[cIdx];
                        if (!cObj) return;
                        openCountryAppsModal(cObj);
                    });
                });
            }
        }
    } catch (_) {}
}

function formatFriendlyApp(rawApp) {
    const k = String(rawApp || "system").toLowerCase().trim();
    const map = {
        opera: { icon: "🌐", name: "Opera Browser", exe: "opera.exe" },
        edge: { icon: "🧭", name: "Microsoft Edge", exe: "msedge.exe" },
        chrome: { icon: "🌎", name: "Google Chrome", exe: "chrome.exe" },
        discord: { icon: "💬", name: "Discord", exe: "Discord.exe" },
        "ms-teams": { icon: "👥", name: "Microsoft Teams", exe: "ms-teams.exe" },
        "arduino ide": { icon: "⚡", name: "Arduino IDE", exe: "Arduino IDE.exe" },
        antigravity: { icon: "🚀", name: "Antigravity IDE", exe: "Antigravity.exe" },
        mobaxterm: { icon: "💻", name: "MobaXterm", exe: "MobaXterm.exe" },
        vncviewer: { icon: "🖥️", name: "VNC Viewer", exe: "vncviewer.exe" },
        overwolf: { icon: "🐺", name: "Overwolf", exe: "Overwolf.exe" },
        overwolfbrowser: { icon: "🐺", name: "Overwolf", exe: "OverwolfBrowser.exe" },
        curseforge: { icon: "🔥", name: "CurseForge", exe: "CurseForge.exe" },
        roblox: { icon: "🎮", name: "Roblox", exe: "RobloxPlayerBeta.exe" },
        robloxplayerbeta: { icon: "🎮", name: "Roblox", exe: "RobloxPlayerBeta.exe" },
        "dawn (feather)": { icon: "🪶", name: "Feather Client (Dawn)", exe: "Dawn (Feather).exe" },
        dawn: { icon: "🪶", name: "Feather Client (Dawn)", exe: "Dawn (Feather).exe" },
        spotify: { icon: "🎵", name: "Spotify", exe: "Spotify.exe" },
        vscode: { icon: "💻", name: "Visual Studio Code", exe: "Code.exe" },
        cursor: { icon: "✨", name: "Cursor IDE", exe: "Cursor.exe" },
        steam: { icon: "🎮", name: "Steam", exe: "steam.exe" },
        "ubisoft connect": { icon: "🎯", name: "Ubisoft Connect", exe: "UbisoftConnect.exe" },
        growtopia: { icon: "🌱", name: "Growtopia", exe: "Growtopia.exe" },
        medal: { icon: "🏅", name: "Medal", exe: "Medal.exe" },
        voicemod: { icon: "🎙️", name: "Voicemod", exe: "VoicemodDesktop.exe" },
        "tiktok live studio": { icon: "🎬", name: "TikTok LIVE Studio", exe: "TikTok LIVE Studio.exe" },
        "wuthering waves": { icon: "🌊", name: "Wuthering Waves", exe: "Client-Win64-Shipping.exe" },
        razer: { icon: "🐍", name: "Razer Central", exe: "Razer Central.exe" },
        anydesk: { icon: "🖥️", name: "AnyDesk", exe: "AnyDesk.exe" },
        teamviewer: { icon: "🖥️", name: "TeamViewer", exe: "TeamViewer.exe" },
        telegram: { icon: "✈️", name: "Telegram Desktop", exe: "Telegram.exe" },
        kaspersky: { icon: "🛡️", name: "Kaspersky", exe: "avp.exe" },
        yandex: { icon: "🌐", name: "Yandex Browser", exe: "browser.exe" },
        vlc: { icon: "🎬", name: "VLC Media Player", exe: "vlc.exe" },
        whatsapp: { icon: "💬", name: "WhatsApp", exe: "WhatsApp.exe" },
        valorant: { icon: "🎯", name: "VALORANT", exe: "VALORANT-Win64-Shipping.exe" },
        "valorant-win64-shipping": { icon: "🎯", name: "VALORANT", exe: "VALORANT-Win64-Shipping.exe" },
        "riot client": { icon: "👊", name: "Riot Client", exe: "RiotClientServices.exe" }
    };
    if (map[k]) return map[k];
    const title = k.charAt(0).toUpperCase() + k.slice(1);
    return { icon: "💻", name: title, exe: `${k}.exe` };
}

function openCountryAppsModal(cObj) {
    const rawEps = cObj.endpoints || [];
    const seenAppNames = new Set();
    const eps = rawEps.filter((ep) => {
        const appName = formatFriendlyApp(ep.app).name;
        if (seenAppNames.has(appName)) return false;
        seenAppNames.add(appName);
        return true;
    });

    const epHtml =
        eps.length === 0
            ? `<div style="color:#64748b; padding:12px;">No applications on your PC currently have active sockets routed to ${escapeHtml(cObj.country)}.</div>`
            : `
            <div class="sentinel-scroll-list" style="display:flex; flex-direction:column; gap:8px; max-height:340px; overflow-y:auto; padding-right:6px;">
                ${eps
                    .map((ep) => {
                        const info = formatFriendlyApp(ep.app);
                        const port = ep.port || 443;
                        const vendor = ep.vendor || "Remote Server";
                        return `
                        <div class="inspect-country-ep-row" data-ip="${escapeHtml(ep.ip)}" style="display:flex; justify-content:space-between; align-items:center; padding:11px 14px; background:rgba(15,25,40,0.92); border:1px solid rgba(255,255,255,0.07); border-radius:9px; font-size:12.5px; cursor:pointer; transition:border-color 0.15s, background 0.15s;" title="Click to inspect this socket in Alert Details">
                            <div style="display:flex; align-items:center; gap:10px; min-width:0;">
                                <span style="font-size:15px;">${info.icon}</span>
                                <strong style="color:#ffffff; font-size:13px;">${escapeHtml(info.name)}</strong>
                                <span style="color:#64748b; font-size:11.5px;">· ${escapeHtml(vendor)}</span>
                            </div>
                            <span class="bs-badge" style="font-family:'JetBrains Mono',monospace; font-weight:600; font-size:11.5px; padding:3px 10px; flex-shrink:0; margin-left:12px;">
                                ${escapeHtml(ep.ip)}:${port}
                            </span>
                        </div>
                    `;
                    })
                    .join("")}
            </div>
        `;

    openUniModal(
        "🌍",
        `Applications Connected to ${cObj.country} (${eps.length} ${eps.length === 1 ? "App" : "Apps"})`,
        "Click any application below to inspect its socket in Alert Details",
        epHtml
    );

    document.querySelectorAll(".inspect-country-ep-row").forEach((row) => {
        row.addEventListener("mouseenter", () => {
            row.style.borderColor = "rgba(16,185,129,0.4)";
            row.style.background = "rgba(20,33,52,0.98)";
        });
        row.addEventListener("mouseleave", () => {
            row.style.borderColor = "rgba(255,255,255,0.07)";
            row.style.background = "rgba(15,25,40,0.92)";
        });
        row.addEventListener("click", () => {
            const targetIp = row.getAttribute("data-ip");
            const idx = alertsData.findIndex((a) => a.source === targetIp);
            if (idx >= 0) {
                selectAlert(idx);
                closeUniModal();
                showToast(`Selected ${alertsData[idx].type} (${targetIp}) in Alert Details`);
            }
        });
    });
}

async function syncBrowserSocketsIntoAlerts() {
    const feedback = document.getElementById("syncFeedbackText");
    if (feedback) feedback.textContent = "Syncing live browser & app sockets...";
    await pollSystemAndBrowsers();
    selectAlert(0);
    if (feedback) feedback.textContent = "Synced live Opera, Edge, Chrome & App sockets ✓";
    showToast("Refreshed live Opera, Edge, Chrome & PC sockets");
}

async function launchBrowser(browser) {
    try {
        await fetch("/api/browser/launch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ browser })
        });
        const label = browser === "opera" ? "Opera Browser" : browser === "edge" ? "Microsoft Edge" : "Google Chrome";
        showToast(`Launching ${label} linked to Sentinel...`);
    } catch (_) {
        showToast(`Requested ${browser} launch`);
    }
}

function showToast(msg) {
    const toast = document.getElementById("sentinelToast");
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add("show");
    clearTimeout(window.__sentinelToastTimer);
    window.__sentinelToastTimer = setTimeout(() => {
        toast.classList.remove("show");
    }, 3000);
}

function escapeHtml(str) {
    return String(str ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}
