/**
 * Sentinel Privacy Desktop App Frontend Controller
 * Matches the exact design and functionality of Sentinel.
 */

let currentFilter = "all";
let currentSearch = "";
let currentInvestigateTarget = null;
let protectMeCandidates = [];

document.addEventListener("DOMContentLoaded", () => {
  refreshDashboard();
  setupEventListeners();
  setInterval(refreshDashboard, 3500);
});

function setupEventListeners() {
  // Filter tabs
  document.querySelectorAll(".filter-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".filter-tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      currentFilter = tab.getAttribute("data-filter");
      renderConnections();
    });
  });

  // Search input
  const searchInput = document.getElementById("search-input");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      currentSearch = e.target.value;
      renderConnections();
    });
  }

  // Demo / Live toggle badge
  const modeBadge = document.getElementById("mode-badge");
  if (modeBadge) {
    modeBadge.addEventListener("click", toggleMode);
  }

  // Protect Me button
  const protectBtn = document.getElementById("btn-protect-me");
  if (protectBtn) {
    protectBtn.addEventListener("click", openProtectMeWizard);
  }

  // Explain My Privacy button
  const explainBtn = document.getElementById("btn-explain-privacy");
  if (explainBtn) {
    explainBtn.addEventListener("click", openExplainPrivacyModal);
  }

  // Settings button
  const settingsBtn = document.getElementById("btn-settings");
  if (settingsBtn) {
    settingsBtn.addEventListener("click", openSettingsModal);
  }
}

// ---------------- DASHBOARD DATA REFRESH ----------------
async function refreshDashboard() {
  try {
    const statsRes = await fetch("/api/stats");
    if (!statsRes.ok) return;
    const stats = await statsRes.json();
    updateStatsUI(stats);
    renderConnections();
  } catch (err) {
    console.error("Dashboard refresh error:", err);
  }
}

function updateStatsUI(stats) {
  // Update score dial (r=58, circumference ≈ 364.4)
  const scoreNum = document.getElementById("score-num");
  const scorePath = document.getElementById("score-path");
  const scoreStatus = document.getElementById("score-status-text");

  if (scoreNum) scoreNum.textContent = stats.privacy_score;
  
  if (scorePath) {
    const circumference = 364.4;
    const offset = circumference - (circumference * (stats.privacy_score / 100));
    scorePath.style.strokeDashoffset = offset;
    
    if (stats.privacy_score >= 80) {
      scorePath.style.stroke = "var(--emerald)";
      if (scoreStatus) {
        scoreStatus.textContent = "Protected & Healthy";
        scoreStatus.style.color = "var(--emerald)";
        scoreStatus.style.background = "var(--emerald-subtle)";
        scoreStatus.style.borderColor = "rgba(16, 185, 129, 0.3)";
      }
    } else if (stats.privacy_score >= 60) {
      scorePath.style.stroke = "var(--amber)";
      if (scoreStatus) {
        scoreStatus.textContent = "Attention Needed";
        scoreStatus.style.color = "var(--amber)";
        scoreStatus.style.background = "var(--amber-subtle)";
        scoreStatus.style.borderColor = "rgba(245, 158, 11, 0.3)";
      }
    } else {
      scorePath.style.stroke = "var(--red)";
      if (scoreStatus) {
        scoreStatus.textContent = "High Risk Exposure";
        scoreStatus.style.color = "var(--red)";
        scoreStatus.style.background = "var(--red-subtle)";
        scoreStatus.style.borderColor = "rgba(239, 68, 68, 0.3)";
      }
    }
  }

  // Update counters
  const totalElem = document.getElementById("stat-total");
  const trackersElem = document.getElementById("stat-trackers");
  const blockedElem = document.getElementById("stat-blocked");
  const highRiskElem = document.getElementById("stat-high-risk");

  if (totalElem) totalElem.textContent = stats.total_connections;
  if (trackersElem) trackersElem.textContent = stats.trackers_detected;
  if (blockedElem) blockedElem.textContent = stats.blocked_count;
  if (highRiskElem) highRiskElem.textContent = stats.high_risk_count;

  // Mode badge
  const modeBadge = document.getElementById("mode-badge");
  if (modeBadge) {
    if (stats.demo_mode) {
      modeBadge.className = "mode-badge demo";
      modeBadge.innerHTML = '<span class="pulse-dot"></span> DEMO MODE (SIMULATED)';
      modeBadge.title = "Click to toggle Live Network Monitoring";
    } else {
      modeBadge.className = "mode-badge live";
      modeBadge.innerHTML = '<span class="pulse-dot"></span> LIVE NETWORK MONITOR';
      modeBadge.title = "Click to switch to Demo Mode";
    }
  }

  // Model tag
  const modelTag = document.getElementById("header-model-tag");
  if (modelTag) {
    const isLive = stats.nebius_connected;
    const shortName = stats.model_name.split("/").pop().toUpperCase();
    modelTag.textContent = isLive ? `NEMOTRON LIVE (${shortName})` : "NEMOTRON READY";
  }
}

// ---------------- CONNECTIONS LIST RENDERING ----------------
async function renderConnections() {
  const container = document.getElementById("activity-container");
  if (!container) return;

  try {
    let url = `/api/connections?filter=${currentFilter}`;
    if (currentSearch) url += `&q=${encodeURIComponent(currentSearch)}`;
    
    const res = await fetch(url);
    if (!res.ok) return;
    const events = await res.json();

    if (events.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; padding: 40px; color: var(--text-dim); background: var(--bg-card); border-radius: var(--radius-md);">
          No matching connections detected in this filter.
        </div>`;
      return;
    }

    container.innerHTML = events.map(ev => {
      const isBlocked = ev.status === "blocked";
      const riskClass = ev.risk_level;
      const appKey = ev.application.toLowerCase();
      const appInitials = getAppInitials(appKey);

      return `
        <div class="connection-item ${isBlocked ? 'blocked' : ''}" data-id="${ev.id}">
          <div class="conn-left">
            <div class="app-badge-box ${appKey}">
              ${appInitials}
            </div>
            <div class="conn-details">
              <div class="conn-domain">
                <span>${escapeHtml(ev.domain)}</span>
                ${isBlocked ? '<span class="badge-blocked">BLOCKED</span>' : ''}
              </div>
              <div class="conn-meta">
                <span>App: <strong>${escapeHtml(ev.application)}</strong></span>
                <span>•</span>
                <span class="badge-cat">${formatCategory(ev.category)}</span>
                <span>•</span>
                <span>${ev.connection_count} conns</span>
                ${ev.vendor ? `<span>• ${escapeHtml(ev.vendor)}</span>` : ''}
              </div>
            </div>
          </div>
          
          <div class="conn-actions">
            <span class="badge-risk ${riskClass}">${riskClass.toUpperCase()} RISK</span>
            <button class="btn-action btn-investigate" onclick="investigateConnection('${escapeHtml(ev.domain)}', '${escapeHtml(ev.application)}')">
              Investigate
            </button>
            ${!isBlocked ? `
              <button class="btn-action btn-block" onclick="quickDecision('${escapeHtml(ev.domain)}', '${escapeHtml(ev.application)}', 'block')">
                Block
              </button>
            ` : `
              <button class="btn-action btn-allow" onclick="quickDecision('${escapeHtml(ev.domain)}', '${escapeHtml(ev.application)}', 'allow')">
                Unblock
              </button>
            `}
          </div>
        </div>
      `;
    }).join("");

  } catch (err) {
    console.error("Error rendering connections:", err);
  }
}

function getAppInitials(app) {
  if (app.includes("chrome")) return "CH";
  if (app.includes("spotify")) return "SP";
  if (app.includes("discord")) return "DI";
  if (app.includes("zoom")) return "ZO";
  if (app.includes("slack")) return "SL";
  if (app.includes("edge")) return "ED";
  if (app.includes("vscode")) return "VS";
  return app.substring(0, 2).toUpperCase();
}

// ---------------- INVESTIGATE WITH NEMOTRON ----------------
async function investigateConnection(domain, application) {
  currentInvestigateTarget = { domain, application };
  const modal = document.getElementById("modal-investigate");
  const modalBody = document.getElementById("investigate-modal-body");
  
  modal.classList.add("active");
  modalBody.innerHTML = `
    <div style="text-align: center; padding: 40px 20px;">
      <div class="pulse-dot" style="width: 24px; height: 24px; margin: 0 auto 16px; background: var(--purple);"></div>
      <h3 style="font-size: 16px; margin-bottom: 6px;">Querying NVIDIA Nemotron via Nebius Token Factory...</h3>
      <p style="color: var(--text-muted); font-size: 13px;">Analyzing domain telemetry, tracking heuristics, and app context for <strong>${escapeHtml(domain)}</strong></p>
    </div>
  `;

  try {
    const res = await fetch("/api/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, application })
    });
    
    if (!res.ok) throw new Error("Investigation request failed");
    const data = await res.json();

    modalBody.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <h2 style="font-size: 20px; font-weight: 700; color: #fff;">${escapeHtml(domain)}</h2>
          <p style="color: var(--text-dim); font-size: 13px;">Target of <strong>${escapeHtml(application)}</strong> • Operated by: <strong>${escapeHtml(data.vendor_profile || "Third-party")}</strong></p>
        </div>
        <span class="badge-risk ${data.risk}">${data.risk.toUpperCase()} RISK</span>
      </div>

      <div class="ai-eval-box">
        <div class="ai-eval-header">
          <div class="ai-model-tag">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
            ${escapeHtml(data.source_model || "NVIDIA Nemotron")}
          </div>
          <span style="font-size: 12px; color: var(--emerald); font-weight: 600;">
            Confidence: ${(data.confidence * 100).toFixed(0)}%
          </span>
        </div>

        <p class="ai-explanation">${escapeHtml(data.explanation)}</p>

        <div class="consequences-title">Potential Consequences If Blocked:</div>
        <ul class="consequence-list">
          ${(data.possible_consequences || []).map(c => `<li>${escapeHtml(c)}</li>`).join("")}
        </ul>
      </div>

      <div style="background: var(--bg-card-inner); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 14px;">
        <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); margin-bottom: 6px; text-transform: uppercase;">Nemotron Recommendation</div>
        <div style="font-size: 14px; color: #fff;">
          Nemotron recommends to <strong>${data.recommendation.toUpperCase()}</strong> this connection based on telemetry classification.
        </div>
      </div>
    `;

  } catch (err) {
    modalBody.innerHTML = `
      <div style="text-align: center; padding: 30px; color: var(--red);">
        Failed to complete investigation: ${err.message}
      </div>
    `;
  }
}

// ---------------- "PROTECT ME" 10-STEP AGENT WIZARD ----------------
async function openProtectMeWizard() {
  const modal = document.getElementById("modal-protect");
  const modalBody = document.getElementById("protect-modal-body");
  const btnApply = document.getElementById("btn-apply-protect");
  
  modal.classList.add("active");
  btnApply.style.display = "none";
  
  modalBody.innerHTML = `
    <div style="text-align: center; padding: 40px 20px;">
      <div class="pulse-dot" style="width: 28px; height: 28px; margin: 0 auto 16px; background: var(--emerald);"></div>
      <h3 style="font-size: 17px; margin-bottom: 6px;">Initiating Sentinel 'Protect Me' Sweep...</h3>
      <p style="color: var(--text-muted); font-size: 13px;">
        Checking recent connections • Extracting sanitized privacy signals • Querying NVIDIA Nemotron for policy recommendations
      </p>
    </div>
  `;

  try {
    const res = await fetch("/api/protect-me/analyze", { method: "POST" });
    if (!res.ok) throw new Error("Protect Me analysis failed");
    const data = await res.json();
    protectMeCandidates = data.items;

    btnApply.style.display = "inline-flex";

    modalBody.innerHTML = `
      <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: var(--radius-md); padding: 16px;">
        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-weight: 700; color: var(--emerald);">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Nemotron Assessment
        </div>
        <p style="font-size: 14px; color: #e2e8f0; line-height: 1.5;">${escapeHtml(data.narrative)}</p>
      </div>

      <div style="margin-top: 10px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <h4 style="font-size: 14px; font-weight: 700; color: #fff;">Proposed Rule Actions (${data.items.length})</h4>
          <span style="font-size: 12px; color: var(--text-dim);">Uncheck any service you wish to keep</span>
        </div>

        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
          <thead>
            <tr style="border-bottom: 1px solid var(--border); text-align: left; color: var(--text-dim); font-size: 11px; text-transform: uppercase;">
              <th style="padding: 8px 12px; width: 36px;"><input type="checkbox" id="select-all-protect" checked onchange="toggleSelectAllProtect(this.checked)"></th>
              <th style="padding: 8px 12px;">Application</th>
              <th style="padding: 8px 12px;">Domain</th>
              <th style="padding: 8px 12px;">Action</th>
              <th style="padding: 8px 12px;">Risk</th>
            </tr>
          </thead>
          <tbody>
            ${data.items.map((it, idx) => `
              <tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.04);">
                <td style="padding: 10px 12px;">
                  <input type="checkbox" class="protect-item-cb" data-idx="${idx}" ${it.selected ? 'checked' : ''} style="accent-color: var(--emerald);">
                </td>
                <td style="padding: 10px 12px;"><strong>${escapeHtml(it.application)}</strong></td>
                <td style="padding: 10px 12px;">
                  <div style="font-weight: 500;">${escapeHtml(it.domain)}</div>
                  <div style="font-size: 11px; color: var(--text-dim);">${escapeHtml(it.explanation.substring(0, 60))}...</div>
                </td>
                <td style="padding: 10px 12px;">
                  <span class="badge-risk ${it.recommended_action === 'block' ? 'high' : 'safe'}" style="font-size: 10px; padding: 2px 7px;">
                    ${it.recommended_action.toUpperCase()}
                  </span>
                </td>
                <td style="padding: 10px 12px;"><span class="badge-risk ${it.risk}" style="font-size: 10px; padding: 2px 7px;">${it.risk.toUpperCase()}</span></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `;

  } catch (err) {
    modalBody.innerHTML = `
      <div style="text-align: center; padding: 30px; color: var(--red);">
        Failed to evaluate protection sweep: ${err.message}
      </div>
    `;
  }
}

function toggleSelectAllProtect(checked) {
  document.querySelectorAll(".protect-item-cb").forEach(cb => {
    cb.checked = checked;
  });
}

async function applyProtectionPlan() {
  const modalBody = document.getElementById("protect-modal-body");
  const btnApply = document.getElementById("btn-apply-protect");
  btnApply.disabled = true;

  const decisions = [];
  document.querySelectorAll(".protect-item-cb").forEach(cb => {
    const idx = parseInt(cb.getAttribute("data-idx"), 10);
    const item = protectMeCandidates[idx];
    if (item) {
      decisions.push({
        domain: item.domain,
        application: item.application,
        action: cb.checked ? item.recommended_action : "allow"
      });
    }
  });

  try {
    const res = await fetch("/api/protect-me/apply", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decisions })
    });
    
    if (!res.ok) throw new Error("Failed to apply protection rules");
    const result = await res.json();

    modalBody.innerHTML = `
      <div style="text-align: center; padding: 30px 10px;">
        <div style="width: 56px; height: 56px; border-radius: 50%; background: var(--emerald-glow); border: 2px solid var(--emerald); display: flex; align-items: center; justify-content: center; margin: 0 auto 16px; color: var(--emerald);">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
        </div>
        <h2 style="font-size: 22px; font-weight: 800; color: #fff; margin-bottom: 8px;">Sentinel Protection Active!</h2>
        <p style="color: #cbd5e1; font-size: 14px; max-width: 480px; margin: 0 auto 20px; line-height: 1.6;">
          ${escapeHtml(result.summary)}
        </p>

        <div style="display: inline-flex; gap: 24px; background: var(--bg-card-inner); padding: 14px 28px; border-radius: var(--radius-md); border: 1px solid var(--border);">
          <div>
            <div style="font-size: 11px; color: var(--text-dim); font-weight: 700;">PREVIOUS SCORE</div>
            <div style="font-size: 20px; font-weight: 700; color: var(--amber);">${result.previous_score}/100</div>
          </div>
          <div style="font-size: 20px; color: var(--text-dim); display: flex; align-items: center;">→</div>
          <div>
            <div style="font-size: 11px; color: var(--text-dim); font-weight: 700;">NEW PRIVACY SCORE</div>
            <div style="font-size: 20px; font-weight: 700; color: var(--emerald);">${result.new_score}/100</div>
          </div>
        </div>
      </div>
    `;

    btnApply.style.display = "none";
    refreshDashboard();
    showToast("Protection rules successfully enforced", "success");

  } catch (err) {
    showToast(`Error: ${err.message}`, "warning");
    btnApply.disabled = false;
  }
}

// ---------------- "EXPLAIN MY PRIVACY" REPORT ----------------
async function openExplainPrivacyModal() {
  const modal = document.getElementById("modal-explain");
  const modalBody = document.getElementById("explain-modal-body");
  
  modal.classList.add("active");
  modalBody.innerHTML = `
    <div style="text-align: center; padding: 40px 20px;">
      <div class="pulse-dot" style="width: 24px; height: 24px; margin: 0 auto 16px; background: var(--purple);"></div>
      <h3 style="font-size: 16px; margin-bottom: 6px;">Synthesizing AI Privacy Audit with NVIDIA Nemotron...</h3>
      <p style="color: var(--text-muted); font-size: 13px;">Analyzing network beacons, tracker distributions, and host application behavior</p>
    </div>
  `;

  try {
    const res = await fetch("/api/explain-privacy");
    if (!res.ok) throw new Error("Could not generate privacy audit");
    const data = await res.json();

    const narrativeHtml = data.narrative_report
      .replace(/### (.*?)\n/g, '<h3 style="font-size: 15px; font-weight: 700; color: #fff; margin: 16px 0 6px;">$1</h3>')
      .replace(/\*\*(.*?)\*\*/g, '<strong style="color: #fff;">$1</strong>')
      .replace(/\n\n/g, '<p style="color: #cbd5e1; font-size: 14px; line-height: 1.6; margin-bottom: 12px;"></p>');

    modalBody.innerHTML = `
      <div style="display: flex; gap: 16px; margin-bottom: 20px;">
        <div style="flex: 1; background: var(--bg-card-inner); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 14px; text-align: center;">
          <div style="font-size: 11px; color: var(--text-dim); text-transform: uppercase; font-weight: 700;">Privacy Score</div>
          <div style="font-size: 26px; font-weight: 800; color: var(--emerald);">${data.score}/100</div>
        </div>
        <div style="flex: 1; background: var(--bg-card-inner); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 14px; text-align: center;">
          <div style="font-size: 11px; color: var(--text-dim); text-transform: uppercase; font-weight: 700;">Trackers Neutralized</div>
          <div style="font-size: 26px; font-weight: 800; color: var(--purple);">${data.blocked_count} / ${data.trackers_detected}</div>
        </div>
        <div style="flex: 1; background: var(--bg-card-inner); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 14px; text-align: center;">
          <div style="font-size: 11px; color: var(--text-dim); text-transform: uppercase; font-weight: 700;">High Risk Threats</div>
          <div style="font-size: 26px; font-weight: 800; color: ${data.high_risk_count > 0 ? 'var(--red)' : 'var(--emerald)'};">${data.high_risk_count}</div>
        </div>
      </div>

      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 20px;">
        ${narrativeHtml}
      </div>
    `;

  } catch (err) {
    modalBody.innerHTML = `
      <div style="text-align: center; padding: 30px; color: var(--red);">
        Failed to generate report: ${err.message}
      </div>
    `;
  }
}

// ---------------- QUICK MANUAL DECISION ----------------
async function quickDecision(domain, application, decision) {
  try {
    const res = await fetch("/api/decision", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, application, decision })
    });
    if (!res.ok) throw new Error("Failed to save decision");
    
    showToast(`Domain ${domain} is now ${decision.toUpperCase()}`, "success");
    refreshDashboard();
  } catch (err) {
    showToast(`Error: ${err.message}`, "warning");
  }
}

async function applyModalDecision(decision) {
  if (!currentInvestigateTarget) return;
  await quickDecision(currentInvestigateTarget.domain, currentInvestigateTarget.application, decision);
  closeModal("modal-investigate");
}

// ---------------- DEMO / LIVE MODE TOGGLE ----------------
async function toggleMode() {
  try {
    const res = await fetch("/api/toggle-mode", { method: "POST" });
    if (!res.ok) return;
    const data = await res.json();
    showToast(data.message, "success");
    refreshDashboard();
  } catch (err) {
    showToast("Failed to switch monitoring mode", "warning");
  }
}

// ---------------- SETTINGS MODAL ----------------
async function openSettingsModal() {
  const modal = document.getElementById("modal-settings");
  modal.classList.add("active");

  try {
    const res = await fetch("/api/settings");
    if (!res.ok) return;
    const data = await res.json();
    
    document.getElementById("input-model").value = data.nebius_model || "";
    document.getElementById("input-base-url").value = data.nebius_base_url || "";
    const statusElem = document.getElementById("nebius-status-badge");
    if (statusElem) {
      if (data.nebius_configured) {
        statusElem.textContent = "CONNECTED (API KEY SET)";
        statusElem.style.color = "var(--emerald)";
      } else {
        statusElem.textContent = "OFFLINE / FALLBACK MODE";
        statusElem.style.color = "var(--amber)";
      }
    }
  } catch (err) {
    console.error("Settings load error:", err);
  }
}

async function saveSettings() {
  const apiKey = document.getElementById("input-api-key").value;
  const model = document.getElementById("input-model").value;
  const baseUrl = document.getElementById("input-base-url").value;

  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        nebius_api_key: apiKey ? apiKey : undefined,
        nebius_model: model,
        nebius_base_url: baseUrl
      })
    });
    if (!res.ok) throw new Error("Failed to save settings");
    showToast("Settings updated successfully", "success");
    closeModal("modal-settings");
    refreshDashboard();
  } catch (err) {
    showToast(`Error: ${err.message}`, "warning");
  }
}

async function resetDemoEnvironment() {
  try {
    await fetch("/api/demo/reset", { method: "POST" });
    showToast("Demo environment reset to baseline", "success");
    closeModal("modal-settings");
    refreshDashboard();
  } catch (err) {
    showToast("Failed to reset demo", "warning");
  }
}

// ---------------- MODAL UTILITIES ----------------
function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.remove("active");
}

function showToast(message, type = "success") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(100%)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 3200);
}

function formatCategory(cat) {
  const map = {
    "ad_tracking": "Ad Tracking",
    "analytics": "Analytics",
    "telemetry": "Telemetry",
    "fingerprinting": "Fingerprinting",
    "crash_reporting": "Crash Log",
    "cdn_content": "CDN Asset",
    "essential_api": "Essential API",
    "unknown": "General"
  };
  return map[cat] || cat;
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
