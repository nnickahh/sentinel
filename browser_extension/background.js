// Sentinel — Browser Link & Active Firewall Enforcer (Edge & Chrome)
const SENTINEL_API = "http://127.0.0.1:8765";
const recentDomains = new Map();
let blockedDomainsSet = new Set();

function detectBrowserName() {
  const ua = navigator.userAgent || "";
  if (ua.includes("OPR/") || ua.includes("Opera")) return "opera";
  if (ua.includes("Edg/")) return "edge";
  return "chrome";
}

// Poll Sentinel's SQLite blocklist (/api/rules) so blocked domains are actively stopped in Edge/Chrome
async function syncBlockedRulesFromSentinel() {
  try {
    const res = await fetch(`${SENTINEL_API}/api/rules`);
    if (!res.ok) return;
    const rules = await res.json();
    const nextSet = new Set();
    for (const r of rules) {
      if (r.decision === "block" && r.domain) {
        nextSet.add(r.domain.toLowerCase().trim());
      }
    }
    blockedDomainsSet = nextSet;
  } catch (_) {}
}

syncBlockedRulesFromSentinel();
setInterval(syncBlockedRulesFromSentinel, 5000);

async function reportDomainToSentinel(domain, url, tabTitle = "") {
  if (!domain || domain === "127.0.0.1" || domain === "localhost") return;
  const now = Date.now();
  const lastSent = recentDomains.get(domain) || 0;
  if (now - lastSent < 8000) return;
  recentDomains.set(domain, now);

  try {
    await fetch(`${SENTINEL_API}/api/browser/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        browser: detectBrowserName(),
        domain: domain,
        url: url,
        ip: "0.0.0.0",
        tab_title: tabTitle
      })
    });
  } catch (_) {}
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (tab.url && tab.url.startsWith("http")) {
    try {
      const parsed = new URL(tab.url);
      const host = parsed.hostname.toLowerCase();

      // Active blocklist enforcement inside Edge & Chrome
      if (blockedDomainsSet.has(host)) {
        chrome.tabs.update(tabId, {
          url: `${SENTINEL_API}/?blocked_domain=${encodeURIComponent(host)}`
        });
        return;
      }

      if (changeInfo.status === "complete") {
        reportDomainToSentinel(host, tab.url, tab.title || "");
      }
    } catch (_) {}
  }
});

if (chrome.webRequest && chrome.webRequest.onBeforeRequest) {
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      if (!details.url || !details.url.startsWith("http")) return;
      try {
        const parsed = new URL(details.url);
        if (parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost") {
          reportDomainToSentinel(parsed.hostname, details.url, "Background WebRequest");
        }
      } catch (_) {}
    },
    { urls: ["<all_urls>"] }
  );
}
