document.addEventListener("DOMContentLoaded", async () => {
  const scoreEl = document.getElementById("extScore");
  const countsEl = document.getElementById("extCounts");
  const statusEl = document.getElementById("extStatus");

  try {
    const res = await fetch("http://127.0.0.1:8765/api/stats");
    const data = await res.json();
    scoreEl.textContent = `${data.privacy_score}/100`;
    countsEl.innerHTML = `Trackers: <b>${data.trackers_detected}</b><br>Blocked: <b>${data.blocked_count}</b>`;
    statusEl.textContent = "LIVE LINK";
  } catch (e) {
    statusEl.textContent = "OFFLINE";
    statusEl.style.color = "#f87171";
  }
});
