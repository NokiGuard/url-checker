"use strict";

// ---------------------------------------------------------------------------
// Risk classification
// ---------------------------------------------------------------------------

function classifyRisk(stats, settings) {
  const malicious  = (stats.malicious  || 0);
  const suspicious = (stats.suspicious || 0);
  const threshMalicious  = settings?.threshMalicious  ?? 5;
  const threshSuspicious = settings?.threshSuspicious ?? 1;

  if (malicious >= threshMalicious)  return "malicious";
  if (malicious >= threshSuspicious || suspicious >= 3) return "suspicious";
  return "clean";
}

const RISK = {
  clean:      { label: "Clean",      icon: "✓", css: "risk-clean",      btnColor: "#2e7d32" },
  suspicious: { label: "Suspicious", icon: "⚠", css: "risk-suspicious", btnColor: "#e65100" },
  malicious:  { label: "Malicious",  icon: "✕", css: "risk-malicious",  btnColor: "#b71c1c" }
};

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

function renderResults(url, analysisResult, settings) {
  // Normalise across /urls/{id} and /analyses/{id} response shapes
  const attrs   = analysisResult.data?.attributes || {};
  const stats   = attrs.last_analysis_stats || attrs.stats || {};
  const results = attrs.last_analysis_results || attrs.results || {};
  const lastTs  = attrs.last_analysis_date;
  const dateStr = lastTs
    ? new Date(lastTs * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })
    : "Just now";

  const risk   = classifyRisk(stats, settings);
  const config = RISK[risk];

  // Banner
  const banner = document.getElementById("risk-banner");
  banner.classList.add(config.css);
  document.getElementById("risk-icon").textContent  = config.icon;
  document.getElementById("risk-label").textContent = config.label;

  if (analysisResult.fromCache) {
    document.getElementById("cache-badge").style.display = "inline";
  }

  // URL
  document.getElementById("url-text").textContent = url;

  // Stats
  const malCount = stats.malicious  || 0;
  const susCount = stats.suspicious || 0;
  const harCount = stats.harmless   || 0;
  const total    = Object.values(stats).reduce((a, b) => a + b, 0);

  const malEl = document.getElementById("stat-malicious");
  malEl.textContent = malCount;
  if (malCount > 0) malEl.classList.add("danger");

  const susEl = document.getElementById("stat-suspicious");
  susEl.textContent = susCount;
  if (susCount > 0) susEl.classList.add("warn");

  document.getElementById("stat-harmless").textContent = harCount;
  document.getElementById("stat-total").textContent    = total;
  document.getElementById("stat-date").textContent     = dateStr;

  // Vendor table — malicious first, then suspicious, then clean
  const SORT_ORDER = { malicious: 0, phishing: 0, suspicious: 1, clean: 9, undetected: 9 };
  const entries = Object.entries(results).sort(([, a], [, b]) => {
    const ao = SORT_ORDER[a.category] ?? 5;
    const bo = SORT_ORDER[b.category] ?? 5;
    return ao - bo;
  });

  const tbody = document.getElementById("vendor-tbody");
  for (const [engine, det] of entries) {
    const tr  = document.createElement("tr");
    const cat = det.category || "undetected";
    const res = det.result   || "—";
    tr.innerHTML = `
      <td title="${esc(engine)}">${esc(engine)}</td>
      <td class="cat-${esc(cat)}">${esc(cat)}</td>
      <td title="${esc(res)}">${esc(res)}</td>
    `;
    tbody.appendChild(tr);
  }

  // Open button colour matches risk
  document.getElementById("btn-open").style.background = config.btnColor;

  // Show results panel
  document.getElementById("loading").style.display = "none";
  document.getElementById("results").style.display  = "block";
}

function showError(msg) {
  document.getElementById("loading").innerHTML = `
    <p style="color:#b71c1c;padding:24px;text-align:center;line-height:1.6">${esc(msg)}</p>
  `;
}

// ---------------------------------------------------------------------------
// Init — fetch data from background, then render
// ---------------------------------------------------------------------------

(async function init() {
  const params = new URLSearchParams(window.location.search);
  const token  = params.get("token");

  if (!token) {
    showError("No result token found. Close this window.");
    return;
  }

  let data, settings;
  try {
    [data, settings] = await Promise.all([
      browser.runtime.sendMessage({ type: "GET_RESULT_DATA", token }),
      browser.storage.local.get("vtSettings").then(s => s.vtSettings || {})
    ]);
  } catch (err) {
    showError(`Failed to load results: ${err.message}`);
    return;
  }

  if (!data) {
    showError("Result data not found or expired. Close this window and try again.");
    return;
  }

  renderResults(data.url, data.analysisResult, settings);
})();

// ---------------------------------------------------------------------------
// Button handlers
// ---------------------------------------------------------------------------

document.getElementById("btn-open").addEventListener("click", () => {
  browser.runtime.sendMessage({ type: "USER_DECISION", decision: "open" });
  // background.js closes this window after processing the decision
});

document.getElementById("btn-cancel").addEventListener("click", () => {
  browser.runtime.sendMessage({ type: "USER_DECISION", decision: "cancel" });
  // background.js closes this window after processing the decision
});

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function esc(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
