
const API_BASE = "http://127.0.0.1:8000";

const fileInput = document.getElementById("fileInput");
const dropzone = document.getElementById("dropzone");
const fileName = document.getElementById("fileName");
const analyzeBtn = document.getElementById("analyzeBtn");
const errorBox = document.getElementById("error");
const apiStatus = document.getElementById("apiStatus");
let latestAnalysis = null;
let originalEmailFile = null;
let latestSource = "upload";
let latestGmailMessageId = null;

const downloadEmlBtn = document.getElementById("downloadEmlBtn");
const downloadHtmlBtn = document.getElementById("downloadHtmlBtn");
const downloadJsonBtn = document.getElementById("downloadJsonBtn");
const exportFormat = document.getElementById("exportFormat");
document.getElementById("exportSelectedBtn").addEventListener("click", () => {
  if (!latestAnalysis) return;
  const format = exportFormat.value;
  if (format === "eml") {
    if (downloadEmlBtn.disabled) {
      document.getElementById("exportAvailabilityNote").textContent = "Original .eml is unavailable for this analysis source.";
      return;
    }
    downloadEmlBtn.click();
  } else if (format === "html") {
    downloadHtmlBtn.click();
  } else if (format === "json") {
    downloadJsonBtn.click();
  }
});
exportFormat.addEventListener("change", () => {
  const note = document.getElementById("exportAvailabilityNote");
  note.textContent = exportFormat.value === "eml" && downloadEmlBtn.disabled
    ? "Original .eml is unavailable for header-only analysis."
    : "Ready to export the selected format.";
});

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function safeFilename(value) {
  return String(value || "analyzed-email")
    .replace(/[^a-z0-9._-]+/gi, "_")
    .replace(/^[_\.]+|[_\.]+$/g, "")
    .slice(0, 80) || "analyzed-email";
}

function getEmailLabel(data) {
  const sender = getObject(data?.sender);
  return safeFilename(data?.subject || sender.from || data?.from || "analyzed-email");
}

function reportHtml(data) {
  const d = getObject(data);
  const sender = getObject(d.sender);
  const auth = getObject(d.authentication);
  const findings = arr(d.findings);
  const urls = arr(d.urls);
  const attachments = arr(d.attachments);
  const received = arr(d.received_chain || d.received);
  const escHtml = value => esc(value).replace(/\n/g, "<br>");
  const list = items => items.length ? `<ul>${items.map(x => `<li>${escHtml(typeof x === "string" ? x : JSON.stringify(x))}</li>`).join("")}</ul>` : "<p>None reported.</p>";
  const table = (items, cols) => items.length ? `<table><thead><tr>${cols.map(c => `<th>${esc(c.label)}</th>`).join("")}</tr></thead><tbody>${items.map(item => `<tr>${cols.map(c => `<td>${escHtml(item?.[c.key] ?? "—")}</td>`).join("")}</tr>`).join("")}</tbody></table>` : "<p>None reported.</p>";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Email Threat Analysis</title><style>body{font:15px/1.5 Arial,sans-serif;max-width:1050px;margin:30px auto;padding:0 18px;color:#182230}h1,h2{color:#12304a}section{border:1px solid #d7e0e8;border-radius:10px;padding:18px;margin:16px 0;break-inside:avoid}.risk{font-size:1.3rem;font-weight:bold}table{width:100%;border-collapse:collapse;table-layout:fixed;overflow-wrap:anywhere}th,td{border:1px solid #d7e0e8;padding:8px;text-align:left;vertical-align:top}th{background:#eef4f8}.muted{color:#667085}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style></head><body><h1>Email Threat Analysis Report</h1><p class="muted">Generated locally by Email Threat Analyzer on ${esc(new Date().toLocaleString())}</p><section><h2>Summary</h2><p class="risk">Risk: ${esc(d.risk_level ?? "Unknown")} | Score: ${esc(d.risk_score ?? "—")} | Confidence: ${esc(d.confidence ?? "—")}</p><p>${escHtml(d.assessment_note ?? "No assessment note provided.")}</p></section><section><h2>Sender</h2><p><b>From:</b> ${escHtml(sender.from ?? d.from ?? "—")}</p><p><b>Reply-To:</b> ${escHtml(sender.reply_to ?? d.reply_to ?? "—")}</p><p><b>Return-Path:</b> ${escHtml(sender.return_path ?? d.return_path ?? "—")}</p></section><section><h2>Authentication</h2><pre>${escHtml(JSON.stringify(auth, null, 2))}</pre></section><section><h2>Findings</h2>${list(findings)}</section><section><h2>URLs</h2>${table(urls, [{ key: "url", label: "URL" }, { key: "indicators", label: "Indicators" }, { key: "reputation", label: "Reputation" }, { key: "virustotal", label: "VirusTotal" }])}</section><section><h2>Attachments</h2>${table(attachments, [{ key: "filename", label: "Filename" }, { key: "sha256", label: "SHA-256" }, { key: "risk", label: "Risk" }, { key: "reputation", label: "Reputation" }])}</section><section><h2>Received chain</h2>${list(received)}</section><p class="muted">This report reflects the analyzer response at export time. Treat external reputation results as point-in-time data.</p></body></html>`;
}

function updateDownloadControls(data, source) {
  latestAnalysis = data;
  latestSource = source;
  document.getElementById("resultExportToolbar").classList.remove("hidden");
  downloadHtmlBtn.disabled = false;
  downloadJsonBtn.disabled = false;
  downloadEmlBtn.disabled = !(originalEmailFile instanceof Blob) && !(source === "gmail" && latestGmailMessageId);
  const note = document.getElementById("exportAvailabilityNote");
  note.textContent = downloadEmlBtn.disabled ? "Original .eml is unavailable for header-only analysis." : "Choose a format and select Export.";
  document.getElementById("exportFormat").value = downloadEmlBtn.disabled ? "html" : "html";
}

// --------------------------------------------------
// 1. GENERAL DISPLAY HELPERS
// --------------------------------------------------

function isObject(value) {
  return value !== null && typeof value === "object";
}

function toText(value) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  if (Array.isArray(value)) {
    return value.length
      ? value.map(item => toText(item)).join(", ")
      : "None";
  }

  if (isObject(value)) {
    return JSON.stringify(value, null, 2);
  }

  return String(value);
}

// Escape HTML so email contents and API responses
// cannot be interpreted as HTML or JavaScript.
function esc(value) {
  return toText(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function arr(value) {
  return Array.isArray(value) ? value : [];
}

function levelClass(level) {
  return String(level || "")
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "");
}

function pills(items) {
  const values = arr(items);

  return values.length
    ? values.map(item =>
      `<span class="pill">${esc(item)}</span>`
    ).join("")
    : '<span class="muted">None</span>';
}

function kv(rows) {
  return rows.map(([key, value]) => `
    <div class="kv-row">
      <div class="key">${esc(key)}</div>
      <div class="value">${esc(value)}</div>
    </div>
  `).join("");
}

// Safely read nested properties without assuming
// every API response has the same structure.
function getObject(value) {
  return isObject(value) && !Array.isArray(value)
    ? value
    : {};
}

function firstValue(...values) {
  for (const value of values) {
    if (
      value !== undefined &&
      value !== null &&
      value !== ""
    ) {
      return value;
    }
  }

  return "—";
}

// --------------------------------------------------
// 2. API STATUS
// --------------------------------------------------

async function checkApi() {
  try {
    const response = await fetch(`${API_BASE}/health`);

    apiStatus.textContent = response.ok
      ? "API: online"
      : "API: error";
  } catch {
    apiStatus.textContent = "API: offline";
  }
}

// --------------------------------------------------
// Tabs, browser-local analysis history, and header paste
// --------------------------------------------------
const HISTORY_KEY = "eta_analysis_history_v1";
function readHistory() { try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch { return []; } }
function saveHistory(data, source) {
  const entry = { id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, saved_at: new Date().toISOString(), source, label: getEmailLabel(data), data };
  const history = [entry, ...readHistory()].slice(0, 100);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  renderHistoryPanels();
  renderDashboard();
}
function renderDashboard() {
  const history = readHistory();
  const $ = id => document.getElementById(id);
  const total = $('dashboardTotal');
  if (!total) return;
  const highCount = history.filter(x => /high|critical/i.test(String(x.data?.risk_level || ''))).length;
  const findings = history.reduce((sum, x) => sum + arr(x.data?.findings).length, 0);
  const average = history.length ? (findings / history.length).toFixed(1) : '0.0';
  total.textContent = String(history.length);
  $('dashboardHigh').textContent = String(highCount);
  $('dashboardFindings').textContent = String(findings);
  $('dashboardAvgFindings').textContent = average;
  $('dashboardHighRate').textContent = history.length ? `${Math.round(highCount / history.length * 100)}%` : '0%';
  $('dashboardRecentCount').textContent = `${history.filter(x => Date.now() - new Date(x.saved_at).getTime() < 7 * 86400000).length} recent`;
  $('dashboardCoverage').textContent = history.length ? `${history.length} saved record${history.length === 1 ? '' : 's'} · local browser storage` : 'No analysis data yet';
  if (history.length) {
    const item = history[0]; const d = new Date(item.saved_at);
    $('dashboardLatest').textContent = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    $('dashboardLatestMeta').textContent = `${item.label || 'Analyzed email'} · ${d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}`;
    $('dashboardLatestRisk').textContent = String(item.data?.risk_level || 'UNKNOWN').toUpperCase();
  } else {
    $('dashboardLatest').textContent = '—'; $('dashboardLatestMeta').textContent = 'No analyses saved yet'; $('dashboardLatestRisk').textContent = '—';
  }

  const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const counts = Object.fromEntries(levels.map(level => [level, history.filter(x => String(x.data?.risk_level || 'UNKNOWN').toUpperCase() === level).length]));
  const colors = { CRITICAL: '#ff5364', HIGH: '#ff874f', MEDIUM: '#f4c35e', LOW: '#45d6a1', UNKNOWN: '#8393aa' };
  const chart = $('dashboardRiskChart');
  if (chart) {
    if (!history.length) chart.innerHTML = '<p class="empty-state">Analyze an email to populate the risk distribution.</p>';
    else {
      const max = Math.max(1, ...levels.map(k => counts[k]));
      let cursor = 0;
      const stops = levels.map(level => { const start = cursor; cursor += counts[level] / history.length * 100; return `${colors[level]} ${start}% ${cursor}%`; }).join(', ');
      chart.innerHTML = `<div class="risk-chart-layout"><div class="risk-donut" style="background:conic-gradient(${stops})" role="img" aria-label="Risk distribution across ${history.length} saved analyses"><div><strong>${history.length}</strong><span>ANALYSES</span></div></div><div class="risk-legend">${levels.map(level => `<div class="risk-legend-row"><span class="risk-dot" style="background:${colors[level]}"></span><span>${level}</span><b>${counts[level]}</b><div class="mini-track"><i style="width:${Math.round(counts[level] / max * 100)}%;background:${colors[level]}"></i></div></div>`).join('')}</div></div><p class="chart-footnote">Counts represent the latest stored verdict per analysis. They are not a live mail-feed or measured detection rate.</p>`;
    }
  }

  const recent = $('dashboardRecent');
  if (recent) {
    recent.innerHTML = history.length ? history.slice(0, 5).map(item => {
      const d = new Date(item.saved_at); const level = String(item.data?.risk_level || 'UNKNOWN').toUpperCase();
      const sender = getObject(item.data?.sender);
      const title = item.data?.subject || item.label || sender.from || 'Analyzed email';
      const findingsCount = arr(item.data?.findings).length;
      return `<button class="recent-analysis" data-restore-history="${esc(item.id)}"><span class="recent-risk risk-${levelClass(level)}">${esc(level)}</span><span class="recent-main"><b>${esc(title)}</b><small>${esc(sender.from || item.source || 'Email analysis')} · ${esc(d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }))}</small></span><span class="recent-findings">${findingsCount}<small>signals</small></span><span class="recent-arrow">↗</span></button>`;
    }).join('') : '<p class="empty-state">No saved analyses yet. Start by analyzing an email.</p>';
  }

  const findingCounts = {};
  history.forEach(item => arr(item.data?.findings).forEach(f => {
    const title = String(f?.title || 'Other finding');
    let group = 'Other indicators';
    if (/url|link|domain|punycode|redirect/i.test(title)) group = 'URLs & domains';
    else if (/spf|dkim|dmarc|authentication/i.test(title)) group = 'Authentication';
    else if (/attachment|archive|yara|file hash/i.test(title)) group = 'Attachments';
    else if (/ip|received|mail route/i.test(title)) group = 'Mail route / IPs';
    else if (/sender|reply-to|return-path/i.test(title)) group = 'Sender identity';
    findingCounts[group] = (findingCounts[group] || 0) + 1;
  }));
  const findingChart = $('dashboardFindingChart');
  if (findingChart) {
    const entries = Object.entries(findingCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const max = Math.max(1, ...entries.map(x => x[1]));
    findingChart.innerHTML = entries.length ? entries.map(([label, count]) => `<div class="finding-bar-row"><div><span>${esc(label)}</span><b>${count}</b></div><div class="finding-bar-track"><i style="width:${Math.round(count / max * 100)}%"></i></div></div>`).join('') : '<p class="empty-state">Finding statistics will appear after analysis.</p>';
  }
}

function renderCurrentEmailIpDashboard(data) {
  const panel = document.getElementById('analysisIpDashboard');
  if (!panel) return;
  panel.classList.remove('hidden');
  const received = data?.received_chain ?? data?.received ?? [];
  const ips = [];
  if (Array.isArray(received)) received.forEach((hop, index) => {
    let hopIps = Array.isArray(hop?.ips) ? hop.ips : [];
    const raw = String(hop?.raw ?? hop?.value ?? hop?.header ?? '');
    if (!hopIps.length) hopIps = [...new Set(raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])].map(ip => ({ ip }));
    hopIps.forEach(item => {
      const obj = typeof item === 'string' ? { ip: item } : item;
      const ip = String(obj?.ip ?? obj?.address ?? obj?.value ?? '');
      if (ip && !ips.some(x => x.ip === ip)) ips.push({ ...obj, ip, hopIndex: index });
    });
  });
  const scoreOf = ip => { const vals = [ip?.abuseipdb?.abuse_confidence_score, ip?.abuseipdb?.data?.abuseConfidenceScore, ip?.abuse_confidence_score, ip?.abuseConfidenceScore]; for (const v of vals) if (v !== undefined && v !== null && v !== '' && Number.isFinite(Number(v))) return Number(v); return null; };
  const vtOf = ip => { const v = ip?.virustotal?.malicious ?? ip?.virustotal?.data?.attributes?.last_analysis_stats?.malicious ?? ip?.malicious; return v === undefined || v === null || v === '' ? null : Number(v); };
  const rows = ips.map(ip => ({ ...ip, score: scoreOf(ip), vt: vtOf(ip) }));
  const highN = rows.filter(x => x.score >= 70 || (x.vt !== null && x.vt > 0)).length;
  const mediumN = rows.filter(x => x.score >= 20 && x.score < 70 && !(x.vt !== null && x.vt > 0)).length;
  const lowN = rows.filter(x => x.score !== null && x.score < 20 && !(x.vt !== null && x.vt > 0)).length;
  const unknownN = rows.filter(x => x.score === null && x.vt === null).length;
  const available = rows.filter(x => x.score !== null || x.vt !== null).length;
  document.getElementById('currentIpTotal').textContent = String(rows.length);
  document.getElementById('currentIpHigh').textContent = String(highN);
  document.getElementById('currentIpScored').textContent = String(available);
  document.getElementById('currentIpScoredMeta').textContent = `Of ${rows.length} unique IPs in this email`;
  const overview = document.getElementById('currentIpOverview');
  overview.innerHTML = `<span><i class="dot high"></i>High risk <b>${highN}</b></span><span><i class="dot medium"></i>Suspicious <b>${mediumN}</b></span><span><i class="dot low"></i>Low risk <b>${lowN}</b></span><span><i class="dot unknown"></i>Unknown <b>${unknownN}</b></span>`;
  const chart = document.getElementById('currentIpChart');
  const scored = rows.filter(x => x.score !== null).sort((a, b) => b.score - a.score);
  chart.innerHTML = scored.length ? `<div class="live-score-chart">${scored.map(x => `<div class="live-score-row"><code>${esc(x.ip)}</code><div class="live-score-track"><span style="width:${Math.max(0, Math.min(100, x.score))}%;background:${x.score >= 70 ? '#ef3340' : x.score >= 20 ? '#f59e0b' : '#10b981'}"></span></div><b>${x.score}/100</b></div>`).join('')}</div>` : '<p class="dashboard-empty-note">No AbuseIPDB confidence scores were returned for IPs in this email.</p>';
  const route = document.getElementById('currentIpRoute');
  if (!Array.isArray(received) || !received.length) route.innerHTML = '<p class="dashboard-empty-note">No Received-chain data was extracted from this email.</p>';
  else route.innerHTML = `<div class="dashboard-live-route">${received.map((hop, i) => { const raw = String(hop?.raw ?? hop?.value ?? hop?.header ?? ''); const fm = raw.match(/\bfrom\s+([^\s(]+)/i); const bm = raw.match(/\bby\s+([^\s;(]+)/i); const hopIps = rows.filter(x => x.hopIndex === i).map(x => x.ip); return `${i ? '<span class="route-link">⟶</span>' : ''}<article class="route-hop-placeholder live-route-hop"><span>${String(i + 1).padStart(2, '0')}</span><b>Hop ${i + 1}</b><small>${esc(hop?.from ?? fm?.[1] ?? 'Sender relay not stated')} → ${esc(hop?.by ?? bm?.[1] ?? 'Receiving relay not stated')}</small><code>${esc(hopIps.join(', ') || 'No IP extracted')}</code><details><summary>Header details</summary><pre>${esc(raw || 'Raw header unavailable')}</pre></details></article>`; }).join('')}</div>`;
  const insights = [];
  const risk = String(data?.risk_level ?? 'Unknown');
  insights.push({ kind: /high|critical/i.test(risk) ? 'high' : /low|clean/i.test(risk) ? 'low' : 'unknown', text: `Email risk verdict: ${risk}. Review the findings and authentication results alongside this IP data.` });
  if (highN) insights.push({ kind: 'high', text: `${highN} IP(s) have a high AbuseIPDB score or at least one VirusTotal malicious detection.` });
  else if (available) insights.push({ kind: 'low', text: 'No high-risk IP signal was found in the returned reputation data; this does not prove the IPs are safe.' });
  else insights.push({ kind: 'unknown', text: 'No usable IP reputation data was returned for this email.' });
  document.getElementById('currentIpInsights').innerHTML = insights.map(x => `<li><i class="dot ${x.kind}"></i><span>${esc(x.text)}</span></li>`).join('');
}

function activateTab(name) {
  document.querySelectorAll(".tab-page").forEach(el => el.classList.toggle("hidden", el.id !== `tab-${name}`));
  document.querySelectorAll(".tab-button").forEach(el => el.classList.toggle("active", el.dataset.tab === name));
  if (name === "history" || name === "reports" || name === "virustotal") renderHistoryPanels();
  if (name === "dashboard") renderDashboard();
  window.scrollTo({ top: 0, behavior: "smooth" });
}
document.querySelectorAll(".tab-button").forEach(btn => btn.addEventListener("click", () => activateTab(btn.dataset.tab)));
document.querySelectorAll("[data-go-tab]").forEach(btn => btn.addEventListener("click", () => activateTab(btn.dataset.goTab)));
document.addEventListener("click", event => { const item = event.target.closest("[data-restore-history]"); if (item) restoreHistory(item.dataset.restoreHistory); });
function restoreHistory(id) {
  const item = readHistory().find(x => x.id === id); if (!item) return;
  latestAnalysis = item.data; latestSource = item.source; originalEmailFile = null; latestGmailMessageId = null;
  render(item.data); updateDownloadControls(item.data, item.source); activateTab("analyze");
}
function renderHistoryPanels() {
  const history = readHistory();
  const query = (document.getElementById("historySearch")?.value || "").trim().toLowerCase();
  const filtered = history.filter(x => !query || `${x.label || ""} ${x.source || ""} ${x.data?.risk_level || ""} ${x.data?.from || ""} ${x.data?.subject || ""} ${JSON.stringify(x.data?.sender || {})}`.toLowerCase().includes(query));
  const makeRows = (items, empty) => items.length ? items.map(x => `<div class="history-item"><div><strong>${esc(x.label || "Analyzed email")}</strong><div class="muted">${esc(new Date(x.saved_at).toLocaleString())} · Source: ${esc(x.source)} · Risk: ${esc(x.data?.risk_level || "Unknown")}</div></div><button class="primary secondary" data-restore="${esc(x.id)}">Open analysis</button></div>`).join("") : `<p class="muted">${empty}</p>`;
  const hist = document.getElementById("historyList"); if (hist) hist.innerHTML = makeRows(filtered, query ? "No saved analyses match that search." : "No analyses saved yet.");
  const count = document.getElementById("historyCount"); if (count) count.textContent = query ? `Showing ${filtered.length} of ${history.length} saved analyses` : `${history.length} saved analyses`;

  const reps = document.getElementById("reportsList"); if (reps) reps.innerHTML = makeRows(history, "No reports available yet.");
  const vt = document.getElementById("vtHistoryList"); if (vt) vt.innerHTML = makeRows(history.filter(x => JSON.stringify(x.data || {}).toLowerCase().includes("virustotal")), "No VirusTotal-containing results in saved analyses yet.");
  document.querySelectorAll("[data-restore]").forEach(btn => btn.addEventListener("click", () => restoreHistory(btn.dataset.restore)));
}
document.getElementById("clearHistoryBtn")?.addEventListener("click", () => { if (confirm("Clear all locally saved analysis history?")) { localStorage.removeItem(HISTORY_KEY); renderHistoryPanels(); renderDashboard(); } });
document.getElementById("historySearch")?.addEventListener("input", renderHistoryPanels);
document.getElementById("copyFeedbackBtn")?.addEventListener("click", async () => {
  const text = `Email Threat Analyzer feedback\nName: ${document.getElementById("contactName").value}\nMessage: ${document.getElementById("contactMessage").value}`;
  try { await navigator.clipboard.writeText(text); document.getElementById("contactStatus").textContent = "Feedback copied. You can paste it into your email or issue tracker."; }
  catch { document.getElementById("contactStatus").textContent = text; }
});
document.getElementById("analyzeHeadersBtn")?.addEventListener("click", async () => {
  const box = document.getElementById("headerInput"), err = document.getElementById("headerError");
  const raw = box.value.trim(); err.textContent = "";
  if (!raw || !/^(from|received|subject|date|return-path|authentication-results|message-id):/im.test(raw)) { err.textContent = "Paste valid raw email headers (one Header: value per line)."; return; }
  const btn = document.getElementById("analyzeHeadersBtn"); btn.disabled = true; btn.textContent = "Analyzing headers..."; setAnalysisProgress("loading", "Submitting the pasted headers for analysis.");
  try {
    const blob = new Blob([raw.replace(/\r?\n/g, "\r\n") + "\r\n\r\n"], { type: "message/rfc822" });
    const fd = new FormData(); fd.append("file", blob, "pasted-headers.eml");
    const response = await fetch(`${API_BASE}/analyze`, { method: "POST", body: fd }); const data = await response.json();
    if (!response.ok) throw new Error(toText(data.detail || "Header analysis failed."));
    originalEmailFile = null; latestGmailMessageId = null; render(data); updateDownloadControls(data, "headers"); saveHistory(data, "headers");
  } catch (e) { err.textContent = `${e.message} Ensure FastAPI is running.`; setAnalysisProgress("error", e.message); }
  finally { btn.disabled = false; btn.textContent = "Analyze Headers"; }
});
renderHistoryPanels();
renderDashboard();

checkApi();

// --------------------------------------------------
// 3. FILE SELECTION AND DRAG/DROP
// --------------------------------------------------

fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];

  fileName.textContent = file
    ? `${file.name} (${Math.round(file.size / 1024)} KB)`
    : "No file selected";
});

["dragenter", "dragover"].forEach(eventName => {
  dropzone.addEventListener(eventName, event => {
    event.preventDefault();
    dropzone.classList.add("drag");
  });
});

["dragleave", "drop"].forEach(eventName => {
  dropzone.addEventListener(eventName, event => {
    event.preventDefault();
    dropzone.classList.remove("drag");
  });
});

dropzone.addEventListener("drop", event => {
  if (event.dataTransfer.files.length) {
    fileInput.files = event.dataTransfer.files;
    fileInput.dispatchEvent(new Event("change"));
  }
});

// --------------------------------------------------
// 4. ANALYZE EMAIL
// --------------------------------------------------

analyzeBtn.addEventListener("click", async () => {
  errorBox.textContent = "";

  const file = fileInput.files[0];

  if (!file) {
    errorBox.textContent =
      "Please select an .eml file first.";
    return;
  }

  if (!file.name.toLowerCase().endsWith(".eml")) {
    errorBox.textContent =
      "Only .eml files are supported.";
    return;
  }

  analyzeBtn.disabled = true;
  analyzeBtn.textContent = "Analyzing...";
  setAnalysisProgress("loading", "Reading the .eml file and checking supported email indicators and configured reputation services.");

  try {
    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      body: formData
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        toText(data.detail || "Analysis failed.")
      );
    }

    originalEmailFile = file;
    latestGmailMessageId = null;
    render(data);
    updateDownloadControls(data, "upload");
    saveHistory(data, "upload");

  } catch (error) {
    errorBox.textContent =
      `${error.message} Make sure the FastAPI server is running on port 8000.`;
    setAnalysisProgress("error", error.message);

  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "Analyze Email";
  }
});


// --------------------------------------------------
// Gmail read-only integration
// --------------------------------------------------
const gmailConnectBtn = document.getElementById("gmailConnectBtn");
const gmailLoadBtn = document.getElementById("gmailLoadBtn");
const gmailDisconnectBtn = document.getElementById("gmailDisconnectBtn");
const gmailAnalyzeBtn = document.getElementById("gmailAnalyzeBtn");
const gmailMessageSelect = document.getElementById("gmailMessageSelect");
const gmailStatus = document.getElementById("gmailStatus");
const gmailError = document.getElementById("gmailError");

async function gmailRequest(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(toText(data.detail || "Gmail request failed."));
  return data;
}

async function refreshGmailStatus() {
  try {
    const data = await gmailRequest("/auth/gmail/status");
    gmailStatus.textContent = data.connected ? "Gmail: connected" : "Gmail: not connected";
    gmailLoadBtn.disabled = !data.connected;
    gmailDisconnectBtn.disabled = !data.connected;
  } catch (err) {
    gmailStatus.textContent = "Gmail status unavailable";
  }
}

gmailConnectBtn.addEventListener("click", async () => {
  gmailError.textContent = "";
  gmailConnectBtn.disabled = true;
  try {
    const data = await gmailRequest("/auth/gmail/start");
    window.location.href = data.authorization_url;
  } catch (err) {
    gmailError.textContent = err.message;
    gmailConnectBtn.disabled = false;
  }
});

gmailLoadBtn.addEventListener("click", async () => {
  gmailError.textContent = "";
  gmailLoadBtn.disabled = true;
  gmailMessageSelect.innerHTML = '<option value="">Loading inbox...</option>';
  try {
    const data = await gmailRequest("/gmail/messages?max_results=20");
    gmailMessageSelect.innerHTML = '<option value="">Select an email</option>';
    for (const msg of arr(data.messages)) {
      const option = document.createElement("option");
      option.value = msg.id;
      option.textContent = `${msg.date || ""} | ${msg.from || "(unknown sender)"} | ${msg.subject || "(no subject)"}`;
      option.title = msg.snippet || "";
      gmailMessageSelect.appendChild(option);
    }
    gmailMessageSelect.disabled = !data.messages?.length;
    gmailAnalyzeBtn.disabled = !data.messages?.length;
    if (!data.messages?.length) gmailMessageSelect.innerHTML = '<option value="">No messages returned</option>';
    gmailStatus.textContent = `Gmail: connected — ${data.messages?.length || 0} messages loaded`;
  } catch (err) {
    gmailError.textContent = err.message;
    gmailMessageSelect.innerHTML = '<option value="">Could not load inbox</option>';
  } finally {
    gmailLoadBtn.disabled = false;
  }
});

gmailMessageSelect.addEventListener("change", () => {
  gmailAnalyzeBtn.disabled = !gmailMessageSelect.value;
});

gmailAnalyzeBtn.addEventListener("click", async () => {
  const id = gmailMessageSelect.value;
  if (!id) return;
  gmailError.textContent = "";
  errorBox.textContent = "";
  gmailAnalyzeBtn.disabled = true;
  gmailAnalyzeBtn.textContent = "Analyzing Gmail message...";
  setAnalysisProgress("loading", "Fetching the selected message using read-only Gmail access, then analyzing its indicators.");
  try {
    const data = await gmailRequest(`/gmail/messages/${encodeURIComponent(id)}/analyze`, { method: "POST" });
    originalEmailFile = null;
    latestGmailMessageId = id;
    render(data);
    updateDownloadControls(data, "gmail");
    saveHistory(data, "gmail");
  } catch (err) {
    gmailError.textContent = err.message;
    setAnalysisProgress("error", err.message);
  } finally {
    gmailAnalyzeBtn.disabled = !gmailMessageSelect.value;
    gmailAnalyzeBtn.textContent = "Analyze selected Gmail message";
  }
});

gmailDisconnectBtn.addEventListener("click", async () => {
  gmailError.textContent = "";
  try {
    await gmailRequest("/auth/gmail/disconnect", { method: "POST" });
    gmailMessageSelect.innerHTML = '<option value="">Connect and load messages first</option>';
    gmailMessageSelect.disabled = true;
    gmailAnalyzeBtn.disabled = true;
    gmailStatus.textContent = "Gmail: not connected";
    gmailLoadBtn.disabled = true;
    gmailDisconnectBtn.disabled = true;
  } catch (err) {
    gmailError.textContent = err.message;
  }
});

// Export analysis as JSON.
downloadJsonBtn.addEventListener("click", () => {
  if (!latestAnalysis) return;
  const payload = {
    exported_at: new Date().toISOString(),
    source: latestSource,
    analysis: latestAnalysis
  };
  downloadBlob(
    new Blob([JSON.stringify(payload, null, 2)], { type: "application/json;charset=utf-8" }),
    `${getEmailLabel(latestAnalysis)}-analysis.json`
  );
});

// Export a standalone readable HTML report.
downloadHtmlBtn.addEventListener("click", () => {
  if (!latestAnalysis) return;
  downloadBlob(
    new Blob([reportHtml(latestAnalysis)], { type: "text/html;charset=utf-8" }),
    `${getEmailLabel(latestAnalysis)}-analysis-report.html`
  );
});

// Download the uploaded .eml, or fetch Gmail's raw RFC 822 message if the
// backend exposes the /gmail/messages/{id}/raw endpoint.
downloadEmlBtn.addEventListener("click", async () => {
  if (originalEmailFile instanceof Blob) {
    downloadBlob(originalEmailFile, `${getEmailLabel(latestAnalysis)}.eml`);
    return;
  }
  if (latestSource !== "gmail" || !latestGmailMessageId) return;

  downloadEmlBtn.disabled = true;
  const oldLabel = downloadEmlBtn.textContent;
  downloadEmlBtn.textContent = "Fetching original...";
  try {
    const result = await gmailRequest(`/gmail/messages/${encodeURIComponent(latestGmailMessageId)}/raw`);
    const raw = result.raw || result.eml || result.message;
    if (!raw) {
      throw new Error("Backend did not return the raw email. The Gmail raw-message endpoint may not be implemented.");
    }

    let bytes;
    if (typeof raw === "string" && /^[A-Za-z0-9_-]+$/.test(raw)) {
      const binary = atob(raw.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(raw.length / 4) * 4, "="));
      bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    } else {
      bytes = new TextEncoder().encode(String(raw));
    }
    downloadBlob(new Blob([bytes], { type: "message/rfc822" }), `${getEmailLabel(latestAnalysis)}.eml`);
  } catch (err) {
    gmailError.textContent = err.message;
  } finally {
    downloadEmlBtn.textContent = oldLabel;
    downloadEmlBtn.disabled = !(originalEmailFile instanceof Blob) && !(latestSource === "gmail" && latestGmailMessageId);
  }
});

refreshGmailStatus();

// --------------------------------------------------
// 5. AUTHENTICATION DISPLAY
// --------------------------------------------------

function renderAuthentication(data) {
  const auth = getObject(data.authentication);

  const spf = getObject(auth.spf);
  const dkim = getObject(auth.dkim);
  const dmarc = getObject(auth.dmarc);

  const spfResult = firstValue(
    auth.spf_result,
    spf.authentication_result,
    spf.result
  );

  const dkimResult = firstValue(
    auth.dkim_result,
    dkim.authentication_result,
    dkim.result,
    dkim.verified === true ? "pass" : null
  );

  const dmarcResult = firstValue(
    auth.dmarc_result,
    dmarc.authentication_result,
    dmarc.result
  );

  const spfAlignment =
    spf.alignment ?? dmarc.spf_alignment;

  const dkimAlignment =
    dkim.alignment ?? dmarc.dkim_alignment;

  const alignment = [
    `SPF: ${toText(spfAlignment)}`,
    `DKIM: ${toText(dkimAlignment)}`
  ].join(" | ");

  document.getElementById("authInfo").innerHTML = kv([
    ["SPF", spfResult],
    ["DKIM", dkimResult],
    ["DMARC", dmarcResult],
    ["Alignment", alignment]
  ]);
}


// Render VirusTotal v3 data safely, including engine-by-engine results
// and the complete response in an expandable JSON block.
function renderVirusTotalDetails(report, label = "VirusTotal report") {
  const vt = getObject(report);
  if (!Object.keys(vt).length) {
    return '<div class="vt-report muted">VirusTotal report not returned.</div>';
  }

  const status = String(vt.status || "");
  const wrappedFileReport = status === "ok";
  const raw = wrappedFileReport ? getObject(vt.data) : vt;
  const data = getObject(raw.data);

  if (!wrappedFileReport && !Object.keys(data).length) {
    return `<div class="vt-report"><strong>VirusTotal:</strong> ${esc(firstValue(vt.message, status, vt.error?.message, "No report data returned"))}</div>`;
  }

  const attributes = getObject(data.attributes);
  const stats = getObject(attributes.last_analysis_stats);
  const engines = getObject(attributes.last_analysis_results);
  const statsText = Object.keys(stats).length
    ? Object.entries(stats).map(([k, v]) => `${k}: ${v}`).join(" | ")
    : "No analysis statistics returned";

  const engineRows = Object.entries(engines).map(([engine, result]) => {
    const r = getObject(result);
    return `<tr>
      <td>${esc(engine)}</td>
      <td>${esc(firstValue(r.category, "—"))}</td>
      <td>${esc(firstValue(r.result, "—"))}</td>
      <td>${esc(firstValue(r.engine_name, "—"))}</td>
      <td>${esc(firstValue(r.engine_version, "—"))}</td>
      <td>${esc(firstValue(r.engine_update, "—"))}</td>
    </tr>`;
  }).join("");
  function formatVTDate(timestamp) {
    if (timestamp === undefined || timestamp === null) {
      return "N/A";
    }

    const date = new Date(Number(timestamp) * 1000);

    if (isNaN(date.getTime())) {
      return "N/A";
    }

    return date.toLocaleString("en-IN", {
      day: "2-digit",
      month: "long",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      timeZone: "UTC",
      timeZoneName: "short"
    });
  }

  const metadata = [
    ["Meaningful name", attributes.meaningful_name],
    ["Type description", attributes.type_description],
    ["Size", attributes.size],
    ["SHA-256", attributes.sha256],
    ["SHA-1", attributes.sha1],
    ["MD5", attributes.md5],
    ["Reputation", attributes.reputation],
    ["Times submitted", attributes.times_submitted],
    ["First submission", formatVTDate(attributes.first_submission_date)],

    ["Last submission", formatVTDate(attributes.last_submission_date)],

    ["Last analysis", formatVTDate(attributes.last_analysis_date)],
    ["Tags", attributes.tags],
    ["Popular threat classification", attributes.popular_threat_classification],
    ["Sandbox verdicts", attributes.sandbox_verdicts],
    ["Crowdsourced YARA results", attributes.crowdsourced_yara_results],
    ["Contacted domains", attributes.contacted_domains],
    ["Contacted IPs", attributes.contacted_ips],
    ["Downloaded files", attributes.downloaded_files],
    ["Embedded domains", attributes.embedded_domains],
    ["Email parents", attributes.email_parents]
  ].filter(([, value]) => value !== undefined && value !== null);

  const metadataHtml = metadata.map(([key, value]) =>
    `<div class="kv-row"><div class="key">${esc(key)}</div><div class="value">${esc(value)}</div></div>`
  ).join("");

  return `
    <details class="vt-report">
      <summary>${esc(label)} — ${esc(statsText)} (expand report)</summary>
      <div class="vt-content">
        <h4>File / URL attributes</h4>
        <div class="kv">${metadataHtml || '<span class="muted">No additional attributes returned.</span>'}</div>
        <h4>Detection engines (${Object.keys(engines).length})</h4>
        <div class="table-wrap">
          <table class="vt-engine-table">
            <thead><tr><th>Engine</th><th>Category</th><th>Detection</th><th>Engine name</th><th>Version</th><th>Updated</th></tr></thead>
            <tbody>${engineRows || '<tr><td colspan="6" class="muted">No per-engine results returned.</td></tr>'}</tbody>
          </table>
        </div>
        <h4>Complete VirusTotal API response</h4>
        <pre>${esc(JSON.stringify(raw, null, 2))}</pre>
      </div>
    </details>`;
}


// --------------------------------------------------
// 6. URL REPUTATION DISPLAY
// --------------------------------------------------

function renderReputation(reputation, status) {
  const rep = getObject(reputation);

  // Handle missing or string-based reputation responses
  if (typeof reputation === "string") {
    return `<div class="vt-report reputation-provider">${esc(reputation)}</div>`;
  }

  if (status && typeof status === "string") {
    return `<div class="vt-report reputation-provider">${esc(status)}</div>`;
  }

  // Create a separate box for each reputation service
  function providerBox(title, body, extraClass = "") {
    return `
      <div class="vt-report reputation-provider ${extraClass}">
        <strong>${esc(title)}</strong>
        <div class="provider-body">${body}</div>
      </div>
    `;
  }

  const boxes = [];

  // ----------------------------------------
  // 1. VIRUSTOTAL
  // ----------------------------------------

  const vt = getObject(rep.virustotal || rep.vt);

  if (Object.keys(vt).length) {
    const vtData = getObject(vt.data);
    const attributes = getObject(vtData.attributes);

    const stats = getObject(
      attributes.last_analysis_stats ||
      vt.last_analysis_stats ||
      vt.stats ||
      vt.analysis_stats
    );

    const malicious = firstValue(
      stats.malicious,
      vt.malicious,
      vt.malicious_count
    );

    const suspicious = firstValue(
      stats.suspicious,
      vt.suspicious,
      vt.suspicious_count
    );

    let vtMessage = "";

    if (malicious !== "—" || suspicious !== "—") {
      vtMessage = `
        <div>Malicious: <strong>${esc(malicious)}</strong></div>
        <div>Suspicious: <strong>${esc(suspicious)}</strong></div>
      `;
    } else {
      const error = getObject(vt.error);

      vtMessage = `
        <div>${esc(firstValue(
        error.message,
        vt.message,
        vt.status,
        vt.error,
        "No analysis data returned"
      ))}</div>
      `;
    }

    boxes.push(
      providerBox("VirusTotal", vtMessage, "vt-provider")
    );
  }

  // ----------------------------------------
  // 2. GOOGLE SAFE BROWSING
  // ----------------------------------------

  const gsb = getObject(rep.google_safe_browsing);

  if (Object.keys(gsb).length) {
    let gsbMessage = "";
    let gsbClass = "";

    const gsbStatus = String(
      firstValue(
        gsb.status,
        gsb.error,
        gsb.result,
        ""
      )
    ).toLowerCase();

    if (Array.isArray(gsb.matches)) {
      if (gsb.matches.length > 0) {
        gsbClass = "provider-danger";

        gsbMessage = `
          <div><strong>Threat matches:</strong> ${gsb.matches.length}</div>
          <div>Google Safe Browsing detected a threat associated with this URL.</div>
          <div class="muted">Avoid opening this URL.</div>
          <ul>
            ${gsb.matches.map(match => {
          const m = getObject(match);

          return `
                <li>
                  ${esc(firstValue(m.threatType, m.threat_type, "Threat"))}
                  ${m.platformType ? ` — ${esc(m.platformType)}` : ""}
                </li>
              `;
        }).join("")}
          </ul>
        `;
      } else {
        // Empty matches array means a successful check with no matches
        gsbClass = "provider-clean";

        gsbMessage = `
          <div><strong>No threat matches found.</strong></div>
          <div class="muted">
            URL was checked. This does not guarantee that it is safe.
          </div>
        `;
      }
    } else if (
      gsbStatus.includes("access_denied") ||
      gsbStatus.includes("unauthorized") ||
      gsbStatus.includes("403") ||
      gsbStatus.includes("401")
    ) {
      gsbClass = "provider-error";

      gsbMessage = `
        <div><strong>API access denied</strong></div>
        <div class="muted">
          Google Safe Browsing could not verify this URL.
          No threat verdict was returned.
        </div>
      `;
    } else if (gsbStatus.includes("not_configured")) {
      gsbClass = "provider-error";

      gsbMessage = `
        <div><strong>API key not configured</strong></div>
        <div class="muted">
          This URL has not been checked.
        </div>
      `;
    } else if (gsbStatus.includes("429")) {
      gsbClass = "provider-error";

      gsbMessage = `
        <div><strong>API request limit reached</strong></div>
        <div class="muted">
          No threat verdict was returned.
        </div>
      `;
    } else {
      gsbClass = "provider-error";

      gsbMessage = `
        <div><strong>Unable to verify URL</strong></div>
        <div class="muted">
          ${esc(firstValue(
        gsb.message,
        gsb.error,
        gsb.status,
        "No result returned by Google Safe Browsing"
      ))}
        </div>
        <div class="muted">
          URL safety remains unverified.
        </div>
      `;
    }

    boxes.push(
      providerBox(
        "Google Safe Browsing",
        gsbMessage,
        gsbClass
      )
    );
  }

  // ----------------------------------------
  // 3. URLHAUS
  // ----------------------------------------

  const urlhaus = getObject(rep.urlhaus);

  if (Object.keys(urlhaus).length) {
    let urlhausMessage = "";
    let urlhausClass = "";

    const queryStatus = String(
      firstValue(
        urlhaus.query_status,
        urlhaus.status,
        ""
      )
    ).toLowerCase();

    if (
      queryStatus === "ok" ||
      urlhaus.threat === true ||
      urlhaus.url_status === "online" ||
      urlhaus.url_status === "offline"
    ) {
      if (
        urlhaus.threat === true ||
        urlhaus.url_status === "online" ||
        urlhaus.url_status === "offline"
      ) {
        urlhausClass = "provider-danger";

        urlhausMessage = `
          <div><strong>Threat found in URLhaus</strong></div>
          <div>
            URL status: ${esc(firstValue(urlhaus.url_status, "Unknown"))}
          </div>
          <div>
            Threat: ${esc(firstValue(urlhaus.threat, "Reported URL"))}
          </div>
          ${urlhaus.tags ? `<div>Tags: ${esc(urlhaus.tags)}</div>` : ""}
        `;
      } else {
        urlhausClass = "provider-clean";

        urlhausMessage = `
          <div><strong>No URLhaus threat record found.</strong></div>
          <div class="muted">
            This does not guarantee that the URL is safe.
          </div>
        `;
      }
    } else if (
      queryStatus.includes("unauthorized") ||
      queryStatus.includes("401") ||
      queryStatus.includes("403")
    ) {
      urlhausClass = "provider-error";

      urlhausMessage = `
        <div><strong>API access denied</strong></div>
        <div class="muted">
          URLhaus could not verify this URL.
        </div>
      `;
    } else if (queryStatus.includes("not_configured")) {
      urlhausClass = "provider-error";

      urlhausMessage = `
        <div><strong>API not configured</strong></div>
        <div class="muted">
          This URL has not been checked.
        </div>
      `;
    } else if (
      queryStatus === "no_results" ||
      queryStatus === "no_result"
    ) {
      urlhausClass = "provider-clean";

      urlhausMessage = `
        <div><strong>No URLhaus threat record found.</strong></div>
        <div class="muted">
          This does not guarantee that the URL is safe.
        </div>
      `;
    } else {
      urlhausClass = "provider-error";

      urlhausMessage = `
        <div><strong>Unable to verify URL</strong></div>
        <div class="muted">
          ${esc(firstValue(
        urlhaus.message,
        urlhaus.error,
        urlhaus.query_status,
        "No result returned by URLhaus"
      ))}
        </div>
        <div class="muted">
          URL safety remains unverified.
        </div>
      `;
    }

    boxes.push(
      providerBox(
        "URLhaus",
        urlhausMessage,
        urlhausClass
      )
    );
  }

  // ----------------------------------------
  // 4. OTHER REPUTATION SERVICES
  // ----------------------------------------

  const knownServices = [
    "virustotal",
    "vt",
    "google_safe_browsing",
    "urlhaus"
  ];

  for (const [service, result] of Object.entries(rep)) {
    if (knownServices.includes(service)) {
      continue;
    }

    const message = isObject(result)
      ? firstValue(
        result.status,
        result.result,
        result.threat,
        result.error,
        JSON.stringify(result)
      )
      : toText(result);

    boxes.push(
      providerBox(service, esc(message))
    );
  }

  // ----------------------------------------
  // 5. VIRUSTOTAL EXPANDABLE REPORT
  // ----------------------------------------


  if (boxes.length === 0) {
    return `
      <div class="vt-report reputation-provider">
        Not available
      </div>
    `;
  }

  return `
  <div class="reputation-provider-list">
    ${boxes.join("")}
  </div>
`;
}
// --------------------------------------------------
// 7. FINDINGS
// --------------------------------------------------

function renderFindings(data) {
  const findings = arr(data.findings);

  const container = document.getElementById("findings");

  if (!findings.length) {
    container.innerHTML =
      '<div class="muted">No findings returned.</div>';
    return;
  }

  container.innerHTML = findings.map(finding => {
    const f = getObject(finding);

    return `
      <div class="finding ${levelClass(f.severity)}">
        <strong>${esc(f.severity || "INFO")}</strong>
        ${esc(
      f.title ||
      f.message ||
      f.description ||
      "Finding"
    )}
        ${f.detail
        ? `<div class="muted">${esc(f.detail)}</div>`
        : ""
      }
      </div>
    `;
  }).join("");
}

// --------------------------------------------------
// 8. URL TABLE
// --------------------------------------------------

function renderUrls(data) {
  const urls = arr(data.urls);

  document.getElementById("urlCount").textContent =
    `${urls.length} found`;

  const container = document.getElementById("urls");

  if (!urls.length) {
    container.innerHTML =
      '<tr><td colspan="3" class="muted">No URLs found.</td></tr>';
    return;
  }

  container.innerHTML = urls.map(item => {
    const url = getObject(item);

    const reputation = renderReputation(
      url.reputation,
      url.reputation_status
    );

    return `
      <tr>
        <td>${esc(
      firstValue(url.url, url.normalized_url)
    )}</td>

        <td>${pills(url.indicators)}</td>

        <td>${reputation}</td>
      </tr>
    `;
  }).join("");
}

// --------------------------------------------------
// 9. ATTACHMENT TABLE
// --------------------------------------------------

function renderAttachments(data) {
  const attachments = arr(data.attachments);

  document.getElementById("attachmentCount").textContent =
    `${attachments.length} found`;

  const container =
    document.getElementById("attachments");

  if (!attachments.length) {
    container.innerHTML =
      '<tr><td colspan="3" class="muted">No attachments found.</td></tr>';
    return;
  }

  container.innerHTML = attachments.map(item => {
    const attachment = getObject(item);

    const indicators = arr(attachment.indicators);

    const yaraMatches = arr(
      attachment.yara_matches
    ).map(match => {
      if (isObject(match)) {
        return firstValue(
          match.rule,
          match.name,
          JSON.stringify(match)
        );
      }

      return match;
    });

    const allIndicators = [
      ...indicators,
      ...yaraMatches
    ];

    return `
      <tr>
        <td>${esc(attachment.filename)}</td>

        <td>
          <code>${esc(attachment.sha256)}</code>
        </td>

        <td>
          ${pills(allIndicators)}
          ${renderVirusTotalDetails(attachment.virustotal, "VirusTotal file hash report")}
        </td>
      </tr>
    `;
  }).join("");
}

// --------------------------------------------------
// 10. RECEIVED CHAIN
// --------------------------------------------------

function renderReceived(data) {
  const receivedRaw = data.received_chain ?? data.received ?? [];
  const container = document.getElementById("received");
  if (!container) return;

  if (!Array.isArray(receivedRaw) || !receivedRaw.length) {
    container.innerHTML = '<span class="muted">No Received-chain data.</span>';
    return;
  }

  const safe = (value) => value === null || value === undefined || value === "" ? "—" : esc(String(value));
  const reputation = (provider, fields) => {
    if (!provider || typeof provider !== "object") return "Not checked";
    if (provider.error) return `Lookup error: ${safe(provider.error)}`;
    if (provider.status === "not_configured") return "API key not configured";
    if (provider.status === "lookup_failed") return "Lookup failed";
    return fields.map(([label, key]) => `<div><strong>${label}:</strong> ${safe(provider[key])}</div>`).join("");
  };

  // Normalize hop data for the graph. Some backend versions may expose IPs only in the raw Received line.
  const hops = receivedRaw.map((item, index) => {
    const raw = String(item?.raw ?? item?.value ?? item?.header ?? "");
    let ips = Array.isArray(item?.ips) ? item.ips : [];
    if (!ips.length) {
      const found = raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
      ips = [...new Set(found)].map(ip => ({ ip, scope: "extracted from header" }));
    }
    const fromMatch = raw.match(/\bfrom\s+([^\s(]+)/i);
    const byMatch = raw.match(/\bby\s+([^\s;(]+)/i);
    const serverMatch = fromMatch;
    const fromServer = item?.from ?? (fromMatch ? fromMatch[1] : "Not stated in header");
    const byServer = item?.by ?? (byMatch ? byMatch[1] : "Not stated in header");
    const server = item?.hostname ?? item?.host ?? fromServer;
    return { item, index, raw, ips, server, fromServer, byServer };
  });

  const ipValue = (ip) => typeof ip === 'string' ? ip : (ip?.ip ?? ip?.address ?? ip?.value ?? 'IP unavailable');
  const ipRisk = (ip) => {
    if (!ip || typeof ip !== 'object') return { label: 'Not assessed', kind: 'unknown' };
    const abuse = Number(ip.abuseipdb?.abuse_confidence_score ?? ip.abuseipdb?.data?.abuseConfidenceScore);
    const malicious = Number(ip.virustotal?.malicious ?? ip.virustotal?.data?.attributes?.last_analysis_stats?.malicious);
    if ((Number.isFinite(abuse) && abuse >= 50) || (Number.isFinite(malicious) && malicious > 0)) return { label: 'Risk signal', kind: 'risk' };
    const hasLookup = Number.isFinite(abuse) || Number.isFinite(malicious) || ip.abuseipdb?.status === 'success' || ip.virustotal?.status === 'success';
    return hasLookup ? { label: 'No flagged result', kind: 'clear' } : { label: 'Not assessed', kind: 'unknown' };
  };
  const allIps = hops.flatMap(hop => hop.ips);
  const flaggedCount = allIps.filter(ip => ipRisk(ip).kind === 'risk').length;
  const checkedCount = allIps.filter(ip => ipRisk(ip).kind !== 'unknown').length;
  const graph = `
    <section class="received-graph-panel" aria-label="Received mail route graph">
      <div class="received-graph-heading">
        <div><span class="received-eyebrow">MESSAGE PATH</span><h4>Received-chain route</h4></div>
        <p class="received-graph-note">Each card represents a parsed <code>Received</code> header. The route is indicative, not proof of sender identity.</p>
      </div>
      <div class="received-route-context">
        <div class="route-endpoint sender-endpoint"><span class="route-endpoint-icon">↗</span><div><small>SENDER-SIDE RELAY</small><strong>${safe(hops.find(h => h.fromServer !== "Not stated in header")?.fromServer ?? "Not identified")}</strong><p>Server named in a recorded <code>from</code> clause</p></div></div>
        <div class="route-context-connector"><span>recorded relay handoffs</span><b>→</b></div>
        <div class="route-endpoint recipient-endpoint"><span class="route-endpoint-icon">↘</span><div><small>RECIPIENT-SIDE RELAY</small><strong>${safe([...hops].reverse().find(h => h.byServer !== "Not stated in header")?.byServer ?? "Not identified")}</strong><p>Server named in a recorded <code>by</code> clause</p></div></div>
        <p class="route-endpoint-caveat">These endpoints are inferred from the available headers, not guaranteed identities. Mail servers usually add Received headers, but earlier parts of a chain may be missing or forged.</p>
      </div>
      <div class="received-route-summary">
        <div class="route-summary-stat"><span class="route-summary-number">${hops.length}</span><span>Mail hops</span></div>
        <div class="route-summary-stat"><span class="route-summary-number">${allIps.length}</span><span>IP addresses</span></div>
        <div class="route-summary-stat ${flaggedCount ? 'has-risk' : ''}"><span class="route-summary-number">${flaggedCount}</span><span>Risk signals</span></div>
        <div class="route-summary-footnote">${checkedCount} of ${allIps.length} IPs have a reputation result or score</div>
      </div>
      <div class="received-route-scroll"><div class="received-route">
        ${hops.map((hop, i) => `
          <article class="received-node">
            <div class="received-node-top"><span class="received-step"><span class="received-step-dot">${i + 1}</span> HOP ${i + 1}</span><span class="received-node-count">${hop.ips.length} IP${hop.ips.length === 1 ? '' : 's'}</span></div>
            <strong class="received-server">${safe(hop.server)}</strong>
            <div class="received-hop-direction"><div><small>FROM / PREVIOUS RELAY</small><span>${safe(hop.fromServer)}</span></div><div class="hop-direction-arrow" aria-hidden="true">↓</div><div><small>BY / RECEIVING RELAY</small><span>${safe(hop.byServer)}</span></div></div>
            <div class="received-node-divider"></div>
            <div class="received-ip-list">${hop.ips.length ? hop.ips.map(ip => { const status = ipRisk(ip); return `<div class="received-ip-row"><code class="received-ip-chip">${safe(ipValue(ip))}</code><span class="route-risk-badge ${status.kind}"><span class="route-risk-dot"></span>${status.label}</span></div>`; }).join('') : '<span class="received-empty-ip">No IP extracted from this header</span>'}</div>
            <details class="received-hop-details">
              <summary><span class="details-summary-title">View IP reputation & header details</span><span class="details-summary-hint">${hop.ips.length} IP record${hop.ips.length === 1 ? '' : 's'}</span></summary>
              ${hop.ips.length ? `<div class="table-wrap received-hop-table-wrap"><table class="results-table received-hop-table"><thead><tr><th>IP Address</th><th>Scope</th><th>Reverse DNS</th><th>AbuseIPDB</th><th>VirusTotal</th></tr></thead><tbody>${hop.ips.map((value) => { const ip = typeof value === 'string' ? { ip: value } : value; return `<tr><td><code>${safe(ip.ip ?? ip.address ?? ip.value)}</code></td><td>${safe(ip.scope)}</td><td>${safe(ip.reverse_dns)}</td><td>${reputation(ip.abuseipdb, [["Abuse confidence", "abuse_confidence_score"], ["Reports", "total_reports"], ["Country", "country_code"], ["ISP", "isp"]])}</td><td>${reputation(ip.virustotal, [["Malicious", "malicious"], ["Suspicious", "suspicious"], ["Harmless", "harmless"], ["Undetected", "undetected"]])}</td></tr>`; }).join('')}</tbody></table></div>` : '<span class="muted">No IP addresses extracted from this hop.</span>'}
              <details class="received-raw"><summary>Inspect raw header</summary><pre>${safe(hop.raw || hop.item?.raw)}</pre></details>
            </details>
          </article>
          ${i < hops.length - 1 ? '<div class="received-arrow" aria-hidden="true"><span>→</span><small>next recorded hop</small></div>' : ''}
        `).join('')}
      </div></div>
      <div class="received-legend"><span><i class="legend-dot risk"></i>Risk signal</span><span><i class="legend-dot clear"></i>No flagged result</span><span><i class="legend-dot unknown"></i>Not assessed</span><span class="received-order-note">Route follows parsed header order; arrows show sequence in this view, not independently verified network traffic.</span></div>
    </section>`;

  container.innerHTML = graph;
}


// --------------------------------------------------
// 11. MAIN DASHBOARD RENDER
// --------------------------------------------------

function setAnalysisProgress(state, message = "") {
  const panel = document.getElementById("analysisProgress");
  if (!panel) return;
  panel.classList.toggle("hidden", state === "hide");
  const title = document.getElementById("progressTitle"), percent = document.getElementById("progressPercent");
  const bar = document.getElementById("progressBar"), note = document.getElementById("progressMessage");
  if (state === "loading") { title.textContent = "Analysis in progress"; percent.textContent = "Working"; bar.style.width = "65%"; bar.classList.remove("complete"); note.textContent = message || "Inspecting the email and waiting for configured checks. This may take a moment."; }
  else if (state === "success") { title.textContent = "Analysis complete"; percent.textContent = "Complete"; bar.style.width = "100%"; bar.classList.add("complete"); note.textContent = message || "The analyzer returned a result. Review each provider status and finding below."; }
  else if (state === "error") { title.textContent = "Analysis could not complete"; percent.textContent = "Needs attention"; bar.style.width = "100%"; bar.classList.remove("complete"); note.textContent = message || "Check the API connection and try again."; }
}

function renderPlainLanguageSummary(d) {
  const panel = document.getElementById("plainLanguagePanel");
  if (!panel) return;
  panel.classList.remove("hidden");
  const level = String(d?.risk_level || "Unknown");
  const normalized = level.toLowerCase();
  const high = /critical|high/.test(normalized), medium = /medium|moderate|suspicious/.test(normalized), low = /low|clean|safe/.test(normalized);
  const badge = document.getElementById("plainRiskBadge");
  badge.textContent = level; badge.className = `plain-risk-badge ${high ? "risk-high" : medium ? "risk-medium" : low ? "risk-low" : "risk-unknown"}`;
  const urls = arr(d?.urls || d?.url_results), attachments = arr(d?.attachments), findings = arr(d?.findings);
  const auth = getObject(d?.authentication || d?.auth);
  const reasons = [];
  if (d?.assessment_note) reasons.push(String(d.assessment_note));
  if (findings.length) reasons.push(`${findings.length} finding(s) were returned. Open the Findings section for the evidence and details.`);
  if (urls.length) reasons.push(`${urls.length} URL result(s) were extracted. A URL being present is not automatically malicious; check its reputation and indicators.`);
  if (attachments.length) reasons.push(`${attachments.length} attachment(s) were identified. Review file names, hashes, and any available reputation checks.`);
  if (!reasons.length) reasons.push("The analyzer returned limited explanatory detail. Review the raw findings and authentication results below.");
  let summary = high ? "The analyzer marked this email as high risk. Do not open links or attachments until you have reviewed the evidence." : medium ? "The analyzer found suspicious or mixed signals. Verify the sender and inspect the evidence before interacting with the message." : low ? "The analyzer returned a lower-risk verdict, but this does not guarantee the email is safe. Check the sender and context." : "The risk level is unknown or inconclusive. This can happen when evidence is limited or checks did not return usable results.";
  document.getElementById("plainSummary").textContent = summary;
  const actions = high ? ["Do not click links, open attachments, or reply.", "Verify the request with the sender using a separate trusted channel.", "Report or quarantine the message according to your organisation’s process."] : medium ? ["Do not use links in the email; navigate to the official site yourself.", "Check the sender address and Reply-To for mismatches.", "Review authentication, URL, attachment, and mail-route evidence before deciding."] : low ? ["Confirm the message was expected and the sender address is correct.", "Treat unexpected requests for money, passwords, or codes as suspicious.", "If anything feels unusual, verify it through a separate trusted channel."] : ["Do not treat missing reputation results as a clean bill of health.", "Review the sender, authentication, links, attachments, and Received chain.", "Retry later if a provider was unavailable; independently verify unusual requests."];
  document.getElementById("plainReasons").innerHTML = reasons.map(x => `<li>${esc(x)}</li>`).join("");
  document.getElementById("plainActions").innerHTML = actions.map(x => `<li>${esc(x)}</li>`).join("");
}

function render(data) {
  const d = getObject(data);
  renderPlainLanguageSummary(d);
  setAnalysisProgress("success", "The backend returned an analysis. A provider may still have unavailable or inconclusive data; check each result below.");

  document.getElementById("summary")
    .classList.remove("hidden");

  document.getElementById("details")
    .classList.remove("hidden");

  // Risk summary
  const level = firstValue(
    d.risk_level,
    "UNKNOWN"
  );

  const risk = document.getElementById("riskLevel");
  const normalizedLevel = String(level).toLowerCase();
  const isHigh = /critical|high/.test(normalizedLevel);
  const isMedium = /medium|moderate|suspicious/.test(normalizedLevel);
  const isLow = /low|clean|safe/.test(normalizedLevel);
  risk.textContent = level;
  risk.className = `plain-risk-badge ${isHigh ? "risk-high" : isMedium ? "risk-medium" : isLow ? "risk-low" : "risk-unknown"}`;

  const urls = arr(d.urls || d.url_results);
  const attachments = arr(d.attachments);
  const findings = arr(d.findings);
  const auth = getObject(d.authentication || d.auth);
  const authText = JSON.stringify(auth).toLowerCase();
  const authPresent = Object.keys(auth).length > 0;
  const authFailed = /fail|softfail|permerror|invalid/.test(authText);
  const authPassed = /pass/.test(authText);
  const urlFlagged = urls.filter(x => /malicious|suspicious|blacklist|phish|threat|flagged/i.test(JSON.stringify(x))).length;
  const attachmentFlagged = attachments.filter(x => /malicious|suspicious|infected|flagged|high risk/i.test(JSON.stringify(x))).length;
  const overallThreatEvidence = findings.filter(x => /critical|high|malicious|phish|suspicious|blocked/i.test(JSON.stringify(x))).length;

  document.getElementById("summaryVerdictTitle").textContent = isHigh ? "Threat indicators detected" : isMedium ? "Some suspicious signals" : isLow ? "No major threats reported" : "Result is inconclusive";
  document.getElementById("summaryVerdictText").textContent = isHigh ? "The analyzer returned a high-risk verdict. Avoid links and attachments until reviewed." : isMedium ? "The analyzer returned mixed or suspicious signals. Verify the sender and inspect the evidence." : isLow ? "The analyzer returned a lower-risk verdict; this is not proof that the message is safe." : "The analyzer could not establish a clear risk level from the available results.";
  document.getElementById("summaryLinksText").textContent = `${urls.length} URL result(s), ${attachments.length} attachment(s); ${urlFlagged + attachmentFlagged} flagged item(s) based on returned indicators. Check details for provider coverage.`;
  document.getElementById("summarySenderText").textContent = !authPresent ? "Authentication data was not returned. Treat sender verification as incomplete." : authFailed ? "Authentication data includes a failure or warning. Review SPF, DKIM, and DMARC details." : authPassed ? "At least one authentication result indicates a pass. Confirm each mechanism and sender identity." : "Authentication data is present but needs review in the detailed results.";
  document.getElementById("summaryActionText").textContent = isHigh ? "Do not click links or open files; verify the sender through a separate trusted channel." : isMedium ? "Avoid using embedded links and verify unusual requests independently." : isLow ? "Confirm the message was expected and the sender address is correct before acting." : "Review detailed findings and retry checks that were unavailable before trusting the email.";
  document.getElementById("riskScore").textContent = toText(d.risk_score);
  document.getElementById("confidence").textContent = toText(d.confidence);
  document.getElementById("assessment").textContent = toText(d.assessment_note);


  // Sender information
  const sender = getObject(d.sender);

  document.getElementById("senderInfo").innerHTML = kv([
    [
      "From",
      firstValue(sender.from, d.from)
    ],
    [
      "Reply-To",
      firstValue(sender.reply_to, d.reply_to)
    ],
    [
      "Return-Path",
      firstValue(sender.return_path, d.return_path)
    ]
  ]);

  // Authentication
  renderAuthentication(d);

  // Findings
  renderFindings(d);

  // URLs and reputation
  renderUrls(d);

  // Attachments
  renderAttachments(d);

  // Received headers and IP dashboard for this email only
  renderReceived(d);
  renderCurrentEmailIpDashboard(d);

  // Scroll to summary
  window.scrollTo({
    top:
      document.getElementById("summary").offsetTop - 20,
    behavior: "smooth"
  });
}