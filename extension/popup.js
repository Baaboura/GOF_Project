/**
 * Adversarial Cognitive Mesh — Extension Popup Logic
 * Connects to the local Python server on localhost:8765
 */

const DEFAULT_SERVER = "http://localhost:8765";

let serverUrl = DEFAULT_SERVER;
let pollTimer  = null;
let ws         = null;

// ── Init ──────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  await loadSettings();
  setupTabs();
  setupButtons();
  await getCurrentTab();
  await checkServer();
  connectWebSocket();
  startPolling();
});

// ── Settings ──────────────────────────────────────────────────────────────────

async function loadSettings() {
  return new Promise(resolve => {
    chrome.storage.local.get(["serverUrl", "scenario"], (data) => {
      if (data.serverUrl) {
        serverUrl = data.serverUrl;
        document.getElementById("setting-server").value = serverUrl;
      }
      if (data.scenario) {
        document.getElementById("setting-scenario").value = data.scenario;
      }
      resolve();
    });
  });
}

document.getElementById("btn-save-settings").addEventListener("click", () => {
  serverUrl = document.getElementById("setting-server").value.trim();
  const scenario = document.getElementById("setting-scenario").value;
  chrome.storage.local.set({ serverUrl, scenario });
  checkServer();
  showToast("Settings saved");
});

// ── Tabs ──────────────────────────────────────────────────────────────────────

function setupTabs() {
  document.querySelectorAll(".tab").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById("tab-" + btn.dataset.tab).classList.add("active");

      if (btn.dataset.tab === "threats") renderThreats();
      if (btn.dataset.tab === "learning") renderLearning();
    });
  });
}

// ── Scan button ───────────────────────────────────────────────────────────────

function setupButtons() {
  document.getElementById("btn-scan").addEventListener("click", startScan);
  document.getElementById("btn-pdf").addEventListener("click", downloadPdf);
}

async function downloadPdf() {
  const btn = document.getElementById("btn-pdf");
  btn.textContent = "⟳ GENERATING PDF…";
  btn.disabled = true;
  try {
    const url = `${serverUrl}/api/report/pdf`;
    const a = document.createElement("a");
    a.href = url;
    a.download = "acm_report.pdf";
    a.click();
  } catch (e) {
    console.error("PDF download failed", e);
  }
  setTimeout(() => {
    btn.textContent = "📄 DOWNLOAD PDF REPORT";
    btn.disabled = false;
  }, 2000);
}

function isLocalhostUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  } catch (_) {
    return false;
  }
}

function showLocalhostWarning() {
  document.getElementById("btn-scan").disabled = true;
  document.getElementById("btn-text").textContent = "🚫 LOCALHOST ONLY";
  setBadge("error", "● BLOCKED");
  const feed = document.getElementById("activity-feed");
  feed.innerHTML = `
    <div class="activity-empty">
      <div class="radar-icon">🔒</div>
      <div style="color:#f472b6;font-weight:600;">Extension disabled on external sites</div>
      <div class="dim">This extension only works on localhost or 127.0.0.1.<br>Navigate to a local development site to use scanning.</div>
    </div>`;
}

async function getCurrentTab() {
  return new Promise(resolve => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        const url = tabs[0].url || "";
        document.getElementById("current-url").textContent = url || "—";
        document.getElementById("current-url").title = url;
        if (!isLocalhostUrl(url)) {
          showLocalhostWarning();
        }
      }
      resolve();
    });
  });
}

async function startScan() {
  const btn = document.getElementById("btn-scan");
  const urlEl = document.getElementById("current-url");
  const url = urlEl.textContent;

  if (!isLocalhostUrl(url)) {
    showLocalhostWarning();
    return;
  }

  const scenario = document.getElementById("setting-scenario").value || null;

  btn.disabled = true;
  document.getElementById("btn-text").textContent = "⟳ SCANNING…";

  resetPipeline();
  setBadge("active", "● SCANNING");

  try {
    const res = await fetch(`${serverUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, scenario }),
    });
    const data = await res.json();
    if (data.error) {
      showOfflineBanner(data.error);
      btn.disabled = false;
      document.getElementById("btn-text").textContent = "⚡ SCAN CURRENT SITE";
    }
  } catch (e) {
    showOfflineBanner("Cannot reach server — run python server.py");
    btn.disabled = false;
    document.getElementById("btn-text").textContent = "⚡ SCAN CURRENT SITE";
    setBadge("error", "● ERROR");
  }
}

// ── Server check ──────────────────────────────────────────────────────────────

async function checkServer() {
  const el = document.getElementById("server-status");
  el.className = "server-status checking";
  el.textContent = "Checking…";
  try {
    const res = await fetch(`${serverUrl}/api/ping`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      el.className = "server-status online";
      el.textContent = "● ONLINE — Ready";
      hideOfflineBanner();
      return true;
    }
  } catch (_) {}
  el.className = "server-status offline";
  el.textContent = "● OFFLINE — Start server";
  showOfflineBanner();
  return false;
}

// ── WebSocket ─────────────────────────────────────────────────────────────────

function connectWebSocket() {
  try {
    const wsUrl = serverUrl.replace("http://", "ws://").replace("https://", "wss://");
    ws = new WebSocket(`${wsUrl}/ws`);

    ws.onopen = () => console.log("[WS] connected");

    ws.onmessage = (evt) => {
      const msg = JSON.parse(evt.data);
      handleServerMessage(msg);
    };

    ws.onclose = () => {
      ws = null;
      setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = () => { ws?.close(); };
  } catch (_) {}
}

function handleServerMessage(msg) {
  switch (msg.type) {
    case "state":
      applyState(msg.data);
      break;
    case "agent_update":
      updateAgent(msg.agent, msg.status, msg.message);
      document.getElementById("agent-message").textContent = msg.message;
      break;
    case "complete":
      onScanComplete(msg.stats);
      break;
    case "error":
      onScanError(msg.message);
      break;
    case "reset":
      resetPipeline();
      break;
  }
}

function applyState(data) {
  if (data.pipeline) {
    for (const [agent, info] of Object.entries(data.pipeline)) {
      updateAgent(agent, info.status, info.message);
    }
  }
  if (data.stats) updateStats(data.stats);
  if (data.activity) renderActivity(data.activity);
  if (data.status === "scanning") {
    setBadge("active", "● SCANNING");
    document.getElementById("btn-scan").disabled = true;
    document.getElementById("btn-text").textContent = "⟳ SCANNING…";
  } else if (data.status === "complete") {
    setBadge("complete", "● COMPLETE");
    document.getElementById("btn-scan").disabled = false;
    document.getElementById("btn-text").textContent = "⚡ SCAN CURRENT SITE";
  }
}

// ── Polling (fallback if WS fails) ────────────────────────────────────────────

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    if (ws && ws.readyState === WebSocket.OPEN) return; // WS handles it
    try {
      const res = await fetch(`${serverUrl}/api/status`);
      const data = await res.json();
      applyState(data);
    } catch (_) {}
  }, 2000);
}

// ── Pipeline UI ───────────────────────────────────────────────────────────────

const AGENTS = ["sentinel", "triage", "red", "blue", "deception", "memory"];

function resetPipeline() {
  AGENTS.forEach(a => updateAgent(a, "idle", "—"));
  document.getElementById("agent-message").textContent = "Waiting for scan…";
  renderActivity([]);
}

function updateAgent(agent, status, _message) {
  const card = document.getElementById(`agent-${agent}`);
  const dot  = document.getElementById(`dot-${agent}`);
  if (!card || !dot) return;

  card.className = `pipeline-agent ${status !== "idle" ? status : ""}`;
  dot.className  = `agent-dot ${status}`;
}

function onScanComplete(stats) {
  setBadge("complete", "● COMPLETE");
  document.getElementById("btn-scan").disabled = false;
  document.getElementById("btn-text").textContent = "⚡ SCAN CURRENT SITE";
  document.getElementById("agent-message").textContent = "✓ Scan complete — incident resolved";
  if (stats) updateStats(stats);
  AGENTS.forEach(a => updateAgent(a, "complete", "Done"));

  document.getElementById("btn-pdf").classList.remove("hidden");
  fetchAndCacheThreats();
}

function onScanError(msg) {
  setBadge("error", "● ERROR");
  document.getElementById("btn-scan").disabled = false;
  document.getElementById("btn-text").textContent = "⚡ SCAN CURRENT SITE";
  document.getElementById("agent-message").textContent = `✗ Error: ${msg}`;
}

// ── Stats ─────────────────────────────────────────────────────────────────────

function updateStats(stats) {
  animateValue("stat-incidents", stats.incidents);
  animateValue("stat-blocked",   stats.blocked);
  animateValue("stat-warnings",  stats.warnings);
  animateValue("stat-dna",       stats.dna_learned);
}

function animateValue(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const current = parseInt(el.textContent) || 0;
  if (current === target) return;
  el.textContent = target;
  el.style.transform = "scale(1.3)";
  setTimeout(() => { el.style.transform = "scale(1)"; el.style.transition = "transform 0.2s"; }, 100);
}

// ── Activity feed ─────────────────────────────────────────────────────────────

function renderActivity(items) {
  const feed = document.getElementById("activity-feed");
  if (!items || items.length === 0) {
    feed.innerHTML = `
      <div class="activity-empty">
        <div class="radar-icon">📡</div>
        <div>Monitoring all traffic…</div>
        <div class="dim">No threats detected yet.</div>
      </div>`;
    return;
  }
  feed.innerHTML = items.map(item => `
    <div class="activity-item">
      <span class="activity-time">${item.time}</span>
      <span class="activity-msg ${item.level === 'success' ? 'success' : item.level === 'error' ? 'error' : ''}">${escHtml(item.message)}</span>
    </div>
  `).join("");
}

// ── Threats tab ───────────────────────────────────────────────────────────────

let cachedThreats = [];

async function fetchAndCacheThreats() {
  try {
    const res = await fetch(`${serverUrl}/api/threats`);
    const data = await res.json();
    cachedThreats = data.threats || [];
  } catch (_) {}
}

function renderThreats() {
  fetchAndCacheThreats().then(() => {
    const el = document.getElementById("threats-list");
    if (!cachedThreats.length) {
      el.innerHTML = `<div class="empty-state">No threats recorded yet.<br>Run a scan first.</div>`;
      return;
    }
    el.innerHTML = cachedThreats.map(t => `
      <div class="threat-card">
        <div class="threat-header">
          <span class="threat-scenario">${escHtml(t.scenario)}</span>
          <span class="threat-severity sev-${t.severity}">${t.severity?.toUpperCase()}</span>
        </div>
        <div class="threat-url">${escHtml(t.url)}</div>
        <div class="threat-summary">${escHtml(t.summary)}</div>
        <div class="threat-footer">
          <span>${t.timestamp ? t.timestamp.slice(0,19).replace("T"," ") : ""}</span>
          <span>${t.duration}s</span>
          <span class="threat-dna">${t.dna ? t.dna.slice(0,8) + "…" : ""}</span>
        </div>
      </div>
    `).join("");
  });
}

// ── Learning tab ──────────────────────────────────────────────────────────────

function renderLearning() {
  fetchAndCacheThreats().then(() => {
    const el = document.getElementById("dna-list");
    if (!cachedThreats.length) {
      el.innerHTML = `<div class="empty-state">No DNA crystallized yet.<br>Complete a scan to learn.</div>`;
      return;
    }
    el.innerHTML = cachedThreats.map(t => `
      <div class="dna-card">
        <div class="dna-hash">${t.dna || "N/A"}</div>
        <div class="dna-meta">${escHtml(t.scenario)} — ${t.timestamp?.slice(0,10) || ""}</div>
        <div class="dna-actions">
          ${(t.countermeasures || []).map(c =>
            `<div class="dna-action-item">${escHtml(c.type)}: ${escHtml(c.target)}</div>`
          ).join("")}
        </div>
      </div>
    `).join("");
  });
}

// ── Badge & Banner helpers ────────────────────────────────────────────────────

function setBadge(type, text) {
  const el = document.getElementById("status-badge");
  el.className = `badge badge-${type}`;
  el.textContent = text;
}

function showOfflineBanner(msg) {
  const el = document.getElementById("offline-banner");
  el.classList.remove("hidden");
  if (msg) el.innerHTML = `⚠ ${escHtml(msg)}`;
}

function hideOfflineBanner() {
  document.getElementById("offline-banner").classList.add("hidden");
}

function showToast(msg) {
  // Simple inline toast via agent-message
  const el = document.getElementById("agent-message");
  if (el) { el.textContent = msg; setTimeout(() => { el.textContent = ""; }, 2000); }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
