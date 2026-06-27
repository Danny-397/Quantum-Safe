/* QuantumSafe dashboard front-end.
   One script for every page; it dispatches on the current document. */

(function () {
  "use strict";

  // ----- config -------------------------------------------------------------
  // Override in production via: window.QUANTUMSAFE_API = "https://api.example.com"
  // (set before this script loads) or localStorage.setItem('qs_api', '...').
  const API_BASE =
    (window.QUANTUMSAFE_API ||
      localStorage.getItem("qs_api") ||
      "http://localhost:5000").replace(/\/$/, "");

  const TOKEN_KEY = "qs_token";

  // ----- tiny helpers -------------------------------------------------------
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const getToken = () => localStorage.getItem(TOKEN_KEY);
  const setToken = (t) => localStorage.setItem(TOKEN_KEY, t);
  const clearToken = () => localStorage.removeItem(TOKEN_KEY);

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function riskClass(level) {
    return { HIGH: "r-high", MEDIUM: "r-medium", LOW: "r-low" }[level] || "";
  }
  function fmtDate(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString();
  }
  function showMsg(el, text, type) {
    if (!el) return;
    el.className = "msg " + (type || "error");
    el.textContent = text;
    el.style.display = "block";
  }
  function hideMsg(el) { if (el) el.style.display = "none"; }

  // ----- API wrapper --------------------------------------------------------
  async function api(path, opts = {}) {
    const headers = opts.headers || {};
    const token = getToken();
    if (token && !opts.noAuth) headers["Authorization"] = "Bearer " + token;
    if (opts.json !== undefined) {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.json);
    }
    const res = await fetch(API_BASE + path, { ...opts, headers });
    if (res.status === 401 && !opts.noRedirect) {
      clearToken();
      if (!/login\.html$/.test(location.pathname)) location.href = "login.html";
      throw new Error("Not authenticated");
    }
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON */ }
    if (!res.ok) {
      const msg = (data && data.error) || `Request failed (${res.status})`;
      throw new Error(msg);
    }
    return data;
  }

  function requireAuth() {
    if (!getToken()) { location.href = "login.html"; return false; }
    return true;
  }

  function wireLogout() {
    const b = $("#btn-logout");
    if (b) b.addEventListener("click", () => { clearToken(); location.href = "index.html"; });
  }

  // =========================================================================
  //  LANDING
  // =========================================================================
  function initLanding() {
    // Pre-warm the API to hide cold starts on hosted backends.
    fetch(API_BASE + "/health").catch(() => {});
  }

  // =========================================================================
  //  AUTH (login / register / forgot / reset)
  // =========================================================================
  function initAuth() {
    const params = new URLSearchParams(location.search);
    const msg = $("#msg");
    const forms = {
      login: $("#form-login"),
      register: $("#form-register"),
      forgot: $("#form-forgot"),
      reset: $("#form-reset"),
    };
    const resetToken = params.get("reset");

    function show(mode) {
      Object.entries(forms).forEach(([k, f]) => f && f.classList.toggle("hidden", k !== mode));
      hideMsg(msg);
    }

    if (resetToken) show("reset");
    else show(params.get("mode") || "login");

    // switch links
    $$("[data-go]").forEach((a) =>
      a.addEventListener("click", (e) => { e.preventDefault(); show(a.dataset.go); }));

    forms.login && forms.login.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const d = await api("/api/v1/auth/login", {
          noAuth: true, noRedirect: true,
          json: { email: forms.login.email.value, password: forms.login.password.value },
        });
        setToken(d.token);
        location.href = "dashboard.html";
      } catch (err) { showMsg(msg, err.message); }
    });

    forms.register && forms.register.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const d = await api("/api/v1/auth/register", {
          noAuth: true, noRedirect: true,
          json: { email: forms.register.email.value, password: forms.register.password.value },
        });
        setToken(d.token);
        const plan = params.get("plan");
        location.href = plan ? "dashboard.html#billing" : "dashboard.html";
      } catch (err) { showMsg(msg, err.message); }
    });

    forms.forgot && forms.forgot.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const d = await api("/api/v1/auth/forgot", {
          noAuth: true, noRedirect: true, json: { email: forms.forgot.email.value },
        });
        showMsg(msg, d.message, "success");
      } catch (err) { showMsg(msg, err.message); }
    });

    forms.reset && forms.reset.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const d = await api("/api/v1/auth/reset", {
          noAuth: true, noRedirect: true,
          json: { token: resetToken, password: forms.reset.password.value },
        });
        showMsg(msg, d.message + " Redirecting…", "success");
        setTimeout(() => (location.href = "login.html"), 1500);
      } catch (err) { showMsg(msg, err.message); }
    });
  }

  // =========================================================================
  //  DASHBOARD
  // =========================================================================
  let trendChart = null;

  function initDashboard() {
    if (!requireAuth()) return;
    wireLogout();

    const views = ["overview", "scans", "findings", "settings", "billing"];
    function route() {
      const hash = (location.hash || "#overview").slice(1);
      const view = views.includes(hash) ? hash : "overview";
      views.forEach((v) => $("#view-" + v).classList.toggle("hidden", v !== view));
      $$("#side-nav a[data-view]").forEach((a) =>
        a.classList.toggle("active", a.dataset.view === view));
      loaders[view] && loaders[view]();
    }

    const loaders = {
      overview: loadOverview, scans: () => loadScans(1),
      findings: loadFindings, settings: loadSettings, billing: loadBilling,
    };

    window.addEventListener("hashchange", route);
    route();

    // new scan modal
    const modal = $("#scan-modal");
    const openModal = () => { hideMsg($("#scan-msg")); modal.classList.remove("hidden"); };
    $("#btn-new-scan") && $("#btn-new-scan").addEventListener("click", openModal);
    $("#btn-new-scan-2") && $("#btn-new-scan-2").addEventListener("click", openModal);
    $("#scan-cancel") && $("#scan-cancel").addEventListener("click", (e) => {
      e.preventDefault(); modal.classList.add("hidden");
    });
    $("#btn-run-scan") && $("#btn-run-scan").addEventListener("click", runScan);

    // settings + billing actions
    $("#btn-gen-key") && $("#btn-gen-key").addEventListener("click", genKey);
    $$("[data-upgrade]").forEach((b) =>
      b.addEventListener("click", () => upgrade(b.dataset.upgrade)));
    $("#btn-portal") && $("#btn-portal").addEventListener("click", openPortal);

    const prefBox = $("#pref-alerts");
    if (prefBox) {
      prefBox.checked = localStorage.getItem("qs_pref_alerts") !== "false";
      prefBox.addEventListener("change", () =>
        localStorage.setItem("qs_pref_alerts", prefBox.checked));
    }
  }

  async function loadOverview() {
    try {
      const d = await api("/api/v1/overview");
      $("#ov-score").textContent = d.latest_score;
      const band = $("#ov-band");
      band.textContent = d.latest_band + " risk";
      band.className = "score-band band-" + d.latest_band;
      $("#ov-score").className = "score-big mono band-" + d.latest_band;
      $("#ov-total").textContent = d.total_scans;
      $("#ov-high").textContent = d.findings.high;
      $("#ov-med").textContent = d.findings.medium;
      $("#ov-low").textContent = d.findings.low;
      $("#ov-month").textContent = d.scans_this_month;
      $("#ov-plan").textContent = "Plan: " + d.plan.toUpperCase();

      const body = $("#ov-recent");
      body.innerHTML = d.recent_scans.length
        ? d.recent_scans.map(scanRow).join("")
        : `<tr><td colspan="5" class="empty">No scans yet. Click “+ New Scan”.</td></tr>`;

      drawTrend(d.trend);
    } catch (err) { console.error(err); }
  }

  function drawTrend(trend) {
    const canvas = $("#trend-chart");
    if (!canvas || typeof Chart === "undefined") return;
    const labels = trend.map((p) => (p.date ? new Date(p.date).toLocaleDateString() : ""));
    const data = trend.map((p) => p.score);
    if (trendChart) trendChart.destroy();
    trendChart = new Chart(canvas, {
      type: "line",
      data: {
        labels,
        datasets: [{
          data, borderColor: "#00FF88", backgroundColor: "rgba(0,255,136,.1)",
          fill: true, tension: 0.25, pointRadius: 2, borderWidth: 2,
        }],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          y: { min: 0, max: 100, grid: { color: "#23232f" }, ticks: { color: "#8a8a9c" } },
          x: { grid: { color: "#16161f" }, ticks: { color: "#8a8a9c", maxTicksLimit: 8 } },
        },
      },
    });
  }

  function scanRow(s) {
    return `<tr>
      <td class="mono">${esc(s.repo_url)}</td>
      <td class="mono">${fmtDate(s.created_at)}</td>
      <td class="num band-${esc(s.risk_band)}">${s.risk_score}</td>
      <td class="mono"><span class="high">${s.summary.high}</span>/<span class="medium">${s.summary.medium}</span>/<span class="low">${s.summary.low}</span></td>
      <td><a class="btn btn-sm" href="scan.html?id=${s.id}">View</a></td>
    </tr>`;
  }

  let scansPage = 1;
  async function loadScans(page) {
    scansPage = page || 1;
    try {
      const d = await api(`/api/v1/scans?page=${scansPage}&per_page=20`);
      const body = $("#scans-body");
      body.innerHTML = d.scans.length
        ? d.scans.map(scanRow).join("")
        : `<tr><td colspan="5" class="empty">No scans yet.</td></tr>`;
      $("#scans-page").textContent = `Page ${d.page} of ${Math.max(1, d.pages)} · ${d.total} total`;
      $("#scans-prev").disabled = d.page <= 1;
      $("#scans-next").disabled = d.page >= d.pages;
    } catch (err) { console.error(err); }
    $("#scans-prev") && ($("#scans-prev").onclick = () => loadScans(scansPage - 1));
    $("#scans-next") && ($("#scans-next").onclick = () => loadScans(scansPage + 1));
  }

  let findingsCache = [];
  async function loadFindings() {
    try {
      const list = await api("/api/v1/scans?per_page=1");
      if (!list.scans.length) {
        $("#findings-body").innerHTML = `<tr><td colspan="5" class="empty">No scans yet.</td></tr>`;
        return;
      }
      const id = list.scans[0].id;
      $("#find-detail-link").href = "scan.html?id=" + id;
      const d = await api("/api/v1/scans/" + id);
      findingsCache = d.scan.findings;
      renderFindings();
      const filter = $("#find-filter");
      filter.onchange = renderFindings;
    } catch (err) { console.error(err); }
  }
  function renderFindings() {
    const lvl = $("#find-filter").value;
    const rows = findingsCache.filter((f) => lvl === "all" || f.risk_level === lvl);
    $("#findings-body").innerHTML = rows.length
      ? rows.map(findingRow).join("")
      : `<tr><td colspan="5" class="empty">No findings at this level.</td></tr>`;
  }
  function findingRow(f) {
    return `<tr>
      <td class="mono">${esc(f.file_path)}</td>
      <td class="num">${f.line_number}</td>
      <td>${esc(f.algorithm)}</td>
      <td><span class="badge ${riskClass(f.risk_level)}">${esc(f.risk_level)}</span></td>
      <td>${esc(f.recommendation)}</td>
    </tr>`;
  }

  async function loadSettings() {
    try {
      const me = (await api("/api/v1/auth/me")).user;
      $("#acct-email").textContent = me.email;
      $("#acct-created").textContent = "Member since " + fmtDate(me.created_at);
      $("#acct-verified").innerHTML = me.email_verified
        ? `<span class="low">✓ Email verified</span>`
        : `<span class="medium">Email not verified</span>`;
      const k = await api("/api/v1/user/apikey");
      $("#apikey-display").textContent = k.has_api_key
        ? `${k.api_key_prefix}••••••••••••••••  (hidden)`
        : "No key generated yet.";
    } catch (err) { console.error(err); }
  }
  async function genKey() {
    try {
      const d = await api("/api/v1/user/apikey", { method: "POST" });
      $("#apikey-display").textContent = d.api_key;
      showMsg($("#global-msg"), "New key generated — copy it now, it won't be shown again.", "success");
    } catch (err) { showMsg($("#global-msg"), err.message); }
  }

  async function loadBilling() {
    try {
      const me = (await api("/api/v1/auth/me")).user;
      $("#bill-plan").textContent = me.plan.toUpperCase();
    } catch (err) { console.error(err); }
  }
  async function upgrade(plan) {
    try {
      const d = await api("/api/v1/billing/checkout", { method: "POST", json: { plan } });
      location.href = d.url;
    } catch (err) { showMsg($("#global-msg"), err.message); }
  }
  async function openPortal() {
    try {
      const d = await api("/api/v1/billing/portal", { method: "POST" });
      location.href = d.url;
    } catch (err) { showMsg($("#global-msg"), err.message); }
  }

  async function runScan() {
    const msg = $("#scan-msg");
    const repo = $("#scan-repo").value.trim();
    const file = $("#scan-file").files[0];
    const btn = $("#btn-run-scan");
    if (!repo && !file) { showMsg(msg, "Provide a GitHub URL or a .zip file."); return; }
    btn.disabled = true; btn.textContent = "Scanning…";
    try {
      let res;
      if (file) {
        const fd = new FormData();
        fd.append("file", file);
        res = await api("/api/v1/scan", { method: "POST", body: fd });
      } else {
        res = await api("/api/v1/scan", { method: "POST", json: { repo_url: repo } });
      }
      location.href = "scan.html?id=" + res.scan_id;
    } catch (err) {
      showMsg(msg, err.message);
    } finally {
      btn.disabled = false; btn.textContent = "Run Scan";
    }
  }

  // =========================================================================
  //  SCAN DETAIL
  // =========================================================================
  let sdCache = [];
  async function initScanDetail() {
    if (!requireAuth()) return;
    wireLogout();
    const id = new URLSearchParams(location.search).get("id");
    if (!id) { showMsg($("#global-msg"), "No scan id provided."); return; }
    $("#sd-migration-link").href = "migration.html?scan=" + id;

    try {
      const scan = (await api("/api/v1/scans/" + id)).scan;
      $("#sd-score").textContent = scan.risk_score;
      $("#sd-score").className = "score-big mono band-" + scan.risk_band;
      $("#sd-band").textContent = scan.risk_band + " risk";
      $("#sd-band").className = "score-band band-" + scan.risk_band;
      $("#sd-target").textContent = scan.repo_url;
      $("#sd-date").textContent = fmtDate(scan.created_at);
      $("#sd-high").textContent = scan.summary.high;
      $("#sd-med").textContent = scan.summary.medium;
      $("#sd-low").textContent = scan.summary.low;
      sdCache = scan.findings;
      renderSd();
      $("#sd-filter").onchange = renderSd;
      $$("[data-export]").forEach((b) =>
        b.addEventListener("click", () => exportScan(id, b.dataset.export)));
    } catch (err) { showMsg($("#global-msg"), err.message); }
  }
  function renderSd() {
    const lvl = $("#sd-filter").value;
    const rows = sdCache.filter((f) => lvl === "all" || f.risk_level === lvl);
    $("#sd-body").innerHTML = rows.length
      ? rows.map(findingRow).join("")
      : `<tr><td colspan="5" class="empty">No findings at this level.</td></tr>`;
  }
  async function exportScan(id, fmt) {
    try {
      const res = await fetch(`${API_BASE}/api/v1/scans/${id}/export?format=${fmt}`, {
        headers: { Authorization: "Bearer " + getToken() },
      });
      if (!res.ok) throw new Error("Export failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `scan_${id}.${fmt}`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    } catch (err) { showMsg($("#global-msg"), err.message); }
  }

  // =========================================================================
  //  MIGRATION PLAN
  // =========================================================================
  async function initMigration() {
    if (!requireAuth()) return;
    wireLogout();
    try {
      let id = new URLSearchParams(location.search).get("scan");
      if (!id) {
        const list = await api("/api/v1/scans?per_page=1");
        if (!list.scans.length) {
          $("#mig-container").innerHTML = `<div class="empty">No scans yet. Run a scan first.</div>`;
          return;
        }
        id = list.scans[0].id;
      }
      const d = await api(`/api/v1/scans/${id}/migration`);
      $("#mig-meta").textContent = `Scan #${d.scan_id} · Score ${d.risk_score} (${d.risk_band})`;
      const order = [["HIGH", "Migrate immediately"], ["MEDIUM", "Plan migration"], ["LOW", "Monitor"]];
      const html = order.map(([lvl, label]) => {
        const items = d.plan[lvl] || [];
        if (!items.length) return "";
        return `<div class="mig-group">
          <h2 class="${riskClass(lvl)}">${lvl} — ${label} (${items.length})</h2>
          ${items.map((it) => migItem(it, lvl)).join("")}
        </div>`;
      }).join("");
      $("#mig-container").innerHTML = html ||
        `<div class="empty low">No quantum-vulnerable cryptography found. Good quantum hygiene.</div>`;
    } catch (err) { showMsg($("#global-msg"), err.message); }
  }
  function migItem(it, lvl) {
    return `<div class="mig-item ${riskClass(lvl)}">
      <div class="row">
        <div><span class="algo">${esc(it.algorithm)}</span>
          <span class="arrow">→</span><span class="algo">${esc(it.replace_with)}</span></div>
        <div class="muted mono">×${it.occurrences}</div>
      </div>
      <div class="meta">${esc(it.detail)}</div>
      <div class="meta mono">${esc(it.nist_reference)} · Complexity: ${esc(it.complexity)} · e.g. ${esc(it.example)}</div>
    </div>`;
  }

  // ----- dispatch -----------------------------------------------------------
  document.addEventListener("DOMContentLoaded", () => {
    const page = location.pathname.split("/").pop() || "index.html";
    if (page === "" || page === "index.html") initLanding();
    else if (page === "login.html") initAuth();
    else if (page === "dashboard.html") initDashboard();
    else if (page === "scan.html") initScanDetail();
    else if (page === "migration.html") initMigration();
  });
})();
