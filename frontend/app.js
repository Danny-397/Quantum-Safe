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

  // Fill a table body with shimmering skeleton rows while data loads.
  function skelRows(tbody, rows = 5, cols = 5) {
    if (!tbody) return;
    const cell = '<td><span class="skel w-80"></span></td>';
    tbody.innerHTML = Array.from(
      { length: rows },
      () => `<tr aria-hidden="true">${cell.repeat(cols)}</tr>`
    ).join("");
  }

  // Put a button into a loading state with animated dots, and restore it.
  function setLoading(btn, on, label) {
    if (!btn) return;
    if (on) {
      if (btn.dataset.loading === "1") return;
      btn.dataset.loading = "1";
      btn.dataset.html = btn.innerHTML;
      btn.disabled = true;
      btn.setAttribute("aria-busy", "true");
      btn.innerHTML = (label ? `<span>${label}</span>` : "") +
        `<span class="dots" aria-hidden="true"><i></i><i></i><i></i></span>`;
    } else {
      if (btn.dataset.loading !== "1") return;
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
      btn.innerHTML = btn.dataset.html || btn.innerHTML;
      delete btn.dataset.loading;
      delete btn.dataset.html;
    }
  }

  // ----- API wrapper --------------------------------------------------------
  async function api(path, opts = {}) {
    const headers = opts.headers || {};
    const token = getToken();
    if (token && !opts.noAuth) headers["Authorization"] = "Bearer " + token;
    if (opts.json !== undefined) {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.json);
      if (!opts.method) opts.method = "POST";  // a JSON body implies POST
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

    // Click the install command to copy it.
    const copyBtn = $("#copy-install");
    if (copyBtn) {
      copyBtn.style.cursor = "pointer";
      copyBtn.title = "Click to copy";
      copyBtn.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText("pip install quantumsafe-scan");
          const orig = copyBtn.textContent;
          copyBtn.textContent = "copied ✓";
          setTimeout(() => (copyBtn.textContent = orig), 1200);
        } catch (_) { /* clipboard may be blocked */ }
      });
    }

    initDemoScanner();
  }

  // ---- In-browser live scanner (client-side, nothing leaves the browser) ----
  const DEMO_SAMPLE =
    "import hashlib\n" +
    "from cryptography.hazmat.primitives.asymmetric import rsa, ec\n\n" +
    "# vulnerable key generation\n" +
    "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n" +
    "ec_key = ec.generate_private_key(ec.SECP256R1())\n\n" +
    "def fingerprint(data):\n" +
    "    return hashlib.md5(data).hexdigest()   # weak hash\n\n" +
    "digest = hashlib.sha256(data).hexdigest()\n" +
    "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)   # deprecated TLS\n";

  const DEMO_RULES = [
    { re: /\brsa\b|generatekeypair(?:sync)?\(\s*['"]rsa|rsa\.generate/i, family: "rsa", algo: "RSA", risk: "HIGH", rec: "CRYSTALS-Kyber / Dilithium (FIPS 203/204)" },
    { re: /\becdsa\b|\becdh\b|\becc\b|elliptic|secp256|prime256v1|crypto\/ecdsa/i, family: "ecc", algo: "ECC / ECDSA", risk: "HIGH", rec: "Kyber / Dilithium" },
    { re: /\bdsa\b/i, family: "dsa", algo: "DSA", risk: "HIGH", rec: "Dilithium (FIPS 204)" },
    { re: /diffie[\s-]?hellman|\bdh\b/i, family: "dh", algo: "Diffie-Hellman", risk: "HIGH", rec: "Kyber (FIPS 203)" },
    { re: /\bmd5\b/i, family: "md5", algo: "MD5", risk: "HIGH", rec: "SHA-3 / SHA-256" },
    { re: /\bsha-?1\b/i, family: "sha1", algo: "SHA-1", risk: "HIGH", rec: "SHA-3 / SHA-256" },
    { re: /tlsv1(?:\.0|\.1)?(?![\d.])|protocol_tlsv1\b|sslv3/i, family: "tls_old", algo: "TLS 1.0/1.1", risk: "MEDIUM", rec: "TLS 1.3" },
    { re: /3des|triple[\s_-]?des|desede/i, family: "3des", algo: "3DES", risk: "MEDIUM", rec: "AES-256" },
    { re: /\brc4\b/i, family: "rc4", algo: "RC4", risk: "MEDIUM", rec: "AES-256-GCM" },
    { re: /\bsha-?256\b/i, family: "sha256", algo: "SHA-256", risk: "LOW", rec: "OK; SHA-384/512 long-term" },
    { re: /\baes-?128\b/i, family: "aes128", algo: "AES-128", risk: "LOW", rec: "AES-256" },
    { re: /tlsv1\.2\b/i, family: "tls12", algo: "TLS 1.2", risk: "LOW", rec: "TLS 1.3" },
  ];
  const DEMO_POINTS = { HIGH: 15, MEDIUM: 5, LOW: 1 };
  const DEMO_RANK = { HIGH: 3, MEDIUM: 2, LOW: 1 };

  function scanDemo(text) {
    const lines = text.split("\n");
    const best = {}; // key: line|family -> finding
    lines.forEach((line, i) => {
      if (!line.trim()) return;
      DEMO_RULES.forEach((r) => {
        if (r.re.test(line)) {
          const key = i + "|" + r.family;
          if (!best[key] || DEMO_RANK[r.risk] > DEMO_RANK[best[key].risk]) {
            best[key] = { line: i + 1, algo: r.algo, risk: r.risk, rec: r.rec, family: r.family };
          }
        }
      });
    });
    const findings = Object.values(best).sort(
      (a, b) => DEMO_RANK[b.risk] - DEMO_RANK[a.risk] || a.line - b.line);
    const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    let score = 0;
    findings.forEach((f) => { counts[f.risk]++; score += DEMO_POINTS[f.risk]; });
    return { findings, counts, score: Math.min(100, score) };
  }

  function demoBand(score) {
    if (score === 0) return ["No risk detected", "var(--safe)"];
    if (score <= 30) return ["Low risk", "var(--safe)"];
    if (score <= 60) return ["Medium risk", "var(--warning)"];
    if (score <= 80) return ["High risk", "var(--high)"];
    return ["Critical risk", "var(--danger)"];
  }

  let demoAnim = null;
  function animateScore(to) {
    const el = $("#demo-score");
    if (!el) return;
    const from = parseInt(el.textContent, 10) || 0;
    const start = performance.now();
    if (demoAnim) cancelAnimationFrame(demoAnim);
    function step(now) {
      const t = Math.min(1, (now - start) / 450);
      el.textContent = Math.round(from + (to - from) * t);
      if (t < 1) demoAnim = requestAnimationFrame(step);
    }
    demoAnim = requestAnimationFrame(step);
  }

  // ---- Score explainer (shared) ----
  const BAND_MEANING = {
    Low: "good quantum hygiene — little to migrate",
    Medium: "plan a migration",
    High: "prioritize migration",
    Critical: "immediate action required",
  };
  function scaleHTML(score) {
    const x = Math.max(0, Math.min(100, Number(score) || 0));
    return `<div class="scale"><div class="scale-bar">
      <div class="scale-track"><span class="seg s-low" style="width:30%"></span><span class="seg s-med" style="width:30%"></span><span class="seg s-high" style="width:20%"></span><span class="seg s-crit" style="width:20%"></span></div>
      <span class="scale-marker" style="left:${x}%"></span></div>
      <div class="scale-legend"><span class="lg-low">0–30 Low</span><span class="lg-med">31–60 Medium</span><span class="lg-high">61–80 High</span><span class="lg-crit">81–100 Critical</span></div></div>`;
  }
  function renderScore(ids, score, band) {
    const s = $(ids.score);
    if (s) { s.innerHTML = `${score}<span class="score-unit">/100</span>`; s.className = "score-big mono band-" + band; }
    const b = $(ids.band);
    if (b) { b.innerHTML = `<span class="band-${band}">${band} risk</span>`; b.className = "score-band"; }
    const m = $(ids.meaning);
    if (m) m.textContent = BAND_MEANING[band] || "";
    const sc = $(ids.scale);
    if (sc) sc.innerHTML = scaleHTML(score);
  }

  function paintDemo(findings, counts, score, emptyMsg) {
    const [bandText, color] = demoBand(score);
    animateScore(score);
    const scoreEl = $("#demo-score");
    if (scoreEl) scoreEl.style.color = color;
    const bandEl = $("#demo-band");
    if (bandEl) { bandEl.textContent = bandText; bandEl.style.color = color; }
    const bar = $("#demo-bar");
    if (bar) { bar.style.width = score + "%"; bar.style.background = color; }
    $("#demo-high").textContent = counts.HIGH;
    $("#demo-med").textContent = counts.MEDIUM;
    $("#demo-low").textContent = counts.LOW;

    const box = $("#demo-findings");
    if (!box) return;
    if (emptyMsg) {
      box.innerHTML = `<div class="muted" style="padding:14px;">${emptyMsg}</div>`;
      return;
    }
    box.innerHTML = findings.length
      ? findings.map((f) => `
        <div class="demo-finding ${riskClass(f.risk)}">
          <span class="badge ${riskClass(f.risk)}">${f.risk}</span>
          <span class="mono">line ${f.line}</span>
          <b>${esc(f.algo)}</b>
          <span class="arrow">→</span>
          <span class="muted">${esc(f.rec)}</span>
        </div>`).join("")
      : `<div class="low" style="padding:14px;">No quantum-vulnerable cryptography detected.</div>`;
  }

  // Instant, client-side preview (runs in the browser).
  function renderDemo() {
    const input = $("#demo-input");
    if (!input) return;
    if (!input.value.trim()) { paintDemo([], { HIGH: 0, MEDIUM: 0, LOW: 0 }, 0, "Paste code to see findings."); return; }
    const { findings, counts, score } = scanDemo(input.value);
    paintDemo(findings, counts, score);
  }

  // The REAL engine: posts the snippet to the backend scanner (with fallback).
  async function runRealDemo() {
    const input = $("#demo-input");
    if (!input || !input.value.trim()) return;
    const btn = $("#demo-run");
    const engine = $("#demo-engine");
    setLoading(btn, true, "Scanning");
    if (engine) engine.textContent = "Scanning with the QuantumSafe engine…";
    try {
      const d = await api("/api/v1/demo-scan", {
        noAuth: true, noRedirect: true,
        json: { code: input.value, filename: "snippet.py" },
      });
      const r = d.report;
      const findings = r.findings.map((f) => ({
        line: f.line_number, algo: f.algorithm, risk: f.risk_level, rec: f.recommendation,
      }));
      paintDemo(findings, { HIGH: r.summary.high, MEDIUM: r.summary.medium, LOW: r.summary.low }, r.risk_score);
      if (engine) engine.textContent = "✓ Scanned by the real QuantumSafe engine (11 languages, AST + regex).";
    } catch (err) {
      renderDemo();
      if (engine) engine.textContent = "Full engine unavailable right now — showing the in-browser preview.";
    } finally {
      setLoading(btn, false);
    }
  }

  function initDemoScanner() {
    const input = $("#demo-input");
    if (!input) return;
    input.value = DEMO_SAMPLE;
    input.addEventListener("input", renderDemo);
    const sample = $("#demo-sample");
    if (sample) sample.addEventListener("click", () => { input.value = DEMO_SAMPLE; renderDemo(); });
    const run = $("#demo-run");
    if (run) run.addEventListener("click", runRealDemo);
    // Value-first: any "Scan free" / hero CTA drops the cursor into the editor
    // once the anchor has scrolled the demo into view.
    $$('a[href="#try"]').forEach((a) =>
      a.addEventListener("click", () => setTimeout(() => input.focus({ preventScroll: true }), 350)));
    renderDemo();
  }

  // ---- Cookie / storage notice (all pages) ----
  function ensureCookieNotice() {
    if (localStorage.getItem("qs_cookie_ack") === "1") return;
    const bar = document.createElement("div");
    bar.className = "cookie-banner";
    bar.innerHTML =
      'We use strictly-necessary local storage to keep you signed in. ' +
      'See our <a href="privacy.html">Privacy Policy</a>. ' +
      '<button class="btn btn-sm btn-primary" id="cookie-ok">Got it</button>';
    document.body.appendChild(bar);
    const ok = bar.querySelector("#cookie-ok");
    ok.addEventListener("click", () => { localStorage.setItem("qs_cookie_ack", "1"); bar.remove(); });
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
      const b = forms.login.querySelector('button[type="submit"]');
      setLoading(b, true, "Signing in");
      try {
        const d = await api("/api/v1/auth/login", {
          noAuth: true, noRedirect: true,
          json: { email: forms.login.email.value, password: forms.login.password.value },
        });
        setToken(d.token);
        location.href = "dashboard.html";
      } catch (err) { setLoading(b, false); showMsg(msg, err.message); }
    });

    forms.register && forms.register.addEventListener("submit", async (e) => {
      e.preventDefault();
      const consent = document.getElementById("reg-consent");
      if (consent && !consent.checked) {
        showMsg(msg, "Please agree to the Terms and Privacy Policy to continue.");
        return;
      }
      const b = forms.register.querySelector('button[type="submit"]');
      setLoading(b, true, "Creating account");
      try {
        const d = await api("/api/v1/auth/register", {
          noAuth: true, noRedirect: true,
          json: {
            email: forms.register.email.value,
            password: forms.register.password.value,
            accept_terms: true,  // user checked the consent box above (enforced)
          },
        });
        setToken(d.token);
        location.href = "dashboard.html";
      } catch (err) { setLoading(b, false); showMsg(msg, err.message); }
    });

    forms.forgot && forms.forgot.addEventListener("submit", async (e) => {
      e.preventDefault();
      const b = forms.forgot.querySelector('button[type="submit"]');
      setLoading(b, true, "Sending");
      try {
        const d = await api("/api/v1/auth/forgot", {
          noAuth: true, noRedirect: true, json: { email: forms.forgot.email.value },
        });
        showMsg(msg, d.message, "success");
      } catch (err) { showMsg(msg, err.message); }
      finally { setLoading(b, false); }
    });

    forms.reset && forms.reset.addEventListener("submit", async (e) => {
      e.preventDefault();
      const b = forms.reset.querySelector('button[type="submit"]');
      setLoading(b, true, "Updating");
      try {
        const d = await api("/api/v1/auth/reset", {
          noAuth: true, noRedirect: true,
          json: { token: resetToken, password: forms.reset.password.value },
        });
        showMsg(msg, d.message + " Redirecting…", "success");
        setTimeout(() => (location.href = "login.html"), 1500);
      } catch (err) { setLoading(b, false); showMsg(msg, err.message); }
    });
  }

  // =========================================================================
  //  DASHBOARD
  // =========================================================================
  let trendChart = null;

  function initDashboard() {
    if (!requireAuth()) return;
    wireLogout();

    const views = ["overview", "scans", "findings", "settings"];
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
      findings: loadFindings, settings: loadSettings,
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

    // settings actions
    $("#btn-gen-key") && $("#btn-gen-key").addEventListener("click", genKey);

    const prefBox = $("#pref-alerts");
    if (prefBox) {
      prefBox.addEventListener("change", async () => {
        try {
          await api("/api/v1/user/preferences", {
            method: "PUT", json: { alert_on_high: prefBox.checked },
          });
        } catch (err) { showMsg($("#global-msg"), err.message); }
      });
    }

    // GDPR/CCPA: export my data
    const exportBtn = $("#btn-export-data");
    if (exportBtn) {
      exportBtn.addEventListener("click", async () => {
        try {
          const res = await fetch(API_BASE + "/api/v1/user/data", {
            headers: { Authorization: "Bearer " + getToken() },
          });
          if (!res.ok) throw new Error("Export failed");
          const blob = await res.blob();
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url; a.download = "quantumsafe_my_data.json";
          document.body.appendChild(a); a.click(); a.remove();
          URL.revokeObjectURL(url);
        } catch (err) { showMsg($("#global-msg"), err.message); }
      });
    }

    // GDPR/CCPA: delete my account (with confirmation)
    const deleteBtn = $("#btn-delete-account");
    if (deleteBtn) {
      deleteBtn.addEventListener("click", async () => {
        if (!confirm("Permanently delete your account and ALL your scans? This cannot be undone.")) return;
        try {
          await api("/api/v1/user/account", { method: "DELETE", noRedirect: true });
          clearToken();
          alert("Your account and all data have been deleted.");
          location.href = "index.html";
        } catch (err) { showMsg($("#global-msg"), err.message); }
      });
    }
  }

  async function loadOverview() {
    skelRows($("#ov-recent"), 4, 5);
    try {
      const d = await api("/api/v1/overview");
      renderScore({ score: "#ov-score", band: "#ov-band", meaning: "#ov-meaning", scale: "#ov-scale" },
                  d.latest_score, d.latest_band);
      $("#ov-total").textContent = d.total_scans;
      $("#ov-high").textContent = d.findings.high;
      $("#ov-med").textContent = d.findings.medium;
      $("#ov-low").textContent = d.findings.low;
      $("#ov-month").textContent = d.scans_this_month;

      const body = $("#ov-recent");
      body.innerHTML = d.recent_scans.length
        ? d.recent_scans.map(scanRow).join("")
        : `<tr><td colspan="5" class="empty">No scans yet. Click “+ New Scan”.</td></tr>`;

      drawTrend(d.trend);
    } catch (err) {
      console.error(err);
      const b = $("#ov-recent");
      if (b) b.innerHTML = `<tr><td colspan="5" class="empty">Couldn't load your data. Refresh to retry.</td></tr>`;
    }
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
          data, borderColor: "#5b73e8", backgroundColor: "rgba(91,115,232,.12)",
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
    skelRows($("#scans-body"), 6, 5);
    try {
      const d = await api(`/api/v1/scans?page=${scansPage}&per_page=20`);
      const body = $("#scans-body");
      body.innerHTML = d.scans.length
        ? d.scans.map(scanRow).join("")
        : `<tr><td colspan="5" class="empty">No scans yet.</td></tr>`;
      $("#scans-page").textContent = `Page ${d.page} of ${Math.max(1, d.pages)} · ${d.total} total`;
      $("#scans-prev").disabled = d.page <= 1;
      $("#scans-next").disabled = d.page >= d.pages;
    } catch (err) {
      console.error(err);
      const b = $("#scans-body");
      if (b) b.innerHTML = `<tr><td colspan="5" class="empty">Couldn't load scans. Refresh to retry.</td></tr>`;
    }
    $("#scans-prev") && ($("#scans-prev").onclick = () => loadScans(scansPage - 1));
    $("#scans-next") && ($("#scans-next").onclick = () => loadScans(scansPage + 1));
  }

  let findingsCache = [];
  async function loadFindings() {
    skelRows($("#findings-body"), 5, 5);
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
    } catch (err) {
      console.error(err);
      const b = $("#findings-body");
      if (b) b.innerHTML = `<tr><td colspan="5" class="empty">Couldn't load findings. Refresh to retry.</td></tr>`;
    }
  }
  function renderFindings() {
    const lvl = $("#find-filter").value;
    const rows = findingsCache.filter((f) => lvl === "all" || f.risk_level === lvl);
    const tb = $("#findings-body");
    tb.innerHTML = rows.length
      ? rows.map(findingRow).join("")
      : `<tr><td colspan="5" class="empty">No findings at this level.</td></tr>`;
    wireFindingToggle(tb);
  }
  function findingRow(f, i) {
    const rid = "find-" + i;
    const meta = [f.nist_reference, f.complexity ? "Complexity: " + f.complexity : ""]
      .filter(Boolean).map(esc).join('<span class="sep">·</span>');
    return `<tr class="finding-row" data-target="${rid}" tabindex="0" role="button" aria-expanded="false" aria-controls="${rid}">
      <td class="mono">${esc(f.file_path)}</td>
      <td class="num">${f.line_number}</td>
      <td>${esc(f.algorithm)}</td>
      <td><span class="badge ${riskClass(f.risk_level)}">${esc(f.risk_level)}</span></td>
      <td>${esc(f.recommendation)}<span class="row-caret" aria-hidden="true">▸</span></td>
    </tr>
    <tr class="finding-detail hidden" id="${rid}"><td colspan="5">
      <div class="why-block">
        <div class="why-q"><span class="why-label">Why it matters</span>${esc(f.why) || "No additional detail."}</div>
        ${meta ? `<div class="why-meta mono">${meta}</div>` : ""}
      </div>
    </td></tr>`;
  }

  // Expand/collapse a finding's quantum-impact detail row. Delegated once per
  // table body so it survives filter re-renders.
  function toggleFinding(tr) {
    const detail = document.getElementById(tr.getAttribute("data-target"));
    if (!detail) return;
    const open = detail.classList.toggle("hidden") === false;
    tr.setAttribute("aria-expanded", open ? "true" : "false");
    tr.classList.toggle("open", open);
  }
  function wireFindingToggle(tbody) {
    if (!tbody || tbody.dataset.wired === "1") return;
    tbody.dataset.wired = "1";
    tbody.addEventListener("click", (e) => {
      const tr = e.target.closest("tr.finding-row");
      if (tr) toggleFinding(tr);
    });
    tbody.addEventListener("keydown", (e) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      const tr = e.target.closest("tr.finding-row");
      if (tr) { e.preventDefault(); toggleFinding(tr); }
    });
  }

  async function loadSettings() {
    try {
      const me = (await api("/api/v1/auth/me")).user;
      $("#acct-email").textContent = me.email;
      const prefBox = $("#pref-alerts");
      if (prefBox) prefBox.checked = me.alert_on_high !== false;
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

  async function runScan() {
    const msg = $("#scan-msg");
    const repo = $("#scan-repo").value.trim();
    const file = $("#scan-file").files[0];
    const btn = $("#btn-run-scan");
    if (!repo && !file) { showMsg(msg, "Provide a GitHub URL or a .zip file."); return; }
    setLoading(btn, true, "Scanning");
    showMsg(msg, "Scanning… cloning and analyzing your code. This can take up to a minute.", "success");
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
      setLoading(btn, false);
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
    skelRows($("#sd-body"), 6, 5);

    try {
      const scan = (await api("/api/v1/scans/" + id)).scan;
      renderScore({ score: "#sd-score", band: "#sd-band", meaning: "#sd-meaning", scale: "#sd-scale" },
                  scan.risk_score, scan.risk_band);
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
    } catch (err) {
      showMsg($("#global-msg"), err.message);
      const b = $("#sd-body");
      if (b) b.innerHTML = `<tr><td colspan="5" class="empty">Couldn't load this scan.</td></tr>`;
    }
  }
  function renderSd() {
    const lvl = $("#sd-filter").value;
    const rows = sdCache.filter((f) => lvl === "all" || f.risk_level === lvl);
    const tb = $("#sd-body");
    tb.innerHTML = rows.length
      ? rows.map(findingRow).join("")
      : `<tr><td colspan="5" class="empty">No findings at this level.</td></tr>`;
    wireFindingToggle(tb);
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
    const mc = $("#mig-container");
    if (mc) {
      mc.innerHTML = ('<div class="mig-item"><span class="skel w-40"></span>' +
        '<div style="height:10px"></div><span class="skel w-80"></span></div>').repeat(3);
    }
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
    } catch (err) {
      showMsg($("#global-msg"), err.message);
      if (mc) mc.innerHTML = `<div class="empty">Couldn't load the migration plan. Refresh to retry.</div>`;
    }
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
    // privacy.html / terms.html need no page init.
    ensureCookieNotice();
  });
})();
