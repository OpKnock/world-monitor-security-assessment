/* World Monitor SPA — hash router + views. Vanilla JS, no frameworks. */
(() => {
  const view = document.getElementById("view");
  const sidebar = document.getElementById("sidebar");
  const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  let pollTimer = null;

  function toast(msg, ok = true) {
    const el = document.createElement("div");
    el.className = "toast-item";
    if (!ok) el.style.borderLeftColor = "var(--critical)";
    el.textContent = msg;
    document.getElementById("toast").appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }


  function targetChip(target) {
    if (!target) return "";
    const t = String(target);
    if (t.includes("3000")) return '<span class="chip realapp">REAL APP :3000</span>';
    if (t === "(source-static)" || t.startsWith("(source"))
      return '<span class="chip realsrc">REAL SOURCE CODE</span>';
    if (t.includes("8080")) return '<span class="chip poc">POC PLAYGROUND :8080</span>';
    return "";
  }

  function stopPoll() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

  /* ---- active-run banner: find your way back to a running assessment ---- */
  let bannerTimer = null;
  function rememberAssessment(id) { localStorage.setItem("wm_active_assessment", id); }

  function ActiveRunBanner() {
    const old = document.getElementById("runBanner");
    if (old) old.remove();
    if (bannerTimer) { clearInterval(bannerTimer); bannerTimer = null; }
    const id = localStorage.getItem("wm_active_assessment");
    if (!id) return;
    if (location.hash === `#/assessment/${id}`) return;
    const refresh = async () => {
      let a = null;
      try { a = await API.get(`/assessments/${id}`); } catch (_) {}
      const b = document.getElementById("runBanner");
      if (!b) return;
      if (!a || ["completed", "failed"].includes(a.status)) {
        b.remove();
        if (bannerTimer) { clearInterval(bannerTimer); bannerTimer = null; }
        return;
      }
      b.innerHTML = `<span class="status ${a.status}">${a.status}</span>
        assessment on <b>${esc(a.target)}</b>
        <button style="padding:3px 10px;font-size:11px" onclick="location.hash='#/assessment/${id}'">VIEW LIVE PROGRESS</button>`;
    };
    const bar = document.createElement("div");
    bar.id = "runBanner";
    bar.style.cssText = "position:fixed;top:10px;left:50%;transform:translateX(-50%);z-index:50;" +
      "background:#111c33;border:1px solid #3d8bfd55;border-radius:9px;padding:8px 16px;" +
      "display:flex;gap:12px;align-items:center;font-size:12.5px;box-shadow:0 6px 18px rgba(0,0,0,.45)";
    bar.innerHTML = "checking…";
    document.body.appendChild(bar);
    refresh();
    bannerTimer = setInterval(refresh, 4000);
  }

  /* ---------------- auth shell ---------------- */
  function AuthScreen(mode = "login") {
    stopPoll();
    sidebar.classList.add("hidden");
    const isLogin = mode === "login";
    view.innerHTML = `
      <div class="auth-wrap"><div class="auth-card">
        <div class="auth-logo">
          <svg width="40" height="40" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#0b1630"/><path d="M16 4l9 4v7c0 6-4 10-9 13-5-3-9-7-9-13V8z" fill="none" stroke="#3d8bfd" stroke-width="2"/><circle cx="16" cy="15" r="3" fill="#3d8bfd"/></svg>
          <div><strong style="letter-spacing:.1em">WORLD MONITOR</strong><br><span class="muted small">Security Assessment Platform</span></div>
        </div>
        <h2 style="margin:0 0 16px">${isLogin ? "Sign in" : "Create account"}</h2>
        <form id="authForm">
          <div class="field"><label>Email</label><input type="email" name="email" required autocomplete="username"></div>
          <div class="field"><label>Password</label><input type="password" name="password" required minlength="${isLogin ? 1 : 10}" autocomplete="current-password"></div>
          <button style="width:100%">${isLogin ? "Sign in" : "Register"}</button>
          <div class="err" id="authErr"></div>
        </form>
        <p class="small muted">${isLogin
          ? `No account? <a href="#" id="toggleAuth">Register</a> — first user becomes admin.`
          : `<a href="#" id="toggleAuth">Back to sign in</a>`}</p>
      </div></div>`;
    document.getElementById("toggleAuth").onclick = (e) => { e.preventDefault(); AuthScreen(isLogin ? "register" : "login"); };
    document.getElementById("authForm").onsubmit = async (e) => {
      e.preventDefault();
      const errBox = document.getElementById("authErr");
      errBox.textContent = "";
      const fd = new FormData(e.target);
      try {
        const path = isLogin ? "/auth/login" : "/auth/register";
        const data = await API.post(path, { email: fd.get("email"), password: fd.get("password") });
        API.setToken(data.access_token);
        toast(isLogin ? "Welcome back" : "Account created");
        // if the hash is already #/dashboard, assigning it again fires no
        // event — render explicitly so the UI leaves the login screen
        if (location.hash === "#/dashboard") router();
        else location.hash = "#/dashboard";
      } catch (err) {
        errBox.textContent = err.message;
      }
    };
  }

  /* ---------------- layout helpers ---------------- */
  function requireAuth() {
    if (!API.getToken()) { location.hash = "#/login"; return false; }
    sidebar.classList.remove("hidden");
    return true;
  }

  const routes = {
    "#/dashboard": Dashboard, "#/assess/new": NewAssessment,
    "#/findings": FindingsList, "#/history": History,
    "#/reports": Reports, "#/settings": Settings,
  };

  function setActiveNav() {
    document.querySelectorAll("[data-nav]").forEach(a => {
      a.classList.toggle("active", location.hash.startsWith(a.getAttribute("href")));
    });
  }

  async function router() {
    stopPoll();
    const h = location.hash || "#/dashboard";

    // unauthenticated visitors only ever see the auth screen
    if (!API.getToken()) {
      sidebar.classList.add("hidden");
      setActiveNav();
      AuthScreen(h === "#/register" ? "register" : "login");
      return;
    }

    sidebar.classList.remove("hidden");
    setActiveNav();
    ActiveRunBanner();
    if (routes[h]) return routes[h]();
    if (h.startsWith("#/assessment/")) return AssessmentDetail(h.split("/")[2]);
    if (h.startsWith("#/finding/")) return FindingDetail(h.split("/")[2]);
    return Dashboard();
  }

  /* ---------------- dashboard ---------------- */
  async function Dashboard() {
    view.innerHTML = `<h1 class="page">Security Posture</h1>
      <p class="sub">Live results from authorized local-lab assessments.</p><div id="dashBody">Loading…</div>`;
    let d;
    try { d = await API.get("/dashboard"); } catch (e) { return void (view.querySelector("#dashBody").textContent = e.message); }
    const kpi = SEV_ORDER.map(s => `
      <div class="kpi ${s.toLowerCase().slice(0, 6)}"><b>${d.severity_counts[s] ?? 0}</b><small>${s}</small></div>`).join("");
    view.querySelector("#dashBody").innerHTML = `
      <div class="grid kpis mb">${kpi}</div>
      <div class="grid two-col">
        <div class="card">
          <div class="row spread"><strong>Finding distribution</strong><span class="muted small">${d.total_findings} total</span></div>
          <div class="row mt" style="justify-content:center">${Charts.donut(d.severity_counts)}</div>
        </div>
        <div class="card"><strong>Posture by category</strong><div class="mt">${Charts.catBars(d.categories)}</div></div>
      </div>
      <div class="card mt">
        <div class="row spread"><strong>Recent assessments</strong>
          <button onclick="location.hash='#/assess/new'">New Assessment</button></div>
        ${d.recent_assessments.length ? `<table class="mt"><tr><th>Target</th><th>Status</th><th>Created</th><th></th></tr>
          ${d.recent_assessments.map(a => `
            <tr class="click" onclick="location.hash='#/assessment/${a.id}'">
              <td class="mono" style="display:flex;gap:8px;align-items:center">
                ${targetChip(a.target)} ${esc(a.target)}</td>
              <td><span class="status ${a.status}">${a.status}</span></td>
              <td class="muted small">${new Date(a.created_at).toLocaleString()}</td>
              <td>›</td></tr>`).join("")}</table>`
          : `<p class="muted small mt">No assessments yet — create the first one.</p>`}
      </div>`;
  }

  /* ---------------- new assessment ---------------- */
  const MODULES = [
    ["authentication", "Authentication", "JWT handling · token acceptance"],
    ["authorization", "Authorization / IDOR", "object-level access control"],
    ["api", "API Security", "rate limiting & bypass"],
    ["input_validation", "Input Validation", "SQLi · reflected input · errors"],
    ["headers", "Client Security Headers", "CSP · HSTS · cookies"],
    ["tls", "TLS / Secure Comm", "HTTPS · certificates"],
    ["secrets", "Secrets Exposure", "hardcoded credentials in lab source"],
    ["dependencies", "Dependencies / SBOM", "known CVEs in lab packages"],
    ["supply_chain", "Supply Chain Hygiene", "typosquat - pinning - licenses"],
    ["graphql", "GraphQL Security", "introspection exposure probe"],
    ["deep_scan", "Network Surface and Banners", "ports - banners - default creds"],
    ["fuzzing", "Mutation Fuzzing", "crash-like 5xx anomaly detection"],
  ];

  function NewAssessment() {
    view.innerHTML = `
      <h1 class="page">New Assessment</h1>
      <p class="sub">All testing is confined to explicitly authorized targets. LAB MODE permits localhost/private addresses only.</p>
      <form id="assessForm" class="grid two-col">
        <div class="card">
          <div class="field"><label>Target URL (HTTP modules)</label>
            <input type="text" id="target" value="http://127.0.0.1:8080/api" placeholder="http://127.0.0.1:8080/api"></div>
          <button type="button" class="ghost" id="presetReal" style="margin-bottom:10px">Load REAL World Monitor source (targets\real-world-monitor)</button>
          <div class="field"><label>Filesystem scope (secrets / dependencies)</label>
            <input type="text" id="sourcePath" value="" placeholder="default: lab/vulnerable-world-monitor"></div>
          <div class="field"><label>Lab token for authenticated checks <button type="button" class="ghost" id="fetchToken" style="padding:2px 8px;font-size:11px">fetch demo token</button></label>
            <input type="text" id="labToken" placeholder="(optional) JWT from the vulnerable lab"></div>
          <details class="mt mb">
            <summary class="muted small" style="cursor:pointer">Per-module target overrides (World Monitor lab layout)</summary>
            <div class="field mt"><label>Authorization / IDOR → reports collection</label>
              <input type="text" id="t-authorization" value="http://127.0.0.1:8080/api/reports"></div>
            <div class="field"><label>API rate-limit probe → public telemetry</label>
              <input type="text" id="t-api" value="http://127.0.0.1:8080/api/monitor"></div>
            <div class="field"><label>SQL injection probe → search endpoint</label>
              <input type="text" id="t-sqli" value="http://127.0.0.1:8080/api/search?id=1"></div>
            <div class="field"><label>Reflection (XSS) probe → greeting endpoint</label>
              <input type="text" id="t-input_validation" value="http://127.0.0.1:8080/greet"></div>
          </details>
          <label class="row" style="gap:9px;cursor:pointer;margin-top:14px">
            <input type="checkbox" id="authorized" style="width:auto">
            <span>I confirm this target is <strong>authorized for security testing</strong> and is my local lab environment.</span>
          </label>
          <div class="mt"><button type="submit" id="startBtn" disabled>START ASSESSMENT</button>
          <span class="muted small" style="margin-left:10px">Authorization confirmation is mandatory.</span></div>
        </div>
        <div class="card">
          <strong>Select modules</strong>
          <table class="mt">${MODULES.map(([k, label, desc], i) => `
            <tr><td style="width:26px"><input type="checkbox" name="mod" value="${k}" style="width:auto" ${i < 5 ? "checked" : ""}></td>
            <td><strong>${label}</strong><br><span class="muted small mono">${desc}</span></td></tr>`).join("")}
          </table>
        </div>
      </form>`;
    document.getElementById("presetReal").onclick = () => {
      document.getElementById('sourcePath').value = 'targets\\real-world-monitor';
      toast('Target set to real World Monitor source - pick Secrets / Dependencies modules');
    };
    const form = document.getElementById("assessForm");
    const cb = document.getElementById("authorized"), btn = document.getElementById("startBtn");
    cb.onchange = () => btn.disabled = !cb.checked;
    document.getElementById("fetchToken").onclick = async () => {
      try {
        const r = await API.post("/lab/token");
        document.getElementById("labToken").value = r.access_token;
        toast("Lab demo token acquired");
      } catch (e) { toast(e.message, false); }
    };
    form.onsubmit = async (e) => {
      e.preventDefault();
      const modules = [...form.querySelectorAll("input[name=mod]:checked")].map(i => i.value);
      if (!modules.length) return toast("Select at least one module", false);
      try {
        const mt = {};
        ["t-authorization", "t-api", "t-sqli", "t-input_validation"].forEach(id => {
          const el = document.getElementById(id);
          if (el && el.value.trim()) mt[id.slice(2)] = el.value.trim();
        });
        const a = await API.post("/assessments", {
          target: document.getElementById("target").value.trim(),
          modules, authorized: true,
          source_path: document.getElementById("sourcePath").value.trim() || null,
          auth_token: document.getElementById("labToken").value.trim() || null,
          module_targets: mt,
        });
        toast("Assessment queued");
        rememberAssessment(a.id);
        location.hash = `#/assessment/${a.id}`;
      } catch (err) { toast(err.message, false); }
    };
  }

  /* ---------------- assessment detail (live progress) ---------------- */
  async function AssessmentDetail(id) {
    view.innerHTML = `<h1 class="page">Assessment</h1><p class="sub mono">${esc(id)}</p><div id="body">Loading…</div>`;
    const body = view.querySelector("#body");
    let lastSnap = null;
    const render = (a) => {
      // re-render only when something actually changed -> no flicker
      const snap = JSON.stringify([
        a.status,
        a.severity_counts,
        a.scan_runs.map(r => [r.scanner, r.status, r.findings_count, r.checks_total, r.error]),
      ]);
      if (snap === lastSnap) { schedulePoll(a); return; }
      lastSnap = snap;
      const scrollY = window.scrollY;
      const done = a.scan_runs.filter(r => ["completed", "failed", "skipped"].includes(r.status)).length;
      const pct = Math.round((done / Math.max(a.scan_runs.length, 1)) * 100);
      const sev = a.severity_counts || {};
      body.innerHTML = `
        <div class="card mb">
          <div class="row spread">
            <div><strong>${esc(a.target)}</strong><br>
            <span class="muted small">modules: ${a.modules.map(esc).join(", ")} · authorized: ${a.authorized ? "CONFIRMED" : "NO"}</span></div>
            <div><span class="status ${a.status}">${a.status}</span></div>
          </div>
          <div class="progressbar mt"><i style="width:${pct}%"></i></div>
        </div>
        <div class="grid kpis mb">${SEV_ORDER.map(s =>
          `<div class="kpi"><b>${sev[s] ?? 0}</b><small>${s}</small></div>`).join("")}</div>
        <div class="card mb"><strong>Scanner runs</strong>
          <table class="mt"><tr><th>Module</th><th>Status</th><th>Checks</th><th>Safe</th><th>Findings</th><th>Duration</th></tr>
          ${a.scan_runs.map(r => `<tr>
            <td class="mono">${esc(r.scanner)}</td>
            <td><span class="status ${r.status}">${r.status}</span>${r.error ? `<br><span class="muted small">${esc(r.error.slice(0, 90))}</span>` : ""}</td>
            <td class="mono">${r.checks_total}</td><td class="mono">${r.checks_safe}</td>
            <td class="mono">${r.findings_count}</td>
            <td class="mono muted">${(r.duration_ms / 1000).toFixed(1)}s</td></tr>`).join("")}</table>
        </div>
        <div id="runFindings"></div>`;
      window.scrollTo(0, scrollY);
      if (["completed", "failed"].includes(a.status)) {
        loadFindingsInto(body.querySelector("#runFindings"), "", null, a.id);
      }
      schedulePoll(a);
    };
    const schedulePoll = (a) => {
      if (["queued", "running"].includes(a.status)) {
        pollTimer = setTimeout(async () => {
          try { render(await API.get(`/assessments/${id}`)); } catch (_) {}
        }, 2000);
      }
    };
    try { render(await API.get(`/assessments/${id}`)); }
    catch (e) { body.textContent = e.message; }
  }

  async function loadFindingsInto(el, qs, filters, assessmentId) {
    let url = assessmentId ? `/assessments/${assessmentId}/findings` : `/assessments/-/findings?`;
    const rows = await API.get(url);
    const order = Object.fromEntries(SEV_ORDER.map((s, i) => [s, i]));
    const sorted = [...rows].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
    el.innerHTML = `<div class="card"><strong>Findings (${rows.length})</strong>
      ${sorted.length ? `<table class="mt"><tr><th>Severity</th><th>CVSS</th><th>Title</th><th>Category</th><th>Status</th></tr>
      ${sorted.map(f => `
        <tr class="click" onclick="location.hash='#/finding/${f.id}'">
          <td><span class="sev ${f.severity}">${f.severity}</span></td>
          <td class="mono">${f.cvss_score ?? "-"}</td>
          <td>${esc(f.title)}</td>
          <td class="muted small">${f.category.replaceAll("_", " ")}</td>
          <td><span class="status completed">${f.status}</span>${f.retest_status ? `<br><span class="small ${f.retest_status === "FIXED" ? "retest-fixed" : "retest-present"}">${f.retest_status}</span>` : ""}</td>
        </tr>`).join("")}</table>` : `<p class="muted small mt">No findings recorded yet.</p>`}</div>`;
  }

  /* ---------------- global findings ---------------- */
  async function FindingsList() {
    view.innerHTML = `<h1 class="page">Findings</h1><p class="sub">All normalized findings across assessments.</p>
      <div id="flist">Loading…</div>`;
    await loadFindingsInto(view.querySelector("#flist"));
  }

  /* ---------------- finding detail ---------------- */
  async function FindingDetail(id) {
    view.innerHTML = `<div id="fdetail">Loading…</div>`;
    const el = view.querySelector("#fdetail");
const f = await API.get(`/assessments/findings/${id}`);
    const evidence = await API.get(`/assessments/findings/${id}/evidence`);
    el.innerHTML = `
      <div class="finding-head">
        <span class="sev ${f.severity}" style="font-size:13px;padding:6px 12px">${f.severity}</span>
        <div style="flex:1"><h1 class="page" style="font-size:19px">${esc(f.title)}</h1>
          <span class="muted small mono">${f.scanner} · ${f.check_id} · CVSS v3.1 <strong style="color:var(--ink)">${f.cvss_score ?? "-"}</strong></span></div>
        <div>
          ${f.retest_status ? `<div class="small" style="text-align:right">RETEST: <span class="${f.retest_status === "FIXED" ? "retest-fixed" : "retest-present"}">${f.retest_status}</span></div>` : ""}
          <button class="ghost mt tiny danger-del" id="delBtn">🗑 DELETE</button>
          <button class="ghost mt" id="retestBtn" style="margin-top:6px">↻ RETEST</button>
        </div>
      </div>
      <div class="grid two-col mt">
        <dl class="kv card">
          <dt>Affected component</dt><dd class="mono">${esc(f.affected_component)}</dd>
          <dt>Target</dt><dd class="mono">${esc(f.target)}</dd>
          <dt>CVSS vector</dt><dd class="mono">${esc(f.cvss_vector || "-")}</dd>
          <dt>Category</dt><dd>${f.category.replaceAll("_", " ")}</dd>
          <dt>Status</dt><dd>${f.status}${f.retest_count ? ` · retests: ${f.retest_count}` : ""}</dd>
          <dt>Detected</dt><dd>${new Date(f.created_at).toLocaleString()}</dd>
          <dt>Authorized</dt><dd>${f.authorized_target ? "local lab only" : "?"}</dd>
        </dl>
        <div class="card">
          <strong>Severity rationale</strong>
          <p class="small mt">${esc(f.severity_rationale || "Score derived from documented preset vector.")}</p>
          <strong>Business impact</strong>
          <p class="small mt">${esc(f.business_impact)}</p>
        </div>
      </div>
      <div class="grid two-col mt">
        <div class="card"><strong>Description</strong><p class="small">${esc(f.description)}</p>
          <strong>Impact</strong><p class="small">${esc(f.impact)}</p></div>
        <div class="card"><strong>Controlled reproduction (lab only)</strong>
          <ol class="small mt">${(f.reproduction || []).map(r => `<li class="mono">${esc(r)}</li>`).join("")}</ol>
          <strong>Remediation</strong><p class="small">${esc(f.remediation)}</p>
          ${(f.references || []).length ? `<strong>References</strong><ul class="small">${f.references.map(r => `<li class="mono">${esc(r)}</li>`).join("")}</ul>` : ""}
        </div>
      </div>
      <div class="card mt"><strong>Evidence (${evidence.length}) — sensitive values masked</strong>
        ${evidence.map(ev => `
          <details class="mt"><summary class="mono small">${esc(ev.summary)}</summary>
          <pre class="evidence-doc">${esc(JSON.stringify(ev.document, null, 2))}</pre></details>`).join("") ||
          `<p class="muted small mt">No evidence documents attached.</p>`}
      </div>`;
    el.querySelector("#delBtn").onclick = async () => {
      if (!confirm("Delete this finding and its evidence permanently?")) return;
      try {
        await API.del(`/findings/${id}`);
        toast("Finding deleted");
        location.hash = "#/findings";
      } catch (e) { toast(e.message, false); }
    };
    el.querySelector("#retestBtn").onclick = async () => {
      try {
        const r = await API.post(`/assessments/findings/${id}/retest`);
        toast(r.retest_status === "FIXED" ? "✓ Vulnerability FIXED on retest" : "✗ STILL PRESENT", r.retest_status === "FIXED");
        FindingDetail(id);
      } catch (e) { toast(e.message, false); }
    };
  }

  /* ---------------- history ---------------- */
  async function History() {
    const rows = await API.get("/assessments");
    view.innerHTML = `<h1 class="page">Assessment History</h1><p class="sub">Every authorized assessment run against the lab.</p>
      <div class="card"><table><tr><th>Target</th><th>Modules</th><th>Status</th><th>Created</th><th></th></tr>
      ${rows.map(a => `<tr class="click" onclick="location.hash='#/assessment/${a.id}'">
        <td class="mono" style="display:flex;gap:8px;align-items:center">
          ${targetChip(a.target)} ${esc(a.target)}</td>
        <td class="muted small">${a.modules.map(esc).join(", ")}</td>
        <td><span class="status ${a.status}">${a.status}</span></td>
        <td class="muted small">${new Date(a.created_at).toLocaleString()}</td>
        <td>${a.status !== "running" && a.status !== "queued"
          ? `<button class="ghost tiny danger-x" title="delete assessment"
              onclick="History.del('${a.id}',event)">🗑</button>` : ""}</td></tr>`).join("")}</table></div>`;
  }


  History.del = async function (id, ev) {
    ev.stopPropagation();
    if (!confirm("Delete this assessment with ALL its findings, evidence and reports?"))
      return;
    try {
      await API.del(`/assessments/${id}`);
      toast("Assessment deleted");
      History();
    } catch (e) { toast(e.message, false); }
  };

  /* ---------------- reports ---------------- */
  async function Reports() {
    const rows = await API.get("/assessments");
    view.innerHTML = `<h1 class="page">Reports</h1>
      <p class="sub">Generate professional deliverables from any completed assessment.</p>
      <div class="card"><table><tr><th>Target</th><th>Status</th><th>Generate</th><th>Downloads</th><th>Stored files</th></tr>
      ${rows.map(a => `<tr>
        <td class="mono">${esc(a.target)}<br><span class="muted small">${new Date(a.created_at).toLocaleString()}</span></td>
        <td><span class="status ${a.status}">${a.status}</span></td>
        <td>${a.status === "completed" ? ["pdf", "json", "md"].map(fmt =>
          `<button class="ghost" style="margin:2px;padding:5px 10px;font-size:11px"
            onclick="Reports.generate('${a.id}','${fmt}',this)">${fmt.toUpperCase()}</button>`).join("") : ""}</td>
        <td class="small" id="dl-${a.id}"></td>
        <td class="small"><button class="ghost tiny" onclick="Reports.loadStored('${a.id}',this)">list stored</button><div id="stored-${a.id}"></div></td></tr>`).join("")}
      </table></div>
      <p class="muted small mt">Tip: generated files stay in reports/ - use "list stored"
      to fetch links for earlier runs.</p>`;
  }

  Reports.loadStored = async function (aid, btn) {
    const rows = await API.get(`/reports/assessment/${aid}`);
    const cell = document.getElementById(`stored-${aid}`);
    if (!cell) return;
    cell.innerHTML = rows.length ? rows.map(r =>
      `<div class="mono small" style="margin:3px 0;display:flex;gap:8px;align-items:center">
         <a href="#" onclick="Reports.download('${r.download}','${r.format}','${aid}');return false">
           [${r.format.toUpperCase()}]</a>
         <span class="muted">${new Date(r.created_at).toLocaleString()}</span>
         <button class="ghost tiny" style="padding:1px 7px;font-size:10px"
           onclick="Reports.del('${r.id}','${aid}')">🗑</button>
       </div>`).join("") : `<span class="muted">no stored reports yet</span>`;
  };

  Reports.del = async function (rid, aid) {
    if (!confirm("Delete this report file?")) return;
    try {
      await API.del(`/reports/${rid}`);
      toast("Report deleted");
      Reports.loadStored(aid, document.activeElement);
    } catch (e) { toast(e.message, false); }
  };
  Reports.generate = async function (id, fmt, btn) {
    btn.disabled = true;
    try {
      const r = await API.post(`/reports/assessment/${id}?format=${fmt}`);
      const cell = document.getElementById(`dl-${id}`);
      if (cell.textContent === "—") cell.innerHTML = "";
      const a = document.createElement("a");
      a.href = "#";
      a.textContent = `[${fmt}] `;
      a.className = "mono";
      a.onclick = (e) => { e.preventDefault(); Reports.download(r.path, fmt, id); };
      cell.appendChild(a);
      toast(`${fmt.toUpperCase()} report generated`);
    } catch (e) { toast(e.message, false); btn.disabled = false; }
  };
  // authenticated download: plain <a href> cannot send the JWT header
  Reports.download = async function (path, fmt, id) {
    try {
      const res = await fetch(path, { headers: { Authorization: `Bearer ${API.getToken()}` } });
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `worldmonitor_report_${id}.${fmt}`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
      toast(`${fmt.toUpperCase()} downloaded`);
    } catch (e) { toast(`download failed: ${e.message}`, false); }
  };

  /* ---------------- settings ---------------- */
  async function Settings() {
    const [s, sc] = await Promise.all([API.get("/settings"), API.get("/scanners")]);
    view.innerHTML = `<h1 class="page">Settings</h1><p class="sub">Platform configuration (read-only).</p>
      <div class="grid two-col">
        <div class="card"><strong>Environment</strong>
          <dl class="kv mt">
            <dt>Version</dt><dd class="mono">${s.version}</dd>
            <dt>LAB_MODE</dt><dd>${s.lab_mode ? "<span class='pill lab'>ENABLED — localhost only</span>" : "disabled"}</dd>
            <dt>Lab app</dt><dd class="mono">${s.lab_url}</dd>
            <dt>Lab source</dt><dd class="mono small">${esc(s.lab_source_dir)}</dd>
            <dt>Evidence dir</dt><dd class="mono small">${esc(s.evidence_dir)}</dd>
            <dt>Report dir</dt><dd class="mono small">${esc(s.report_dir)}</dd>
            <dt>portia binary</dt><dd>${s.binaries_present.portia ? "✔ present" : "✘ missing — run scripts/build_go_tools.ps1"}</dd>
            <dt>bomber binary</dt><dd>${s.binaries_present.bomber ? "✔ present" : "✘ missing — run scripts/build_go_tools.ps1"}</dd>
          </dl>
        </div>
        <div class="card"><strong>Scanner modules</strong>
          <table class="mt">${sc.modules.map(m => `<tr><td class="mono">${m.key}</td>
            <td class="muted small">${m.label}</td><td>${m.needs}</td></tr>`).join("")}</table>
        </div>
      </div>
      <div class="card mt"><strong>Safety model</strong>
        <p class="small mt muted">Scans are refused unless (1) the operator confirms authorization, and (2) the target passes
        the gate: loopback/RFC1918 resolution or an explicit ALLOWED_TARGETS entry. Filesystem scanners are jailed to the
        lab tree. Evidence masks tokens, cookies, keys before storage. All actions are audit-logged.</p></div>`;
  }

  window.Reports = Reports;

  document.getElementById("logout").onclick = () => { API.setToken(null); location.hash = "#/login"; };
  window.addEventListener("hashchange", router);
  if (!location.hash) location.hash = "#/dashboard";
  router();
})();
