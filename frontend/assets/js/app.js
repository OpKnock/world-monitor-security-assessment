/* World Monitor SPA — premium rewrite v2. Hardened, audited, accessibility & performance tuned. */
(() => {
  "use strict";

  const $view = document.getElementById("view");
  const $sidebar = document.getElementById("sidebar");
  const $topbar = document.getElementById("topbar");
  const $footer = document.getElementById("appFooter");
  const $banner = document.getElementById("runBanner");
  const $scrim = document.getElementById("scrim");
  const $menuBtn = document.getElementById("menuBtn");
  const $themeToggle = document.getElementById("themeToggle");
  const $crumb = document.getElementById("breadcrumb");

  const SEV = ["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"];
  const SEV_ORDER = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFORMATIONAL:4 };
  const SEV_COLOR = { CRITICAL:"#f43f5e", HIGH:"#fb923c", MEDIUM:"#fbbf24", LOW:"#38bdf8", INFORMATIONAL:"#94a3b8" };
  const healthColor = s => s>=80 ? "#22c55e" : s>=60 ? "#84cc16" : s>=40 ? "#f59e0b" : s>=20 ? "#f97316" : "#ef4444";
  const HEALTH_WEIGHTS = {CRITICAL:5,HIGH:3,MEDIUM:1.5,LOW:0.5,INFORMATIONAL:0};
  const computeHealth = c => Math.max(0, Math.min(100, Math.round(100 - ( (c.CRITICAL||0)*5 + (c.HIGH||0)*3 + (c.MEDIUM||0)*1.5 + (c.LOW||0)*0.5 ))));
  const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
  const truncate = (s, n=48) => s.length>n ? s.slice(0,n)+"…" : s;
  let pollId = null, bannerTimer = null;

  /* ── utils ── */
  function debounce(fn, ms=300){ let t; return (...a)=>{ clearTimeout(t); t=setTimeout(()=>fn(...a), ms); }; }
  async function copyText(t){ try{ await navigator.clipboard.writeText(t); toast("Copied to clipboard"); }catch{ toast("Copy failed", false); } }

  /* ── mobile nav ── */
  function openNav(){ $sidebar.classList.add("open"); $scrim.classList.remove("hidden"); $menuBtn.setAttribute("aria-expanded","true"); document.body.style.overflow="hidden"; }
  function closeNav(){ $sidebar.classList.remove("open"); $scrim.classList.add("hidden"); $menuBtn.setAttribute("aria-expanded","false"); document.body.style.overflow=""; }
  $menuBtn.addEventListener("click", ()=> $sidebar.classList.contains("open") ? closeNav() : openNav());
  $scrim.addEventListener("click", closeNav);
  document.addEventListener("keydown", e=>{ if(e.key==="Escape" && $sidebar.classList.contains("open")) closeNav(); });

  /* ── dock auto-hide like Mac ── */
  const dockTrigger = document.getElementById("dockTrigger");
  const dockEl = document.getElementById("sidebar");
  if(dockEl && dockTrigger){
    let dockTimeout;
    const openDock = ()=> dockEl.classList.add("dock-open");
    const closeDock = ()=> { clearTimeout(dockTimeout); dockTimeout = setTimeout(()=> dockEl.classList.remove("dock-open"), 300); };
    dockTrigger.addEventListener("mouseenter", openDock);
    dockEl.addEventListener("mouseenter", ()=> { clearTimeout(dockTimeout); dockEl.classList.add("dock-open"); });
    dockEl.addEventListener("mouseleave", closeDock);
    dockTrigger.addEventListener("mouseleave", ()=> { if(!dockEl.matches(":hover")) closeDock(); });
    document.addEventListener("mousemove", (e)=>{
      try{
        if(e.clientX < 16 && window.API && API.getToken()) openDock();
        else if(e.clientX > 240) dockEl.classList.remove("dock-open");
      }catch(_){}
    });
  }

  /* ── theme toggle ── */
  function initTheme(){
    const saved = localStorage.getItem("wm_theme");
    if(saved){ document.documentElement.setAttribute("data-theme", saved); }
    else if(window.matchMedia("(prefers-color-scheme: dark)").matches && !localStorage.getItem("wm_theme")){ document.documentElement.setAttribute("data-theme", "dark"); }
    updateThemeIcon();
  }
  function updateThemeIcon(){
    if(!$themeToggle) return;
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    $themeToggle.innerHTML = isDark ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>` : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`;
  }
  if($themeToggle){
    $themeToggle.addEventListener("click", ()=>{
      const isDark = document.documentElement.getAttribute("data-theme") === "dark";
      const next = isDark ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("wm_theme", next);
      updateThemeIcon();
    });
  }
  initTheme();

  /* ── toast ── */
  function toast(msg, ok=true){
    const el = document.createElement("div");
    el.className = "toast-item" + (ok ? "" : " bad");
    el.setAttribute("role","status");
    const icon = document.createElement("span");
    icon.className="toast-icon"; icon.setAttribute("aria-hidden","true"); icon.textContent= ok ? "✓" : "✕";
    const txt = document.createElement("span"); txt.textContent= String(msg);
    el.append(icon, txt);
    document.getElementById("toast").appendChild(el);
    setTimeout(()=> { el.style.opacity="0"; el.style.transform="translateX(12px)"; setTimeout(()=> el.remove(), 220); }, 4200);
  }

  function stopPoll(){ if(pollId){ clearTimeout(pollId); pollId=null; } }
  function stopBanner(){ if(bannerTimer){ clearInterval(bannerTimer); bannerTimer=null; } $banner.style.display="none"; }
  function rememberRun(id){ try{ localStorage.setItem("wm_active", id); }catch{} }
  function forgetRun(){ try{ localStorage.removeItem("wm_active"); }catch{} }

  /* ── breadcrumb ── */
  function setBreadcrumb(parts){
    if(!parts || !parts.length){ $crumb.innerHTML=""; return; }
    const frag=document.createDocumentFragment();
    parts.forEach((p,i)=>{
      const last=i===parts.length-1;
      if(last){
        const s=document.createElement("span"); s.className="cur"; s.textContent=p.label; frag.appendChild(s);
      } else {
        const a=document.createElement("a"); a.href=p.href; a.textContent=p.label; frag.appendChild(a);
        const sep=document.createElement("span"); sep.className="sep"; sep.textContent="›"; frag.appendChild(sep);
      }
    });
    $crumb.replaceChildren(frag);
  }

  /* ── health check (for footer version) ── */
  async function refreshHealth(){
    try{
      const controller = new AbortController();
      const t=setTimeout(()=>controller.abort(), 4000);
      const h = await fetch("/api/health", { signal: controller.signal }).then(r=> r.json());
      clearTimeout(t);
      const fv = document.getElementById("footerVer");
      if(fv && h.version) fv.textContent = "v" + h.version;
    }catch{
      // silent fail
    }
  }

  /* ── active-run banner ── */
  function showBanner(){
    let id; try{ id=localStorage.getItem("wm_active"); }catch{ id=null; }
    if(!id || location.hash===`#/assessment/${id}` || !API.getToken()){ stopBanner(); return; }
    API.get(`/assessments/${id}`).then(a=>{
        if(!a || a.status==="completed" || a.status==="failed"){ stopBanner(); forgetRun(); return; }
        $banner.style.display="flex";
        $banner.replaceChildren();
        const st=document.createElement("span"); st.className=`status ${a.status}`; st.textContent=a.status;
        const tgt=document.createElement("span"); tgt.className="mono small"; tgt.textContent=truncate(String(a.target), 56); tgt.title=String(a.target);
        const viewBtn=document.createElement("button"); viewBtn.className="tiny"; viewBtn.textContent="VIEW PROGRESS →"; viewBtn.onclick=()=> location.hash=`#/assessment/${id}`;
        const dismiss=document.createElement("button"); dismiss.className="ghost xs"; dismiss.textContent="✕"; dismiss.title="Dismiss"; dismiss.onclick=()=>{ forgetRun(); $banner.style.display="none"; if(bannerTimer){ clearInterval(bannerTimer); bannerTimer=null; } };
        $banner.append(st, tgt, viewBtn, dismiss);
      }).catch(()=>{});
    if(!bannerTimer) bannerTimer=setInterval(showBanner, 6000);
  }

  /* ── user chip ── */
  function loadUserChip(){
    API.get("/auth/me").then(u=>{
      const chip=document.getElementById("userChip");
      if(!chip) return;
      const av=chip.querySelector(".avatar");
      const whoB=chip.querySelector(".who b");
      const whoS=chip.querySelector(".who span");
      if(av) av.textContent = (u.email||"?")[0].toUpperCase();
      if(whoB) whoB.textContent = u.email;
      if(whoS) whoS.textContent = (u.role||"").toUpperCase();
    }).catch(()=>{});
  }

  /* ── skeletons / empty / error ── */
  function skeletonKpis(){
    return `<div class="grid kpis">${SEV.map(()=> `<div class="skeleton sk-kpi" aria-hidden="true"></div>`).join("")}</div>`;
  }
  function skeletonTable(rows=4){
    return `<div class="skeleton-wrap" aria-hidden="true">${Array.from({length:rows},()=> `<div class="skeleton sk-table-row"></div>`).join("")}</div>`;
  }
  function skeletonCards(n=2){
    return `<div class="grid two-col">${Array.from({length:n},()=> `<div class="skeleton sk-card" aria-hidden="true"></div>`).join("")}</div>`;
  }
  function emptyState({icon="◈", title="Nothing here yet", hint="", action=""}){
    const act = action ? `<div class="mt">${action}</div>` : "";
    return `<div class="empty" role="status">
      <div class="empty-ill" aria-hidden="true">${esc(icon)}</div>
      <h3>${esc(title)}</h3>
      <p>${esc(hint)}</p>
      ${act}
    </div>`;
  }
  function errorState(msg, onRetry){
    const id="retry-"+Math.random().toString(36).slice(2,7);
    setTimeout(()=>{
      const b=document.getElementById(id);
      if(b && onRetry) b.addEventListener("click", onRetry);
    },0);
    return `<div class="error-state" role="alert">
      <h3>Something went wrong</h3>
      <p>${esc(msg)}</p>
      <button id="${id}" class="ghost tiny">↻ Try again</button>
    </div>`;
  }

  /* ── auth ── */
  function AuthScreen(mode="login"){
    stopPoll(); stopBanner();
    // Clear any stale token
    API.setToken(null);
    $sidebar.classList.add("hidden");
    $topbar.classList.add("hidden");
    $footer.classList.add("hidden");
    $view.setAttribute("aria-busy","false");
    const isLogin = mode==="login";
    $view.innerHTML = `
      <div class="min-h-[70vh] flex items-center justify-center p-6 bg-paper">
        <div class="auth-simple w-full max-w-md" style="animation:fadeUp .6s var(--ease-soft) both">
          <div class="text-center mb-7">
            <div class="w-logo">W</div>
            <div class="font-display text-xl mt-3 tracking-tight text-ink">World Monitor</div>
            <div class="meta-mono" style="font-size:10px;margin-top:4px">Security Assessment Platform</div>
            <h1 class="font-display text-2xl font-semibold tracking-tight text-ink mt-5">${isLogin ? "Welcome back" : "Create your account"}</h1>
            <p class="text-ash text-sm mt-2">${isLogin ? "Sign in to your security workspace." : "Analyst accounts can run assessments."}</p>
          </div>
          <form id="authForm" novalidate class="space-y-4">
            <div class="field"><label for="email" class="meta-mono">Email</label><input id="email" type="email" name="email" required autocomplete="username" placeholder="you@company.com" aria-describedby="emailHelp"></div>
            <div class="field"><label for="password" class="meta-mono">Password</label><input id="password" type="password" name="password" required minlength="${isLogin?1:12}" autocomplete="${isLogin?"current-password":"new-password"}" placeholder="${isLogin?"••••••••":"min 12 characters"}" aria-describedby="pwHelp"><div id="pwHelp" class="help" aria-live="polite"></div></div>
            <button class="w-full bg-ink text-paper hover:bg-ink/90 transition-colors py-3 font-medium" type="submit">${isLogin ? "Sign in" : "Create account"}</button>
            <div class="err" id="authErr" role="alert" aria-live="polite"></div>
          </form>
          <p class="meta-mono text-center mt-6" style="font-size:10px;color:hsl(var(--ash)/0.6)">Secure workspace — authorized assessment only</p>
        </div>
      </div>`;
    const tgAuth = document.getElementById("tgAuth"); if (tgAuth) tgAuth.onclick = e=>{ e.preventDefault(); AuthScreen(isLogin ? "register" : "login"); };
    const form=document.getElementById("authForm");
    const pwInput=document.getElementById("password");
    const pwHelp=document.getElementById("pwHelp");
    if(!isLogin && pwInput){
      pwInput.addEventListener("input", ()=>{
        const v=pwInput.value;
        let msg="";
        if(!v) msg="";
        else if(v.length<12) msg=`Too short — ${12 - v.length} more chars needed`;
        else if(!/[A-Z]/.test(v) || !/[0-9]/.test(v)) msg="Tip: include uppercase + number for stronger password";
        else msg="✓ Length OK";
        pwHelp.textContent=msg;
        pwHelp.style.color = v.length>=12 ? "var(--ok)" : "var(--text-3)";
      });
    }
    form.onsubmit = async e=>{
      e.preventDefault();
      const errBox=document.getElementById("authErr");
      errBox.textContent="";
      const emailVal=form.querySelector("#email").value.trim();
      const pwVal=form.querySelector("#password").value;
      if(!emailVal || !emailVal.includes("@")){ errBox.textContent="Enter a valid email address."; return; }
      if(!isLogin && pwVal.length<12){ errBox.textContent="Password must be at least 12 characters."; return; }
      const btn=form.querySelector('button[type="submit"]');
      const orig=btn.innerHTML; btn.disabled=true; btn.innerHTML=`<span class="spinner" aria-hidden="true"></span> ${isLogin?"Signing in…":"Creating…"}`;
      try{
        const data=await API.post(isLogin?"/auth/login":"/auth/register",{ email:emailVal, password:pwVal });
        API.setToken(data.access_token);
        toast(isLogin ? "Welcome back" : "Account created — signed in");
        loadUserChip();
        if(location.hash==="#/welcome") router(); else location.hash="#/welcome";
      }catch(err){
        const msg = String(err.message||"Request failed");
        // map common server messages to friendlier text
        if(/rate_limited/i.test(msg)) errBox.textContent="Too many attempts — wait 60s and retry.";
        else if(/401|invalid/i.test(msg)) errBox.textContent="Invalid email or password.";
        else errBox.textContent=msg;
        btn.disabled=false; btn.innerHTML=orig;
      }
    };
    // focus email for accessibility
    setTimeout(()=> document.getElementById("email")?.focus(), 0);
  }

  /* ── router ── */
  const ROUTES = {
    "#/welcome": Welcome,
    "#/dashboard": Dashboard,
    "#/assess/new": NewAssessment,
    "#/findings": FindingsList,
    "#/history": History,
    "#/reports": Reports,
    "#/settings": Settings,
  };
  function setActiveNav(){
    document.querySelectorAll("[data-nav]").forEach(a=>{
      const href=a.getAttribute("href");
      const isActive = href && (location.hash===href || (href!=="#/dashboard" && location.hash.startsWith(href)));
      a.classList.toggle("active", !!isActive);
      if(isActive) a.setAttribute("aria-current","page"); else a.removeAttribute("aria-current");
    });
  }
  async function router(){
    stopPoll(); closeNav();
    const rawH=location.hash || "";
    const hasToken = !!API.getToken();
    // header always visible — toggle login/commission
    const hc = document.getElementById("headerCommissionBtn");
    const hl = document.getElementById("headerLoginBtn");
    const uc = document.getElementById("userChip");
    const ml = document.getElementById("mobileLoginBtn");
    const lo = document.getElementById("logout");
    const um = document.getElementById("userChipMobile");
    if(hc) hc.classList.toggle("hidden", !hasToken);
    if(hl) hl.classList.toggle("hidden", hasToken);
    if(uc) uc.classList.toggle("hidden", !hasToken);
    if(ml) ml.classList.toggle("hidden", hasToken);
    if(lo) lo.classList.toggle("hidden", !hasToken);
    if(um) um.classList.toggle("hidden", !hasToken);
    if(!hasToken){
      $sidebar.classList.add("hidden");
      $topbar.classList.add("hidden");
      $footer.classList.add("hidden");
      setActiveNav();
      const wantRegister = rawH==="#/register" || rawH==="#/assess/new";
      AuthScreen(wantRegister && rawH==="#/register" ? "register" : "login");
      if(wantRegister && rawH==="#/assess/new") toast("Please sign in to create assessments", false);
      return;
    }
    $sidebar.classList.remove("hidden");
    $topbar.classList.remove("hidden");
    $footer.classList.remove("hidden");
    const h = rawH || "#/welcome";
    // Welcome + Home have their own editorial meta row — hide breadcrumb bar to save upper space
    if(h==="#/welcome"||h==="#/dashboard"||h==="") { if($topbar) $topbar.style.display="none"; }
    else { if($topbar) $topbar.style.display=""; }
    setActiveNav();
    loadUserChip();
    refreshHealth();
    showBanner();
    $view.setAttribute("aria-busy","true");
    try{
      if(ROUTES[h]) await ROUTES[h]();
      else if(h.startsWith("#/assessment/")) await AssessmentDetail(h.split("/")[2]);
      else if(h.startsWith("#/finding/")) await FindingDetail(h.split("/")[2]);
      else await Welcome();
    }catch(e){
      $view.innerHTML = `<div class="card">${errorState(e.message || "Failed to load view", router)}</div>`;
    }finally{
      $view.setAttribute("aria-busy","false");
    }
  }

  /* ═══════════ WELCOME — platform editorial, distinct from lab, animated 3D star+orbit, no Tailwind ═══════════ */
  function Welcome(){
    const today = new Date().toLocaleDateString("en-GB",{day:"2-digit",month:"long",year:"numeric"}).toUpperCase();
    setBreadcrumb([]);
    if($topbar) $topbar.style.display="none";
    $view.innerHTML = `
      <div style="background:hsl(var(--paper));color:hsl(var(--ink))">
        <div class="container-editorial" style="padding-top:24px">
          <div style="display:grid;grid-template-columns:repeat(12,1fr);gap:16px;border-bottom:1px solid hsl(var(--ink)/0.15);padding-bottom:12px" class="meta-mono">
            <span style="grid-column:span 4;color:hsl(var(--ink));font-weight:700;letter-spacing:-0.01em">World Monitor Security Assessment</span>
            <span style="grid-column:span 2;color:hsl(var(--ink)/0.7)">Assessment Vol. I</span>
            <span style="grid-column:span 3;color:hsl(var(--ink)/0.7)">Scan · Score · Secure</span>
            <span style="grid-column:span 3;text-align:right;color:hsl(var(--ink))">${esc(today)}</span>
          </div>
        </div>
        <div class="container-editorial" style="padding-top:44px;padding-bottom:36px">
          <div style="display:grid;grid-template-columns:repeat(12,1fr);gap:40px">
            <div style="grid-column:span 7;display:flex;flex-direction:column;gap:26px">
              <div style="display:flex;align-items:center;gap:16px;animation:fadeUp .6s var(--ease-soft) both">
                <span class="meta-mono">Security Assessment Platform</span>
                <span style="display:block;height:1px;width:40px;background:hsl(var(--ink)/0.4)"></span>
                <span class="label-eyebrow">scan · score · secure</span>
              </div>
              <h1 class="font-display" style="font-size:clamp(2.6rem,6.5vw,5rem);line-height:0.94;letter-spacing:-0.04em;margin:0;animation:fadeUp .85s var(--ease-soft) .08s both">See your <span class="display-italic" style="color:hsl(var(--oxblood))">exposure.</span><br>Prove your <span class="display-italic" style="color:hsl(var(--ink)/0.85)">security.</span></h1>
              <p style="max-width:520px;color:hsl(var(--ash));font-size:15px;line-height:1.7;margin:0;animation:fadeUp .6s var(--ease-soft) .14s both">World Monitor Security Assessment runs <strong style="color:hsl(var(--ink))">authorized scans</strong>, scores every finding with CVSS 3.1, and gates releases <strong style="color:hsl(var(--ink))">fail-closed</strong> — BLOCKED until health, findings and evidence pass.</p>
              <div class="card" style="max-width:560px;background:hsl(var(--card));animation:fadeUp .6s var(--ease-soft) .16s both">
                <div class="label-eyebrow" style="margin-bottom:10px">What is this · How to use</div>
                <div style="display:grid;gap:10px;font-size:13.5px;line-height:1.65;color:hsl(var(--ash))">
                  <div><strong style="color:hsl(var(--ink))">What:</strong> 12 scanners (auth, IDOR, headers, TLS, secrets, SBOM, supply-chain…) → normalized findings with masked evidence + retest proof.</div>
                  <div><strong style="color:hsl(var(--ink))">How:</strong> 1) Start New Assessment on 127.0.0.1:3000 / :8080 or source → 2) watch live → 3) triage Findings → 4) export Report → 5) Retest to FIXED.</div>
                  <div class="meta-mono" style="font-size:10px">Authorized targets only · loopback gate · fully audited</div>
                </div>
              </div>
              <div style="display:flex;gap:12px;flex-wrap:wrap;animation:fadeUp .6s var(--ease-soft) .20s both">
                <a href="#/dashboard" class="btn-primary" style="text-decoration:none">Enter Home →</a>
                <a href="#/assess/new" class="btn-ghost" style="text-decoration:none">＋ New Assessment</a>
              </div>
              <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;padding-top:16px;border-top:1px solid hsl(var(--ink)/0.1);max-width:560px;animation:fadeUp .6s var(--ease-soft) .26s both" class="meta-mono">
                <div><div style="font-family:var(--display);font-size:24px;color:hsl(var(--ink))">12</div>Security scanners</div>
                <div><div style="font-family:var(--display);font-size:24px;color:hsl(var(--ink))">46</div>Checks passing</div>
                <div><div style="font-family:var(--display);font-size:24px;color:hsl(var(--ink))">${new Date().getFullYear()}</div>Live assessments</div>
              </div>
            </div>
            <div style="grid-column:span 5">
              <div class="reveal grain" style="aspect-ratio:3/4;background:radial-gradient(120% 100% at 50% 0%, hsl(var(--ink)) 40%, #1a1a1e 100%);color:hsl(var(--paper));position:relative;overflow:hidden;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px;text-align:center">
                <div class="wm-float" style="position:relative;width:230px;height:230px;display:grid;place-items:center;margin-bottom:18px">
                  <div class="wm-orbit-ring" style="inset:0;width:230px;height:230px"><span class="wm-orbit-dot"></span></div>
                  <div class="wm-orbit-ring dashed" style="inset:28px;width:174px;height:174px;margin:28px"><span class="wm-orbit-dot" style="width:6px;height:6px;background:hsl(var(--oxblood));margin-left:-3px"></span></div>
                  <div class="wm-pulse" style="width:118px;height:118px;border-radius:50%;background:hsl(var(--paper)/0.06);border:1px solid hsl(var(--paper)/0.22);display:grid;place-items:center">
                    <svg width="72" height="72" viewBox="0 0 100 100" fill="none"><g fill="hsl(var(--paper))"><path d="M50 8 L57 28 L77 28 L60 40 L67 62 L50 52 L33 62 L40 40 L23 28 L43 28 Z" stroke="hsl(var(--paper))" stroke-width="2" stroke-linejoin="round"/><path d="M18 58 C28 75, 50 88, 78 58 L82 62 C52 92, 22 80, 16 60 Z"/><path d="M78 58 C70 40, 48 18, 22 32 L18 28 C50 12, 78 36, 82 58 Z" opacity="0.85"/></g></svg>
                  </div>
                </div>
                <div class="label-eyebrow" style="color:hsl(var(--paper)/0.7);animation:fadeUp .6s var(--ease-soft) .35s both">World Monitor · Live</div>
                <div class="font-display" style="font-size:22px;color:hsl(var(--paper));margin-top:8px;line-height:1.3;animation:fadeUp .6s var(--ease-soft) .4s both">Scan. Score.<br><span class="display-italic" style="color:hsl(var(--paper)/0.85)">Secure.</span></div>
                <div class="meta-mono" style="color:hsl(var(--paper)/0.5);margin-top:14px;animation:fadeUp .6s var(--ease-soft) .45s both">FAIL-CLOSED · EVIDENCE-BACKED</div>
                <div style="position:absolute;bottom:0;left:0;right:0;padding:12px 16px;border-top:1px solid hsl(var(--paper)/0.1);display:flex;justify-content:space-between" class="meta-mono"><span>Security Assessment</span><span>Platform</span></div>
              </div>
            </div>
          </div>
        </div>
        <div class="container-editorial"><div class="editorial-rule" style="margin-bottom:24px"></div></div>
        <div class="container-editorial" style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;padding-bottom:32px">
          <div class="card"><div class="label-eyebrow" style="margin-bottom:10px">01 — Scan</div><p style="font-size:13px;color:hsl(var(--ash));line-height:1.65;margin:0">Authorized scans on loopback / source — rate-limit, TLS, secrets, SBOM, supply-chain with DNS pinning and jailed files.</p></div>
          <div class="card"><div class="label-eyebrow" style="margin-bottom:10px">02 — Score</div><p style="font-size:13px;color:hsl(var(--ash));line-height:1.65;margin:0">CVSS 3.1 + fingerprint + masked evidence. Health 0–100, release gate BLOCKED / APPROVED with reasons.</p></div>
          <div class="card"><div class="label-eyebrow" style="margin-bottom:10px">03 — Secure</div><p style="font-size:13px;color:hsl(var(--ash));line-height:1.65;margin:0">Export PDF / JSON / MD / CSV, remediate, then Retest until FIXED. Every step audited.</p></div>
        </div>
      </div>`;
    const st=document.createElement("style"); st.textContent="@media(max-width:900px){.container-editorial div[style*='grid-column:span 7'],.container-editorial div[style*='grid-column:span 5']{grid-column:span 12 !important}}"; $view.appendChild(st);
  }

/* ═══════════ DASHBOARD (Home) — single screen, one compact meta row, history scroll only ═══════════ */
  async function Dashboard(){
    const today = new Date().toLocaleDateString("en-GB",{day:"2-digit",month:"long",year:"numeric"}).toUpperCase();
    setBreadcrumb([]);
    if($topbar) $topbar.style.display="none";
    $view.innerHTML = `
      <div id="dashBody" style="background:hsl(var(--paper))">
        <div class="container-editorial" style="padding-top:16px">
          <div style="display:grid;grid-template-columns:repeat(12,1fr);gap:12px;border-bottom:1px solid hsl(var(--ink)/0.15);padding-bottom:10px;align-items:baseline" class="meta-mono">
            <span style="grid-column:span 3;color:hsl(var(--ink));font-weight:700;font-size:11px">Home — Dashboard</span>
            <span style="grid-column:span 6;color:hsl(var(--ink)/0.6);font-size:10px">health · ranking · history</span>
            <span style="grid-column:span 3;text-align:right;color:hsl(var(--ink));font-size:10px">${esc(today)}</span>
          </div>
        </div>
        <div class="container-editorial" style="padding-top:16px;padding-bottom:16px;display:flex;flex-direction:column;gap:14px">
          <div id="metricsGrid" style="display:grid;grid-template-columns:1fr 1fr;gap:14px">${skeletonCards(2)}</div>
          <div id="kpiGrid" class="kpis" style="margin:0">${skeletonKpis()}</div>
          <div id="dashCards" class="dash-cards grid" style="margin:0"><div class="skeleton sk-card"></div><div class="skeleton sk-card"></div></div>
        </div>
      </div>`;
    const el=$view.querySelector("#dashBody");
    let d;
    try{ d=await API.get("/dashboard"); }
    catch(e){ el.innerHTML = errorState(e.message, Dashboard); return; }

    const total=d.total_findings||0;
    const counts=d.severity_counts||{};
    const categories=d.categories||{};
    const recent=d.recent_assessments||[];
    const health = d.health || {score: computeHealth(counts), penalty: 0, weights: HEALTH_WEIGHTS};
    const recentHealth = d.recent_health || [];
    const retestSummary = d.retest_summary || {};
    const healthCol = healthColor(health.score);
    const healthMap = Object.fromEntries((recentHealth||[]).map(h=>[h.id, h.score]));
    const healthLabel = health.score>=80 ? "Healthy" : health.score>=60 ? "Needs attention" : health.score>=40 ? "At risk" : health.score>=20 ? "Critical" : "Severe";
    const kpis = SEV.map(s=>{
      const n=counts[s]??0;
      const cls=s.toLowerCase().slice(0,6);
      const sub = total ? `${Math.round((n/total)*100)}% of findings` : "—";
      return `<div class="kpi ${cls}" role="status" aria-label="${s} ${n}"><b>${n}</b><small>${s}</small><span class="kpi-sub">${sub}</span></div>`;
    }).join("");
    const heroKpi = `<div class="kpi total" role="status" aria-label="Total findings ${total}"><b>${total}</b><small>TOTAL FINDINGS</small><span class="kpi-sub">${recent.length} recent assessments</span></div>`;
    
    const healthCard = `<div class="card health-hero">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px">
        <div style="flex:1;min-width:0">
          <div class="meta-mono" style="font-size:10px;letter-spacing:0.12em;color:hsl(var(--ash));margin-bottom:8px">SECURITY HEALTH</div>
          <div style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap">
            <span class="health-number">${health.score}</span>
            <span style="font-size:16px;color:hsl(var(--ash));font-weight:500">/100</span>
            <span class="badge" style="background:${healthCol};color:#fff;border-color:${healthCol};font-size:10px;padding:4px 10px">${healthLabel}</span>
          </div>
          <div class="meta-mono" style="font-size:10px;color:hsl(var(--ash));margin-top:6px">Penalty ${health.penalty} · ${total} findings</div>
        </div>
      </div>
      <div class="health-bar" style="margin-top:16px"><div class="health-fill" style="width:${health.score}%;background:${healthCol}"></div></div>
      ${recentHealth.length>=2 ? `<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:12px;padding:8px 12px;background:hsl(var(--bone)/0.6);border:1px solid hsl(var(--border));border-radius:6px">
        <span class="meta-mono" style="font-size:10px">Before/after (last 2):</span>
        <span class="mono" style="font-size:12px;font-weight:700;color:hsl(var(--ink))">${recentHealth[1].score} → ${recentHealth[0].score}</span>
        <span class="badge" style="background:${healthColor(recentHealth[0].score)};color:#fff;font-size:10px">${recentHealth[0].score - recentHealth[1].score >=0 ? "+" : ""}${recentHealth[0].score - recentHealth[1].score} pts</span>
        <span class="muted" style="font-size:11px">${recentHealth[0].score>recentHealth[1].score?"Improved":"Stable"}</span>
      </div>` : ""}
    </div>`;
    
    const releaseRisk = d.release_risk || {score: 0, status: "PENDING", reason: "No data", health: 0, has_incomplete: false, has_failed: false, policy: {}};
    const gate = d.gate || {status: releaseRisk.status, reason: releaseRisk.reason};
    const riskScore = releaseRisk.score || 0;
    const riskStatus = gate.status || "PENDING";
    const riskReason = gate.reason || releaseRisk.reason || "—";
    const riskHealth = releaseRisk.health || health.score;
    const riskHasIncomplete = releaseRisk.has_incomplete || false;
    const riskHasFailed = releaseRisk.has_failed || false;
    const riskColor = riskStatus === "BLOCKED" ? "hsl(var(--destructive))" : riskStatus === "APPROVED" ? "hsl(142 70% 35%)" : "hsl(var(--ash))";
    const riskLabel = riskStatus === "BLOCKED" ? "BLOCKED" : riskStatus === "APPROVED" ? "APPROVED" : "PENDING";
    const policy = releaseRisk.policy || {};

    const releaseHero = `<div class="card release-hero" style="border-color:${riskStatus==="BLOCKED" ? "hsl(var(--destructive)/0.25)" : riskStatus==="APPROVED" ? "hsl(142 70% 35% /0.22)" : "hsl(var(--border))"}">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px">
        <div style="flex:1;min-width:0">
          <div class="meta-mono" style="font-size:10px;letter-spacing:0.12em;color:hsl(var(--ash));margin-bottom:8px">RELEASE SECURITY GATE</div>
          <div style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap">
            <span class="health-number">${riskScore}</span>
            <span style="font-size:16px;color:hsl(var(--ash));font-weight:500">/100</span>
            <span class="badge" style="background:${riskColor};color:#fff;border-color:${riskColor};font-size:10px;padding:4px 10px">${riskLabel}</span>
          </div>
          <div class="meta-mono" style="font-size:10px;color:hsl(var(--ash));margin-top:6px">Health ${riskHealth}/100${riskHasIncomplete ? " · INCOMPLETE" : ""}${riskHasFailed ? " · FAILED" : ""}</div>
        </div>
      </div>
      <div class="health-bar" style="margin-top:16px"><div class="health-fill" style="width:${riskScore}%;background:${riskColor}"></div></div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:12px;align-items:center">
        <span class="meta-mono" style="font-size:10px">Policy:</span>
        ${Object.entries(policy).length ? Object.entries(policy).map(([k,v])=>`<span class="badge" style="background:hsl(var(--paper));border:1px solid hsl(var(--border));color:hsl(var(--ink));font-size:10px">${esc(k)}: ${esc(String(v))}</span>`).join("") : `<span class="muted" style="font-size:11px">—</span>`}
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;align-items:center">
        <span class="meta-mono" style="font-size:10px">Reasons:</span>
        ${riskReason.split("; ").map(r=>`<span class="badge" style="background:hsl(var(--paper));border:1px solid hsl(var(--border));color:hsl(var(--ink));font-size:10px">${esc(r.trim())}</span>`).join("")}
      </div>
    </div>`;

    const metricsGrid = document.getElementById("metricsGrid");
    if(metricsGrid) metricsGrid.innerHTML = healthCard + releaseHero;

    const kpiGrid = document.getElementById("kpiGrid");
    if(kpiGrid) kpiGrid.innerHTML = heroKpi + kpis;

    const dashCards = document.getElementById("dashCards");
    if(dashCards) dashCards.innerHTML = `
      <div class="card"><div class="row spread"><strong style="font-size:13px">Distribution</strong><span class="badge" style="font-size:10px">${total} total</span></div>
        <div class="row mt" style="justify-content:center;min-height:160px">${Charts.donut(counts)}</div>
        <div class="row mt" style="gap:8px;flex-wrap:wrap;justify-content:center">
          ${SEV.map(s=> `<span style="display:inline-flex;align-items:center;gap:6px;font-size:11px;color:hsl(var(--ash))"><i style="width:8px;height:8px;border-radius:50%;background:${SEV_COLOR[s]};display:inline-block" aria-hidden="true"></i>${esc(s)} <strong style="color:hsl(var(--ink))">${counts[s]??0}</strong></span>`).join("")}
        </div>
      </div>
      <div class="card"><div class="row spread"><strong style="font-size:13px">Posture by category</strong><span class="muted" style="font-size:11px">${Object.keys(categories).length} categories</span></div><div class="mt" style="display:flex;flex-direction:column;gap:4px">${Charts.catBars(categories)}</div></div>
      <div class="card" style="display:flex;flex-direction:column"><div class="row spread"><strong style="font-size:13px">New Assessment</strong><span class="meta-mono" style="font-size:10px">Start a new scan</span></div><p class="muted small mt" style="font-size:12px;line-height:1.5">Authorized scan on loopback or source tree. Evidence masked, files jailed, DNS pinned.</p><div style="margin-top:auto;padding-top:14px"><button onclick="location.hash='#/assess/new'" style="width:100%;padding:11px;font-size:13.5px">＋ Start New Scan →</button></div></div>
      <div class="card"><div class="row spread"><strong style="font-size:13px">History</strong><button class="ghost tiny" onclick="location.hash='#/history'" style="font-size:11px">View all →</button></div><div class="history-preview mt-3" style="display:flex;flex-direction:column;gap:8px">
        ${recent.length ? recent.slice(0,5).map(a=> `<div class="flex items-center gap-3 p-3 bg-paper border border-ink/10 hover:bg-bone/50 transition-colors cursor-pointer" style="border-radius:6px" onclick="location.hash='#/assessment/${esc(a.id)}'"><div style="width:36px;height:36px;border-radius:50%;background:hsl(var(--bone));display:grid;place-items:center;flex-shrink:0"><span style="font-size:11px;font-weight:700;color:hsl(var(--ink))">${esc((a.modules||[])[0]?.[0]?.toUpperCase()||"—")}</span></div><div class="flex-1 min-w-0"><p style="font-size:13px;font-weight:500;color:hsl(var(--ink));white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(a.target)}</p><p style="font-size:11px;color:hsl(var(--ash))">${esc((a.modules||[]).slice(0,2).join(", ")||"No modules")}</p></div><div style="text-align:right;flex-shrink:0"><span class="badge" style="background:${healthColor(healthMap[a.id]??50)};color:#fff;font-size:10px;padding:3px 8px">${healthMap[a.id]??"?"}</span><div class="meta-mono" style="font-size:10px;margin-top:4px">${a.created_at ? new Date(a.created_at).toLocaleDateString() : "—"}</div></div></div>`).join("") : `<div class="text-center py-8 muted small">No recent assessments — commission one.</div>`}
      </div></div>
    `;
  }

  function targetChip(target){
    if(!target) return "";
    const t=String(target);
    if(t.includes("3000")) return `<span class="chip realapp">REAL APP</span>`;
    if(t.startsWith("(source")) return `<span class="chip realsrc">SOURCE</span>`;
    if(t.includes("8080")) return `<span class="chip poc">PLAYGROUND</span>`;
    return "";
  }

  /* ═══════════ NEW ASSESSMENT ═══════════ */
  const MODULES = [
    ["authentication","Authentication","JWT handling · token acceptance"],
    ["authorization","Authorization / IDOR","object-level access control"],
    ["api","API Security","rate limiting & bypass"],
    ["input_validation","Input Validation","SQLi · XSS · error disclosure · CSRF"],
    ["headers","Client Security Headers","CSP · HSTS · cookies"],
    ["tls","TLS / Secure Comms","HTTPS · certificates"],
    ["secrets","Secrets Exposure","hardcoded credentials in source"],
    ["dependencies","Dependencies / SBOM","known CVEs via OSV.dev"],
    ["supply_chain","Supply Chain Hygiene","typosquat · pinning · licenses"],
    ["deep_scan","Deep Scan","ports · banners · default creds"],
    ["fuzzing","Mutation Fuzzing","5xx anomaly detection (opt-in)"],
    ["graphql","GraphQL Security","introspection exposure"],
  ];
  function NewAssessment(){
    setBreadcrumb([{label:"Dashboard", href:"#/dashboard"}, {label:"New Assessment"}]);
    $view.innerHTML = `
      <div class="page-head"><div><h1 class="page">New Assessment</h1><p class="sub" style="color:hsl(var(--ink));opacity:0.75">Authorized scans only — loopback / RFC1918 gate, cloud metadata always blocked.</p></div><span class="badge" id="modCount">6 selected</span></div>
      <form id="assessForm" class="grid two-col" style="gap:20px;align-items:start" novalidate>
        <div class="card assess-card">
          <div class="label-eyebrow" style="margin-bottom:12px">01 — Target</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
            <button type="button" class="preset-btn" id="presetReal">🌐 Real app :3000</button>
            <button type="button" class="preset-btn" id="presetLab">🧪 Playground :8080</button>
            <button type="button" class="preset-btn" id="presetSource">📁 Source only</button>
          </div>
          <div class="field"><label for="target" style="color:hsl(var(--ink))">Target URL — authorized & reachable</label>
            <input type="text" id="target" value="http://127.0.0.1:3000" placeholder="http://127.0.0.1:3000" spellcheck="false" autocomplete="off" aria-describedby="targetHelp" style="color:hsl(var(--ink))"><div id="targetHelp" class="help" aria-live="polite" style="color:hsl(var(--ash));font-size:11.5px"></div></div>
          <div class="field"><label for="sourcePath" style="color:hsl(var(--ink))">Filesystem scope — secrets / SBOM / supply-chain</label>
            <input type="text" id="sourcePath" placeholder="lab/vulnerable-world-monitor" spellcheck="false" aria-describedby="sourceHelp" style="color:hsl(var(--ink))"><div id="sourceHelp" class="help" style="color:hsl(var(--ash));font-size:11.5px">Defaults to lab source when source modules selected.</div></div>
          <div class="field"><label for="labToken" style="color:hsl(var(--ink))">Lab token <button type="button" class="ghost xs" id="fetchToken" style="margin-left:8px">fetch from lab</button></label>
            <input type="text" id="labToken" placeholder="optional — authenticated checks" spellcheck="false" autocomplete="off" style="color:hsl(var(--ink))">
            <div class="help" style="color:hsl(var(--ash));font-size:11.5px"><span class="mono">POST /lab/token</span> · alice/user123 · never persisted.</div>
          </div>
          <details style="border:1px solid hsl(var(--border));border-radius:8px;padding:12px 14px;background:hsl(var(--paper))"><summary style="cursor:pointer;font-size:13px;font-weight:600;color:hsl(var(--ink))">Advanced — per-module overrides</summary>
            <div class="field" style="margin-top:12px"><label for="t-authorization" style="color:hsl(var(--ink))">IDOR → reports</label><input type="text" id="t-authorization" placeholder="http://127.0.0.1:8080/api/reports" spellcheck="false" style="color:hsl(var(--ink))"></div>
            <div class="field"><label for="t-api" style="color:hsl(var(--ink))">Rate limit → monitor</label><input type="text" id="t-api" placeholder="http://127.0.0.1:8080/api/monitor" spellcheck="false" style="color:hsl(var(--ink))"></div>
            <div class="field"><label for="t-sqli" style="color:hsl(var(--ink))">SQLi → search</label><input type="text" id="t-sqli" placeholder="http://127.0.0.1:8080/api/search?id=1" spellcheck="false" style="color:hsl(var(--ink))"></div>
            <div class="field" style="margin-bottom:0"><label for="t-input_validation" style="color:hsl(var(--ink))">XSS → greet</label><input type="text" id="t-input_validation" placeholder="http://127.0.0.1:8080/greet?name=x" spellcheck="false" style="color:hsl(var(--ink))"></div>
          </details>
          <label style="display:flex;gap:10px;cursor:pointer;margin-top:14px;background:hsl(var(--bone)/0.5);border:1px solid hsl(var(--border));padding:12px 14px;border-radius:8px;align-items:flex-start">
            <input type="checkbox" id="authorized" style="width:16px;height:16px;margin-top:2px;accent-color:hsl(var(--ink))" aria-describedby="authHelp">
            <span style="font-size:12.5px;line-height:1.55;color:hsl(var(--ink))">I confirm this target is <strong>authorized</strong> for security testing.</span>
          </label>
          <div class="help" style="margin-top:6px;color:hsl(var(--ash));font-size:11.5px">Server enforces the gate regardless of UI.</div>
          <div style="margin-top:14px"><button type="submit" id="startBtn" disabled style="width:100%;padding:13px;font-size:14px" aria-describedby="startHelp">▶ Start Scan →</button>
            <p id="startHelp" class="help" style="text-align:center;color:hsl(var(--ash));font-size:11.5px">Check authorized + pick ≥1 module.</p></div>
        </div>
        <div class="card assess-card"><div class="row spread"><span class="label-eyebrow">02 — Modules</span><div style="display:flex;gap:6px;background:hsl(var(--paper));border:1px solid hsl(var(--border));border-radius:99px;padding:4px"><button type="button" class="ghost xs" id="selAll" style="padding:5px 10px;border-radius:99px">All</button><button type="button" class="ghost xs" id="selNone" style="padding:5px 10px;border-radius:99px">Clear</button></div></div>
          <p style="margin:8px 0 12px;color:hsl(var(--ink));opacity:0.75;font-size:13px">Baseline: first six. Add source & supply-chain for full coverage.</p>
          <div style="display:flex;gap:8px;margin-bottom:12px"><input id="modFilter" type="text" placeholder="Filter modules…" style="flex:1;color:hsl(var(--ink))" aria-label="Filter modules"></div>
          <div class="table-wrap" style="max-height:560px;border-radius:8px"><table><thead><tr><th style="width:36px;color:hsl(var(--ink))"></th><th style="color:hsl(var(--ink))">Module</th><th style="color:hsl(var(--ink))">Coverage</th></tr></thead><tbody id="modTable">
            ${MODULES.map(([k,l,d],i)=> `<tr data-mod="${esc(k)}"><td style="text-align:center"><input type="checkbox" name="mod" value="${esc(k)}" style="width:auto;accent-color:hsl(var(--ink))" ${i<6?"checked":""} aria-label="${esc(l)}"></td><td><strong style="font-size:12.5px;color:hsl(var(--ink))">${esc(l)}</strong><div style="color:hsl(var(--ink));opacity:0.6;font-size:11px;font-family:var(--mono)">${esc(k)}</div></td><td style="color:hsl(var(--ink));opacity:0.6;font-size:11px;font-family:var(--mono)">${esc(d)}</td></tr>`).join("")}
          </tbody></table></div>
        </div>
      </form>`;
    const form=document.getElementById("assessForm");
    const cb=document.getElementById("authorized"), btn=document.getElementById("startBtn");
    const modCount=document.getElementById("modCount");
    const targetInput=document.getElementById("target");
    const targetHelp=document.getElementById("targetHelp");
    function updateModCount(){ const n=form.querySelectorAll("input[name=mod]:checked").length; modCount.textContent=n+" selected"; modCount.style.color = ""; btn.disabled = !(cb.checked && n>0); }
    function validateTarget(){
      const v=targetInput.value.trim();
      // source-only is signaled by empty target + at least one source module checked
      const hasSource = [...form.querySelectorAll("input[name=mod]:checked")].some(i=> ["secrets","dependencies","supply_chain"].includes(i.value));
      if(!v && hasSource){ targetHelp.textContent="Source-only — no HTTP target needed."; targetHelp.style.color="var(--ok)"; targetInput.style.borderColor=""; return true; }
      if(!v){ targetHelp.textContent="Enter a target URL (http://127.0.0.1:3000 or :8080) or select only source modules for source-only."; targetHelp.style.color="var(--text-3)"; return false; }
      if(!/^https?:\/\/.+/i.test(v)){ targetHelp.textContent="Must start with http:// or https://"; targetHelp.style.color="var(--crit)"; targetInput.style.borderColor="var(--crit)"; return false; }
      try{ new URL(v); }catch{ targetHelp.textContent="Invalid URL format"; targetHelp.style.color="var(--crit)"; return false; }
      targetHelp.textContent="✓ Looks valid — gate will still enforce loopback/RFC1918."; targetHelp.style.color="var(--ok)"; targetInput.style.borderColor="var(--ok)"; return true;
    }
    form.querySelectorAll("input[name=mod]").forEach(c=> c.addEventListener("change", ()=>{ updateModCount(); validateTarget(); }));
    targetInput.addEventListener("input", debounce(()=> validateTarget(), 300));
    targetInput.addEventListener("blur", validateTarget);
    updateModCount(); validateTarget();
    cb.onchange=()=> updateModCount();
    document.getElementById("selAll").onclick=()=>{ form.querySelectorAll("input[name=mod]").forEach(c=> { if(c.closest("tr").style.display!=="none") c.checked=true; }); updateModCount(); validateTarget(); };
    document.getElementById("selNone").onclick=()=>{ form.querySelectorAll("input[name=mod]").forEach(c=> c.checked=false); updateModCount(); validateTarget(); };
    document.getElementById("modFilter").addEventListener("input", e=>{
      const q=e.target.value.toLowerCase().trim();
      form.querySelectorAll("#modTable tr").forEach(tr=>{
        const hay=(tr.dataset.mod + " " + tr.textContent).toLowerCase();
        tr.style.display = !q || hay.includes(q) ? "" : "none";
      });
    });
    document.getElementById("presetReal").onclick=()=>{
      targetInput.value="http://127.0.0.1:3000";
      document.getElementById("sourcePath").value="lab/vulnerable-world-monitor";
      validateTarget(); toast("Target set to REAL World Monitor — :3000");
    };
    document.getElementById("presetLab").onclick=()=>{
      targetInput.value="http://127.0.0.1:8080";
      document.getElementById("sourcePath").value="lab/vulnerable-world-monitor";
      validateTarget(); toast("Target set to lab playground — :8080");
    };
    document.getElementById("presetSource").onclick=()=>{
      targetInput.value="";
      document.getElementById("sourcePath").value="lab/vulnerable-world-monitor";
      // select source modules
      form.querySelectorAll("input[name=mod]").forEach(c=> c.checked = ["secrets","dependencies","supply_chain"].includes(c.value));
      updateModCount(); validateTarget(); toast("Source-only preset — no HTTP target");
    };
    document.getElementById("fetchToken").onclick= async ()=>{
      const b=document.getElementById("fetchToken");
      const orig=b.textContent; b.disabled=true; b.innerHTML=`<span class="spinner" style="width:11px;height:11px;border-width:1.7px" aria-hidden="true"></span> fetching…`;
      try{
        const r=await API.post("/lab/token");
        document.getElementById("labToken").value=r.access_token||"";
        toast("Lab token acquired");
      }catch(e){ toast(e.message,false); }
      finally{ b.disabled=false; b.textContent=orig; }
    };
    form.onsubmit= async e=>{
      e.preventDefault();
      if(!validateTarget()) return toast("Fix target URL before starting", false);
      const modules=[...form.querySelectorAll("input[name=mod]:checked")].map(i=> i.value);
      if(!modules.length) return toast("Select at least one module", false);
      if(!cb.checked) return toast("Confirm authorization first", false);
      const mt={};
      // map sqli alias to input_validation internally; but keep both keys for backwards compat
      const overrides = {
        "authorization": document.getElementById("t-authorization").value.trim(),
        "api": document.getElementById("t-api").value.trim(),
        "sqli": document.getElementById("t-sqli").value.trim(),
        "input_validation": document.getElementById("t-input_validation").value.trim(),
      };
      for(const [k,v] of Object.entries(overrides)) if(v) mt[k]=v;
      // normalize sqli alias
      if(mt.sqli && !mt.input_validation) mt.input_validation = mt.sqli;
      btn.disabled=true; const origBtn=btn.innerHTML; btn.innerHTML=`<span class="spinner" aria-hidden="true"></span> Starting…`;
      try{
        const a=await API.post("/assessments",{
          target:targetInput.value.trim(),
          modules, authorized:true,
          source_path:document.getElementById("sourcePath").value.trim()||null,
          auth_token:document.getElementById("labToken").value.trim()||null,
          module_targets:mt,
        });
        rememberRun(a.id);
        toast("Assessment queued — live progress will appear");
        location.hash=`#/assessment/${a.id}`;
      }catch(err){ toast(err.message,false); btn.disabled=false; btn.innerHTML=origBtn; }
    };
  }

  /* ═══════════ ASSESSMENT DETAIL ═══════════ */
  async function AssessmentDetail(id){
    if(!id || !/^[0-9a-f]{32}$/i.test(id)){ $view.innerHTML=`<div class="card">${errorState("Invalid assessment ID", ()=> location.hash="#/history")}</div>`; return; }
    setBreadcrumb([{label:"History", href:"#/history"}, {label:"Assessment "+id.slice(0,8)}]);
    $view.innerHTML = `<div class="page-head"><h1 class="page">Assessment <span class="mono" style="font-size:14px;color:var(--text-2)">${esc(id.slice(0,8))}…</span></h1><p class="sub mono" style="word-break:break-all">${esc(id)}</p></div>
      <div id="adBody">
        <div class="card">${skeletonTable(2)}</div>
        <div class="grid kpis mt">${SEV.map(()=> `<div class="skeleton sk-kpi"></div>`).join("")}</div>
        <div class="card mt">${skeletonTable(5)}</div>
      </div>`;
    const body=$view.querySelector("#adBody");
    let lastSnap=null;
    let pollBackoff=2500;
    function render(a){
      const snap=JSON.stringify([a.status,a.severity_counts,a.scan_runs.map(r=> [r.scanner,r.status,r.findings_count,r.checks_total,r.error])]);
      if(snap===lastSnap){ schedule(a); return; }
      lastSnap=snap;
      pollBackoff=2500;
      const y=window.scrollY;
      const done=a.scan_runs.filter(r=> ["completed","failed","skipped"].includes(r.status)).length;
      const pct=Math.round((done / Math.max(a.scan_runs.length,1))*100);
      const sev=a.severity_counts||{};
      const running=["queued","running"].includes(a.status);
      body.innerHTML = `
        <div class="card mb">
          <div class="row spread">
            <div style="min-width:0"><div class="row" style="gap:8px;flex-wrap:wrap"><strong class="mono" style="word-break:break-all">${esc(a.target)}</strong> ${targetChip(a.target)}</div>
              <div class="muted small mono" style="margin-top:4px">modules: ${esc((a.modules||[]).join(", "))} · ${a.created_at ? new Date(a.created_at).toLocaleString() : "—"}</div>
              ${a.error ? `<div class="err mt" style="max-width:640px;word-break:break-word">${esc(a.error.slice(0,600))}</div>` : ""}</div>
            <div style="text-align:right;flex-shrink:0"><span class="status ${esc(a.status)}">${esc(a.status)}</span><div class="muted small mono" style="margin-top:4px">${pct}% · ${done}/${a.scan_runs.length} scanners</div><div class="mt"><button class="ghost xs" onclick="navigator.clipboard.writeText('${esc(a.id)}').then(()=>toast('ID copied'))">⎘ Copy ID</button></div></div>
          </div>
          <div class="progressbar mt" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"><i style="width:${pct}%"></i></div>
          ${running ? `<p class="muted small mt" style="display:flex;align-items:center;gap:8px"><span class="spinner" style="width:12px;height:12px;border-width:2px;border-top-color:var(--cyan)" aria-hidden="true"></span> Live — updates every 2.5s. Keep this tab open or follow from the banner.</p>` : ""}
          ${a.finished_at ? `<p class="muted small" style="margin-top:6px">Finished: ${new Date(a.finished_at).toLocaleString()} ${a.started_at ? `· took ${((new Date(a.finished_at)-new Date(a.started_at))/1000).toFixed(1)}s` : ""}</p>` : ""}
        </div>
        <div class="grid kpis mb">${SEV.map(s=> `<div class="kpi ${s.toLowerCase().slice(0,6)}"><b>${sev[s]??0}</b><small>${s}</small></div>`).join("")}</div>
        <div class="card mb">
          <div class="row spread"><strong>Scanner runs</strong><span class="badge">${a.scan_runs.length} modules</span></div>
          <div class="table-wrap mt"><table><thead><tr><th>Module</th><th>Status</th><th>Checks</th><th>Findings</th><th>Duration</th></tr></thead><tbody>
            ${a.scan_runs.map(r=> `<tr><td class="mono" style="font-weight:600">${esc(r.scanner)}</td>
              <td><span class="status ${esc(r.status)}">${esc(r.status)}</span>${r.error ? `<div class="muted small mono" style="max-width:220px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(r.error)}">${esc(r.error.slice(0,120))}</div>`:""}</td>
              <td class="mono">${r.checks_total ?? 0}</td><td class="mono" style="font-weight:700">${r.findings_count ?? 0}</td>
              <td class="mono muted">${((r.duration_ms||0)/1000).toFixed(1)}s</td></tr>`).join("")}
          </tbody></table></div>
        </div>
        <div id="runFindings"></div>`;
      window.scrollTo(0,y);
      if(["completed","failed"].includes(a.status)){
        const c=body.querySelector("#runFindings");
        if(c){
          c.innerHTML=`<div class="card"><div class="row spread"><strong>Findings</strong><span class="muted small">sorted by severity</span></div><div class="mt">${skeletonTable(4)}</div></div>`;
          API.get(`/assessments/${a.id}/findings`).then(rows=>{
            if(!rows.length){ c.innerHTML=`<div class="card">${emptyState({icon:"✓", title:"No findings", hint:"All checks passed for this assessment — no findings were produced.", action:""})}</div>`; return; }
            rows.sort((x,y)=> (SEV_ORDER[x.severity]??9) - (SEV_ORDER[y.severity]??9));
            c.innerHTML=`<div class="card"><div class="row spread"><strong>Findings</strong><span class="badge">${rows.length}</span></div>
              <div class="table-wrap mt"><table><thead><tr><th>Severity</th><th>Title</th><th>Scanner</th><th></th></tr></thead><tbody>
              ${rows.map(f=> `<tr class="click" onclick="location.hash='#/finding/${esc(f.id)}'"><td><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span></td><td style="font-weight:500">${esc(f.title)}</td><td class="mono muted small">${esc(f.scanner)}</td><td style="color:var(--text-3)" aria-hidden="true">›</td></tr>`).join("")}
            </tbody></table></div></div>`;
          }).catch(()=>{ c.innerHTML=`<div class="card"><p class="muted small">Could not load findings.</p></div>`; });
        }
      }
      schedule(a);
    }
    function schedule(a){
      if(["queued","running"].includes(a.status)){
        pollId=setTimeout(async()=>{
          try{ const next=await API.get(`/assessments/${id}`); render(next); }
          catch(e){
            pollBackoff=Math.min(pollBackoff*1.5, 10000);
            pollId=setTimeout(()=> schedule(a), pollBackoff);
          }
        }, pollBackoff);
      }
    }
    try{ render(await API.get(`/assessments/${id}`)); }
    catch(e){ body.innerHTML=`<div class="card">${errorState(e.message, ()=> AssessmentDetail(id))}</div>`; }
  }

  /* ═══════════ FINDINGS LIST (server-side filter + pagination) ═══════════ */
  const FINDINGS_PAGE_SIZE = 25;
  async function FindingsList(){
    setBreadcrumb([{label:"Findings"}]);
    $view.innerHTML = `
      <div class="page-head row spread"><div><h1 class="page">Findings</h1><p class="sub">All normalized findings across assessments — deduplicated, scored with CVSS v3.1.</p></div>
        <div class="page-actions"><span class="badge" id="findCount">—</span></div></div>
      <div class="row" style="gap:8px;margin-bottom:12px;flex-wrap:wrap">
        <input id="findSearch" type="text" placeholder="Search title, check_id, category…" style="flex:1;min-width:220px;color:hsl(var(--ink))" aria-label="Search findings">
        <div class="filter-bar" id="filterBar" role="group" aria-label="Filter by severity">
          <button class="chip-filter active" data-sev="" aria-pressed="true">All</button>
          ${SEV.map(s=> `<button class="chip-filter" data-sev="${s}" aria-pressed="false"><span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:${SEV_COLOR[s]}" aria-hidden="true"></span> ${s}</button>`).join("")}
        </div>
      </div>
      <div id="fl">${skeletonTable(6)}</div>
      <div id="findPager" class="row spread mt" style="display:none">
        <span class="muted small" id="findRange">—</span>
        <div style="display:flex;gap:8px">
          <button class="ghost tiny" id="findPrev">← Prev</button>
          <button class="ghost tiny" id="findNext">Next →</button>
        </div>
      </div>`;
    const el=$view.querySelector("#fl");
    const countEl=document.getElementById("findCount");
    const searchEl=document.getElementById("findSearch");
    const pagerEl=document.getElementById("findPager");
    const rangeEl=document.getElementById("findRange");
    const prevBtn=document.getElementById("findPrev");
    const nextBtn=document.getElementById("findNext");
    let activeSev="", query="", page=0, total=0, reqSeq=0;
    function params(){
      const p = new URLSearchParams({ limit: String(FINDINGS_PAGE_SIZE), offset: String(page*FINDINGS_PAGE_SIZE) });
      if(activeSev) p.set("severity", activeSev);
      if(query) p.set("q", query);
      return p.toString();
    }
    async function load(){
      const myReq = ++reqSeq;
      el.innerHTML=skeletonTable(6);
      pagerEl.style.display="none";
      try{
        const {rows, total: t} = await API.page(`/assessments/-/findings?${params()}`);
        if(myReq !== reqSeq) return; // stale response (fast typing)
        total = t;
        if(countEl) countEl.textContent = total + (total===1 ? " finding" : " findings");
        render(rows);
      }catch(e){ el.innerHTML=`<div class="card">${errorState(e.message, load)}</div>`; }
    }
    function render(rows){
      rows.sort((a,b)=> (SEV_ORDER[a.severity]??9) - (SEV_ORDER[b.severity]??9));
      if(!rows.length){
        const filtered = activeSev || query;
        el.innerHTML=emptyState({icon: filtered ? "◍" : "◈", title: filtered ? "No matching findings" : "No findings yet",
          hint: filtered ? "No findings match filter. Try clearing search or severity." : "No findings yet — run an assessment first.",
          action: filtered ? `<button class="ghost tiny" id="clearFindFilters">Clear filters</button>` : `<button onclick="location.hash='#/assess/new'">Run an assessment</button>`});
        const cb=document.getElementById("clearFindFilters");
        if(cb) cb.onclick=()=>{ query=""; activeSev=""; page=0; searchEl.value="";
          document.querySelectorAll(".chip-filter").forEach(b=>{ b.classList.toggle("active", (b.dataset.sev||"")===""); b.setAttribute("aria-pressed", (b.dataset.sev||"")==="" ? "true" : "false"); });
          load(); };
        return;
      }
      el.innerHTML=`<div class="card" style="padding:0;overflow:hidden"><div class="table-wrap" style="border:none"><table><thead><tr><th>Severity</th><th>CVSS</th><th>Title</th><th>Category</th><th>Status</th><th></th></tr></thead><tbody>
        ${rows.map(f=> `<tr class="click" onclick="location.hash='#/finding/${esc(f.id)}'">
          <td><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span></td>
          <td class="mono" style="font-weight:700">${f.cvss_score ?? "—"}</td>
          <td style="font-weight:500;max-width:360px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(f.title)}">${esc(f.title)}</td>
          <td class="muted small mono">${esc((f.category||"").replaceAll("_"," "))}</td>
          <td class="small">${esc(f.status)}${f.retest_status ? `<br><span class="${f.retest_status==="FIXED"?"retest-fixed":"retest-present"}" style="font-size:11px">${esc(f.retest_status)}</span>`:""}</td>
          <td style="color:var(--text-3)" aria-hidden="true">›</td></tr>`).join("")}
      </tbody></table></div></div>`;
      const from = total ? page*FINDINGS_PAGE_SIZE+1 : 0;
      const to = Math.min(total, (page+1)*FINDINGS_PAGE_SIZE);
      rangeEl.textContent = `Showing ${from}–${to} of ${total}`;
      prevBtn.disabled = page===0;
      nextBtn.disabled = to>=total;
      pagerEl.style.display = total ? "" : "none";
    }
    searchEl.addEventListener("input", debounce(e=>{
      query=e.target.value.trim(); page=0; load();
    }, 400));
    document.getElementById("filterBar")?.addEventListener("click", e=>{
      const btn=e.target.closest(".chip-filter");
      if(!btn) return;
      document.querySelectorAll(".chip-filter").forEach(b=> { b.classList.remove("active"); b.setAttribute("aria-pressed","false"); });
      btn.classList.add("active"); btn.setAttribute("aria-pressed","true");
      activeSev=btn.dataset.sev || ""; page=0; load();
    });
    prevBtn.onclick=()=>{ if(page>0){ page--; load(); } };
    nextBtn.onclick=()=>{ page++; load(); };
    await load();
  }

  /* ═══════════ FINDING DETAIL ═══════════ */
  async function FindingDetail(id){
    if(!id || !/^[0-9a-f]{32}$/i.test(id)){ $view.innerHTML=`<div class="card">${errorState("Invalid finding ID", ()=> location.hash="#/findings")}</div>`; return; }
    setBreadcrumb([{label:"Findings", href:"#/findings"}, {label:"Finding "+id.slice(0,8)}]);
    $view.innerHTML=`<div id="fd"><div class="card">${skeletonTable(3)}</div><div class="grid two-col mt">${skeletonCards(2)}</div></div>`;
    const el=$view.querySelector("#fd");
    let f;
    try{ f=await API.get(`/assessments/findings/${id}`); }
    catch(e){ el.innerHTML=`<div class="card">${errorState(e.message, ()=> FindingDetail(id))}</div>`; return; }
    setBreadcrumb([{label:"Findings", href:"#/findings"}, {label: truncate(f.title,36)}]);
    let evidence=[];
    try{ evidence=await API.get(`/assessments/findings/${id}/evidence`); }catch(_){}
    const cvssTone = f.cvss_score!=null ? (f.cvss_score>=9 ? "var(--crit)" : f.cvss_score>=7 ? "var(--high)" : f.cvss_score>=4 ? "var(--med)" : "var(--low)") : "var(--text-3)";
    const prettyEvidence = evidence.map(ev=>{
      let jsonStr="";
      try{ jsonStr=JSON.stringify(ev.document,null,2); if(jsonStr.length>12000) jsonStr=jsonStr.slice(0,12000)+"\n… truncated — download evidence via API for full payload"; }catch{ jsonStr="(unserializable)"; }
      return { ...ev, pretty: jsonStr };
    });
    el.innerHTML = `
      <div class="finding-head">
        <span class="sev ${esc(f.severity)}" style="font-size:13px;padding:7px 14px">${esc(f.severity)}</span>
        <div style="flex:1;min-width:240px"><h1 class="page" style="font-size:18px;line-height:1.3;margin:0">${esc(f.title)}</h1>
          <div class="muted small mono" style="margin-top:4px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
            <span>${esc(f.scanner)} · ${esc(f.check_id)}</span>
            <span style="display:inline-flex;align-items:center;gap:6px">CVSS <strong style="color:${cvssTone};font-size:13px">${f.cvss_score ?? "—"}</strong> <span class="muted">${esc(f.cvss_vector||"")}</span></span>
          </div></div>
        <div style="text-align:right;display:flex;flex-direction:column;gap:8px;align-items:flex-end">
          ${f.retest_status ? `<div class="small" style="font-weight:700">RETEST: <span class="${f.retest_status==="FIXED"?"retest-fixed":"retest-present"}">${esc(f.retest_status)}</span> ${f.retest_count?`· ${f.retest_count} retests`:""}</div>`:""}
          <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end">
            <button class="ghost tiny" id="copyLinkBtn" title="Copy link">⎘ Link</button>
            <button class="ghost tiny danger" id="delBtn">🗑 Delete</button>
            <button id="retestBtn">↻ Retest</button>
          </div>
        </div>
      </div>
      <div class="card mt why-card" style="border-left:4px solid ${cvssTone};background:linear-gradient(135deg, ${cvssTone}08, transparent)"><h3 style="margin:0 0 6px">Why this matters?</h3><p class="small" style="color:var(--text-2)"><strong>Risk:</strong> <span class="sev ${esc(f.severity)}">${esc(f.severity)}</span> CVSS ${f.cvss_score ?? "?"} &mdash; ${esc(f.business_impact||f.impact||"See impact")}</p><p class="small" style="color:var(--text-2)"><strong>Affected:</strong> <span class="mono">${esc(f.affected_component||"?")}</span></p><p class="small" style="color:var(--text-2)"><strong>Fix:</strong> ${esc(f.remediation||"?")}</p><p class="small"><strong>Retest:</strong> <span class="${f.retest_status==="FIXED"?"retest-fixed":"retest-present"}">${esc(f.retest_status||"Pending")}</span> ${f.retest_count?`(${f.retest_count} retests)`:""}</p></div>
      <div class="detail-grid mt">
        <dl class="kv card">
          <dt>Affected</dt><dd class="mono">${esc(f.affected_component || "—")} <button class="ghost xs" style="margin-left:6px" onclick="navigator.clipboard.writeText('${esc(f.affected_component).replace(/'/g,"\\'")}').then(()=>toast('Copied'))">copy</button></dd>
          <dt>Target</dt><dd class="mono" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">${targetChip(f.target)} <span style="word-break:break-all">${esc(f.target)}</span></dd>
          <dt>CVSS vector</dt><dd class="mono small" style="word-break:break-all">${esc(f.cvss_vector||"—")}</dd>
          <dt>Category</dt><dd class="mono small">${esc((f.category||"").replaceAll("_"," "))}</dd>
          <dt>Status</dt><dd>${esc(f.status)}${f.retest_count ? ` · retests: ${f.retest_count}`:""} ${f.retested_at ? `· ${new Date(f.retested_at).toLocaleString()}`:""}</dd>
          <dt>Detected</dt><dd class="mono small">${f.created_at ? new Date(f.created_at).toLocaleString() : "—"}</dd>
          <dt>Assessment</dt><dd><a class="mono small" href="#/assessment/${esc(f.assessment_id)}">${esc(f.assessment_id.slice(0,8))}…</a> <button class="ghost xs" onclick="navigator.clipboard.writeText('${esc(f.assessment_id)}').then(()=>toast('Copied'))">copy</button></dd>
        </dl>
        <div class="card"><h3>Why this score</h3><p class="small" style="color:var(--text-2);line-height:1.65">${esc(f.severity_rationale||"Standard preset for this check.")}</p>
          <div class="divider"></div><h3>Business impact</h3><p class="small" style="color:var(--text-2);line-height:1.65">${esc(f.business_impact||"—")}</p></div>
      </div>
      <div class="detail-grid mt">
        <div class="card"><h3>Description</h3><p class="small" style="color:var(--text-2);line-height:1.7">${esc(f.description||"—")}</p>
          <h3 style="margin-top:14px">Impact</h3><p class="small" style="color:var(--text-2);line-height:1.7">${esc(f.impact||"—")}</p></div>
        <div class="card"><h3>Reproduction <span class="muted" style="font-weight:400">— lab only</span></h3>
          <ol class="small mono" style="margin:8px 0 0 18px;line-height:1.7">${(f.reproduction||[]).map(r=> `<li>${esc(r)}</li>`).join("") || `<li class="muted">No steps recorded.</li>`}</ol>
          <h3 style="margin-top:14px">Remediation</h3><p class="small" style="color:var(--text-2);line-height:1.7">${esc(f.remediation||"—")}</p>
          ${(f.references||[]).length ? `<h3 style="margin-top:14px">References</h3><ul class="small mono" style="margin-left:18px">${f.references.map(r=> `<li style="word-break:break-all"><a href="${esc(r)}" target="_blank" rel="noopener">${esc(r)}</a></li>`).join("")}</ul>`:""}
        </div>
      </div>
      <div class="card mt"><div class="row spread"><strong>Evidence <span class="badge">${prettyEvidence.length}</span></strong><span class="muted small">sensitive values masked before storage</span></div>
        ${prettyEvidence.length ? prettyEvidence.map(ev=> `<details class="mt"><summary class="mono small" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap"><span>${esc(ev.summary)}</span> <span class="muted">· ${esc(ev.kind)}</span><button class="ghost xs" style="margin-left:auto" onclick="event.preventDefault(); navigator.clipboard.writeText(document.getElementById('ev-${esc(ev.id)}').textContent).then(()=>toast('Evidence copied'))">copy</button></summary><pre class="evidence-doc" id="ev-${esc(ev.id)}">${esc(ev.pretty)}</pre></details>`).join("") : `<div class="mt">${emptyState({icon:"—", title:"No evidence documents", hint:"This finding has no attached evidence — the check may have produced a synthetic result.", action:""})}</div>`}
      </div>`;
    el.querySelector("#copyLinkBtn").onclick=()=> copyText(location.href);
        el.querySelector("#retestBtn").onclick= async ()=>{
      const btn=el.querySelector("#retestBtn");
      btn.disabled=true; const orig=btn.innerHTML; btn.innerHTML=`<span class="spinner" aria-hidden="true"></span> Verifying fix...`;
      const overlay=document.createElement("div"); overlay.style.cssText="position:fixed;inset:0;background:rgba(6,10,19,.88);display:grid;place-items:center;z-index:9999;color:#fff;text-align:center;padding:24px";
      overlay.innerHTML=`<div><div class="spinner" style="width:42px;height:42px;border-width:4px;margin:0 auto 16px"></div><div style="font-size:18px;font-weight:800">Retesting...</div><div class="muted small" style="color:#94a3b8;margin-top:6px">Re-running scanner for this check</div></div>`;
      document.body.appendChild(overlay);
      try{
        const r=await API.post(`/assessments/findings/${id}/retest`);
        overlay.innerHTML = r.retest_status==="FIXED" ? `<div style="background:#22c55e;color:#fff;padding:28px;border-radius:16px;min-width:280px"><div style="font-size:42px">OK</div><div style="font-size:22px;font-weight:800;margin-top:8px">FIXED</div><div style="opacity:.9;margin-top:4px">Remediation verified</div></div>` : `<div style="background:#ef4444;color:#fff;padding:28px;border-radius:16px;min-width:280px"><div style="font-size:42px">X</div><div style="font-size:22px;font-weight:800;margin-top:8px">STILL PRESENT</div><div style="opacity:.9;margin-top:4px">Not yet remediated</div></div>`;
        toast(r.retest_status==="FIXED" ? "FIXED - remediation verified" : "STILL PRESENT - not yet remediated", r.retest_status==="FIXED");
        setTimeout(()=>{ overlay.remove(); FindingDetail(id); }, 1600);
      }catch(e){ overlay.remove(); toast(e.message,false); btn.disabled=false; btn.innerHTML=orig; }
    };
    el.querySelector("#delBtn").onclick= async ()=>{
      if(!confirm("Delete this finding and its evidence? This also purges related audit rows.")) return;
      const btn=el.querySelector("#delBtn"); btn.disabled=true;
      try{ await API.del(`/findings/${id}`); toast("Finding deleted"); location.hash="#/findings"; }
      catch(e){ toast(e.message,false); btn.disabled=false; }
    };
  }

  /* ═══════════ HISTORY ═══════════ */
  async function History(){
    setBreadcrumb([{label:"History"}]);
    $view.innerHTML = `<div class="page-head row spread"><div><h1 class="page">Assessment History</h1><p class="sub">Every authorized assessment run — newest first.</p></div><span class="badge" id="histCount">—</span><button class="ghost xs danger" id="freshStartBtn" title="Delete all assessments for fresh start" style="margin-left:8px">Fresh Start</button></div>
      <div class="row" style="gap:8px;margin-bottom:12px"><input id="histSearch" type="text" placeholder="Filter by target…" style="flex:1" aria-label="Filter history"><button class="ghost xs" onclick="History()">↻ Refresh</button></div>
      <div class="card" style="padding:0;overflow:hidden"><div id="histBody" style="padding:16px">${skeletonTable(5)}</div></div>`;
    const body=$view.querySelector("#histBody");
    const cntEl=document.getElementById("histCount");
    let rows=[];
    try{ rows=await API.get("/assessments?limit=20"); }catch(e){ body.innerHTML=errorState(e.message, History); return; }
    const searchEl=document.getElementById("histSearch");
    function render(){
      const q=(searchEl.value||"").toLowerCase().trim();
      let filtered=rows;
      if(q) filtered=rows.filter(a=> String(a.target||"").toLowerCase().includes(q) || String(a.status||"").toLowerCase().includes(q));
      if(cntEl) cntEl.textContent=filtered.length+" / "+rows.length;
      if(!filtered.length){
        body.innerHTML=emptyState({icon:"◍", title: q ? "No matching assessments" : "No assessments yet", hint: q ? `No assessments match “${q}”. Clear the filter to see all.` : "Run your first authorized assessment to see history here.", action: q ? "" : `<button onclick="location.hash='#/assess/new'">New Assessment</button>`});
        return;
      }
      body.innerHTML=`<div class="table-wrap" style="border:none"><table><thead><tr><th>Target</th><th>Modules</th><th>Status</th><th>Created</th><th></th></tr></thead><tbody>
        ${filtered.map(a=> `<tr class="click" onclick="location.hash='#/assessment/${esc(a.id)}'">
          <td class="mono" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">${targetChip(a.target)} <span title="${esc(a.target)}">${esc((a.target||"").length>44? a.target.slice(0,44)+"…":a.target)}</span></td>
          <td class="muted small" title="${esc((a.modules||[]).join(", "))}">${esc((a.modules||[]).slice(0,3).join(", "))}${(a.modules||[]).length>3?` +${(a.modules||[]).length-3}`:""}</td>
          <td><span class="status ${esc(a.status)}">${esc(a.status)}</span></td>
          <td class="muted small mono">${a.created_at ? new Date(a.created_at).toLocaleString() : "—"}</td>
          <td>${a.status!=="running" && a.status!=="queued" ? `<button class="ghost xs" title="Delete assessment" onclick="History.del('${esc(a.id)}',event)">🗑</button>`:""}</td>
        </tr>`).join("")}
      </tbody></table></div>`;
    }
    searchEl.addEventListener("input", debounce(render, 250));
    document.getElementById("freshStartBtn")?.addEventListener("click", async ()=>{
      if(!confirm("Fresh start: delete ALL assessments, findings, evidence and reports from this PC? This cannot be undone.")) return;
      const btn=document.getElementById("freshStartBtn"); const orig=btn.textContent; btn.disabled=true; btn.textContent="Clearing...";
      try{ await API.del("/assessments"); toast("All history cleared - fresh start"); rows = []; render(); }catch(e){ toast(e.message,false); btn.disabled=false; btn.textContent=orig; }
    });
    render();
  }
  window.History=History;
  History.del= async function(id, ev){
    ev.stopPropagation();
    if(!confirm("Delete this assessment with ALL findings, evidence and reports? Audit rows referencing it will be purged.")) return;
    const btn=ev.currentTarget; const orig=btn.innerHTML; btn.disabled=true; btn.innerHTML=`<span class="spinner" style="width:10px;height:10px;border-width:1.6px" aria-hidden="true"></span>`;
    try{ await API.del(`/assessments/${id}`); toast("Assessment deleted"); rows = rows.filter(a=> a.id !== id); render(); }
    catch(e){ toast(e.message,false); btn.disabled=false; btn.innerHTML=orig; }
  };

  /* ═══════════ REPORTS ═══════════ */
  async function Reports(){
    setBreadcrumb([{label:"Reports"}]);
    $view.innerHTML = `<div class="page-head"><h1 class="page">Reports</h1><p class="sub">Generate professional deliverables per assessment — PDF, JSON, Markdown, CSV. Stored reports can be downloaded or deleted.</p></div>
      <div class="card" style="padding:0;overflow:hidden"><div id="repBody" style="padding:16px">${skeletonTable(4)}</div></div>`;
    const body=$view.querySelector("#repBody");
    let rows=[];
    try{ rows=await API.get("/assessments?limit=20"); }catch(e){ body.innerHTML=errorState(e.message, Reports); return; }
    if(!rows.length){
      body.innerHTML=emptyState({icon:"📄", title:"No assessments to report on", hint:"Create and complete an assessment first — only completed runs can generate reports.", action:`<button onclick="location.hash='#/assess/new'">New Assessment</button>`});
      return;
    }
    body.innerHTML=`<div class="table-wrap" style="border:none"><table><thead><tr><th>Target</th><th>Status</th><th>Generate</th><th>Stored</th></tr></thead><tbody>
      ${rows.map(a=> `<tr>
        <td class="mono" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">${targetChip(a.target)} <span title="${esc(a.target)}">${esc((a.target||"").length>38? a.target.slice(0,38)+"…":a.target)}</span></td>
        <td><span class="status ${esc(a.status)}">${esc(a.status)}</span></td>
        <td>${a.status==="completed" ? ["pdf","json","md","csv"].map(fmt=> `<button class="ghost xs" style="margin:2px" onclick="Reports.gen('${esc(a.id)}','${fmt}',this)">${fmt.toUpperCase()}</button>`).join("") : `<span class="muted small">complete first</span>`}</td>
        <td class="small" id="cell-${esc(a.id)}"><button class="ghost xs" onclick="Reports.list('${esc(a.id)}',this)">list</button><div id="stored-${esc(a.id)}" class="stored-list"></div></td>
      </tr>`).join("")}
    </tbody></table></div>
    <p class="help" style="margin-top:10px">Tip: click <em>list</em> to load stored reports for that assessment. Downloads are authenticated via <span class="mono">Authorization: Bearer …</span>.</p>`;
  }
  window.Reports=Reports;
  Reports.gen= async (id, fmt, btn)=>{
    const orig=btn.innerHTML; btn.disabled=true; btn.innerHTML=`<span class="spinner" style="width:10px;height:10px;border-width:1.6px" aria-hidden="true"></span> ${fmt.toUpperCase()}`;
    try{
      await API.post(`/reports/assessment/${id}?format=${fmt}`);
      toast(`${fmt.toUpperCase()} report generated`);
      const listBtn=document.querySelector(`#cell-${CSS.escape(id)} button`);
      if(listBtn) Reports.list(id, listBtn);
      else Reports.list(id, btn);
    }catch(e){ toast(e.message,false); }
    finally{ btn.disabled=false; btn.innerHTML=orig; }
  };
  Reports.list= async (aid, btn)=>{
    const box=document.getElementById(`stored-${aid}`);
    if(!box) return;
    if(btn){ btn.disabled=true; btn.textContent="…"; }
    try{
      const rows=await API.get(`/reports/assessment/${aid}`);
      if(!rows.length){ box.innerHTML=`<span class="muted small">no stored reports</span>`; return; }
      box.innerHTML=rows.map(r=> `<div class="stored-item">
        <a href="#" onclick="Reports.dl('${esc(r.download)}','${esc(r.format)}','${esc(aid)}');return false">${esc(r.format.toUpperCase())}</a>
        <span class="muted mono small">${r.created_at ? new Date(r.created_at).toLocaleString() : ""}</span>
        <button class="ghost xs" style="margin-left:auto;padding:2px 7px" onclick="Reports.del('${esc(r.id)}','${esc(aid)}')" title="Delete report">🗑</button>
      </div>`).join("");
    }catch(e){ toast(e.message,false); box.innerHTML=`<span class="muted small">load failed</span>`; }
    finally{ if(btn){ btn.disabled=false; btn.textContent="list"; } }
  };
  Reports.dl= async (path, fmt, id)=>{
    try{
      const res=await fetch(path, { headers:{ Authorization:`Bearer ${API.getToken()}` } });
      if(!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      const blob=await res.blob();
      const a=document.createElement("a");
      a.href=URL.createObjectURL(blob);
      a.download=`report_${id}.${fmt}`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(()=> URL.revokeObjectURL(a.href), 5000);
      toast(`${fmt.toUpperCase()} downloaded`);
    }catch(e){ toast(`download failed: ${e.message}`, false); }
  };
  Reports.del= async (rid, aid)=>{
    if(!confirm("Delete this report file?")) return;
    try{
      await API.del(`/reports/${rid}`);
      toast("Report deleted");
      const btn=document.querySelector(`#cell-${CSS.escape(aid)} button`);
      Reports.list(aid, btn);
    }catch(e){ toast(e.message,false); }
  };

  /* ═══════════ SETTINGS ═══════════ */
  async function Settings(){
    setBreadcrumb([{label:"Settings"}]);
    $view.innerHTML=`<div class="page-head"><h1 class="page">Settings</h1><p class="sub">Platform configuration and module catalog — read-only.</p></div>
      <div class="grid two-col">${skeletonCards(2)}</div><div class="card mt" style="height:90px"><div class="skeleton" style="height:100%"></div></div>`;
    let s, sc;
    try{ [s, sc]=await Promise.all([API.get("/settings"), API.get("/scanners")]); }
    catch(e){ $view.innerHTML+=errorState(e.message, Settings); return; }
    const appName = s.app || s.app_name || "World Monitor";
    const bin = s.binaries_present||{};
    const chainOk = bin.chainscanner, portiaOk = bin.portia, bomberOk = bin.bomber;
    $view.innerHTML = `<div class="page-head"><div><h1 class="page">Settings</h1><p class="sub">Workspace, toolchain and safety — live from <span class="mono">/api/settings</span>.</p></div></div>
      <div class="grid two-col">
        <div class="card"><div class="row spread"><h3 style="margin:0">Environment</h3>${s.lab_mode?`<span class="pill lab">● LAB_MODE</span>`:`<span class="badge">prod</span>`}</div>
          <dl class="kv mt">
            <dt>App</dt><dd style="font-weight:700">${esc(appName)}</dd>
            <dt>Version</dt><dd class="mono">${esc(s.version||"—")}</dd>
            <dt>Lab app</dt><dd class="mono small" style="word-break:break-all">${esc(s.lab_url||s.lab_app_url||"—")}</dd>
            <dt>Lab source</dt><dd class="mono small" style="word-break:break-all">${esc(s.lab_source_dir||"—")}</dd>
            <dt>Evidence</dt><dd class="mono small" style="word-break:break-all">${esc(s.evidence_dir||"—")}</dd>
            <dt>Reports</dt><dd class="mono small" style="word-break:break-all">${esc(s.report_dir||"—")}</dd>
          </dl>
          <div class="divider"></div>
          <div class="label-eyebrow" style="margin-bottom:8px">Toolchain — required for full coverage</div>
          <div style="display:grid;gap:8px">
            <div class="row spread" style="border:1px solid hsl(var(--border));padding:10px 12px;border-radius:6px"><span class="mono small" style="font-weight:700">chainscanner <span class="muted">· supply-chain</span></span>${chainOk?`<span class="pill lab">✔ present</span>`:`<span class="badge">✘ missing — scripts/build_go_tools.ps1</span>`}</div>
            <div class="row spread" style="border:1px solid hsl(var(--border));padding:10px 12px;border-radius:6px"><span class="mono small" style="font-weight:700">portia <span class="muted">· secrets</span></span>${portiaOk?`<span class="pill lab">✔ present</span>`:`<span class="badge">✘ missing</span>`}</div>
            <div class="row spread" style="border:1px solid hsl(var(--border));padding:10px 12px;border-radius:6px"><span class="mono small" style="font-weight:700">bomber <span class="muted">· SBOM</span></span>${bomberOk?`<span class="pill lab">✔ present</span>`:`<span class="badge">✘ missing</span>`}</div>
          </div></div>
        <div style="display:flex;flex-direction:column;gap:16px">
          <div class="card"><div class="row spread"><h3 style="margin:0">Session</h3><span class="badge">workspace</span></div>
            <p class="muted small mt">Signed in as <strong id="setEmail" style="color:hsl(var(--ink))">…</strong> · <span id="setRole" class="mono">…</span></p>
            <div class="row mt" style="gap:8px;flex-wrap:wrap"><button class="ghost tiny" onclick="location.hash='#/dashboard'">← Home</button><button class="ghost tiny" onclick="navigator.clipboard.writeText(localStorage.getItem('wm_token')||'').then(()=>toast('Token copied'))">⎘ Copy token</button><button class="ghost tiny danger" id="setLogout">Sign out</button></div>
            <div class="divider"></div>
            <div class="label-eyebrow" style="margin-bottom:8px">Danger zone</div>
            <button class="ghost tiny danger" id="setFresh">Fresh Start — delete all history</button>
            <p class="help">Clears assessments, findings, evidence and reports on this PC. Cannot be undone.</p></div>
          <div class="card"><div class="row spread"><h3 style="margin:0">Modules</h3><span class="badge">${(sc.modules||[]).length}</span></div>
            <div class="table-wrap mt" style="max-height:260px"><table><thead><tr><th>Key</th><th>Label</th></tr></thead><tbody>
              ${(sc.modules||[]).map(m=> `<tr><td class="mono small" style="font-weight:700">${esc(m.key)}</td><td class="muted small">${esc(m.label||m.key)}</td></tr>`).join("")}
            </tbody></table></div></div>
        </div>
      </div>
      <div class="card mt"><h3>Safety model</h3>
        <div class="prose mt">
          <p>Scans are refused unless <strong>(1)</strong> you confirm authorization and <strong>(2)</strong> target passes gate: loopback / RFC1918 or <span class="mono">ALLOWED_TARGETS</span>. Cloud-metadata IPs always blocked. Filesystem scanners jailed to lab tree.</p>
          <p>Evidence masks tokens/cookies/keys before storage. Every run is audited in <span class="mono">audit_logs</span>.</p>
        </div>
        <div class="divider"></div>
        <div class="row" style="gap:8px;flex-wrap:wrap"><a class="ghost xs" href="/api/docs" target="_blank" rel="noopener">OpenAPI →</a><a class="ghost xs" href="/api/health" target="_blank" rel="noopener">/health →</a><a class="ghost xs" href="/api/openapi.json" target="_blank" rel="noopener">openapi.json →</a><span class="muted small mono">AGPL-3.0</span></div>
      </div>`;
    API.get("/auth/me").then(u=>{ const e=document.getElementById("setEmail"); const r=document.getElementById("setRole"); if(e) e.textContent=u.email||"—"; if(r) r.textContent=(u.role||"").toUpperCase(); }).catch(()=>{});
    document.getElementById("setLogout")?.addEventListener("click", ()=> document.getElementById("logout")?.click());
    document.getElementById("setFresh")?.addEventListener("click", async ()=>{ if(!confirm("Delete ALL history?")) return; try{ await API.del("/assessments"); toast("Fresh start done"); }catch(e){ toast(e.message,false); } });
  }

  /* ── boot ── */
  console.log("[WorldMonitor] boot v60018, hash=" + location.hash);
  function fatalBoot(e, where){
    console.error("[WorldMonitor] FATAL at " + where + ":", e);
    try{
      $view.innerHTML = `<div class="container-editorial" style="padding:48px 0"><div class="card" style="border-color:hsl(0 70% 42%)"><h3 style="color:hsl(0 70% 42%)">App failed to start (${esc(where)})</h3><p class="muted small mono" style="word-break:break-all">${esc((e && e.stack) || (e && e.message) || String(e))}</p><p class="muted small">Screenshot this and share it. Try hard refresh (Ctrl+Shift+R) in incognito.</p></div></div>`;
    }catch(_){}
  }
  window.addEventListener("error", (ev)=>{ if(ev && ev.error && (!$view.innerHTML.trim() || $view.querySelector("#bootFallback"))) fatalBoot(ev.error, "window.onerror"); });
  try{
    document.getElementById("logout").onclick=()=>{
      API.setToken(null);
      forgetRun();
      stopPoll(); stopBanner();
      location.hash="#/login";
    };
  }catch(e){ fatalBoot(e, "logout-bind"); }
  window.addEventListener("hashchange", ()=>{ stopPoll(); Promise.resolve(router()).catch(e=> fatalBoot(e, "hashchange")); });
  window.addEventListener("hashchange", closeNav);
  document.addEventListener("visibilitychange", ()=>{ if(document.hidden) stopPoll(); else if(API.getToken() && location.hash.startsWith("#/assessment/")) router(); });
  window.addEventListener("beforeunload", ()=>{ stopPoll(); stopBanner(); });
  if(!location.hash) location.hash="#/dashboard";
  Promise.resolve().then(()=> router()).catch(e=> fatalBoot(e, "initial-router"));
  setInterval(()=>{ if(API.getToken()) refreshHealth(); }, 30000);
  document.addEventListener("keydown", e=>{
    if(!API.getToken() || e.target.tagName==="INPUT" || e.target.tagName==="TEXTAREA" || e.ctrlKey || e.metaKey) return;
    if(e.key==="n" || e.key==="N"){ e.preventDefault(); location.hash="#/assess/new"; }
  });
  console.log("[WorldMonitor] boot listeners attached");
})();


