/* World Monitor SPA — premium rewrite v2. Hardened, audited, accessibility & performance tuned. */
(() => {
  "use strict";

  const $view = document.getElementById("view");
  const $sidebar = document.getElementById("sidebar");
  const $topbar = document.getElementById("topbar");
  const $footer = document.getElementById("appFooter");
  const $banner = document.getElementById("runBanner");
  const $scrim = document.getElementById("scrim");
  const $crumb = document.getElementById("breadcrumb");
  const $health = document.getElementById("healthDot");
  const $menuBtn = document.getElementById("menuBtn");

  const SEV = ["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"];
  const SEV_ORDER = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFORMATIONAL:4 };
  const SEV_COLOR = { CRITICAL:"#f43f5e", HIGH:"#fb923c", MEDIUM:"#fbbf24", LOW:"#38bdf8", INFORMATIONAL:"#94a3b8" };
  const healthColor = s => s>=80 ? "#22c55e" : s>=60 ? "#84cc16" : s>=40 ? "#f59e0b" : s>=20 ? "#f97316" : "#ef4444";
  const HEALTH_WEIGHTS = {CRITICAL:5,HIGH:3,MEDIUM:1.5,LOW:0.5,INFORMATIONAL:0};
  const computeHealth = c => Math.max(0, Math.min(100, Math.round(100 - ( (c.CRITICAL||0)*5 + (c.HIGH||0)*3 + (c.MEDIUM||0)*1.5 + (c.LOW||0)*0.5 ))));
  const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
  const truncate = (s, n=48) => s.length>n ? s.slice(0,n)+"…" : s;
  let pollId = null, bannerTimer = null;
  let activeFindingSearch = "";

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
      if(e.clientX < 16 && API.getToken()) openDock();
      else if(e.clientX > 240) dockEl.classList.remove("dock-open");
    });
  }

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

  /* ── health dot ── */
  async function refreshHealth(){
    try{
      const controller = new AbortController();
      const t=setTimeout(()=>controller.abort(), 4000);
      const h = await fetch("/api/health", { signal: controller.signal }).then(r=> r.json());
      clearTimeout(t);
      const ok = h && h.status==="healthy";
      $health.className = "health " + (ok ? "ok" : "bad");
      $health.textContent=""; 
      const dot=document.createElement("i"); $health.appendChild(dot);
      $health.append(` ${ok ? "healthy" : "degraded"} · ${h.version||""}`);
      const fv = document.getElementById("footerVer");
      if(fv && h.version) fv.textContent = "v" + h.version;
    }catch{
      $health.className="health bad"; $health.textContent=""; const dot=document.createElement("i"); $health.appendChild(dot); $health.append(" offline");
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

  /* ═══════════ WELCOME — 7-5 lab exact, clamp 3.5rem 9vw 8.5rem leading 0.90, study/surface italic, imageReveal 1.2s saturate 0.12 ═══════════ */
  function Welcome(){
    const today = new Date().toLocaleDateString("en-GB",{day:"2-digit",month:"long",year:"numeric"}).toUpperCase();
    setBreadcrumb([{label:"Welcome"}]);
    $view.innerHTML = `
      <div class="bg-paper">
        <div class="container-editorial pt-6 sm:pt-7">
          <div class="grid grid-cols-12 gap-x-4 sm:gap-x-6 items-baseline meta-mono border-b border-ink/15 pb-3">
            <span class="col-span-3 sm:col-span-4 text-ink font-bold" style="letter-spacing:-0.01em">World Monitor Security Assessment</span>
            <span class="hidden sm:block sm:col-span-2 text-ink/70">Vol. I</span>
            <span class="hidden md:block md:col-span-3 text-ink/60">Independent · Security · Editorial</span>
            <span class="col-span-9 sm:col-span-6 md:col-span-3 text-right text-ink">${esc(today)}</span>
          </div>
        </div>
        <div class="container-editorial pt-10 sm:pt-12 lg:pt-14 pb-10">
          <div class="welcome-grid grid">
            <div class="col-span-12 lg:col-span-7 flex flex-col gap-8">
              <div class="flex items-center gap-4" style="animation:fadeUp .6s var(--ease-soft) both">
                <span class="meta-mono" style="color:hsl(var(--ash))">Issue 01 — Platform</span><span class="block h-px w-10 bg-ink/20"></span><span class="label-eyebrow">the surface, the signal, the fix</span>
              </div>
              <h1 class="welcome-hero-title" style="animation:fadeUp .85s var(--ease-soft) .08s both">A continuous<br><span class="display-italic">study</span> of your<br>attack <span class="display-italic">surface.</span></h1>
              <p class="text-[15px] leading-[1.7] text-ash max-w-xl" style="animation:fadeUp .6s var(--ease-soft) .14s both">World Monitor is a <span class="text-ink font-medium">continuous study</span> of your attack surface — not a scanner. We detect, verify, score and remediate with <span class="text-ink font-medium">fail-closed</span> gates and paper-trail evidence.</p>
              <p class="text-[13px] leading-[1.7] text-ash/80 max-w-xl" style="animation:fadeUp .6s var(--ease-soft) .16s both">A continuous study of your attack surface. A neat, clean editorial for engineering teams who care about the difference between a scan and a decision. Every assessment is authorized, every finding has provenance, every report is retetable.</p>
              <div class="flex flex-wrap gap-3 mt-1" style="animation:fadeUp .6s var(--ease-soft) .20s both">
                <a href="#/dashboard" class="inline-flex items-center gap-2 px-7 py-3.5 bg-ink text-paper hover:bg-ink/85 transition-all hover:-translate-y-px hover:shadow-md text-[14px] font-medium tracking-tight">Enter Home →</a>
                <a href="#/assess/new" class="inline-flex items-center gap-2 px-7 py-3.5 border border-ink text-ink hover:bg-ink hover:text-paper transition-colors text-[14px] font-medium tracking-tight">Commission</a>
              </div>
              <div class="grid grid-cols-3 gap-6 pt-6 border-t border-ink/10 max-w-xl" style="animation:fadeUp .6s var(--ease-soft) .26s both">
                <div><div class="font-display text-2xl text-ink leading-none">46</div><div class="meta-mono mt-1.5" style="font-size:10px">Tests passing</div></div>
                <div><div class="font-display text-2xl text-ink leading-none">8</div><div class="meta-mono mt-1.5" style="font-size:10px">Modules</div></div>
                <div><div class="font-display text-2xl text-ink leading-none">MMXXIV</div><div class="meta-mono mt-1.5" style="font-size:10px">Established</div></div>
              </div>
            </div>
            <div class="col-span-12 lg:col-span-5">
              <div class="welcome-image-wrap" style="animation:imageReveal 1.2s var(--ease-editorial) .12s both">
                <div class="absolute inset-0 bg-bone flex items-center justify-center">
                  <div class="w-24 h-24 rounded-full border border-ink/10 bg-paper flex items-center justify-center" style="animation:fadeUp .8s var(--ease-soft) .3s both"><svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" class="text-ink"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9v-5z"/><path d="M9 12l2 2 4-4"/></svg></div>
                </div>
                <div class="absolute inset-0 bg-gradient-to-t from-ink/5 via-transparent to-transparent"></div>
                <div class="absolute bottom-0 left-0 right-0 bg-paper/95 backdrop-blur-sm border-t border-ink/10 p-5 flex flex-col gap-1">
                  <span class="meta-mono" style="font-size:10px;letter-spacing:0.08em">Security Study — Threat Surface</span>
                  <span class="font-display text-sm text-ink">Production, Worldwide — <span class="display-italic">Verified</span></span>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div class="container-editorial"><div class="editorial-rule"></div></div>
        <div class="container-editorial py-8">
          <div class="grid grid-cols-12 gap-6 text-[13px] leading-relaxed">
            <div class="col-span-12 md:col-span-4"><div class="label-eyebrow">01 — Detect</div><p class="text-ash mt-2.5">Twelve scanners — authentication, authorization, headers, TLS, secrets, supply-chain — normalize to a canonical finding schema with CVSS 3.1 and fingerprint.</p></div>
            <div class="col-span-12 md:col-span-4"><div class="label-eyebrow">02 — Verify</div><p class="text-ash mt-2.5">Evidence is masked, files are jailed, DNS is pinned. Every finding carries provenance, not AI hallucination.</p></div>
            <div class="col-span-12 md:col-span-4"><div class="label-eyebrow">03 — Decide</div><p class="text-ash mt-2.5">Fail-closed gates: <span class="text-ink font-medium">BLOCKED</span> until health, findings and scans pass. Retest until <span class="text-ink font-medium">FIXED</span>.</p></div>
          </div>
        </div>
      </div>`;
  }

/* ═══════════ DASHBOARD (Home) — full single screen, health/circle/history, no extra scroll ═══════════ */
  async function Dashboard(){
    const today = new Date().toLocaleDateString("en-GB",{day:"2-digit",month:"long",year:"numeric"}).toUpperCase();
    setBreadcrumb([{label:"Home"}]);
    $view.innerHTML = `
      <div id="dashBody" class="bg-paper">
        <div class="container-editorial pt-4">
          <div class="grid grid-cols-12 gap-x-4 items-baseline meta-mono text-ash border-b border-ink/10 pb-2">
            <span class="col-span-4 sm:col-span-3 text-ink font-bold text-[11px]">World Monitor</span>
            <span class="hidden sm:block sm:col-span-3 text-ink/60">Vol. I — Home</span>
            <span class="hidden md:block md:col-span-3 text-ink/60">Health · Ranking · History</span>
            <span class="col-span-8 sm:col-span-6 md:col-span-3 text-right text-ink text-[11px]">${esc(today)}</span>
          </div>
        </div>
        <div class="container-editorial py-4">
          <div id="metricsGrid" class="grid grid-cols-1 lg:grid-cols-2 gap-4">${skeletonCards(2)}</div>
          <div id="kpiGrid" class="kpis mt-4">${skeletonKpis()}</div>
          <div id="dashCards" class="dash-cards grid mt-4"><div class="skeleton sk-card"></div><div class="skeleton sk-card"></div></div>
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
      <div class="card" style="display:flex;flex-direction:column"><div class="row spread"><strong style="font-size:13px">New Assessment</strong><span class="meta-mono" style="font-size:10px">Commission a new scan</span></div><p class="muted small mt" style="font-size:12px;line-height:1.5">Start an authorized assessment against a loopback target or source tree. Evidence is masked, files jailed, DNS pinned.</p><div style="margin-top:auto;padding-top:16px"><button onclick="location.hash='#/assess/new'" class="w-full bg-ink text-paper py-3 font-medium hover:bg-ink/90 transition-colors" style="font-size:14px">Commission Assessment →</button></div></div>
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
      <div class="page-head"><h1 class="page">New Assessment</h1><p class="sub">All testing is confined to authorized targets. LAB_MODE permits loopback / RFC1918 only — cloud metadata is always blocked.</p></div>
      <form id="assessForm" class="grid two-col" novalidate>
        <div class="card card-pad-lg">
          <div class="row" style="gap:8px;margin-bottom:12px;flex-wrap:wrap">
            <button type="button" class="ghost tiny" id="presetReal" title="Load REAL app defaults (port 3000)">🌐 Real app — :3000</button>
            <button type="button" class="ghost tiny" id="presetLab" title="Load lab playground (port 8080)">🧪 Playground — :8080</button>
            <button type="button" class="ghost tiny" id="presetSource" title="Source-only scan">📁 Source only</button>
          </div>
          <div class="field"><label for="target">Target URL <span class="muted" style="font-weight:400">— must be authorized & reachable</span></label>
            <input type="text" id="target" value="http://127.0.0.1:3000" placeholder="http://127.0.0.1:3000" spellcheck="false" autocomplete="off" aria-describedby="targetHelp"><div id="targetHelp" class="help" aria-live="polite"></div></div>
          <div class="field"><label for="sourcePath">Filesystem scope <span class="muted" style="font-weight:400">— for secrets / dependencies / supply_chain</span></label>
            <input type="text" id="sourcePath" placeholder="lab/vulnerable-world-monitor — leave empty if not scanning source" spellcheck="false" aria-describedby="sourceHelp"><div id="sourceHelp" class="help">Defaults to lab source when scanning source modules.</div></div>
          <div class="field"><label for="labToken">Lab token <button type="button" class="ghost xs" id="fetchToken" style="margin-left:8px">fetch from lab</button></label>
            <input type="text" id="labToken" placeholder="optional — enables authenticated checks" spellcheck="false" autocomplete="off">
            <div class="help">Fetched from <span class="mono">POST /lab/token</span> via the lab demo account (alice/user123). Never persisted.</div>
          </div>
          <details class="mt"><summary>Per-module target overrides (advanced)</summary>
            <div class="field mt"><label for="t-authorization">IDOR → reports</label><input type="text" id="t-authorization" placeholder="http://127.0.0.1:8080/api/reports" spellcheck="false"></div>
            <div class="field"><label for="t-api">Rate limit → monitor</label><input type="text" id="t-api" placeholder="http://127.0.0.1:8080/api/monitor" spellcheck="false"></div>
            <div class="field"><label for="t-sqli">SQLi → search (input_validation)</label><input type="text" id="t-sqli" placeholder="http://127.0.0.1:8080/api/search?id=1" spellcheck="false"></div>
            <div class="field"><label for="t-input_validation">XSS reflection → greet</label><input type="text" id="t-input_validation" placeholder="http://127.0.0.1:8080/greet?name=x" spellcheck="false"></div>
            <p class="help">Only used when the corresponding module is selected. Map to :8080 for the vulnerable lab or :3000 for the real app.</p>
          </details>
          <label class="row" style="gap:10px;cursor:pointer;margin-top:16px;background:rgba(251,191,36,.06);border:1px solid rgba(251,191,36,.18);padding:10px 12px;border-radius:10px">
            <input type="checkbox" id="authorized" style="width:auto" aria-describedby="authHelp">
            <span style="font-size:12.5px">I confirm this target is <strong>authorized for security testing</strong> and I have permission to scan it.</span>
          </label><div id="authHelp" class="help" style="margin-top:6px">Server enforces the gate regardless of UI state.</div>
          <div class="mt"><button type="submit" id="startBtn" disabled style="width:100%;padding:12px" aria-describedby="startHelp">START ASSESSMENT →</button>
            <p id="startHelp" class="help" style="text-align:center">Check “authorized” and pick at least one module to enable.</p></div>
        </div>
        <div class="card"><div class="row spread"><strong>Select modules</strong><span class="badge" id="modCount">6 selected</span></div>
          <p class="muted small" style="margin:6px 0 10px">Pick at least one. First six are a solid baseline; add source & supply-chain for the real app.</p>
          <div style="display:flex;gap:6px;margin-bottom:8px"><input id="modFilter" type="text" placeholder="Filter modules…" style="flex:1;padding:7px 10px" aria-label="Filter modules"><button type="button" class="ghost xs" id="selAll">All</button><button type="button" class="ghost xs" id="selNone">Clear</button></div>
          <div class="table-wrap" style="max-height:520px"><table><thead><tr><th style="width:36px"></th><th>Module</th><th>Coverage</th></tr></thead><tbody id="modTable">
            ${MODULES.map(([k,l,d],i)=> `<tr data-mod="${esc(k)}"><td style="text-align:center"><input type="checkbox" name="mod" value="${esc(k)}" style="width:auto" ${i<6?"checked":""} aria-label="${esc(l)}"></td><td><strong style="font-size:12.5px">${esc(l)}</strong><div class="mono muted small">${esc(k)}</div></td><td class="muted small mono">${esc(d)}</td></tr>`).join("")}
          </tbody></table></div>
        </div>
      </form>`;
    const form=document.getElementById("assessForm");
    const cb=document.getElementById("authorized"), btn=document.getElementById("startBtn");
    const modCount=document.getElementById("modCount");
    const targetInput=document.getElementById("target");
    const targetHelp=document.getElementById("targetHelp");
    function updateModCount(){ const n=form.querySelectorAll("input[name=mod]:checked").length; modCount.textContent=n+" selected"; modCount.style.color=n? "var(--text-1)" : "var(--crit)"; btn.disabled = !(cb.checked && n>0); }
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

  /* ═══════════ FINDINGS LIST ═══════════ */
  async function FindingsList(){
    setBreadcrumb([{label:"Findings"}]);
    $view.innerHTML = `
      <div class="page-head row spread"><div><h1 class="page">Findings</h1><p class="sub">All normalized findings across assessments — deduplicated, scored with CVSS v3.1.</p></div>
        <div class="page-actions"><span class="badge" id="findCount">—</span></div></div>
      <div class="row" style="gap:8px;margin-bottom:12px;flex-wrap:wrap">
        <input id="findSearch" type="text" placeholder="Search title, check_id, category…" style="flex:1;min-width:220px" aria-label="Search findings">
        <div class="filter-bar" id="filterBar" role="group" aria-label="Filter by severity">
          <button class="chip-filter active" data-sev="" aria-pressed="true">All</button>
          ${SEV.map(s=> `<button class="chip-filter" data-sev="${s}" aria-pressed="false"><span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:${SEV_COLOR[s]}" aria-hidden="true"></span> ${s}</button>`).join("")}
        </div>
      </div>
      <div id="fl">${skeletonTable(6)}</div>`;
    const el=$view.querySelector("#fl");
    const countEl=document.getElementById("findCount");
    const searchEl=document.getElementById("findSearch");
    let allRows=[];
    let activeSev="";
    async function load(){
      el.innerHTML=skeletonTable(6);
      try{
        allRows=await API.get("/assessments/-/findings");
        if(countEl) countEl.textContent=allRows.length+" findings";
        render();
      }catch(e){ el.innerHTML=errorState(e.message, load); }
    }
    function render(){
      let rows=[...allRows];
      if(activeSev) rows=rows.filter(r=> r.severity===activeSev);
      if(activeFindingSearch){
        const q=activeFindingSearch.toLowerCase();
        rows=rows.filter(r=> (r.title+" "+r.check_id+" "+r.category+" "+r.scanner).toLowerCase().includes(q));
      }
      if(countEl) countEl.textContent=rows.length+" / "+allRows.length;
      if(!rows.length){
        const hint = activeSev || activeFindingSearch ? `No findings match filter. Try clearing search or severity.` : "No findings yet — run an assessment first.";
        el.innerHTML=emptyState({icon: activeSev ? "◍" : "◈", title: !rows.length && (activeSev||activeFindingSearch) ? `No matching findings` : "No findings yet", hint, action: !activeSev && !activeFindingSearch ? `<button onclick="location.hash='#/assess/new'">Run an assessment</button>` : `<button class="ghost tiny" onclick="document.getElementById('findSearch').value='';activeFindingSearch='';document.querySelectorAll('.chip-filter').forEach(b=>{b.classList.remove('active'); b.setAttribute('aria-pressed','false')});document.querySelector('[data-sev=\\'\\']').classList.add('active');document.querySelector('[data-sev=\\'\\']').setAttribute('aria-pressed','true');activeSev='';render();">Clear filters</button>`});
        // re-bind clear button inline handler needs render access via global
        window._findingsRender=render;
        return;
      }
      rows.sort((a,b)=> (SEV_ORDER[a.severity]??9) - (SEV_ORDER[b.severity]??9));
      el.innerHTML=`<div class="card" style="padding:0;overflow:hidden"><div class="table-wrap" style="border:none"><table><thead><tr><th>Severity</th><th>CVSS</th><th>Title</th><th>Category</th><th>Status</th><th></th></tr></thead><tbody>
        ${rows.map(f=> `<tr class="click" onclick="location.hash='#/finding/${esc(f.id)}'">
          <td><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span></td>
          <td class="mono" style="font-weight:700">${f.cvss_score ?? "—"}</td>
          <td style="font-weight:500;max-width:360px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(f.title)}">${esc(f.title)}</td>
          <td class="muted small mono">${esc((f.category||"").replaceAll("_"," "))}</td>
          <td class="small">${esc(f.status)}${f.retest_status ? `<br><span class="${f.retest_status==="FIXED"?"retest-fixed":"retest-present"}" style="font-size:11px">${esc(f.retest_status)}</span>`:""}</td>
          <td style="color:var(--text-3)" aria-hidden="true">›</td></tr>`).join("")}
      </tbody></table></div></div>`;
    }
    searchEl.addEventListener("input", debounce(e=>{
      activeFindingSearch=e.target.value.trim();
      render();
    }, 250));
    document.getElementById("filterBar")?.addEventListener("click", e=>{
      const btn=e.target.closest(".chip-filter");
      if(!btn) return;
      document.querySelectorAll(".chip-filter").forEach(b=> { b.classList.remove("active"); b.setAttribute("aria-pressed","false"); });
      btn.classList.add("active"); btn.setAttribute("aria-pressed","true");
      activeSev=btn.dataset.sev || "";
      render();
    });
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
    $view.innerHTML = `<div class="page-head"><h1 class="page">Settings</h1><p class="sub">Platform configuration and module catalog — read-only.</p></div>
      <div class="grid two-col">
        <div class="card"><h3>Environment</h3>
          <dl class="kv mt">
            <dt>App</dt><dd style="font-weight:600">${esc(appName)}</dd>
            <dt>Version</dt><dd class="mono">${esc(s.version||"—")}</dd>
            <dt>LAB_MODE</dt><dd>${s.lab_mode ? `<span class="pill lab">● ENABLED — loopback only</span>` : `<span class="badge">disabled</span>`}</dd>
            <dt>Lab app</dt><dd class="mono small" style="word-break:break-all">${esc(s.lab_url||s.lab_app_url||"—")}</dd>
            <dt>Lab source</dt><dd class="mono small" style="word-break:break-all">${esc(s.lab_source_dir||"—")}</dd>
            <dt>Evidence dir</dt><dd class="mono small" style="word-break:break-all">${esc(s.evidence_dir||"—")}</dd>
            <dt>Report dir</dt><dd class="mono small" style="word-break:break-all">${esc(s.report_dir||"—")}</dd>
            <dt>portia</dt><dd>${s.binaries_present?.portia ? `<span class="pill lab">✔ present</span>` : `<span class="badge">✘ not found</span>`}</dd>
            <dt>bomber</dt><dd>${s.binaries_present?.bomber ? `<span class="pill lab">✔ present</span>` : `<span class="badge">✘ not found</span>`}</dd>
            <dt>chainscanner</dt><dd>${s.binaries_present?.chainscanner ? `<span class="pill lab">✔ present</span>` : `<span class="badge">✘ not found</span>`}</dd>
          </dl></div>
        <div class="card"><div class="row spread"><h3 style="margin:0">Modules</h3><span class="badge">${(sc.modules||[]).length}</span></div>
          <div class="table-wrap mt"><table><thead><tr><th>Key</th><th>Label</th><th>Needs</th></tr></thead><tbody>
            ${(sc.modules||[]).map(m=> `<tr><td class="mono small" style="font-weight:600">${esc(m.key)}</td><td class="muted small">${esc(m.label||m.key)}</td><td class="mono small muted">${esc(m.needs||"")}</td></tr>`).join("")}
          </tbody></table></div>
        </div>
      </div>
      <div class="card mt"><h3>Safety model</h3>
        <div class="prose mt">
          <p>Scans are refused unless <strong>(1)</strong> the operator confirms authorization and <strong>(2)</strong> the target passes the gate: loopback / RFC1918 resolution or an explicit <span class="mono">ALLOWED_TARGETS</span> entry. Cloud-metadata IPs are always blocked. Filesystem scanners are jailed to the lab tree.</p>
          <p>Evidence masks tokens, cookies and keys before storage; sensitive headers are redacted. Every assessment, scan, report and retest is written to <span class="mono">audit_logs</span>.</p>
        </div>
        <div class="divider"></div>
        <div class="row" style="gap:8px;flex-wrap:wrap"><a class="ghost xs" href="/api/docs" target="_blank" rel="noopener">OpenAPI →</a><a class="ghost xs" href="/api/health" target="_blank" rel="noopener">/health →</a><a class="ghost xs" href="/api/openapi.json" target="_blank" rel="noopener">openapi.json →</a><span class="muted small mono">AGPL-3.0 · see NOTICE.md</span></div>
      </div>`;
  }

  /* ── boot ── */
  document.getElementById("logout").onclick=()=>{
    API.setToken(null);
    forgetRun();
    stopPoll(); stopBanner();
    location.hash="#/login";
  };
  window.addEventListener("hashchange", ()=>{ stopPoll(); router(); });
  window.addEventListener("hashchange", closeNav);
  // cleanup timers on page hide/unload
  document.addEventListener("visibilitychange", ()=>{ if(document.hidden) stopPoll(); else if(API.getToken() && location.hash.startsWith("#/assessment/")) router(); });
  window.addEventListener("beforeunload", ()=>{ stopPoll(); stopBanner(); });
  if(!location.hash) location.hash="#/dashboard";
  router();
  setInterval(()=>{ if(API.getToken()) refreshHealth(); }, 30000);
  // keyboard shortcut: N = new assessment when authenticated
  document.addEventListener("keydown", e=>{
    if(!API.getToken() || e.target.tagName==="INPUT" || e.target.tagName==="TEXTAREA" || e.ctrlKey || e.metaKey) return;
    if(e.key==="n" || e.key==="N"){ e.preventDefault(); location.hash="#/assess/new"; }
  });
})();


