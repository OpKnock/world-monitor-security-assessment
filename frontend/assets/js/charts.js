/* SVG chart helpers — no external deps. Animated donut + category bars. */
const Charts = (() => {
  const SEV_COLORS = {
    CRITICAL:"#ff4d5e", HIGH:"#ff7a45", MEDIUM:"#ffb227",
    LOW:"#38bdf8", INFORMATIONAL:"#94a3b8",
  };
  const SEV_GRAD = {
    CRITICAL:["#ff4d5e","#e11d48"], HIGH:["#ff7a45","#ea580c"],
    MEDIUM:["#ffb227","#d97706"], LOW:["#38bdf8","#0ea5e9"],
    INFORMATIONAL:["#94a3b8","#64748b"],
  };

  function donut(counts, size = 152){
    const order = ["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"];
    const total = order.reduce((s,k)=> s + (counts[k]||0), 0);
    const r = size/2 - 14, cx = size/2, cy = size/2;
    const circ = 2 * Math.PI * r;
    let segs = "", angle = -Math.PI/2;
    let offset = 0;
    for(const k of order){
      const v = counts[k]||0;
      if(!v || !total) continue;
      const sweep = (v/total) * Math.PI*2;
      const x1 = cx + r*Math.cos(angle), y1 = cy + r*Math.sin(angle);
      angle += sweep;
      const x2 = cx + r*Math.cos(angle), y2 = cy + r*Math.sin(angle);
      const large = sweep > Math.PI ? 1 : 0;
      const dash = (v/total)*circ, gap = circ - dash;
      // segment with glow filter + rounded caps
      segs += `<path d="M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}" fill="none" stroke="${SEV_COLORS[k]}" stroke-width="13" stroke-linecap="round" opacity=".96" style="filter:drop-shadow(0 0 6px ${SEV_COLORS[k]}66)"/>`;
    }
    const label = total
      ? `<text x="${cx}" y="${cy-1}" text-anchor="middle" fill="#e2e8f0" font-size="26" font-family="JetBrains Mono,monospace" font-weight="800">${total}</text>
         <text x="${cx}" y="${cy+15}" text-anchor="middle" fill="#64748b" font-size="9" font-family="Inter,sans-serif" font-weight="700" letter-spacing=".12em">FINDINGS</text>`
      : `<text x="${cx}" y="${cy+4}" text-anchor="middle" fill="#4a5a7a" font-size="11" font-family="Inter,sans-serif" font-weight="600">NO DATA</text>`;
    return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" role="img" aria-label="Severity distribution, ${total} total findings">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="rgba(30,45,74,.9)" stroke-width="13"/>
      <g style="animation:donut-in .7s cubic-bezier(.21,1.02,.73,1)">${segs}</g>
      ${label}
      <style>@keyframes donut-in{from{opacity:0;transform:scale(.92)}to{opacity:1;transform:scale(1)}}</style>
    </svg>`;
  }

  function catBars(categories){
    const rank = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1, INFORMATIONAL:0 };
    const rows = Object.entries(categories).sort((a,b)=> (rank[b[1].worst_severity]??-1) - (rank[a[1].worst_severity]??-1));
    if(!rows.length) return `<div class="empty" style="padding:22px"><div class="empty-ill">◈</div><p class="muted small" style="margin:0">Run an assessment to populate the posture matrix.</p></div>`;
    const maxTotal = Math.max(1, ...rows.map(([,v])=> v.total));
    const labels = {
      AUTHENTICATION:"Authentication", AUTHORIZATION:"Authorization",
      INPUT_VALIDATION:"Input Validation", API_SECURITY:"API Security",
      CLIENT_SECURITY:"Client Security", SECURE_COMMUNICATION:"TLS",
      DATA_PRIVACY:"Privacy / Secrets", DEPENDENCIES:"Dependencies",
      INFRASTRUCTURE:"Infrastructure",
    };
    return rows.map(([key,v], i)=>{
      const color = SEV_COLORS[v.worst_severity] || "#94a3b8";
      const pct = Math.round((v.total / maxTotal)*100);
      const label = labels[key] || key.replaceAll("_"," ");
      return `<div class="cat-row" style="animation:row-in .4s both;animation-delay:${i*45}ms">
        <span class="name" title="${key}">${label}</span>
        <span class="bar"><i style="width:${pct}%;background:${color};box-shadow:0 0 10px ${color}55"></i></span>
        <span class="tag"><span class="sev ${v.worst_severity}">${v.worst_severity}</span></span>
        <span class="count">${v.total}</span>
      </div>`;
    }).join("") + `<style>@keyframes row-in{from{opacity:0;transform:translateX(6px)}to{opacity:1;transform:translateX(0)}}</style>`;
  }

  return { donut, catBars, SEV_COLORS, SEV_GRAD };
})();
