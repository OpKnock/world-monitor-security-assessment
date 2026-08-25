/* Tiny SVG chart helpers — no chart libraries. */
const Charts = (() => {
  const SEV_COLORS = {
    CRITICAL: "#ff4d5e", HIGH: "#ff7a45", MEDIUM: "#ffb227",
    LOW: "#38bdf8", INFORMATIONAL: "#94a3b8",
  };

  function donut(counts, size = 150) {
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
    const total = order.reduce((s, k) => s + (counts[k] || 0), 0);
    const r = size / 2 - 12, cx = size / 2, cy = size / 2;
    let segs = "", angle = -Math.PI / 2;
    for (const k of order) {
      const v = counts[k] || 0;
      if (!v || !total) continue;
      const sweep = (v / total) * Math.PI * 2;
      const x1 = cx + r * Math.cos(angle), y1 = cy + r * Math.sin(angle);
      angle += sweep;
      const x2 = cx + r * Math.cos(angle), y2 = cy + r * Math.sin(angle);
      const large = sweep > Math.PI ? 1 : 0;
      segs += `<path d="M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}" fill="none" stroke="${SEV_COLORS[k]}" stroke-width="14" stroke-linecap="butt"/>`;
    }
    const label = total
      ? `<text x="${cx}" y="${cy - 2}" text-anchor="middle" fill="#dbe4f5" font-size="24" font-family="monospace" font-weight="700">${total}</text>
         <text x="${cx}" y="${cy + 16}" text-anchor="middle" fill="#8fa3c8" font-size="9.5">FINDINGS</text>`
      : `<text x="${cx}" y="${cy + 4}" text-anchor="middle" fill="#5b6f96" font-size="10">NO DATA</text>`;
    return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#101b31" stroke-width="14"/>${segs}${label}</svg>`;
  }

  function catBars(categories) {
    const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFORMATIONAL: 0 };
    const rows = Object.entries(categories).sort((a, b) => rank[b[1].worst_severity] - rank[a[1].worst_severity]);
    const maxTotal = Math.max(1, ...rows.map(([, v]) => v.total));
    const labels = {
      AUTHENTICATION: "Authentication", AUTHORIZATION: "Authorization",
      INPUT_VALIDATION: "Input Validation", API_SECURITY: "API Security",
      CLIENT_SECURITY: "Client Security", SECURE_COMMUNICATION: "TLS",
      DATA_PRIVACY: "Privacy / Secrets", DEPENDENCIES: "Dependencies",
      INFRASTRUCTURE: "Infrastructure",
    };
    return rows.map(([key, v]) => {
      const color = SEV_COLORS[v.worst_severity] || "#94a3b8";
      const pct = Math.round((v.total / maxTotal) * 100);
      return `<div class="cat-row">
        <span class="name">${labels[key] || key}</span>
        <span class="bar"><i style="width:${pct}%;background:${color}"></i></span>
        <span class="tag"><span class="sev ${v.worst_severity}">${v.worst_severity}</span></span>
        <span class="mono muted" style="width:22px;text-align:right">${v.total}</span>
      </div>`;
    }).join("") || `<p class="muted small">Run an assessment to populate the posture matrix.</p>`;
  }

  return { donut, catBars, SEV_COLORS };
})();
