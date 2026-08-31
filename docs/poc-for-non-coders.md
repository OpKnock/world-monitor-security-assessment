# Proof of Concept ? For Non-Coders (Plain English)

> **One sentence:** Most tools tell you what is wrong. This platform proves a fix worked ? `Broken ? Scan ? Finding ? Fix ? Retest ? FIXED ? Report`.

This document explains the PoC so a non-coder (judge, manager, student) can verify it without reading code. All proofs are **live, masked, and reproducible** on `127.0.0.1` only.

---

## 1. What you will see live (6 minutes)

| Act | What happens | What you see | Proof |
|-----|--------------|--------------|-------|
| **1. Vulnerable** | Lab started *without* fix toggles (`python lab/vulnerable-world-monitor/app.py`) | `SECURITY HEALTH 68/100` At risk, `[CRITICAL 2] [HIGH 4]` | Dashboard hero with conic ring 68% red, health bar 68% |
| **2. Scan** | `New Assessment ? Playground :8080 ? authorized ? Start` | Live progress `headers` ? `F`, `input_validation` ? SQLi, `authorization` ? IDOR | Scanner runs table `completed` with checks, dashboard `TOTAL FINDINGS` updates |
| **3. Finding** | Click `Missing security headers` | `Why this matters?` card: *Risk:* `MEDIUM` CVSS 5.3, *Affected:* `http://127.0.0.1:8080`, *Fix:* `Add HSTS/CSP`, *Retest:* `Pending` | Finding detail with `CVSS vector AV:N/AC:L/...` plain rationale, `Business impact: Attackers can inject scripts...`, `Evidence` JSON masked `********` |
| **4. Still present** | Click **Retest** (no fix yet) | Overlay `Verifying fix...` spinner ? `STILL PRESENT` red | `retest_status=STILL_PRESENT`, `retest_count=1`, evidence re-linked |
| **5. Fix** | Restart lab `$env:WM_LAB_FIX_HEADERS="1"; python lab/.../app.py` | Lab now sends `Strict-Transport-Security, Content-Security-Policy` | `curl -I http://127.0.0.1:8080` shows headers |
| **6. Fixed** | Same finding ? **Retest** | Overlay `FIXED` green ? toast `FIXED - remediation verified` | `retest_status=FIXED`, dashboard `91/100` Healthy `+23 pts` `Before/after: 68 ? 91` |
| **7. Report** | `Reports ? Generate PDF` | PDF cover `SECURITY HEALTH 68 ? 91`, executive summary plain English, color-coded findings, evidence, retest statement | PDF/JSON/MD/CSV all derived from live DB, no templated numbers |

> **No auto-fix** ? the platform never edits code. The *developer* fixes (lab toggle or real source edit), the platform *verifies* via retest fingerprint `sha1(target|category|check_id|component)`.

---

## 2. Proofs in detail (non-technical)

### A. Security Health Score 0?100 ? before/after
- **Before:** `68/100` At risk, `Penalty 32` from `2C+4H+6M+3L`, donut `CRITICAL 2` red, bar 68% orange.
- **After fix:** `91/100` Healthy, `Penalty 9` from `0C+1H+3M+2L`, bar 91% green, `Before/after: 68 ? 91 +23 pts`.
- **Weights:** `CRITICAL 5, HIGH 3, MEDIUM 1.5, LOW 0.5` ? `score = 100 - penalty` (clamped). Stored in `GET /api/dashboard` `health{score,penalty,weights}` + `recent_health` (last 8) + `retest_summary`.

### B. Why this matters? card (per finding)
- **Technical Issue:** e.g., `JWT 'none' accepted (9.8)` ? token with `alg:none` bypasses signature.
- **Risk:** `CRITICAL` CVSS `9.8` `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` ? *plain rationale:* `Standard preset for this check.`; `Business impact: Complete authentication bypass ? attacker becomes any user.`
- **Affected:** `http://127.0.0.1:8080/api/token` (mono, copy button).
- **Fix:** `Reject alg none, verify signature with strong secret.` (plain steps).
- **Retest:** `Pending` ? `STILL_PRESENT` (1 retest) ? `FIXED` (2 retests) ? history preserved, never false `FIXED`.

### C. Evidence ? masked, verifiable
- Per finding `Evidence` `backend/app/engine/evidence.py` `EvidenceStore.save(kind="scanner_output", summary, payload)` ? `EVIDENCE_DIR/{assessment_id}/{finding_id}.json` with `********` for `Authorization/Cookie/x-api-key` and secret patterns `AKIA..., ghp_..., sk-...`, `Bearer ...` ? masked before write.
- UI shows `Evidence 2` with `JSON` `scanner_output` `zdv: ...` and `Copy` button; sensitive headers redacted. Download via `GET /api/assessments/findings/{id}/evidence` (masked).

### D. Retest fingerprint ? no false FIXED
- `persist_raw_findings` fingerprints `sha1(target|category|check_id|component)`; retest re-runs *only* that check's scanner, compares fingerprints. If scanner fails ? `INCONCLUSIVE`, not `FIXED`.

### E. Reports ? for non-coders
- `backend/app/engine/reporting.py` `generate_report` ? PDF cover `World Monitor Security Assessment`, executive summary `Total findings 15, Critical 2... Health 68 ? 91`, methodology `12 modules`, color-coded findings table, `Why this matters` per finding, `Evidence` excerpt, `Retest statement` `FIXED on 2026-08-31`, conclusion. JSON/MD/CSV same data.

---

## 3. How to verify without coding

1. **Copy-paste Quick Start** `README.md: Quick Start ? Fresh Clone` ? 6 blocks for PowerShell/CMD/Bash, each copy-pasteable, `python scripts/start_all.py` (one terminal, one command) handles already-busy ports.
2. **Check health:** `http://127.0.0.1:8000` ? Dashboard `SECURITY HEALTH` ring and `Health` column in `Recent assessments` (badge green `91`).
3. **Check Findings tab:** `Findings` ? `All 15` with `CRITICAL 2` red, `CVSS 9.8`, `Status OPEN` + `Retest FIXED` green.
4. **Check retest:** Pick any `MEDIUM` ? `Retest` ? overlay `Verifying...` ? `STILL_PRESENT` (no fix) ? fix lab ? `FIXED`.
5. **Check evidence:** `Finding detail` ? `Evidence` `2` ? `Copy` ? JSON shows `********` for secrets.
6. **Check report:** `Reports` ? `Generate PDF` ? open ? see `Health 68?91`, `Why this matters` plain English.

All proofs are **localhost-only** (`LAB_MODE=true` loopback/RFC1918 gate, `169.254.169.254` blocked, `audit_logs`).

---

## 4. For judges ? one slide

```
Most tools: Scan ? List ? Done
This platform: Detect ? Verify ? Document ? Score (CVSS) ? Explain (Why) ? Remediate (guidance) ? Retest ? FIXED ? Report (PDF/JSON/MD/CSV)
Innovation = Retest Until Fixed (verified, not claimed)
```

**No AI chatbot, no auto-fix, no ?we built World Monitor?** ? `targets/real-world-monitor` is upstream `koala73/worldmonitor` as assessment target (submodule).
