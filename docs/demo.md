# Demo Script (judges / evaluators)

Total time: ~6 minutes. Everything runs on localhost; nothing leaves the machine.

## 0. One-time setup (before the demo)

```powershell
.\.venv\Scripts\pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File scripts\build_go_tools.ps1
Copy-Item .env.example .env
```

## 1. Start both services

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1
```

Platform: http://127.0.0.1:8000 · Lab: http://127.0.0.1:8080 (clearly labeled
VULNERABLE LAB). Sign in as `admin@example.com` / `ChangeMe_Admin_2026!`.

## 2. Show the safety gate first

* New Assessment → try unchecking **authorization** → START stays disabled.
* (Optional) paste `https://example.com` as target with authorization ticked →
  backend refuses with `LAB_MODE permits only localhost/private-lab targets`.
  This is the single most important slide of the demo.

## 3. Run the full assessment

Restore `http://127.0.0.1:8080/api`, keep the pre-filled per-module lab layout,
tick authorization, START. Narrate while scanners stream:

> "Authentication probes JWT handling — watch for the none-algorithm check…
> Authorization walks object IDs as another user… Rate-limit module fires ~200
> paced requests and tries IP-spoofing bypasses… Headers grades CSP/HSTS…"

## 4. Results & drill-down

Dashboard shows real counts (typically 4-5 CRITICAL / 5 HIGH). Open:
* **JWT 'none' accepted (9.8)** — evidence shows the forged token exchange.
* **IDOR** — alice reading bob's/admin's reports, status 200.
* **Hardcoded credential** — note the secret is masked even in evidence.

## 5. Retest loop (the wow moment)

1. On *Missing HSTS* click RETEST → `STILL_PRESENT` (red).
2. In the lab window: Ctrl+C, then `$env:WM_LAB_FIX_HEADERS="1"` and re-run
   `python lab\vulnerable-world-monitor\app.py` (or press the prepared second
   terminal in scripts/start_all.ps1 -FixHeaders).
3. RETEST again → `FIXED` (green) — original + retest evidence both retained.

Same flow works for IDOR via `-PatchIdor`.

## 6. Reports

Reports page → generate PDF/JSON/MD for the assessment. Open the PDF: cover,
executive summary with real counts, methodology, color-coded findings with CVSS
vectors and remediation, evidence/retest statement, conclusion.

## 7. CLI (same engine)

```powershell
python cli\world_monitor.py findings --severity CRITICAL
python cli\world_monitor.py report <assessment-id> --format pdf
```

## Talking points if asked

* Why not integrate all 20 repos? → Phase-0 audit dropped 10 (documented in
  docs/repository-audit.md): wrong domain, exotic toolchains, no JSON output,
  or pure duplicates.
* Where do scores come from? → CVSS v3.1 formulas computed from curated vectors
  per check; rationale text explains each metric choice.
* Can it scan a real server? → Add it to ALLOWED_TARGETS with LAB_MODE=false;
  architecture unchanged, gate still mandatory and audited.
