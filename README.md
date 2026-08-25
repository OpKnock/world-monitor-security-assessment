# World Monitor — Security Assessment Platform

A unified, localhost-only security assessment platform that
scans an intentionally vulnerable "World Monitor" lab application, normalizes results
into one finding format, scores them with CVSS v3.1, stores sanitized evidence,
explains business impact, recommends remediation, supports **retest-until-FIXED**,
and generates professional PDF/JSON/Markdown reports.

```
DETECT → VERIFY → DOCUMENT → SCORE → EXPLAIN IMPACT → REMEDIATE → RETEST → REPORT
```

## Quick start (Windows, no Docker required)

```powershell
git clone <this-repo> world-monitor-security-assessment
cd world-monitor-security-assessment
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
Copy-Item .env.example .env          # defaults are fine for the demo
powershell -ExecutionPolicy Bypass -File scripts\build_go_tools.ps1   # builds bin\portia.exe, bomber.exe, chainscanner.exe
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1
```

| Service | URL | Notes |
|---|---|---|
| **Platform UI** | http://127.0.0.1:8000 | sign in `admin@example.com` / `ChangeMe_Admin_2026!` |
| Vulnerable lab | http://127.0.0.1:8080 | **intentionally insecure — loopback only** |
| API docs | http://127.0.0.1:8000/api/docs | OpenAPI |

Demo users on the lab: `alice/user123`, `bob/user456`, `admin/admin123`.

### The 60-second demo

1. Sign in → **New Assessment** → keep the pre-filled World Monitor lab layout.
2. Tick *"I confirm this target is authorized…"* (mandatory gate) → **START ASSESSMENT**.
3. Watch live per-scanner progress → findings appear with CVSS + evidence.
4. Open a finding → request/response evidence (masked) → remediation.
5. Click **RETEST** → `STILL_PRESENT`.
6. Restart the lab with the fix toggle (`$env:WM_LAB_FIX_HEADERS=1`) → **RETEST** again → `FIXED`.
7. **Reports** → generate PDF/JSON/MD.

Or entirely from the CLI (same engine):

```powershell
.\.venv\Scripts\python cli\world_monitor.py scan --lab
.\.venv\Scripts\python cli\world_monitor.py findings --severity CRITICAL
.\.venv\Scripts\python cli\world_monitor.py retest <finding-id>
.\.venv\Scripts\python cli\world_monitor.py report <assessment-id> --format pdf
```

## What it detects on the lab (real results, never faked)

| Finding | Severity | CVSS |
|---|---|---|
| JWT `none` algorithm accepted | CRITICAL | 9.8 |
| Boolean-based blind SQL injection (`/api/search`) | CRITICAL | 7.5 |
| Hardcoded demo credentials in source ×3 | CRITICAL | 7.4 |
| Broken object-level authorization / IDOR (`/api/reports/{id}`) | HIGH | 6.5 |
| Reflected input without encoding (`/greet`) | HIGH | 6.1 |
| Missing CSP · HSTS · rate limiting | HIGH | 4–6 |
| Missing XCTO / XFO (+ cookie flag audit) | MEDIUM | 4.3 |
| Missing Referrer-Policy / Permissions-Policy | LOW | 3.1 |

Optional modules add TLS/certificate checks and OSV-based dependency CVEs.

## Assessing the REAL World Monitor (two-target model)

1. Clone the genuine application: `git clone https://github.com/koala73/worldmonitor targets\real-world-monitor` then `npm install` and run `npm run dev -- --port 3000`.
2. Static sweep: New Assessment -> Load REAL World Monitor source -> Secrets + Dependencies + Supply Chain.
3. Dynamic sweep: target http://127.0.0.1:3000 -> Authentication/API/Headers/TLS/Input Validation.

## Repository layout

```
backend/app/engine/    authorization gate · orchestration/jobs · finding engine
                       evidence engine · CVSS engine · reporting (PDF/JSON/MD)
backend/app/scanners/  adapters: headers · authn/authz/rate-limit (vendored) ·
                       sqli+xss · tls · secrets(portia) · dependencies(bomber)
backend/app/vendor/    vendored upstream scanners (AGPL — see NOTICE.md)
frontend/              no-build SPA (vanilla JS) served by FastAPI
lab/vulnerable-world-monitor/   intentionally vulnerable target + fix toggles
cli/world_monitor.py   unified CLI driving the same engine
tests/                 38 pytest tests incl. full lifecycle e2e
docs/                  architecture · audit · security model · SIH mapping …
```

## Safety model (non-negotiable)

* `LAB_MODE=true` (default): scans are **refused** unless the target resolves to
  loopback/RFC1918 or appears in explicit `ALLOWED_TARGETS`; cloud-metadata IPs are
  always blocked; filesystem scanners are jailed to the lab tree.
* The authorization checkbox is enforced server-side, not just in the UI.
* Evidence masks tokens/cookies/keys before storage; sensitive headers redacted.
* Every assessment, scan, report and retest is written to an append-friendly
  `audit_logs` table.

See `docs/security-model.md` for the full threat model of the platform itself.

## Tests

```powershell
.\.venv\Scripts\python -m pytest tests -q
```

Covers: CVSS math against FIRST reference vectors, authorization gate, masking,
fingerprints/dedupe, RBAC, report generation, and a live end-to-end run against the
vulnerable lab including the retest-FIXED flow.

## Documentation index

`docs/repository-audit.md` (Phase-0 decisions) · `docs/architecture.md` ·
`docs/security-model.md` · `docs/api.md` · `docs/demo.md` · `docs/deployment.md` ·
`docs/integration.md` · `docs/scanner-development.md` · `docs/requirements-coverage.md`

## License & attribution

Integrated components come from the author's own repositories and are AGPL-3.0;
accordingly this repository ships AGPL-compatible — see `NOTICE.md`.
