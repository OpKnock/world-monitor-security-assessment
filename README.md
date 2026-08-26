# World Monitor — Security Assessment Platform

A unified, localhost-only security assessment platform that scans an intentionally vulnerable lab application and the real World Monitor codebase, normalizes results into one finding format, scores them with CVSS v3.1, stores sanitized evidence, explains business impact, recommends remediation, supports **retest-until-FIXED**, and generates professional PDF / JSON / Markdown / CSV reports.

```
DETECT → VERIFY → DOCUMENT → SCORE → EXPLAIN IMPACT → REMEDIATE → RETEST → REPORT
```

## Two targets, one platform

| Target | What it is | How it is scanned |
|---|---|---|
| **Vulnerable Lab** (`lab/vulnerable-world-monitor`) | Intentionally vulnerable Flask clone of World Monitor, localhost-only, 10 deliberately planted weaknesses + 4 fix toggles | Dynamic modules: `authentication`, `authorization`, `api`, `input_validation`, `headers`, `tls`, `graphql`, `deep_scan`, `fuzzing` |
| **Real World Monitor** (`targets/real-world-monitor`) | Genuine production codebase cloned from source | Static modules: `secrets`, `dependencies`, `supply_chain` + dynamic modules against its running dev server |

Both targets use the same engine, same finding schema, same scoring, and same reporting. No separate toolchain is required.

## The 12 scanner modules

| # | Module key | Category | What it proves |
|---|---|---|---|
| 1 | `authentication` | Authentication | Missing auth, JWT `none` / signature bypass, invalid token acceptance |
| 2 | `authorization` | Authorization | IDOR / BOLA via numeric & string ID manipulation |
| 3 | `api` | API Security | Missing rate limiting, header-spoof & path-variant bypass |
| 4 | `input_validation` | Input Validation | Boolean / error-based SQL injection, reflected XSS canary, verbose errors |
| 5 | `headers` | Client Security | 6 security headers graded A–F + Set-Cookie flag audit |
| 6 | `tls` | Secure Communication | Certificate validity / expiry, HTTPS availability & redirect |
| 7 | `secrets` | Data Privacy | Hardcoded credentials in source (`portia` binary) |
| 8 | `dependencies` | Dependencies | Known CVEs via OSV (`bomber` binary) |
| 9 | `supply_chain` | Supply Chain | Typosquat, pinning, license hygiene (`chainscanner` binary) |
| 10 | `graphql` | API Security | Introspection, depth & field abuse probes |
| 11 | `deep_scan` | Infrastructure | Open ports, banner disclosure, default-credential probes |
| 12 | `fuzzing` | Input Validation | Mutation fuzzing with 5xx anomaly detection (opt-in) |

Optional modules (`tls`, `graphql`, `deep_scan`, `fuzzing`, `supply_chain`) degrade gracefully to `skipped` when the environment cannot support them — they never fabricate findings.

## Quick start (Windows, macOS, Linux — no Docker required)

```powershell
git clone <this-repo> world-monitor-security-assessment
cd world-monitor-security-assessment
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
Copy-Item .env.example .env          # defaults are correct for the local demo
powershell -ExecutionPolicy Bypass -File scripts\build_go_tools.ps1   # builds bin\portia.exe, bin\bomber.exe, bin\chainscanner.exe
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1
```

| Service | URL | Credentials |
|---|---|---|
| **Platform UI** | http://127.0.0.1:8000 | `admin` / `admin` (email `admin@example.com`) |
| Vulnerable lab | http://127.0.0.1:8080 | **intentionally insecure — loopback only** |
| Real World Monitor dev | http://127.0.0.1:3000 | run `npm install; npm run dev -- --port 3000` inside `targets/real-world-monitor` |
| API docs | http://127.0.0.1:8000/api/docs | OpenAPI (JWT bearer) |

Lab demo accounts: `alice` / `user123`, `bob` / `user456`, `admin` / `admin123`.
Platform default: `admin` / `admin` (also reachable as `admin@example.com` / `admin`; override via `ADMIN_EMAIL` / `ADMIN_PASSWORD` in `.env`).

### 60-second demonstration

1. Sign in → **New Assessment** → keep the pre-filled lab layout (or use presets 🌐 Real app / 🧪 Playground / 📁 Source only).
2. Use the module filter to focus on e.g. `headers` or `secrets`, check the live target validation (green ✓ when gate will pass).
3. Tick *“I confirm this target is authorized …”* (server-enforced gate) → **Start Assessment**.
4. Watch live per-scanner progress with progress bar + `X-Request-ID` tracing → findings appear with CVSS scores and evidence.
5. Open a finding → masked request/response evidence (copy button, truncated safe display) → remediation guidance + references.
6. Click **Retest** → `STILL_PRESENT` while the weakness remains.
7. Restart the lab with a fix toggle (`$env:WM_LAB_FIX_HEADERS=1; python lab\vulnerable-world-monitor\app.py`) → **Retest** again → `FIXED`.
8. **Reports** → generate PDF / JSON / Markdown / CSV · **Findings** → search + severity filter + copy link.

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

## Repository layout

```
backend/app/engine/     authorization gate · orchestration / jobs · finding engine
                        evidence engine · CVSS engine · reporting (PDF/JSON/MD/CSV)
backend/app/scanners/   adapters: headers · authn/authz/rate-limit (vendored) ·
                        sqli + xss · tls · secrets (portia) · dependencies (bomber) ·
                        supply chain (chainscanner) · graphql · deep_scan · fuzzing
backend/app/vendor/     vendored upstream scanners (AGPL — see NOTICE.md)
frontend/               no-build SPA (vanilla JS) served by FastAPI
lab/vulnerable-world-monitor/   intentionally vulnerable target + fix toggles + secrets_demo.py
cli/world_monitor.py    unified CLI driving the same engine (scan / findings / report / retest)
targets/real-world-monitor/   genuine application source (static + dynamic targets)
tests/                  40 pytest tests incl. full lifecycle end-to-end
docs/                   architecture · security model · API · demo · deployment ·
                        integration · scanner development · coverage · audit
scripts/                build_go_tools.ps1 · start_all.ps1 · full_scan.py · full_verify.py
docker/                 api.Dockerfile · lab.Dockerfile · docker-compose.yml
```

## Safety model (non-negotiable)

* `LAB_MODE=true` (default): scans are **refused** unless the target resolves to loopback / RFC1918 or appears in explicit `ALLOWED_TARGETS`; cloud-metadata IPs are always blocked; filesystem scanners are jailed to the authorized source tree.
* The authorization checkbox is enforced server-side, not just in the UI.
* Evidence masks tokens / cookies / keys before storage; sensitive headers are redacted.
* Every assessment, scan, report and retest is written to an `audit_logs` table.

See `docs/security-model.md` for the full platform threat model.

## Tests

```powershell
.\.venv\Scripts\python -m pytest tests -q
```

Covers: CVSS math against FIRST reference vectors, authorization gate, evidence masking, fingerprint / dedupe, RBAC, report generation, delete cascade, and a live end-to-end run against the vulnerable lab including the retest-FIXED flow.

## Documentation index

`docs/architecture.md` · `docs/security-model.md` · `docs/api.md` · `docs/demo.md` · `docs/deployment.md` · `docs/integration.md` · `docs/scanner-development.md` · `docs/requirements-coverage.md` · `docs/repository-audit.md`

## License & attribution

Integrated components come from the referenced open-source projects and are AGPL-3.0; accordingly this repository is distributed under AGPL-3.0 — see `NOTICE.md` and `LICENSE`.

## Obtaining the Target Application

The real World Monitor application (`targets/real-world-monitor/`) is cloned from the upstream repository:

```bash
git clone https://github.com/koala73/worldmonitor.git targets/real-world-monitor
cd targets/real-world-monitor
npm install
npm run dev -- --port 3000 --host 127.0.0.1
```

- **Upstream repo**: https://github.com/koala73/worldmonitor (AGPL-3.0)
- **Description**: Real-time global intelligence dashboard with AI-powered news aggregation, geopolitical monitoring, and infrastructure tracking
- **Used in this project**: Genuine production codebase target for static + dynamic security assessment

The vulnerable lab (`lab/vulnerable-world-monitor/`) is a separate, intentionally insecure Flask application included in this repository for scanner demonstration.
