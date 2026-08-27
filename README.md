# World Monitor Security Assessment Platform

[![ci](https://github.com/OpKnock/world-monitor-security-assessment/actions/workflows/ci.yml/badge.svg)](https://github.com/OpKnock/world-monitor-security-assessment/actions/workflows/ci.yml)

A unified, localhost-only security assessment platform that scans an intentionally vulnerable lab application and the real World Monitor codebase, normalizes results into one finding format, scores them with CVSS v3.1, stores sanitized evidence, explains business impact, recommends remediation, supports **retest-until-FIXED**, and generates professional PDF / JSON / Markdown / CSV reports. Docker images run as non-root with healthchecks; CI runs 46 tests + `pip-audit` on every push. All three UIs — assessment platform, vulnerable lab, and cloned World Monitor (`targets/real-world-monitor`, premium glass/gradient overlay) — share a cohesive dark premium theme.

```
DETECT -> VERIFY -> DOCUMENT -> SCORE -> EXPLAIN IMPACT -> REMEDIATE -> RETEST -> REPORT
```

## Two Targets, One Platform

| Target | What it is | How it is scanned |
|---|---|---|
| **Vulnerable Lab** (`lab/vulnerable-world-monitor`) | Intentionally vulnerable Flask clone of World Monitor, localhost-only, 10 deliberately planted weaknesses + 4 fix toggles | Dynamic modules: `authentication`, `authorization`, `api`, `input_validation`, `headers`, `tls`, `graphql`, `deep_scan`, `fuzzing` |
| **Real World Monitor** (`targets/real-world-monitor`) | Genuine production codebase cloned from koala73/worldmonitor | Static modules: `secrets`, `dependencies`, `supply_chain` + dynamic modules against its running dev server |

Both targets use the same engine, same finding schema, same scoring, and same reporting. No separate toolchain is required.

## The 12 Scanner Modules

| # | Module key | Category | What it proves |
|---|---|---|---|
| 1 | `authentication` | Authentication | Missing auth, JWT `none` / signature bypass, invalid token acceptance |
| 2 | `authorization` | Authorization | IDOR / BOLA via numeric & string ID manipulation |
| 3 | `api` | API Security | Missing rate limiting, header-spoof & path-variant bypass |
| 4 | `input_validation` | Input Validation | Boolean / error-based SQL injection, reflected XSS canary, verbose errors |
| 5 | `headers` | Client Security | 6 security headers graded A-F + Set-Cookie flag audit |
| 6 | `tls` | Secure Communication | Certificate validity / expiry, HTTPS availability & redirect |
| 7 | `secrets` | Data Privacy | Hardcoded credentials in source (`portia` binary) |
| 8 | `dependencies` | Dependencies | Known CVEs via OSV (`bomber` binary) |
| 9 | `supply_chain` | Supply Chain | Typosquat, pinning, license hygiene (`chainscanner` binary) |
| 10 | `graphql` | API Security | Introspection, depth & field abuse probes |
| 11 | `deep_scan` | Infrastructure | Open ports, banner disclosure, default-credential probes |
| 12 | `fuzzing` | Input Validation | Mutation fuzzing with 5xx anomaly detection (opt-in) |

Optional modules (`tls`, `graphql`, `deep_scan`, `fuzzing`, `supply_chain`) degrade gracefully to `skipped` when the environment cannot support them \u2014 they never fabricate findings.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.11+ | [python.org](https://python.org) |
| Node.js | 18+ | [nodejs.org](https://nodejs.org) |
| Go | 1.21+ | [go.dev](https://go.dev) |
| Git | Latest | [git-scm.com](https://git-scm.com) |

**Windows:** Use PowerShell (Admin). **Mac/Linux:** Terminal.

---

## 

---

## Run Everything

Bash
# Terminal 1 - Lab
cd lab/vulnerable-world-monitor
python app.py

# Terminal 2 - Platform
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1

# Terminal 3 (optional) - Real App
cd targets/real-world-monitor
npm install
npm run dev -- --port 3000 --host 127.0.0.1
`

---

Three-Terminal Setup

**Terminal 1 \u2014 Lab (Vulnerable App):**
```bash
cd lab/vulnerable-world-monitor
python app.py
# -> http://127.0.0.1:8080
```

**Terminal 2 \u2014 Platform (Main App):**
```bash
# From repo root
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1
# Or manually:
.venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
# -> http://127.0.0.1:8000
```

**Terminal 3 (Optional) \u2014 Real World Monitor App:**
```bash
cd targets/real-world-monitor
npm install
npm run dev -- --port 3000 --host 127.0.0.1
# -> http://127.0.0.1:3000
```

---

## Verification Checklist

| Service | URL | Test |
|---------|-----|------|
| **Lab** | http://127.0.0.1:8080 | Loads "VULNERABLE LAB" page, login works |
| **Platform** | http://127.0.0.1:8000 | Loads login page |
| **API Docs** | http://127.0.0.1:8000/api/docs | Swagger UI loads |
| **Health** | http://127.0.0.1:8000/api/health | Returns `{"status":"healthy"}` |
| **Lab Health** | http://127.0.0.1:8080/health | Returns JSON with toggles |

---

## Quick Demo (2 min)

1. **Open Platform:** http://127.0.0.1:8000
2. **Login:** `admin@example.com` / `admin`
3. **New Assessment** -> Preset `Playground :8080` -> Check "authorized" -> **Start**
4. Watch live progress -> Findings appear with CVSS scores
5. Click finding -> **Retest** -> `STILL_PRESENT`
6. Restart lab with fix: `$env:WM_LAB_FIX_HEADERS=1; python lab\vulnerable-world-monitor\app.py`
7. **Retest** again -> `FIXED` \u2713
8. **Reports** -> Generate PDF/JSON/MD/CSV

---

## Common Issues

| Problem | Fix |
|---------|-----|
| `python` not found | Add Python to PATH, or use `python3` / `py` |
| `go` not found | Install Go, restart terminal |
| `npm` fails | Delete `node_modules` + `package-lock.json`, re-run `npm install` |
| Go build fails | Ensure Go 1.21+, check `GOPATH`/`GOMODULE` |
| Port 8000/8080 in use | Kill process: `netstat -ano | findstr :8000` -> `taskkill /PID <pid> /F` |
| Tests fail | Run from repo root with venv active |
| Login "invalid credentials" | You didn't copy `.env.example` → `.env`; default is `admin@example.com` / `ChangeMe_Use_Strong_Password_Here` |
| `.venv\sripts\activate` fails | Typo — it's **Scripts** (capital S), not `sripts` |

---

## How It Works (Architecture)

```
┌─────────────┐     ┌─────────────┐     ┌──────────────────┐
│   SPA UI    │────▶│  FastAPI    │────▶│  Auth Gate       │
│  (vanilla)  │     │  Backend    │     │  (loopback only) │
└─────────────┘     └──────┬──────┘     └────────┬─────────┘
                           │                     │
                    ┌──────▼──────────┐          │
                    │  Orchestrator   │◀─────────┘
                    │  (job runner)   │
                    └──────┬──────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
   ┌─────────┐        ┌─────────┐        ┌─────────┐
   │ Scanner │        │ Scanner │   ...  │ Scanner │
   │  (12)   │        │  (12)   │        │  (12)   │
   └────┬────┘        └────┬────┘        └────┬────┘
        │                  │                   │
        └──────────────────┼───────────────────┘
                           ▼
              ┌───────────────────────┐
              │  Finding Engine       │
              │  • Normalize          │
              │  • Dedupe (fingerprint)│
              │  • CVSS v3.1 scoring  │
              │  • Evidence masking   │
              └───────────┬───────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
        ┌─────────────┐           ┌─────────────┐
        │   Reports   │           │   Retest    │
        │ PDF/JSON/   │           │ FIXED /     │
        │ MD/CSV      │           │ STILL_PRESENT
        └─────────────┘           └─────────────┘
```

**Key Components:**

| Component | Technology | Purpose |
|-----------|------------|---------|
| **API** | FastAPI + SQLAlchemy 2 | REST + OpenAPI, JWT auth, RBAC |
| **Database** | SQLite WAL (Postgres-ready) | Findings, evidence, reports, audit logs |
| **Job Runner** | Thread-per-assessment + watchdog | Isolated scanner execution, 10-min timeout |
| **Scanner Registry** | 12 modules (6 Go binaries + 6 native) | Unified `ScannerModule.run(ctx)` interface |
| **Evidence Engine** | JSON files + masking | Masked headers/body, file references in DB |
| **CVSS Engine** | Pure Python, FIRST v3.1 spec | 38 curated presets, deterministic scoring |
| **Frontend** | Vanilla JS (ES6), SVG charts | Zero build, served by FastAPI |

---

## How Each Scanner Works

### Dynamic Scanners (require running target)

| Module | Target | Technique |
|--------|--------|-----------|
| **authentication** | `/api/` + auth endpoints | Tests missing auth, JWT `none` alg, signature bypass, invalid token acceptance |
| **authorization** | `/api/reports/:id`, numeric IDs | IDOR/BOLA via numeric & string ID enumeration across users |
| **api** | Rate limit endpoints | Sends paced requests, tests IP/header spoofing, path-variant bypass |
| **input_validation** | `/api/search?id=`, `/greet?name=` | Boolean-blind SQLi (error/boolean), reflected XSS canary, verbose error disclosure |
| **headers** | `/` + all responses | Grades 6 headers (HSTS, CSP, XCTO, XFO, Referrer-Policy, Permissions-Policy) A-F; audits Set-Cookie flags |
| **tls** | HTTPS endpoints | Cert validity/expiry, HTTPS availability, redirect check |
| **graphql** | `/graphql` endpoint | Introspection query, depth/field abuse, alias explosion |
| **deep_scan** | Target host:port | Port scan, banner grab, default credential probes (ssh/telnet/db) |
| **fuzzing** | All endpoints | Mutation fuzzing (opt-in), 5xx anomaly detection |

### Static Scanners (require source path)

| Module | Input | Technique |
|--------|-------|-----------|
| **secrets** | Source directory | `portia` binary: ~110 regex/entropy rules, entropy-gated generics, git history scan |
| **dependencies** | `package.json`, `go.mod`, `requirements.txt`, `pyproject.toml` | `bomber` binary: parses manifests -> SBOM -> OSV.dev CVE matching + CVSS v3 |
| **supply_chain** | Project directory | `chainscanner` binary: typosquat detection, unpinned deps, license hygiene |

---

## How the Retest Loop Works

1. **Finding Created** \u2192 Fingerprint = `sha1(target | category | check_id | component)`
2. **Developer Fixes** \u2192 Restarts lab with fix toggle (e.g., `WM_LAB_FIX_HEADERS=1`)
3. **User Clicks "Retest"** \u2192 Platform re-runs *only* that check's scanner
4. **Fingerprint Comparison** \u2192 New findings compared to original fingerprint
5. **Verdict**:
   - `FIXED` \u2192 fingerprint no longer found
   - `STILL_PRESENT` \u2192 fingerprint still matches
6. **Evidence Linked** \u2192 New evidence attached to original finding, history preserved

---

## Quick Start (Fresh Clone — Copy/Paste This)

```bash
# 1. Clone & Submodule (do NOT use "Download ZIP")
git clone --recurse-submodules https://github.com/OpKnock/world-monitor-security-assessment.git
cd world-monitor-security-assessment

# 2. Python venv + deps
python -m venv .venv
.venv\Scripts\activate          # Windows (NOTE: Scripts NOT sripts)
source .venv/bin/activate       # Mac/Linux
.venv\Scripts\pip install -r requirements.txt

# 3. Build Go binaries (required for secrets/deps/supply_chain scanners)
powershell -ExecutionPolicy Bypass -File scripts\build_go_tools.ps1
# Mac/Linux: chmod +x scripts/build_go_tools.sh && ./scripts/build_go_tools.sh

# 4. Verify binaries
ls bin/  # portia.exe, bomber.exe, chainscanner.exe

# 5. CRITICAL: Configure environment BEFORE starting
copy .env.example .env   # Windows
cp .env.example .env     # Mac/Linux
# EDIT .env if you want custom passwords, but defaults work for demo
```

**Default login after step 5:** `admin@example.com` / `ChangeMe_Use_Strong_Password_Here`  
*(override via `ADMIN_PASSWORD` in `.env`)*

---

## Three-Terminal Setup

**Terminal 1 \u2014 Lab (Vulnerable App):**
```bash
cd lab/vulnerable-world-monitor
python app.py
# -> http://127.0.0.1:8080
```

**Terminal 2 \u2014 Platform (Main App):**
```bash
# From repo root
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1
# Or manually:
.venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
# -> http://127.0.0.1:8000
```

**Terminal 3 (Optional) \u2014 Real World Monitor App:**
```bash
cd targets/real-world-monitor
npm install
npm run dev -- --port 3000 --host 127.0.0.1
# -> http://127.0.0.1:3000
```

---

## Verification Checklist

| Service | URL | Test |
|---------|-----|------|
| **Lab** | http://127.0.0.1:8080 | Loads "VULNERABLE LAB" page, login works |
| **Platform** | http://127.0.0.1:8000 | Loads login page |
| **API Docs** | http://127.0.0.1:8000/api/docs | Swagger UI loads |
| **Health** | http://127.0.0.1:8000/api/health | Returns `{"status":"healthy"}` |
| **Lab Health** | http://127.0.0.1:8080/health | Returns JSON with toggles |

---

## Quick Demo (2 min)

1. **Open Platform:** http://127.0.0.1:8000
2. **Login:** `admin@example.com` / `admin`
3. **New Assessment** \u2192 Preset `Playground :8080` \u2192 Check "authorized" \u2192 **Start**
4. Watch live progress \u2192 Findings appear with CVSS scores
5. Click finding \u2192 **Retest** \u2192 `STILL_PRESENT`
6. Restart lab with fix: `$env:WM_LAB_FIX_HEADERS=1; python lab\vulnerable-world-monitor\app.py`
7. **Retest** again \u2192 `FIXED` \u2713
8. **Reports** \u2192 Generate PDF/JSON/MD/CSV

---

## Lab Fix Toggles (for demo)

| Toggle | Effect |
|--------|--------|
| `WM_LAB_PATCH_IDOR=1` | Fixes IDOR on `/api/reports/:id` |
| `WM_LAB_FIX_HEADERS=1` | Enables HSTS, CSP, XCTO, XFO |
| `WM_LAB_PATCH_SQLI=1` | Parametrized query on `/api/search` |
| `WM_LAB_RATELIMIT=1` | 20 req/min on `/api/*` |

---

## Lab Demo Accounts

| User | Password | Role |
|------|----------|------|
| alice | user123 | user |
| bob | user456 | user |
| admin | admin123 | admin |

Platform: `admin@example.com` / `admin` (override via `ADMIN_PASSWORD` in `.env`)

---

## Running Tests

```bash
.venv\Scripts\python.exe -m pytest tests -v    # Verbose
.venv\Scripts\python.exe -m pytest tests -q    # Quiet (40 passed)
```

---

## Key Paths

```
world-monitor-security-assessment/
├── backend/app/           # FastAPI backend
├── frontend/              # SPA (vanilla JS)
├── lab/vulnerable-world-monitor/   # Flask lab (port 8080)
├── targets/real-world-monitor/     # koala73/worldmonitor (submodule)
├── scripts/               # start_all.ps1, build_go_tools.ps1, make_sih_ppt.py
├── docs/                  # Architecture, API, security model, etc.
├── tests/                 # 40 pytest tests
└── bin/                   # Go binaries (portia, bomber, chainscanner)
```

---

## Quick Commands Reference

```bash
# Activate venv (NOTE: Scripts NOT sripts)
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # Mac/Linux

# Run tests
.venv\Scripts\python.exe -m pytest tests -v
.venv\Scripts\python.exe -m pytest tests -q        # Quiet
.venv\Scripts\python.exe -m pytest tests/test_e2e_lab.py -v  # E2E only

# Build Go tools
scripts\build_go_tools.ps1     # Windows
./scripts/build_go_tools.sh    # Mac/Linux

# Generate PPTs
python scripts\make_sih_ppt.py
python scripts\make_sih_ppt_v2.py

# Full scan (CLI)
.venv\Scripts\python cli\world_monitor.py scan --lab
.venv\Scripts\python cli\world_monitor.py findings --severity CRITICAL
```

---

## Safety Model

* `LAB_MODE=true` (default): scans are **refused** unless the target resolves to loopback / RFC1918 or appears in explicit `ALLOWED_TARGETS`; cloud-metadata IPs are always blocked; filesystem scanners are jailed to the authorized source tree.
* The authorization checkbox is enforced server-side, not just in the UI.
* Evidence masks tokens / cookies / keys before storage; sensitive headers are redacted.
* Every assessment, scan, report and retest is written to an `audit_logs` table.

See `docs/security-model.md` for the full platform threat model.

---

## Tests

```powershell
.venv\Scripts\python -m pytest tests -q
```

Covers: CVSS math against FIRST reference vectors, authorization gate, evidence masking, fingerprint / dedupe, RBAC, report generation, delete cascade, and a live end-to-end run against the vulnerable lab including the retest-FIXED flow.

---

## Documentation Index

`docs/architecture.md` \u00b7 `docs/security-model.md` \u00b7 `docs/api.md` \u00b7 `docs/demo.md` \u00b7 `docs/deployment.md` \u00b7 `docs/integration.md` \u00b7 `docs/scanner-development.md` \u00b7 `docs/requirements-coverage.md` \u00b7 `docs/repository-audit.md`

---

## License & Attribution

Integrated components from the referenced open-source projects are AGPL-3.0; accordingly this repository is distributed under AGPL-3.0 \u2014 see `NOTICE.md` and `LICENSE`.

---

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
- **Purpose in this project**: Genuine production codebase target for static + dynamic security assessment

The vulnerable lab (`lab/vulnerable-world-monitor/`) is a separate, intentionally insecure Flask application included in this repository for scanner demonstration.
