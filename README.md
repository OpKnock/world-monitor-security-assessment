# World Monitor Security Assessment Platform

[![ci](https://github.com/OpKnock/world-monitor-security-assessment/actions/workflows/ci.yml/badge.svg)](https://github.com/OpKnock/world-monitor-security-assessment/actions/workflows/ci.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![License AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-green)

A unified, **localhost-only** security assessment platform that scans an intentionally vulnerable lab and the real World Monitor codebase, normalizes findings into one schema, scores them with **CVSS v3.1**, stores masked evidence, explains business impact, recommends remediation, supports **retest-until-FIXED**, and generates **PDF / JSON / Markdown / CSV** reports. Docker images run as non-root with healthchecks. CI runs **46 tests + pip-audit** on every push.

```
DETECT -> VERIFY -> DOCUMENT -> SCORE -> EXPLAIN IMPACT -> REMEDIATE -> RETEST -> REPORT
```

---

## Two Targets, One Platform

| Target | What it is | How it is scanned |
|---|---|---|
| **Vulnerable Lab** (`lab/vulnerable-world-monitor`) | Intentionally vulnerable Flask clone — **localhost-only**, 10 planted weaknesses + 4 fix toggles | Dynamic modules: `authentication`, `authorization`, `api`, `input_validation`, `headers`, `tls`, `graphql`, `deep_scan`, `fuzzing` |
| **Real World Monitor** (`targets/real-world-monitor`) | Genuine production codebase from `koala73/worldmonitor` (submodule) | Static modules: `secrets`, `dependencies`, `supply_chain` + dynamic scans against its dev server |

Same engine, same finding schema, same scoring, same reporting — no separate toolchain.

---

## The 12 Scanner Modules

| # | Module | Category | What it proves |
|---|---|---|---|
| 1 | `authentication` | Authentication | Missing auth, JWT `none` / signature bypass |
| 2 | `authorization` | Authorization | IDOR / BOLA via numeric & string IDs |
| 3 | `api` | API Security | Missing rate limiting, header-spoof & path bypass |
| 4 | `input_validation` | Input Validation | SQLi (boolean/error), reflected XSS, verbose errors |
| 5 | `headers` | Client Security | 6 headers graded A–F + Set-Cookie flag audit |
| 6 | `tls` | Secure Communication | Cert validity, HTTPS availability & redirect |
| 7 | `secrets` | Data Privacy | Hardcoded creds (`portia` Go binary) |
| 8 | `dependencies` | Dependencies | Known CVEs via OSV (`bomber` Go binary) |
| 9 | `supply_chain` | Supply Chain | Typosquat, pinning, license hygiene |
| 10 | `graphql` | API Security | Introspection, depth & alias abuse |
| 11 | `deep_scan` | Infrastructure | Open ports, banner disclosure, default creds |
| 12 | `fuzzing` | Input Validation | Mutation fuzzing with 5xx anomaly detection |

Optional modules (`tls`, `graphql`, `deep_scan`, `fuzzing`, `supply_chain`) degrade to `skipped` when the environment can't support them — never fabricated.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.11+ | [python.org](https://python.org) |
| Node.js | 18+ | [nodejs.org](https://nodejs.org) |
| Go | 1.21+ | [go.dev](https://go.dev) |
| Git | Latest | [git-scm.com](https://git-scm.com) |
| Docker | Latest (optional) | [docker.com](https://docker.com) |

> **Windows:** PowerShell (Admin). **Mac/Linux:** Terminal. `requirements.txt` includes `Flask` for the lab — one `pip install -r requirements.txt` covers platform + lab.

---

## Quick Start — Fresh Clone

Copy/paste this. Do **not** use “Download ZIP”.

```bash
# 1. Clone with submodule
git clone --recurse-submodules https://github.com/OpKnock/world-monitor-security-assessment.git
cd world-monitor-security-assessment

# 2. Python env
python -m venv .venv
.venv\Scripts\activate          # Windows — Scripts with capital S
source .venv/bin/activate       # Mac/Linux
pip install -r requirements.txt  # includes Flask, FastAPI, etc.

# 3. Build Go scanners (secrets / deps / supply_chain)
powershell -ExecutionPolicy Bypass -File scripts\build_go_tools.ps1
# Mac/Linux: chmod +x scripts/build_go_tools.sh && ./scripts/build_go_tools.sh

# 4. Verify binaries
ls bin/   # portia.exe, bomber.exe (or portia/bomber on Linux/Mac)

# 5. Configure env BEFORE first run
copy .env.example .env   # Windows
cp .env.example .env     # Mac/Linux
# defaults work for demo; change SECRET_KEY + ADMIN_PASSWORD before real use
```

**Default login after step 5:** `admin@example.com` / `ChangeMe_Use_Strong_Password_Here`  
Override via `ADMIN_PASSWORD` in `.env`.

---

## Three-Terminal Setup

**Terminal 1 — Vulnerable Lab** (`http://127.0.0.1:8080`):
```bash
cd lab/vulnerable-world-monitor
python app.py
```

**Terminal 2 — Platform** (`http://127.0.0.1:8000`):
```bash
# from repo root
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1
# or manually:
.venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

**Terminal 3 — Real World Monitor** (optional, `http://127.0.0.1:3000`):
```bash
cd targets/real-world-monitor
npm install
npm run dev -- --port 3000 --host 127.0.0.1
```

### Verification

| Service | URL | Expect |
|---------|-----|--------|
| Lab | http://127.0.0.1:8080 | “VULNERABLE LAB” page loads, lab login works |
| Platform | http://127.0.0.1:8000 | Login page loads |
| API Docs | http://127.0.0.1:8000/api/docs | Swagger UI |
| Health | http://127.0.0.1:8000/api/health | `{"status":"healthy"}` |
| Lab Health | http://127.0.0.1:8080/health | JSON with fix toggles |

---

## Quick Demo (2 min)

1. Open `http://127.0.0.1:8000` → Login `admin@example.com` / `ChangeMe_Use_Strong_Password_Here`
2. **New Assessment** → Preset `Playground :8080` → tick “authorized” → **Start**
3. Watch live progress → findings appear with CVSS scores
4. Click a finding → **Retest** → `STILL_PRESENT`
5. Restart lab with a fix: `$env:WM_LAB_FIX_HEADERS=1; python lab\vulnerable-world-monitor\app.py`
6. **Retest** again → `FIXED` ✓
7. **Reports** → Generate PDF / JSON / Markdown / CSV

---

## Environment Variables

`.env` is **not committed**. Copy from `.env.example` and edit. Key vars:

| Var | Default | Purpose |
|-----|---------|---------|
| `SECRET_KEY` | `CHANGE-ME-...` | JWT signing — **must be random 64 hex chars in prod** (`python -c "import secrets; print(secrets.token_hex(32))"`) |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | `admin@example.com` / `ChangeMe_...` | Bootstrap platform login |
| `ANALYST_EMAIL` / `ANALYST_PASSWORD` | `analyst@example.com` / `ChangeMe_...` | Viewer role |
| `LAB_MODE` | `true` | Only allow loopback / RFC1918 targets; cloud metadata IPs always blocked |
| `LAB_APP_URL` | `http://127.0.0.1:8080` | Lab address |
| `LAB_SOURCE_DIR` | `lab/vulnerable-world-monitor` | Source scope for static scans (jailed) |
| `MAX_SCAN_WORKERS` | `4` | Concurrent scanner threads |
| `API_RATE_LIMIT_PER_MINUTE` | `600` | Global API throttle |

> Fresh clone without `.env` falls back to `ADMIN_PASSWORD=ChangeMe_Use_Strong_Password_Here` from `backend/app/config.py`. That’s why “invalid credentials” means you forgot `copy .env.example .env`.

---

## Docker Alternative

Images run as **non-root** (`appuser`/`labuser`) with healthchecks. No Go toolchain needed on host — binaries built inside `api` image.

```bash
docker build -f docker/api.Dockerfile -t world-monitor:api .
docker build -f docker/lab.Dockerfile -t world-monitor:lab .

docker run --rm -d -p 8080:8080 --name lab world-monitor:lab
docker run --rm -d -p 8000:8000 --name api world-monitor:api
# platform reads .env at runtime; mount it if you customized:
# docker run --rm -d -p 8000:8000 --env-file .env --name api world-monitor:api

curl -fsS http://localhost:8000/api/health   # {"status":"healthy"}
curl -fsS http://localhost:8080/health
```

---

## Lab Fix Toggles (for retest demo)

| Toggle | Effect |
|--------|--------|
| `WM_LAB_PATCH_IDOR=1` | Fixes IDOR on `/api/reports/:id` |
| `WM_LAB_FIX_HEADERS=1` | Enables HSTS, CSP, X-Content-Type-Options, X-Frame-Options |
| `WM_LAB_PATCH_SQLI=1` | Parameterized query on `/api/search` |
| `WM_LAB_RATELIMIT=1` | 20 req/min on `/api/*` |

```powershell
$env:WM_LAB_FIX_HEADERS="1"; python lab\vulnerable-world-monitor\app.py
```

---

## Demo Accounts

**Lab** (`http://127.0.0.1:8080`):

| User | Password | Role |
|------|----------|------|
| alice | user123 | user |
| bob | user456 | user |
| admin | admin123 | admin |

**Platform** (`http://127.0.0.1:8000`): `admin@example.com` / `ChangeMe_Use_Strong_Password_Here` (or your `.env` value) · Analyst: `analyst@example.com` / `ChangeMe_Use_Strong_Password_Here`

---

## Architecture

```
┌───────────┐    ┌──────────┐    ┌──────────────┐
│  SPA UI   │───▶│ FastAPI  │───▶│  Auth Gate   │
│ (vanilla) │    │ Backend  │    │(loopback only)│
└───────────┘    └────┬─────┘    └──────┬───────┘
                      │                 │
               ┌──────▼───────┐         │
               │ Orchestrator │◀────────┘
               │ (job runner) │
               └──────┬───────┘
                      │
      ┌───────────────┼───────────────┐
      ▼               ▼               ▼
 ┌─────────┐     ┌─────────┐     ┌─────────┐
 │ Scanner │     │ Scanner │ ... │ Scanner │  12 modules
 └────┬────┘     └────┬────┘     └────┬────┘
      └───────────────┼───────────────┘
                      ▼
         ┌───────────────────────┐
         │   Finding Engine      │
         │  • Normalize          │
         │  • Dedupe (fingerprint)│
         │  • CVSS v3.1 scoring  │
         │  • Evidence masking   │
         └───────────┬───────────┘
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
   ┌───────────┐           ┌───────────┐
   │  Reports  │           │  Retest   │
   │PDF/JSON/  │           │FIXED /    │
   │MD/CSV     │           │STILL_PRESENT│
   └───────────┘           └───────────┘
```

| Component | Tech | Purpose |
|-----------|------|---------|
| API | FastAPI + SQLAlchemy 2 | REST + OpenAPI, JWT (HS256, `aud` verified), RBAC |
| DB | SQLite WAL (Postgres-ready) | Findings, evidence refs, reports, `audit_logs` |
| Job Runner | Thread-per-assessment + watchdog | Isolated scanners, 10-min timeout, `MAX_SCAN_WORKERS` |
| Scanner Registry | 12 modules (Go + native) | Unified `ScannerModule.run(ctx)` |
| Evidence | JSON files + masking | Tokens/cookies/keys redacted before write |
| CVSS Engine | Pure Python, FIRST v3.1 | 38 curated presets, deterministic |
| Frontend | Vanilla JS (ES6), SVG charts | Zero build, served by FastAPI |

---

## How Each Scanner Works

**Dynamic** (requires running target):

| Module | Target | Technique |
|--------|--------|-----------|
| `authentication` | `/api/*` + auth | Missing auth, JWT `none` alg, signature bypass |
| `authorization` | `/api/reports/:id` | IDOR/BOLA via numeric & string enumeration |
| `api` | Rate-limit endpoints | Paced requests, header-spoof & path-variant bypass |
| `input_validation` | `/api/search?id=`, `/greet?name=` | SQLi (boolean/error), reflected XSS canary |
| `headers` | `/*` | 6 headers graded A–F + `Set-Cookie` flags |
| `tls` | HTTPS | Cert validity/expiry, redirect check |
| `graphql` | `/graphql` | Introspection, depth/field & alias abuse |
| `deep_scan` | `host:port` | Port scan, banner grab, default-credential probes |
| `fuzzing` | All endpoints | Mutation fuzzing, 5xx anomaly detection (opt-in) |

**Static** (requires `source_path`):

| Module | Input | Technique |
|--------|-------|-----------|
| `secrets` | Source dir | `portia` ~110 regex/entropy rules, git history scan |
| `dependencies` | `package.json`, `go.mod`, `requirements.txt` | `bomber` → SBOM → OSV.dev CVE + CVSS v3 |
| `supply_chain` | Project dir | Typosquat, unpinned deps, license hygiene |

---

## How the Retest Loop Works

1. **Finding created** → fingerprint `sha1(target|category|check_id|component)`
2. **Developer fixes** → restarts lab with a toggle (`WM_LAB_FIX_HEADERS=1`)
3. **Click Retest** → platform re-runs *only* that check’s scanner
4. **Compare fingerprints** → `FIXED` if fingerprint gone, `STILL_PRESENT` if still found
5. **Evidence linked** → new evidence attached, history preserved (failed retests → `INCONCLUSIVE`, never false `FIXED`)

---

## Running Tests

```bash
# from repo root, venv active
python -m pytest tests -v          # verbose — 46 passed
python -m pytest tests -q          # quiet
python -m pytest tests/test_e2e_lab.py -v  # E2E only

# with import mode required by CI
python -m pytest tests -q --import-mode=importlib
```

Covers: CVSS math vs FIRST vectors, auth gate (DNS pinning, redirect block, special-IP reject, Windows drive-path jail), evidence masking, fingerprint/dedupe, RBAC, report generation, delete cascade, live E2E lab + retest-FIXED flow, `MAX_SCAN_WORKERS` bound, and `INCONCLUSIVE` on scanner failure.

---

## Key Paths

```
world-monitor-security-assessment/
├── backend/app/              # FastAPI backend
├── frontend/                 # SPA (vanilla JS)
├── lab/vulnerable-world-monitor/   # Flask lab :8080 (Flask in requirements.txt:21)
├── targets/real-world-monitor/     # koala73/worldmonitor submodule
├── bin/                      # Go binaries (portia, bomber) — built, not committed
├── scripts/                  # start_all.ps1, build_go_tools.ps1/.sh
├── docker/                   # api.Dockerfile, lab.Dockerfile (non-root + healthcheck)
├── docs/                     # architecture, security-model, api, demo, etc.
├── tests/                    # 46 pytest tests
└── .github/workflows/ci.yml  # test + docker + pip-audit
```

---

## Quick Commands

```bash
# venv
.venv\Scripts\activate          # Windows — Scripts, not sripts
source .venv/bin/activate       # Mac/Linux

# tests
python -m pytest tests -q --import-mode=importlib

# Go tools
powershell -ExecutionPolicy Bypass -File scripts\build_go_tools.ps1
./scripts/build_go_tools.sh     # Mac/Linux

# PPTs
python scripts\make_sih_ppt.py

# CLI scans
python cli\world_monitor.py scan --lab
python cli\world_monitor.py findings --severity CRITICAL
```

---

## Safety Model

- `LAB_MODE=true` (default): scans refused unless target resolves to **loopback / RFC1918** or is in `ALLOWED_TARGETS`; cloud-metadata IPs (`169.254.169.254`, etc.) always blocked; DNS is re-resolved at scan time with IP pinning; redirects to special IPs rejected; filesystem scanners jailed to the authorized `source_path` (Windows `C:\` drive paths rejected even on Linux).
- Authorization checkbox enforced **server-side**, not just UI.
- Evidence **masks** tokens/cookies/keys before storage; sensitive headers redacted.
- Every assessment/scan/report/retest written to `audit_logs`.
- JWT: `iss` + `aud` (`world-monitor-api`) + `exp` verified; 720-min expiry.

See `docs/security-model.md` for the full threat model.

---

## Branch & CI

`master` is **protected** (public repo — free). All changes via PR:

```bash
git checkout -b feat/my-change
git commit -m "feat: ..."
git push origin feat/my-change
gh pr create --base master --title "feat: my change" --body "..."
# requires: 1 approving review + checks test + docker + pip-audit green
```

CI (`.github/workflows/ci.yml`): `test` (46 tests + `pip-audit` + `pip check`) and `docker` (build `api` + `lab` + `curl /api/health`). Docker images use `python:3.12-slim` / `python:3.14-slim`, Go 1.22, non-root users, and `HEALTHCHECK`.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `python` not found | Add Python to PATH or use `python3` / `py` |
| `go` not found | Install Go 1.21+, restart terminal |
| `npm` fails | `rm -rf node_modules package-lock.json && npm install` |
| Go build fails | Ensure Go 1.21+, check `GOPATH`/`GOMODULE` |
| Port 8000/8080 in use | `netstat -ano | findstr :8000` → `taskkill /PID <pid> /F` (Win) or `lsof -i :8000` → `kill` (Mac/Linux) |
| Tests fail | Run from repo root with venv active + `--import-mode=importlib` |
| Login “invalid credentials” | Forgot `copy .env.example .env` — defaults are `admin@example.com` / `ChangeMe_Use_Strong_Password_Here` |
| `.venv\Scripts\activate` fails | Typo — **Scripts** with capital S, not `sripts`; also `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` if PowerShell blocks it |
| `git submodule update` → “not a git repository” | Run **inside** `world-monitor-security-assessment/`; don’t use Download ZIP; use `git clone --recurse-submodules <url>` or `git submodule sync --recursive && git submodule update --init --recursive` |
| `No url found for submodule` | `git pull` then `git submodule sync --recursive` |
| Flask not found / `requirements.txt` has no Flask | It’s at `requirements.txt:21` (`flask>=3.1,<4`) — you forgot `pip install -r requirements.txt` or venv not active |
| DB locked / login still fails after `.env` | Delete `database/worldmonitor.db` and restart platform — it re-seeds from current `.env` |

**Reset DB (fresh seed):**
```powershell
Remove-Item database/worldmonitor.db -Force -ErrorAction SilentlyContinue
.venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
# log in with your current .env ADMIN_EMAIL/PASSWORD
```

---

## Documentation Index

`docs/architecture.md` · `docs/security-model.md` · `docs/api.md` · `docs/demo.md` · `docs/deployment.md` · `docs/integration.md` · `docs/scanner-development.md` · `docs/requirements-coverage.md` · `docs/repository-audit.md`

---

## License & Attribution

Integrated scanner components are **AGPL-3.0**; this repository is distributed under **AGPL-3.0** — see `NOTICE.md` and `LICENSE`.

---

## Target Attribution

**Real World Monitor** (`targets/real-world-monitor/`, submodule `https://github.com/koala73/worldmonitor`): real-time global intelligence dashboard with AI news aggregation and geopolitical monitoring (AGPL-3.0). Used as the genuine production codebase target for static + dynamic assessment.

**Vulnerable Lab** (`lab/vulnerable-world-monitor/`): intentionally insecure Flask app included in this repo for scanner demonstration — **never expose beyond `127.0.0.1`**.

