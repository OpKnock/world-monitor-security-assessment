<div align="center">

# World Monitor Security Assessment Platform

**Unified · Localhost-only · 12 Scanner Modules · CVSS v3.1 · Retest-until-FIXED**

[![ci](https://github.com/OpKnock/world-monitor-security-assessment/actions/workflows/ci.yml/badge.svg)](https://github.com/OpKnock/world-monitor-security-assessment/actions/workflows/ci.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white)
![Tests 46 passed](https://img.shields.io/badge/tests-46%20passed-brightgreen?style=flat-square)
![CVSS v3.1](https://img.shields.io/badge/CVSS-v3.1-orange?style=flat-square)
![License AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-green?style=flat-square)
![Security localhost-only](https://img.shields.io/badge/security-localhost--only-critical?style=flat-square)

_A unified security assessment platform that scans an intentionally vulnerable lab and the real World Monitor codebase, normalizes findings into one schema, scores with **CVSS v3.1**, computes a **Security Health Score 0-100** (penalty-weighted by severity), stores masked evidence, explains business impact, recommends remediation, supports **cinematic retest-until-FIXED** with `Why this matters?` and before/after health, and generates **PDF / JSON / Markdown / CSV** reports. Docker images run as non-root with healthchecks. CI runs **46 tests + pip-audit** on every push._

</div>

```
DETECT -> VERIFY -> DOCUMENT -> SCORE -> EXPLAIN IMPACT -> REMEDIATE -> RETEST -> REPORT
```

<details>
<summary><strong>Contents</strong></summary>

- [Two Targets, One Platform](#two-targets-one-platform)
- [The 12 Scanner Modules](#the-12-scanner-modules)
- [Architecture](#architecture)
- [Security Health Score (0–100)](#security-health-score-0100)
- [How Each Scanner Works](#how-each-scanner-works)
- [How Retest and Fix Work (for judges)](#how-retest-and-fix-work-for-judges)
- [How the Retest Loop Works](#how-the-retest-loop-works)
- [Prerequisites](#prerequisites)
- [Quick Start — Fresh Clone](#quick-start--fresh-clone)
- [One-Command Setup (recommended) — 1 terminal, 1 command](#one-command-setup-recommended-1-terminal-1-command)
- [Three-Terminal Setup (advanced — manual)](#three-terminal-setup-advanced--manual)
- [Quick Demo (2 min)](#quick-demo-2-min)
- [Lab Fix Toggles (for retest demo)](#lab-fix-toggles-for-retest-demo)
- [Demo Accounts](#demo-accounts)
- [Environment Variables](#environment-variables)
- [Docker Alternative](#docker-alternative)
- [Running Tests](#running-tests)
- [Key Paths](#key-paths)
- [Quick Commands](#quick-commands)
- [Safety Model](#safety-model)
- [Branch & CI](#branch--ci)
- [Troubleshooting](#troubleshooting)
- [Documentation Index](#documentation-index)

</details>

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

## Security Health Score (0–100)

One number for judges, before & after:

```
SECURITY HEALTH  68/100  At risk        Penalty 32
[CRITICAL 2] [HIGH 4] [MEDIUM 6] [LOW 3]   FIXED 0  STILL_PRESENT 5

  FIX applied (WM_LAB_FIX_HEADERS=1)

SECURITY HEALTH  91/100  Healthy        Penalty 9
[CRITICAL 0] [HIGH 1] [MEDIUM 3] [LOW 2]   FIXED 5  STILL_PRESENT 0
```

- **Weights:** `CRITICAL 5, HIGH 3, MEDIUM 1.5, LOW 0.5, INFO 0` -> `score = 100 - penalty` clamped 0–100. Example `2C+4H+6M+3L = 32.5 -> 68`; after fixing `2C+3H+3M` -> `91` (+23 pts).
- **Dashboard hero:** `SECURITY HEALTH 68/100` with conic-gradient ring, health bar, penalty, `FIXED/STILL_PRESENT` counts, severity breakdown, and `Before/after (last 2): 68 → 91 +23 pts` (from `GET /api/dashboard` `health`, `recent_health`, `retest_summary`).
- **Recent table:** new `Health` column per assessment (badge `healthColor`).
- **Endpoint:** `GET /api/dashboard` now returns `health{score,penalty,weights}`, `recent_health[{id,score,counts}]` (last 8), `retest_summary`.


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

## How Retest and Fix Work (for judges)

**Fix is not automatic ? the platform proves a fix was verified:**

1. **Vulnerable lab has fix toggles** (`lab/vulnerable-world-monitor/app.py`): `WM_LAB_PATCH_IDOR=1`, `WM_LAB_FIX_HEADERS=1`, `WM_LAB_PATCH_SQLI=1`, `WM_LAB_RATELIMIT=1`. Restarting the lab with a toggle *actually* patches the code path (e.g., `FIX_HEADERS` adds HSTS/CSP, `PATCH_SQLI` uses parametrized query).
2. **Assessment finds the weakness** ? e.g., `headers` scanner grades 6 headers `F` before fix.
3. **Remediation guidance** is shown per finding (`Why this matters?` card: Risk/CVSS, Affected, Fix, Retest) ? the *developer* applies the fix (in the lab: restart with toggle; in real code: edit source).
4. **Retest** (`POST /api/assessments/findings/{id}/retest`) re-runs *only* that check's scanner against the *current* target. Fingerprint `sha1(target|category|check_id|component)` is compared: `FIXED` if gone, `STILL_PRESENT` if still found, `INCONCLUSIVE` if scanner failed (never false `FIXED`).
5. **Dashboard health updates** `68 -> 91` and `FIXED` count increases ? the cinematic `Verifying fix...` overlay -> `FIXED` (green) is the demo moment. Evidence is re-linked and audit-logged.

**Try it:**
```powershell
# 1. Start lab vulnerable (no toggles) -> Scan Playground :8080 -> see CRITICAL/HIGH findings, health 68
# 2. Restart lab fixed:
$env:WM_LAB_FIX_HEADERS="1"; $env:WM_LAB_PATCH_SQLI="1"; python lab/vulnerable-world-monitor/app.py
# 3. In platform: Findings -> click header finding -> Retest -> overlay -> FIXED, health 91
```

`fuzzing` is opt-in (`WM_ENABLE_FUZZING=1`) and `tls`/`graphql`/`deep_scan` degrade to `skipped` when not applicable ? `skipped` is not a failure.

---

## How the Retest Loop Works

1. **Finding created** → fingerprint `sha1(target|category|check_id|component)` ? `Why this matters?` card shows Risk/CVSS, Affected, Fix, Retest status
2. **Developer fixes** → restarts lab with a toggle (`WM_LAB_FIX_HEADERS=1`)
3. **Click Retest** → cinematic overlay `Verifying fix...` (spinner) → platform re-runs *only* that check’s scanner
4. **Compare fingerprints** → overlay `FIXED` (green) if gone, `STILL_PRESENT` (red) if still found ? then `Why this matters?` updates, dashboard `SECURITY HEALTH 68 → 91`
5. **Evidence linked** → new evidence attached, history preserved (failed retests → `INCONCLUSIVE`, never false `FIXED`); `Findings` tab now correctly lists via `GET /api/assessments/-/findings` (fixed hijack)

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

> ⚠️ **Do NOT run from `C:\\WINDOWS\\System32`** (you will get `Permission denied` / `Access is denied`). Open **PowerShell** normally and first run `Set-Location $HOME\Desktop` (or `cd %USERPROFILE%\Desktop` for CMD) ? then copy/paste one block at a time below. Do **not** use “Download ZIP”.

### Windows PowerShell

```powershell
# 0. Go to a writable folder FIRST ? do NOT stay in C:\WINDOWS\System32 (Permission denied)
Set-Location $HOME\Desktop

# 1. Clone with submodule
git clone --recurse-submodules https://github.com/OpKnock/world-monitor-security-assessment.git
Set-Location world-monitor-security-assessment

# 2. Python env
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt  # includes Flask, FastAPI, etc.

# 3. Build Go scanners
powershell -ExecutionPolicy Bypass -File scripts\build_go_tools.ps1

# 4. Verify binaries
Get-ChildItem bin

# 5. Configure env BEFORE first run
Copy-Item .env.example .env
# defaults work for demo; change SECRET_KEY + ADMIN_PASSWORD before real use

# 6. Run — one terminal, one command
python scripts/start_all.py
```

### Windows CMD

```cmd
:: 0. Go to Desktop first ? not System32
cd /d %USERPROFILE%\Desktop

:: 1. Clone
git clone --recurse-submodules https://github.com/OpKnock/world-monitor-security-assessment.git
cd world-monitor-security-assessment

:: 2. Python env
python -m venv .venv
.\.venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt

:: 3. Build Go scanners
powershell -ExecutionPolicy Bypass -File scripts\build_go_tools.ps1

:: 4. Verify
dir bin

:: 5. Configure
copy .env.example .env

:: 6. Run
python scripts\start_all.py
```

### Mac / Linux

```bash
# 1. Clone
git clone --recurse-submodules https://github.com/OpKnock/world-monitor-security-assessment.git
cd world-monitor-security-assessment

# 2. Python env
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

# 3. Build Go scanners
chmod +x scripts/build_go_tools.sh && ./scripts/build_go_tools.sh

# 4. Verify
ls bin/

# 5. Configure
cp .env.example .env

# 6. Run
python scripts/start_all.py
```

**Default login after step 5:** `admin@example.com` / `ChangeMe_Use_Strong_Password_Here`  
Override via `ADMIN_PASSWORD` in `.env`.

---

## One-Command Setup (recommended) — 1 command, 3 terminals

Runs **lab :8080 + platform :8000 + real app :3000 (optional)** together. On **Windows** it pops up 3 new PowerShell windows (one per service) so the three-terminal setup shows properly; on **Mac/Linux** it streams prefixed `[lab]/[platform]/[real-app]` logs in one terminal. If a port is already busy it is skipped (“already existence”).

```bash
# from repo root, venv active — one command, 3 terminals pop up (Windows)
python scripts/start_all.py
```

> **That is it.** 3 terminals pop up: `lab :8080` + `platform :8000` + `real app :3000` (optional). If a port is already busy it is skipped. `Ctrl+C` in each window to stop or close the window.


<details>
<summary>Variants (optional) ? only if you need them</summary>

```bash
# with fix toggles for retest demo (headers + IDOR)
python scripts/start_all.py --fix-headers --patch-idor
# lab + platform only, skip real app
python scripts/start_all.py --no-real-app

# Windows PowerShell wrapper (same)
powershell -ExecutionPolicy Bypass -File scripts/start_all.ps1
# Mac/Linux wrapper
chmod +x scripts/start_all.sh && ./scripts/start_all.sh
```

All wrappers delegate to the same `scripts/start_all.py` ? pick one.

</details>

What it does: checks `.venv`, checks ports 8080/8000/3000 (skips if already listening), starts Flask lab and uvicorn platform (and `npm run dev` for real app if `node_modules` exists, otherwise hints `python scripts/ensure_real_app.py` + `npm install`), streams `[lab]/[platform]/[real-app]` logs, `Ctrl+C` stops all.

> **If `targets/real-world-monitor` shows vite import error** `Failed to resolve import "./_inventory-facts.generated.js"` ? `python scripts/ensure_real_app.py` then `cd targets/real-world-monitor && npm install`.

---

## Three-Terminal Setup (advanced ? manual)

If you prefer 3 separate terminals:

**Terminal 1 ? Vulnerable Lab** (`http://127.0.0.1:8080`):
```bash
cd lab/vulnerable-world-monitor
python app.py
```

**Terminal 2 ? Platform** (`http://127.0.0.1:8000`):
```bash
# from repo root
.venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

**Terminal 3 — Real World Monitor** (optional, `http://127.0.0.1:3000`):
```bash
# from repo root — no manual cd needed, also fixes vite _inventory-facts.generated.js if missing
npm --prefix targets/real-world-monitor install
python scripts/ensure_real_app.py
npm --prefix targets/real-world-monitor run dev -- --port 3000 --host 127.0.0.1
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

1. Open `http://127.0.0.1:8000` → Login `admin@example.com` / `ChangeMe_Use_Strong_Password_Here` (see `PLATFORM` vs `LAB` boxes on login)
2. **Dashboard** shows `SECURITY HEALTH 68/100` (At risk) — penalty-weighted `2C+4H+6M+3L`; `Findings` tab now lists all normalized findings (fixed `/-/findings` hijack 404)
3. **New Assessment** → Preset `Playground :8080` → tick “authorized” → **Start** — watch live progress & health bar
4. Click a finding → `Why this matters?` card (Risk/CVSS, Affected, Fix, Retest) → **Retest** → cinematic overlay `Verifying fix...` → `STILL_PRESENT` (red)
5. Restart lab with a fix: `$env:WM_LAB_FIX_HEADERS=1; python lab\vulnerable-world-monitor\app.py`
6. **Retest** again → overlay `FIXED` (green) ✓ — dashboard updates `SECURITY HEALTH 91/100` Healthy (+23 pts), `Before/after: 68 → 91`
7. **Reports** → Generate PDF / JSON / Markdown / CSV (now includes health)

> **New to security?** See `docs/poc-for-non-coders.md` ? plain-English proofs, before/after health, `Why this matters?` per finding, masked evidence, and how to verify without coding.

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
| `ModuleNotFoundError: No module named .flask.` on `lab/app.py` | Not in venv / missed `pip install`. Fix: `.venv\\Scripts\\activate` (Win) or `source .venv/bin/activate` (Mac/Linux) then `pip install -r requirements.txt` (has `flask>=3.1,<4` at line 21). Or run: `.venv\\Scripts\\python lab/vulnerable-world-monitor/app.py`. The lab now shows a friendly hint if Flask is missing. |
| Vite `[plugin:vite:import-analysis] Failed to resolve import "./_inventory-facts.generated.js"` in `targets/real-world-monitor` | Generated file gitignored, missing on fresh clone until `postinstall`. Fix: `cd targets/real-world-monitor && npm install` (postinstall runs `npm run inventory:facts` -> creates `api/_inventory-facts.generated.js` + `api/_product-catalog.generated.js`). Or quick stub: `python scripts/ensure_real_app.py` (creates minimal stubs so `npm run dev` can start), then `npm run inventory:facts && npm run product:facts` for authoritative data. See `scripts/ensure_real_app.py`. |
| Assessment shows `4) skipped` / `experimental module - disabled by default` while scanning | Not an error -- `fuzzing` is an *optional experimental* module disabled by default. `skipped` means the scanner was not applicable and does **not** fail the assessment. Enable with `WM_ENABLE_FUZZING=1` (PowerShell: `$env:WM_ENABLE_FUZZING="1"`) before starting the platform, or just ignore -- other 11 modules still run and `completed` is still success. See `backend/app/scanners/zdv_scan.py: FuzzingModule`. |

**Reset DB (fresh seed):**
```powershell
Remove-Item database/worldmonitor.db -Force -ErrorAction SilentlyContinue
.venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
# log in with your current .env ADMIN_EMAIL/PASSWORD
```

---

## Documentation Index

`docs/architecture.md` · `docs/security-model.md` · `docs/api.md` · `docs/demo.md` · `docs/poc-for-non-coders.md` · `docs/deployment.md` · `docs/integration.md` · `docs/scanner-development.md` · `docs/requirements-coverage.md` · `docs/repository-audit.md`

---

## Keywords / Tags

`security` · `vulnerability-scanner` · `security-assessment` · `dast` · `sast` · `sca` · `supply-chain-security` · `secrets-detection` · `cvss` · `owasp` · `penetration-testing` · `devsecops` · `appsec` · `vulnerability-management` · `security-automation` · `threat-modeling` · `fastapi` · `docker` · `python` · `go`

> GitHub repository topics are also set — see the **About** section on GitHub for filterable tags.

---

## License & Attribution

Integrated scanner components are **AGPL-3.0**; this repository is distributed under **AGPL-3.0** — see `NOTICE.md` and `LICENSE`.

---

## Target Attribution

**Real World Monitor** (`targets/real-world-monitor/`, submodule `https://github.com/koala73/worldmonitor`): real-time global intelligence dashboard with AI news aggregation and geopolitical monitoring (AGPL-3.0). Used as the genuine production codebase target for static + dynamic assessment.

**Vulnerable Lab** (`lab/vulnerable-world-monitor/`): intentionally insecure Flask app included in this repo for scanner demonstration — **never expose beyond `127.0.0.1`**.
