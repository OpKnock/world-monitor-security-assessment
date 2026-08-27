# Deployment

## A. Native (recommended for local use)

See `README.md` quick start. Two processes:

* **Platform** — `uvicorn backend.main:app --host 127.0.0.1 --port 8000`
* **Vulnerable lab** — `python lab/vulnerable-world-monitor/app.py` (binds `127.0.0.1:8080` only)

Helper:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1            # normal
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1 -FixHeaders  # with header fix
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1 -PatchIdor   # with IDOR fix
```

For production-grade serving on Linux, replace `uvicorn` with `gunicorn -k uvicorn.workers.UvicornWorker backend.main:app` or `waitress`; both read the same `backend.main:app`.

The API has been smoke-tested with two Uvicorn workers (`--workers 2`) and
`GET /api/health` returns healthy responses from both processes. Assessment
execution is bounded per process; use a shared queue/rate-limit service when
running multiple replicas behind a load balancer.

## B. Docker Compose

`docker/docker-compose.yml` defines two services:

* `lab` — vulnerable World Monitor, exposed only on `127.0.0.1:8080`.
* `api` — platform + UI on `127.0.0.1:8000`; builds Go scanner binaries in a builder stage so no host toolchain is needed.

```powershell
docker compose -f docker/docker-compose.yml up --build
```

Volumes persist `database/`, `evidence/`, `reports/` on the host.

Fix toggles via environment on the `lab` service:

```yaml
environment:
  WM_LAB_PATCH_IDOR: "1"
  WM_LAB_FIX_HEADERS: "1"
```

## C. Configuration reference

All configuration is environment-driven (`.env`, see `.env.example`). Never commit `.env`.

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | `CHANGE-ME-…` | JWT signing key — generate with `python -c "import secrets;print(secrets.token_hex(32))"` and rotate per installation |
| `DATABASE_URL` | `sqlite:///database/worldmonitor.db` | SQLAlchemy URL; set to `postgresql+psycopg://…` for Postgres |
| `EVIDENCE_DIR` | `evidence` | Evidence store root (relative to repo root) |
| `REPORT_DIR` | `reports` | Report output root |
| `LAB_MODE` | `true` | When `true`, only loopback / RFC1918 targets are allowed |
| `ALLOWED_TARGETS` | `` | Comma-separated extra URLs always permitted |
| `LAB_APP_URL` | `http://127.0.0.1:8080` | Vulnerable lab URL (platform fetches demo tokens here) |
| `LAB_SOURCE_DIR` | `lab/vulnerable-world-monitor` | Default filesystem scope for `secrets` / `dependencies` / `supply_chain` |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | `admin@example.com` / `admin` | Bootstrap admin account (password synced on every boot) |
| `ANALYST_EMAIL` / `ANALYST_PASSWORD` | `analyst@example.com` / `admin` | Bootstrap analyst account |
| `MAX_SCAN_WORKERS` | `4` | Maximum concurrent assessment workers per process |
| `API_RATE_LIMIT_PER_MINUTE` | `600` | General rate limit |
| `AUTH_RATE_LIMIT_PER_MINUTE` | `30` | Auth endpoint rate limit |

## D. Data layout

| Path | Contents |
|---|---|
| `database/worldmonitor.db` | SQLite database (swap `DATABASE_URL` for Postgres) |
| `evidence/<assessment-id>/*.json` | Sanitized evidence documents (one file per exchange / scanner output) |
| `reports/report_<id>_<ts>.{pdf,json,md,csv}` | Generated deliverables |
| `bin/portia.exe` / `bin/bomber.exe` / `bin/chainscanner.exe` | Built Go scanners (produced by `scripts/build_go_tools.ps1`) |

All three directories are on `.gitignore`; evidence and reports are never committed.

## E. Health & operations

* `GET /api/health` — liveness probe with `lab_mode` flag.
* `GET /api/settings` — effective configuration (no secrets).
* `python cli/world_monitor.py status` — config + binary presence check.
* `GET /api/audit-logs` (admin) or `SELECT * FROM audit_logs` — full audit trail.
* Logs: platform writes to stdout; lab writes to stdout; both are visible in the `start_all.ps1` windows or `docker compose logs`.

## F. Upgrading

1. Pull latest code.
2. `.\.venv\Scripts\pip install -r requirements.txt` (migrations run automatically via `Base.metadata.create_all`).
3. Rebuild Go binaries only if scanner sources changed: `scripts\build_go_tools.ps1`.
4. Restart both services.
