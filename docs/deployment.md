# Deployment

## A. Native Windows / Linux (recommended for the demo)

See README quick start. Services: uvicorn (platform) + Flask dev server (lab).
For production-grade serving swap in `gunicorn -k uvicorn.workers.UvicornWorker`
(Linux) or waitress; both read the same `backend.main:app`.

## B. Docker Compose

`docker/docker-compose.yml` defines three services:

* `lab` — vulnerable World Monitor, bound to the compose-internal network and
  published on 127.0.0.1:8080 only.
* `api` — platform + UI on 127.0.0.1:8000; builds Go scanner binaries in a
  builder stage so no host toolchain is needed.
* Volumes for `database/`, `evidence/`, `reports/`.

```powershell
docker compose -f docker/docker-compose.yml up --build
```

**Honesty note:** Docker Desktop was *not installed* on the machine where this
repository was built, so the compose file is provided but was validated by
inspection + native-run parity, not by a live `up`. The native path above is
the battle-tested one. Fix toggles via environment:
`WM_LAB_PATCH_IDOR=1`, `WM_LAB_FIX_HEADERS=1` on the `lab` service.

## C. Configuration reference

All configuration is environment-driven (`.env`, see `.env.example`):
`SECRET_KEY`, `DATABASE_URL`, `EVIDENCE_DIR`, `REPORT_DIR`, `LAB_MODE`,
`ALLOWED_TARGETS`, `LAB_APP_URL`, `LAB_SOURCE_DIR`, bootstrap admin/analyst
credentials, worker/limit knobs. Never commit `.env`; rotate `SECRET_KEY`
per-installation (`python -c "import secrets;print(secrets.token_hex(32))"`).

## D. Data layout

| Path | Contents |
|---|---|
| `database/worldmonitor.db` | SQLite (swap URL for Postgres) |
| `evidence/<assessment-id>/*.json` | sanitized evidence documents |
| `reports/report_<id>_<ts>.{pdf,json,md}` | generated deliverables |
| `bin/portia.exe`, `bin/bomber.exe` | built Go scanners |

## E. Health & operations

* `GET /api/health` — liveness + LAB_MODE flag.
* `python cli\world_monitor.py status` — config + binary presence.
* Audit trail: `/api/audit-logs` (admin) or query `audit_logs` table.
