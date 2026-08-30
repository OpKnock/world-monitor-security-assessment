# API Reference (v1)

Base URL: `http://127.0.0.1:8000/api` · Interactive docs: `/api/docs` (OpenAPI JSON at `/api/openapi.json`). Authentication: `Authorization: Bearer <jwt>`.

All endpoints return JSON. Errors use `{"detail": "..."}` with status `401` unauthenticated, `403` RBAC or authorization-gate refusal, `422` validation, `429` rate-limited.

## Auth

| Method | Path | Body | Success | Notes |
|---|---|---|---|---|
| POST | `/auth/register` | `{email, password}` | `201` → `{access_token, user}` | First user becomes admin; `30/min` per IP |
| POST | `/auth/login` | `{email, password}` | `200` → `{access_token, user}` | Timing-safe verify; `401` on failure |
| GET | `/auth/me` | — | `200` → `{id, email, role}` | Current user + role |

Password rules: minimum 12 characters; validated by Pydantic. Roles: `viewer` (read-only) < `analyst` (create / retest / report) < `admin` (full).

## Assessments & findings

| Method | Path | Body / Query | Auth | Notes |
|---|---|---|---|---|
| POST | `/assessments` | `{target, modules[], authorized, source_path?, auth_token?, module_targets?{}}` | analyst+ | **403 unless gate passes**; `201` → assessment with queued `scan_runs` |
| GET | `/assessments` | `?limit=50&offset=0&status` | any | Summaries (`id`, `target`, `status`, `modules`) paginated (limit 1–200) |
| GET | `/assessments/{id}` | — | any | Full detail incl. `scan_runs[]` + `severity_counts` + `total_findings`/`total_duration_ms` |
| GET | `/assessments/{id}/findings` | — | any | Findings for one assessment |
| GET | `/assessments/-/findings` | `?severity&category&status&limit=300&offset=0` | any | Global findings feed (up to 1000) |
| GET | `/assessments/findings/{id}` | — | any | Single finding by ID |
| POST | `/assessments/findings/{id}/retest` | — | analyst+ | Returns `{retest_status: FIXED\|STILL_PRESENT, evidence[]}` |
| GET | `/assessments/findings/{id}/evidence` | — | any | Sanitized evidence documents for one finding |
| DELETE | `/assessments/{id}` | — | analyst+ | Deletes assessment + findings + evidence files + reports + related audit rows |
| DELETE | `/findings/{id}` | — | analyst+ | Deletes single finding + its evidence files |
| DELETE | `/reports/{id}` | — | analyst+ | Deletes single report file + DB row |

### Module keys (12 total — API contract)

```
authentication · authorization · api · input_validation · headers · tls ·
secrets · dependencies · supply_chain · graphql · deep_scan · fuzzing
```

* HTTP modules (`authentication`, `authorization`, `api`, `input_validation`, `headers`, `tls`, `graphql`, `deep_scan`, `fuzzing`) require `target` — a gate-validated `http(s)://` URL.
* Filesystem modules (`secrets`, `dependencies`, `supply_chain`) require `source_path` — a gate-validated path inside the authorized source tree (defaults to `lab/vulnerable-world-monitor`).
* Hybrid assessments may combine both kinds in one `modules` array.
* Per-module URL overrides via `module_targets`, e.g. `{"authorization": "http://127.0.0.1:8080/api/reports"}` — each override is gate-validated independently.

## Platform & operations

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/dashboard` | any | Totals, `by_severity`, `category` matrix, recent assessments |
| GET | `/scanners` | any | Module catalogue (`key`, `label`, `needs`, `available`) + `lab_mode` |
| POST | `/lab/token` | any | Fetch lab demo JWT (`alice` / `user123`) for authenticated scans |
| POST | `/reports/assessment/{id}?format=pdf\|json\|md\|csv` | analyst+ | Generate report; returns `{id, format, path}` |
| GET | `/reports/assessment/{id}` | any | List generated reports for one assessment |
| GET | `/reports/{id}/download` | any | Download report file (correct `Content-Type`) |
| GET | `/audit-logs` | admin | Last 200 audit entries |
| GET | `/settings` | any | Effective configuration (no secrets) |
| GET | `/health` | none | Liveness: `{status, app, version, lab_mode}` |

## Rate limiting & tracing

Sliding-window per IP: `30/min` on `/auth/*`, `600/min` general, `20/min` on `POST /assessments`, `20/min` via `WM_LAB_RATELIMIT=1` on lab `/api/*`. Exceeding the window returns `429` with `Retry-After` and `X-Request-ID`. Every response carries `X-Request-ID` for tracing (client may supply one).

## Pagination & filtering

* `GET /assessments` — paginated (`limit` 1–200, default 50; `offset` 0+), ordered by `created_at` desc; optional `status` filter.
* `GET /assessments/-/findings` — paginated (`limit` 1–1000, default 300), filterable by `severity`, `category`, `status` (case-insensitive) with `offset`.
* Findings within an assessment are ordered by `severity` for stable UI rendering.
* All list endpoints support `X-Request-ID` correlation for audit.

## OpenAPI

The schema is served at `/api/openapi.json` and rendered at `/api/docs` (Swagger UI). All Pydantic request models are fully typed, so client generation (`openapi-generator`, `swagger-codegen`) works against the live endpoint.
