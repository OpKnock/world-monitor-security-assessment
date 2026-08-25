# API Reference (v1)

Base URL: `http://127.0.0.1:8000/api` · Interactive: `/api/docs` (OpenAPI JSON at
`/api/openapi.json`). Auth: `Authorization: Bearer <jwt>`.

## Auth
| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/auth/register` | `{email, password}` | 201 → token; first user = admin; 30/min |
| POST | `/auth/login` | `{email, password}` | timing-safe verify; 401 on failure |
| GET | `/auth/me` | — | current user + role |

## Assessments
| Method | Path | Body/Query | Notes |
|---|---|---|---|
| POST | `/assessments` | `{target, modules[], authorized, source_path?, auth_token?, module_targets?{}}` | **403 unless gate passes**; 201 → assessment with queued scan_runs; analyst+ |
| GET | `/assessments` | — | last 50 summaries |
| GET | `/assessments/{id}` | — | full detail incl. scan_runs + severity_counts |
| GET | `/assessments/{id}/findings` | — | findings for one assessment |
| GET | `/assessments/-/findings` | `?severity&category&status` | global findings feed |
| POST | `/assessments/findings/{id}/retest` | — | returns `{retest_status: FIXED\|STILL_PRESENT, evidence[]}`; analyst+ |
| GET | `/assessments/findings/{id}/evidence` | — | sanitized evidence documents |

## Modules keys
`authentication · authorization · api · input_validation · headers · tls · secrets · dependencies`

HTTP modules need `target`; `secrets`/`dependencies` need `source_path`
(defaults to the lab tree). Overrides are per-module via `module_targets`.

## Platform
| Method | Path | Notes |
|---|---|---|
| GET | `/dashboard` | totals, by-severity, category matrix, recent |
| GET | `/scanners` | module metadata + LAB_MODE |
| POST | `/lab/token` | fetch lab demo JWT (alice) for authenticated scans |
| POST | `/reports/assessment/{id}?format=pdf\|json\|md` | generate report |
| GET | `/reports/assessment/{id}` | list generated reports |
| GET | `/reports/{report_id}/download` | download file |
| GET | `/audit-logs` | admin only |
| GET | `/settings` | effective configuration |
| GET | `/health` | liveness |

Errors: RFC-ish JSON `{"detail": "..."}`; 401 unauthenticated, 403 RBAC/gate,
422 validation, 429 rate-limited.
