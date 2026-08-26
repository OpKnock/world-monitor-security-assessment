# Security Model

The platform assesses security; it must not become an attack tool or be itself trivially compromised.

## 1. Authorized-target protection

* `LAB_MODE=true` (default). `validate_http_target()` resolves DNS and allows only loopback / RFC1918 addresses; link-local metadata (`169.254.169.254`, `metadata.google.internal`) is always refused; public IPs are rejected with `403` and an explanatory message.
* Explicit escape hatch via `ALLOWED_TARGETS` (comma-separated, audited, stored in the assessment note).
* Filesystem scopes (`secrets`, `dependencies`, `supply_chain`) must resolve inside the authorized source tree (`validate_source_path` — checks against both `LAB_SOURCE_DIR` and the repository root).
* The UI authorization checkbox alone does nothing — the server refuses `authorized=false` regardless of client state.

## 2. Platform authentication & sessions

* Passwords: PBKDF2-HMAC-SHA256, 390 000 iterations, per-user 16-byte salt (standard library only; no compiled dependencies). Verification is timing-safe with a pre-computed dummy hash to prevent account enumeration.
* Sessions: HS256 JWT, algorithm allow-list pinned to `["HS256"]` (`none` is never accepted by the platform), issuer `world-monitor` checked, 12 h expiry, transported in the `Authorization` header (no cookie — no CSRF surface for the JSON API), `leeway=10s` for clock skew.
* First registered user becomes admin; bootstrap accounts come from `.env`. Passwords are synced from `.env` on every boot so stale credentials cannot lock the operator out.

## 3. Role-based access control

| Role | Capabilities |
|---|---|
| `viewer` | Read dashboards, findings, evidence, reports |
| `analyst` | All of viewer + create assessments, generate reports, run retests, delete findings/assessments/reports |
| `admin` | All of analyst + read `audit_logs`, manage users |

Enforced server-side via `require_role()` dependencies, mirrored (UX only) in the single-page app. Every role check is tested by the RBAC test suite.

## 4. Input / output hardening

* All persistence via SQLAlchemy parameterized queries (no string-interpolated SQL); Pydantic validates with length limits (e.g. `target` ≤2048, password ≥12).
* Pydantic models validate every request body; unknown fields are ignored; module lists deduped and normalized.
* Output encoding: the SPA escapes all interpolated strings (`esc()`) — no `innerHTML` with raw user data; evidence display truncates at 12k chars with copy-to-clipboard.
* Rate limiting: sliding-window per IP — `30/min` auth endpoints, `600/min` general, `20/min` assessment creation, plus lab `20/min` with `WM_LAB_RATELIMIT=1` and `Retry-After`.
* Secure response headers set globally (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-*`, `HSTS preload`); API responses carry `Cache-Control: no-store` and CSP `default-src 'none'`.
* Request ID tracing: every response carries `X-Request-ID`; audit logs capture IP and user-agent when available.

## 5. Evidence hygiene

* Sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key` variants, `Proxy-Authorization`) are masked to `Bearer ********` style before storage.
* Body and text masking covers `password`, `token`, `api_key` assignments, AWS keys (`AKIA…`), GitHub tokens (`ghp_…`), OpenAI keys (`sk-…`), and PEM private-key blocks.
* `portia` masks secret values *before* emitting JSON; the platform stores that already-masked form.
* Evidence documents live under `evidence/<assessment-id>/` as plain JSON files, referenced (not embedded) from the database.

## 6. Audit logging

Actions logged: `assessment.created`, `scan.finished` (with status / duration / finding count), `retest.executed`, `report.generated`, `assessment.deleted`, `finding.deleted`, `report.deleted`, `auth.register`, `auth.login`, `scan.watchdog`. Each entry captures `ip_address` and `user_agent` when available; never logged: passwords, raw tokens, or unmasked secret values. Logs are readable by admins via `GET /api/audit-logs`.

On delete, audit rows referencing the deleted identifiers are purged so no orphaned traces remain; the delete operation itself writes one `*.deleted` audit entry. Assessment rows now track `total_findings` and `total_duration_ms` for dashboards.

## 7. Lab isolation

The vulnerable application binds `127.0.0.1` only, prints its intentionally-insecure status on every page, uses only fake documented credentials, and ships fix toggles used by the retest demonstration. It must never be exposed beyond loopback.

## 8. Known limitations

* SQLite suits the single-node deployment; set `DATABASE_URL` to Postgres for multi-worker deployments (SQLAlchemy layer is portable; see `docs/deployment.md`).
* In-process job threads reset if the backend restarts mid-scan (rows stuck at `running` are swept to `failed` on next boot).
* Scanner binaries are built for the host platform by `scripts/build_go_tools.ps1`; cross-platform builds use `GOOS` / `GOARCH` overrides.
