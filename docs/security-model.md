# Security Model

The platform assesses security; it must not become an attack tool or be itself
trivially compromised. Controls below map to spec §46-§48.

## 1. Authorized-target protection

* `LAB_MODE=true` default. `validate_http_target()` resolves DNS and allows only
  loopback / RFC1918 addresses; link-local metadata (`169.254.169.254`,
  `metadata.google.internal`) is always refused; public IPs raise 403 with an
  explanatory message.
* Explicit escapes hatch via `ALLOWED_TARGETS` env (documented, audited).
* Filesystem scopes (`secrets`, `dependencies`) must resolve inside the repo/lab
  tree (`validate_source_path`).
* The UI checkbox alone does nothing — the server refuses `authorized=false`
  regardless of client.

## 2. Platform authentication & sessions

* Passwords: PBKDF2-HMAC-SHA256, 390k iterations, per-user salt (stdlib; no
  compiled deps). Verification is timing-safe with a pre-computed dummy hash
  (pattern adopted from OpKnock/siem-dashboard) to prevent enumeration.
* Sessions: HS256 JWT, algorithm allow-list pinned (`["HS256"]` — `none` can never
  be accepted by the platform itself), issuer checked, 12 h expiry, transported in
  `Authorization` header (no cookie ⇒ no CSRF surface for the JSON API).
* First registered user becomes admin; seeded demo accounts come from `.env` and
  must be changed outside demos.

## 3. RBAC

| Role | Can |
|---|---|
| viewer | read dashboards/findings/reports |
| analyst | create assessments, generate reports, run retests |
| admin | everything incl. `/api/audit-logs`, user management |

Enforced server-side in dependencies (`require_role`), mirrored (UX only) in SPA.

## 4. Input/output hardening

* All persistence via SQLAlchemy parameterization (no string SQL).
* Pydantic models validate every request body; unknown fields ignored.
* Output encoding: React-free SPA escapes all interpolated strings (`esc()`).
* Rate limiting: sliding-window per IP — 30/min auth endpoints, 600/min general,
  20/min assessment creation.
* Secure response headers set globally (`nosniff`, `DENY`, `no-referrer`);
  API responses marked `no-store`.

## 5. Evidence hygiene

* Sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, API-key variants)
  masked to `Bearer ********` style.
* Body/regex masking for passwords, tokens, AWS/GitHub/OpenAI shapes, PEM blocks.
* portia masks secret values *before* emitting JSON; we store that masked form.
* Evidence documents live under `evidence/<assessment>/` as plain JSON files,
  referenced (not embedded) from the DB.

## 6. Audit logging

Actions logged: assessment created, scan finished (status/duration/count),
retest executed, report generated, auth register/login. Never logged: passwords,
tokens, raw sensitive bodies. Logs are readable by admins via the API.

## 7. Lab isolation

The vulnerable app binds `127.0.0.1` only, prints its intentionally-insecure
status on every page, uses fake credentials exclusively, and ships two fix
toggles used by the retest demo. It must never be exposed beyond loopback.

## 8. Known limitations (honesty list)

* SQLite suits the single-node demo; switch `DATABASE_URL` to Postgres for
  multi-worker deployments (SQLAlchemy layer is portable).
* In-process job queue resets if the backend restarts mid-scan (rows stay
  `running`; a sweep marks stale rows failed on boot — future work).
* Scanner binaries are Windows builds here; CI/Linux builds follow the same
  script with GOOS overrides.
