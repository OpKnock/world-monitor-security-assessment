# Architecture

## System view

```
Browser SPA (no-build vanilla JS, hash router)
        │  fetch /api/*  (JWT bearer)
        ▼
FastAPI backend  ──► SQLite (users, assessments, scan_runs,
        │                      findings, evidence, reports, audit_logs)
        │
        ├── engine/authorization_gate   target + path validation, LAB_MODE
        ├── engine/orchestration        thread-per-assessment job runner
        │       └── per module: ScanRun row → scanner adapter(s)
        │               └── RawFinding (Common Finding Format) → persist + dedupe
        ├── engine/evidence             masked JSON evidence store
        ├── engine/cvss                 CVSS v3.1 math + curated preset vectors
        ├── engine/findings             normalize · fingerprint · dedupe · KB enrich
        └── engine/reporting            PDF (fpdf2) · JSON · Markdown · CSV
```

* No build step for the frontend — one HTML shell, hand-written design system, three small JS modules (`api.js`, `charts.js`, `app.js`) served directly by FastAPI. Eliminating the frontend toolchain removes a class of deployment failures.
* No background queue service — each assessment spawns a dedicated daemon thread. A stuck scanner can never starve other assessments, and the watchdog (10 min) fails the assessment cleanly if the thread hangs.
* SQLite is the default store (WAL + `busy_timeout` + `DB_WRITE_LOCK`). Switching `DATABASE_URL` to Postgres requires no code change; SQLAlchemy is portable.

## Middleware & observability

* **Request ID** — every request gets `X-Request-ID` (client-supplied or auto-generated) propagated to logs and responses.
* **Security headers** — `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, plus hardened `HSTS` (`preload`) and CSP for API.
* **Request logging** — structured `req_start` / `req_end` with method, path, client IP, duration_ms and request_id at INFO.
* **Global rate limiting** — per-IP sliding window with distinct `global:` key, scoped correctly so per-route limits (e.g. auth 30/min) still take precedence.

## Scanner contract

Every adapter implements a single method:

```python
class ScannerModule(ABC):
    name: str       # stable, becomes Finding.scanner
    category: str   # e.g. AUTHENTICATION, AUTHORIZATION, ...
    def run(self, ctx: ScanContext) -> ScanResult: ...
```

where

```python
@dataclass
class ScanContext:
    target: str              # gate-validated http(s) URL
    source_path: str         # gate-validated filesystem scope
    auth_token: str | None   # lab demo JWT, never a real secret
    evidence: EvidenceStore  # must be present — findings are never orphaned
    options: dict

@dataclass
class ScanResult:
    scanner: str
    status: Literal["completed", "failed", "skipped"]
    findings: list[RawFinding]
    duration_s: float
    errors: list[str]
    checks_total: int
    checks_safe: int
```

`RawFinding` is the Common Finding Format with a stable `check_id` used for CVSS presets, remediation KB lookup, dedupe fingerprints, and retest identity. Every adapter **must** set `scan_target` to the exact URL or path probed — the fingerprint is `sha1(target | category | check_id | affected_component)` and both creation and retest derive it from the actually scanned URL.

## The 12 modules — implementation map

| # | Module key | Scanner class(es) | Category | Implementation | Origin |
|---|---|---|---|---|---|
| 1 | `authentication` | `AuthenticationModule` | AUTHENTICATION | vendored `AuthScanner` (missing-auth, JWT none/sig, invalid tokens) | api-security-scanner |
| 2 | `authorization` | `AuthorizationModule` | AUTHORIZATION | vendored `IDORScanner` (numeric + string ID manipulation) | api-security-scanner |
| 3 | `api` | `ApiSecurityModule` | API_SECURITY | vendored `RateLimitScanner` (+ header spoofing & path-variant bypass) | api-security-scanner |
| 4 | `input_validation` | `SqliModule` + `ReflectedXssModule` | INPUT_VALIDATION | vendored SQLi probes + native reflected-XSS canary | api-security-scanner + original |
| 5 | `headers` | `ClientSecurityHeadersModule` | CLIENT_SECURITY | vendored pure-function header grader + Set-Cookie flag audit | http-headers-scanner |
| 6 | `tls` | `TlsModule` | SECURE_COMMUNICATION | native certificate & HTTPS-redirect checker | original |
| 7 | `secrets` | `SecretsModule` | DATA_PRIVACY | subprocess `portia scan --format json` (banner-tolerant parser) | secrets-scanner |
| 8 | `dependencies` | `DependenciesModule` | DEPENDENCIES | subprocess `bomber vuln --format json` (int-enum mapping) | sbom-generator-vulnerability-matcher |
| 9 | `supply_chain` | `SupplyChainModule` | SUPPLY_CHAIN | subprocess `chainscanner -dir --format json` (typosquat / pinning / licenses) | supply-chain-security-analyzer |
| 10 | `graphql` | `GraphqlModule` | API_SECURITY | native GraphQL introspection probe | graphql-security-tester |
| 11 | `deep_scan` | `DeepScanModule` | INFRASTRUCTURE | plugin engine (ports / banners / default creds) | zero-day-vulnerability-scanner |
| 12 | `fuzzing` | `FuzzingModule` | INPUT_VALIDATION | mutation fuzzing (5xx anomaly detection, opt-in) | zero-day-vulnerability-scanner |

Module keys are API-contract — they appear in `POST /api/assessments {modules: [...]}` and in `AVAILABLE_MODULES` (`backend/app/scanners/base.py`). Renaming a key is a breaking change.

Upstream scanners are patched at the *join layer*, not rewritten: `patch_base_path_awareness()` rewrites their relative endpoints so path-scoped targets (`…/api`, `…/api/reports`) probe correctly.

## Fingerprints & retest

`fingerprint = sha1(scan_target | category | check_id | affected_component)`. Creation and retest both derive it from the *actually scanned* URL or path, so a finding survives assessment restarts but disappears once the underlying check passes — enabling deterministic `FIXED` / `STILL_PRESENT` verdicts with fresh evidence linked to the original finding.

## Evidence

Every finding carries one or more `Evidence` rows pointing to sanitized JSON files under `evidence/<assessment_id>/`. The `EvidenceStore` masks sensitive values before writing; the DB stores only the file path, never the raw secret.

## Persistence

```
User 1──* Assessment 1──* ScanRun
                    └──* Finding 1──* Evidence
                    └──* Report
AuditLog (append-only, per-action)
```

All deletes cascade: removing an assessment removes its findings, evidence files, reports, scan runs, and any audit rows referencing the deleted identifiers (no orphaned traces).

## Frontend

Single `index.html` shell, one CSS design system, three JS modules (API client, SVG charts, views/router). Hash routing, no framework, no bundler. All assets are served by the backend itself so the platform is a single deployable unit.
