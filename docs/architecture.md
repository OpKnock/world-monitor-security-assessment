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
        ├── engine/orchestration        ThreadPoolExecutor job system
        │       └── per module: ScanRun row → scanner adapter(s)
        │               └── RawFinding(common format) → persist+dedupe
        ├── engine/evidence             masked JSON evidence store
        ├── engine/cvss                 CVSS v3.1 math + curated presets
        ├── engine/findings             normalize · fingerprint · dedupe · KB
        └── engine/reporting            PDF (fpdf2) · JSON · Markdown
```

## Scanner contract

Every adapter implements `ScannerModule.run(ctx: ScanContext) -> ScanResult`
where `ScanResult = {scanner, status, findings[RawFinding], duration_s, errors,
checks_total, checks_safe}`. `RawFinding` is the Common Finding Format (§9 of
the SIH prompt) with a stable `check_id` used for CVSS presets, remediation KB,
dedupe fingerprints and retest identity.

## Module → implementation map

| Module key | Implementation | Origin |
|---|---|---|
| authentication | vendored `AuthScanner` (missing-auth, JWT none/sig, invalid tokens) | api-security-scanner |
| authorization | vendored `IDORScanner` (numeric/string ID manipulation) | api-security-scanner |
| api | vendored `RateLimitScanner` (+header spoofing & path-variant bypass) | api-security-scanner |
| input_validation | vendored `SQLiScanner` + native reflected-XSS canary probe | api-security-scanner / original |
| headers | vendored pure-function header grader + Set-Cookie flag audit | http-headers-scanner / extension |
| tls | native certificate & HTTPS-redirect checker | original |
| secrets | subprocess `portia scan --format json` (banner-tolerant parser) | secrets-scanner |
| dependencies | subprocess `bomber vuln --format json` (int-enum mapping) | sbom-generator-vulnerability-matcher |

Upstream scanners are patched at the *join layer*, not rewritten:
`patch_base_path_awareness()` rewrites their relative endpoints so
path-scoped targets (`…/api`, `…/api/reports`) probe correctly.

## Fingerprints & retest

`fingerprint = sha1(scan_target | category | check_id | affected_component)`.
Creation and retest both derive it from the *actually scanned* URL/path, so a
finding survives assessment restarts but disappears once the underlying check
passes — enabling deterministic `FIXED` / `STILL_PRESENT` verdicts with fresh
evidence linked to the original finding.

## Frontend

Deliberately framework-free: one HTML shell, hand-written CSS design system,
three small JS modules (api client, SVG charts, views/router). Zero build step
eliminates npm/toolchain failure modes during judging; everything is served by
the backend itself.
