# Integration Guide — How Upstream Components Became This Platform

## Vendoring (in-process)

| Upstream | Copied into | Transformations |
|---|---|---|
| `api-security-scanner` (`backend/scanners/*.py`, `core/enums.py`, `schemas/test_result_schemas.py`) | `backend/app/vendor/api_security_scanner/` | Imports re-pointed to a `compat.py` settings shim so vendor code no longer requires `DATABASE_URL` / `SECRET_KEY` coupling; unused destructive payload lists (UNION / ERROR / STACKED, XSS payloads) removed at the adapter layer; `patch_base_path_awareness()` fixes `urljoin` base-path loss |
| `http-headers-scanner` (single module) | `backend/app/vendor/http_headers_scanner/scanner.py` | Verbatim copy; adapter serializes dataclasses to `RawFinding` and adds Set-Cookie flag audit |
| `graphql-security-tester` | `backend/app/vendor/graphql_security_tester/` | Vendored; adapter probes introspection / depth at `ctx.target` |
| `zero-day-vulnerability-scanner` | `backend/app/vendor/zdv_scanner/` | Vendored; `deep_scan` and `fuzzing` modules use its port / banner / fuzz engines |

## Subprocess adapters

| Binary | Invocation | Parsing notes |
|---|---|---|
| `bin/portia.exe` (secrets-scanner) | `portia scan <path> --format json --no-color` | Decorative banner may precede JSON — parser seeks first `{`; UTF-8 with replacement; secrets are pre-masked by portia |
| `bin/bomber.exe` (sbom-generator-vulnerability-matcher) | `bomber vuln <dir> --format json --no-cache` | Go default marshaling uses capitalized keys and integer enums (`Ecosystem 0..2`, `Severity 1..4`) — adapter maps them to names |
| `bin/chainscanner.exe` (supply-chain-security-analyzer) | `chainscanner -dir <path> --format json` | Offline JSON with `ecosystem`, `dependencies[]`, `summary`; typosquat and license checks |

Build script `scripts/build_go_tools.ps1` clones (or reuses a local checkout in `_sources/candidates/`) each repository, applies documented patches, and emits Windows binaries into `bin/`. The Docker build does the same inside a `gobuilder` stage.

## Module registration

All 12 modules are registered in `backend/app/scanners/registry.py` via `AVAILABLE_MODULES` in `backend/app/scanners/base.py`. `load_registry()` is idempotent, thread-safe, and called by orchestration before every assessment. Each module key maps to one or two scanner instances:

* `input_validation` → `SqliModule` + `ReflectedXssModule` (two scanners, one user-facing key)
* Every other key → single scanner instance

## Adding a new scanner

1. Implement `ScannerModule.run(ctx) -> ScanResult` returning `RawFinding`s with a stable `check_id`; set `scan_target=ctx.target` (or source path) so retest fingerprints align.
2. Attach evidence via `ctx.require_evidence().save_http_exchange()` or `save_scanner_output()` helpers.
3. Add a CVSS preset vector and remediation KB entry keyed by `check_id`.
4. Register in `backend/app/scanners/registry.py` and add UI metadata in `backend/app/scanners/base.py::AVAILABLE_MODULES`.
5. Add a unit test using a captured fixture; extend the vulnerable lab if new target behavior is required.

## Dropped candidates and why

| Candidate | Reason |
|---|---|
| `bug-bounty-platform` | Report tracker, not a finder — manages reports in memory without persistence or auth |
| `simple-vulnerability-scanner` | Duplicate of `bomber` with terminal-only output (no machine-readable JSON) |
| `mobile-app-security-analyzer` | Mobile static analysis — wrong domain for a web assessment platform |
| `linux-cis-hardening-auditor` | 104 CIS controls requiring root on Linux; web scope is the product, not host hardening |
| `ja3-ja4-tls-fingerprinting` | Requires libpcap / Npcap SDK and privileged capture; forensic scope |
| `network-traffic-analyzer` | Live capture with scapy + root — no finding value for authorized web testing |
| `firewall-rule-engine` | Text-file linting for iptables / nftables — no JSON output, separate toolchain |
| `credential-rotation-enforcer` | Crystal ≥1.20, no stable Windows support; rotation ops ≠ vulnerability assessment |
| `api-rate-limiter` | Defense library, not an assessment tool — the lab demonstrates *missing* rate limiting |
| `docker-security-audit` | Requires Docker daemon; kept as optional module that reports “unsupported” instead of fake results |
| `monitor-the-situation-dashboard` | Multi-feed SOC globe — constant internet dependence, reference for dashboard layout only |
| `siem-dashboard` (as component) | Mounted on Mongo + Redis; too heavy — timing-safe auth patterns and RBAC design referenced, reimplemented on SQLite / FastAPI |
