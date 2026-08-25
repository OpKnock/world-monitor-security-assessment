# Integration Guide — how the candidate repos became this platform

Full audit: `docs/repository-audit.md`. This file records *mechanics*.

## Vendoring (in-process)

| Upstream | Copied into | Transformations |
|---|---|---|
| api-security-scanner `backend/scanners/*.py`, `core/enums.py`, `schemas/test_result_schemas.py` | `backend/app/vendor/api_security_scanner/` | imports re-pointed to a `compat.py` settings shim (no DATABASE_URL/SECRET_KEY coupling); destructive-but-unused payload lists (UNION/ERROR/STACKED, XSSPayloads) removed; `patch_base_path_awareness()` fixes urljoin base-path loss |
| http-headers-scanner single module | `backend/app/vendor/http_headers_scanner/scanner.py` | verbatim; adapter serializes dataclasses + adds Set-Cookie flag audit |

## Subprocess adapters

| Binary | Invocation | Parsing notes |
|---|---|---|
| `bin/portia.exe` (secrets-scanner) | `portia scan <path> --format json --no-color` | decorative banner precedes JSON → parse from first `{`; UTF-8 with replacement; upstream nil-context panic patched at build time |
| `bin/bomber.exe` (sbom-generator) | `bomber vuln <dir> --format json --no-cache` | Go default marshaling ⇒ capitalized keys & int enums (`Ecosystem 0..2`, `Severity 1..4`) mapped in adapter |

Build script `scripts/build_go_tools.ps1` clones (or reuses a local clone of)
the two repos, applies documented patches, and emits Windows binaries into
`bin/`.

## Dropped integrations and why (summary)

bug-bounty-platform (tracker w/o persistence), siem-dashboard as component
(Mongo-coupled; patterns absorbed), simple-vulnerability-scanner (duplicate,
terminal-only), mobile-app-security-analyzer (wrong domain),
linux-cis-hardening-auditor / firewall-rule-engine / credential-rotation-enforcer
(host/toolchain mismatch), ja3-ja4-tls-fingerprinting +
network-traffic-analyzer (pcap/Npcap build pain, forensic scope),
api-rate-limiter (defense lib, not assessment), monitor-the-situation-dashboard
(reference only).

## Adding a new scanner (checklist)

1. Implement `ScannerModule.run(ctx)` returning `ScanResult`.
2. Emit `RawFinding`s with a stable `check_id`; set `scan_target=ctx.target`
   (or source path) so retest fingerprints line up.
3. Attach evidence via `ctx.require_evidence()` helpers.
4. Add a CVSS preset vector + remediation KB entry keyed by `check_id`.
5. Register in `scanners/registry.py` under a module key; add UI metadata in
   `base.AVAILABLE_MODULES` if new.
6. Unit-test the parser with a captured fixture; extend the lab if a target
   behavior is required.
