# Scanner Development Guide

## Contract

```python
from backend.app.scanners.base import ScannerModule, ScanContext, ScanResult
from backend.app.engine.findings import RawFinding

class MyModule(ScannerModule):
    name = "my_scanner"          # unique; becomes finding.scanner
    category = "API_SECURITY"    # one of the SIH categories

    def run(self, ctx: ScanContext) -> ScanResult:
        store = ctx.require_evidence()
        # ... probe ctx.target (already gate-validated) ...
        doc = store.save_http_exchange(method="GET", url=ctx.target,
                                       status_code=resp.status_code,
                                       response_headers=dict(resp.headers),
                                       response_body=resp.text, note="probe")
        return ScanResult(
            scanner=self.name, status="completed",
            findings=[RawFinding(
                title="...", description="...",
                severity="HIGH",              # CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL
                category=self.category,
                affected_component=ctx.target,
                scanner=self.name,
                check_id="my_scanner.my_check",   # STABLE id — never rename casually
                reproduction=["curl ..."],
                impact="...", business_impact="...", remediation="...",
                references=["https://..."],
                scan_target=ctx.target,           # fingerprint basis (required!)
                evidence_payloads=[doc],
            )],
            checks_total=1, checks_safe=0)
```

Register in `backend/app/scanners/registry.py::load_registry` and (if user-facing)
add an entry to `AVAILABLE_MODULES`.

## Rules that keep the platform honest

1. **Never** invent severities or scores — add a CVSS preset vector for your
   `check_id` in `engine/cvss.py::CVSS_PRESETS`; the engine computes and explains.
2. **Always** set `scan_target`; retest identity depends on it.
3. **Always** route requests through the gate-validated `ctx.target` — adapters
   receive targets only after `validate_http_target()`.
4. Mask anything sensitive through the EvidenceStore helpers; raw secrets must
   never reach a RawFinding field.
5. Failures go into `ScanResult.errors` / status `failed` — never raise past the
   adapter boundary, never fabricate "safe" when you could not check.

## Testing your scanner

* Unit: feed captured fixtures to your parsing logic.
* Integration: point at the lab (`tests/conftest.py` spins it on an ephemeral
  port) or a local dummy HTTP server.
* Retest: flip a lab toggle (e.g. `WM_LAB_FIX_HEADERS`) and assert FIXED.
