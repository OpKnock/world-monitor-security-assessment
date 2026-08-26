# Scanner Development Guide

## Contract

Every scanner is a single class implementing one method:

```python
from backend.app.scanners.base import ScannerModule, ScanContext, ScanResult
from backend.app.engine.findings import RawFinding

class MyModule(ScannerModule):
    name = "my_scanner"          # unique, becomes Finding.scanner
    category = "API_SECURITY"    # taxonomy bucket

    def run(self, ctx: ScanContext) -> ScanResult:
        store = ctx.require_evidence()  # fail loud if evidence store missing
        # ... probe ctx.target (already gate-validated) ...
        doc = store.save_http_exchange(
            method="GET", url=ctx.target,
            status_code=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=resp.text, note="probe")
        return ScanResult(
            scanner=self.name, status="completed",
            findings=[RawFinding(
                title="Human-readable title",
                description="What was tested and what was observed.",
                severity="HIGH",              # CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
                category=self.category,
                affected_component=ctx.target,
                scanner=self.name,
                check_id="my_scanner.my_check",   # STABLE id — never rename casually
                reproduction=["curl -i http://127.0.0.1:8080/api/..."],
                impact="Technical impact if exploited.",
                business_impact="Business impact in plain language.",
                remediation="Step-by-step fix.",
                references=["https://owasp.org/..."],
                scan_target=ctx.target,           # fingerprint basis — required
                evidence_payloads=[doc],
            )],
            checks_total=1, checks_safe=0)
```

Register the module in `backend/app/scanners/registry.py::load_registry` and, if user-facing, add an entry to `backend/app/scanners/base.py::AVAILABLE_MODULES`.

## Rules that keep the platform honest

1. **Never invent severities or scores.** Add a CVSS preset vector for your `check_id` in `backend/app/engine/cvss.py::CVSS_PRESETS`; the engine computes the score and the rationale.
2. **Always set `scan_target`.** Retest identity and dedupe fingerprints depend on it.
3. **Always probe `ctx.target` (or `ctx.source_path`).** Scanners receive targets only after `validate_http_target()` / `validate_source_path()` — never widen the scope.
4. **Route every secret through evidence masking.** Use `EvidenceStore` helpers; raw secrets must never reach a `RawFinding` field.
5. **Failures go into `ScanResult.errors` / `status="failed"`.** Never raise past the adapter boundary; never fabricate “safe” when you could not check. Use `status="skipped"` when the module is not applicable (binary missing, opt-in flag unset, no surface).

## Scanner lifecycle

```
POST /api/assessments  →  create Assessment + ScanRun rows (queued)
                       →  thread-per-assessment calls load_registry()
                       →  for each module_key: scanners_for([module_key])
                       →  for each instance: instance.run(ScanContext)
                       →  persist_raw_findings() (fingerprint + dedupe)
                       →  ScanRun.status = completed | failed | skipped
                       →  Assessment.status = completed | failed
```

## Evidence helpers

```python
store.save_http_exchange(method, url, request_headers, request_body,
                         status_code, response_headers, response_body, note)
store.save_scanner_output(scanner, raw_output, note)
store.save_file_match(file_path, line_number, snippet_masked, rule_id)
store.save(kind, payload, summary)  # low-level, sanitized
```

All helpers mask sensitive values before writing to `evidence/<assessment-id>/`.

## Testing your scanner

* **Unit:** feed captured fixtures to your parsing and scoring logic; assert `check_id`, `severity`, `scan_target`, and evidence shape.
* **Integration:** point at the vulnerable lab (`tests/conftest.py` starts it on an ephemeral port) or a local dummy HTTP server; assert real findings with expected vectors.
* **Retest:** flip a lab toggle (e.g. `WM_LAB_FIX_HEADERS=1`) and assert the retest status transitions from `STILL_PRESENT` to `FIXED`.

## Check-id conventions

* Prefix by scanner family: `auth.*`, `idor.*`, `rate_limit.*`, `sqli.*`, `input_validation.*`, `headers.*`, `tls.*`, `secrets.*`, `dependencies.*`, `supply_chain.*`, `graphql.*`, `deep_scan.*`, `fuzzing.*`.
* Suffix by specific check: `auth.jwt_none_algorithm_accepted`, `headers.strict_transport_security`.
* Once shipped, a `check_id` must not be renamed — fingerprints and retest stability depend on it.
