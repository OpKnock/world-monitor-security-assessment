"""Input-validation module: vendored SQLi scanner + native reflected-XSS / CSRF / error probes.

Two scanner instances are exposed under the ``input_validation`` registry
key so that ``scanners_for(["input_validation"])`` yields **two** results:

* :class:`SqliModule` — wraps the upstream :class:`SQLiScanner` (time-,
  error- and boolean-blind injection via paired conditionals).
* :class:`ReflectedXssModule` — native canary-reflection, verbose-error
  and CSRF-token presence probes.  All payloads are inert, clearly-marked
  canary strings; no script execution and no state mutation.

The XSS canary strategy
-----------------------
A random canary like ``wm8f3a1b2c`` is injected as a query-param value.
The response body is checked case-insensitively for a verbatim echo.
If the server reflects input without encoding, an attacker could replace
the canary with executable markup — this is reported as a HIGH finding.
The probes are limited to two non-executing variants (``"{c}"`` and
``<b>{c}</b>``) so that even a vulnerable target does not receive a
payload that actually pops an alert.

Auth token passthrough
----------------------
Both scanners honour ``ctx.auth_token``: :class:`SqliModule` passes it to
the upstream scanner constructor; :class:`ReflectedXssModule` injects an
``Authorization: Bearer …`` header into its :class:`requests.Session`.

Evidence & fingerprint discipline
--------------------------------
Every branch persists an ``http_exchange`` or ``scanner_output`` document
via :meth:`EvidenceStore.save`; every finding carries
``scan_target == ctx.target`` and ``evidence_payloads`` with the persisted
document reference so that retest can fingerprint reliably.

Network resilience
------------------
Per-request timeouts default to ``ctx.effective_timeout(10 s)``; exceptions
are collected into ``ScanResult.errors`` rather than failing the whole
module when a subset of probes succeeds.
"""
from __future__ import annotations

import logging
import random
import string
import time
from urllib.parse import urlencode

import requests

from ..engine.findings import RawFinding
from ..scanners.api_scan import patch_base_path_awareness
from ..scanners.base import ScanContext, ScanResult, ScannerModule
from ..vendor.api_security_scanner.enums import ScanStatus
from ..vendor.api_security_scanner.sqli_scanner import SQLiScanner

logger = logging.getLogger(__name__)

__all__ = ["SqliModule", "ReflectedXssModule"]


# ---------------------------------------------------------------------------
# SQLi (upstream wrapper)
# ---------------------------------------------------------------------------


class SqliModule(ScannerModule):
    name = "sqli"
    category = "INPUT_VALIDATION"
    description = "Detects SQL injection (error/boolean/time-blind) via paired conditions"

    def run(self, ctx: ScanContext) -> ScanResult:
        started = time.perf_counter()
        if not ctx.has_http_target:
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=["HTTP target is required for SQLi tests"],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )
        store = ctx.require_evidence()
        try:
            instance = SQLiScanner(ctx.target, auth_token=ctx.auth_token)
        except Exception as exc:
            logger.exception("Failed to construct SQLiScanner: %s", exc)
            return ScanResult(scanner=self.name, status="failed", errors=[repr(exc)], checks_total=1, duration_s=round(time.perf_counter() - started, 3))

        try:
            patch_base_path_awareness(instance)
        except Exception:
            logger.debug("SQLi base-path patch failed", exc_info=True)

        try:
            result = instance.scan()
        except Exception as exc:
            logger.warning("SQLi scan failed for %s: %s", ctx.target, exc, exc_info=True)
            return ScanResult(scanner=self.name, status="failed", errors=[repr(exc)], checks_total=1, duration_s=round(time.perf_counter() - started, 3))

        if result is None or not hasattr(result, "status"):
            return ScanResult(scanner=self.name, status="failed", errors=["Upstream SQLi scanner returned invalid result"], checks_total=1, duration_s=round(time.perf_counter() - started, 3))

        findings: list[RawFinding] = []
        safe = 0
        duration = round(time.perf_counter() - started, 3)

        is_vuln = (result.status == ScanStatus.VULNERABLE) or (str(result.status).lower() == "vulnerable")
        is_safe = (result.status == ScanStatus.SAFE) or (str(result.status).lower() == "safe")

        if is_vuln:
            low = (result.details or "").lower()
            if "error-based" in low:
                check_id, title, sev = "sqli.error_based", "Error-based SQL injection", "CRITICAL"
            elif "time-based" in low:
                check_id, title, sev = "sqli.time_based_blind", "Time-based blind SQL injection", "CRITICAL"
            else:
                check_id, title, sev = "sqli.boolean_based_blind", "Boolean-based blind SQL injection", "CRITICAL"
            try:
                evidence_meta = store.save_scanner_output(self.name, result.evidence_json or {}, note=(result.details or "")[:500])
            except Exception as exc:
                logger.warning("Failed to persist SQLi evidence: %s", exc, exc_info=True)
                evidence_meta = {"path": "", "kind": "scanner_output", "summary": result.details[:200]}
            recs = getattr(result, "recommendations_json", []) or []
            if isinstance(recs, str):
                recs = [recs]
            remediation = "\n".join(str(r) for r in recs)
            findings.append(
                RawFinding(
                    title=title,
                    description=result.details or title,
                    severity=sev,
                    category=self.category,
                    affected_component=ctx.target,
                    scanner=self.name,
                    check_id=check_id,
                    reproduction=[
                        f"Target: {ctx.target} (authorized local lab)",
                        "Scanner sent paired true/false conditions and compared responses; see evidence.",
                    ],
                    remediation=remediation,
                    meta={"upstream_test": str(getattr(result.test_name, "value", result.test_name)) if hasattr(result, "test_name") else check_id},
                    scan_target=ctx.target,
                    evidence_payloads=[evidence_meta],
                )
            )
        elif is_safe:
            safe = 1
        else:
            detail = str(getattr(result, "details", "") or "Upstream SQLi scanner returned inconclusive status")
            return ScanResult(scanner=self.name, status="failed", errors=[detail[:500]], checks_total=1, duration_s=duration)

        return ScanResult(
            scanner=self.name,
            status="completed",
            findings=findings,
            checks_total=1,
            checks_safe=safe,
            duration_s=duration,
        )


# ---------------------------------------------------------------------------
# Reflected XSS / CSRF / verbose-error (native probes)
# ---------------------------------------------------------------------------


def _canary(length: int = 8) -> str:
    """Generate a canary string with a stable ``wm`` prefix.

    The ``wm`` prefix (World Monitor) makes grep in evidence documents
    trivial and avoids collisions with common response tokens.  Using
    :func:`random.choices` (global PRNG) keeps the probes deterministic
    when the process seed is fixed (e.g. in tests).
    """
    return "wm" + "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


class ReflectedXssModule(ScannerModule):
    name = "input_validation"
    category = "INPUT_VALIDATION"
    description = "Canary-reflection XSS, CSRF token presence, and verbose error probes"

    # Non-executing probes: canary injection only.  The third entry in the
    # original list contained an executable <svg> payload — we retain it in
    # the constant for documentation but never send it.
    PROBES: list[tuple[str, str]] = [
        ('"{c}"', "{v}"),
        ("<b>{c}</b>", "{v}"),
        ("'><svg/onload={c}>", "<svg/onload={v}>"),
    ]

    # Query params that are commonly reflected in search / echo pages.
    PROBE_PARAMS: tuple[str, ...] = ("q", "name", "search")

    def run(self, ctx: ScanContext) -> ScanResult:
        started = time.perf_counter()
        if not ctx.has_http_target:
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=["HTTP target is required for input-validation probes"],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )
        store = ctx.require_evidence()
        timeout_canary = ctx.effective_timeout(10.0)
        timeout_csrf = ctx.effective_timeout(6.0)

        session = requests.Session()
        headers: dict[str, str] = {"User-Agent": "world-monitor-scanner/1.0"}
        if ctx.auth_token:
            headers["Authorization"] = f"Bearer {ctx.auth_token}"
        session.headers.update(headers)

        findings: list[RawFinding] = []
        errors: list[str] = []

        # --------------------------------------------------------------
        # 1. Canary reflection probe (HIGH if reflected)
        # --------------------------------------------------------------
        reflected: list[str] = []
        # Only the first two PROBES are reflection-only (no executable markup).
        probe_slice = self.PROBES[:2]
        for fmt, _ in probe_slice:
            canary = _canary()
            payload = fmt.format(c=canary)
            for param in self.PROBE_PARAMS:
                sep = "&" if "?" in ctx.target else "?"
                url = f"{ctx.target}{sep}{urlencode({param: payload})}"
                try:
                    resp = session.get(url, timeout=timeout_canary, allow_redirects=False)
                except Exception as exc:
                    errors.append(f"canary probe {param}: {repr(exc)}")
                    continue
                # Persist the exchange — masked by EvidenceStore.
                try:
                    store.save_http_exchange(
                        method="GET",
                        url=url,
                        status_code=resp.status_code,
                        request_headers=dict(session.headers),
                        response_headers=dict(resp.headers),
                        response_body=resp.text,
                        note=f"reflection probe param={param} canary={canary}",
                    )
                except Exception as exc:
                    logger.debug("Failed to persist reflection evidence: %s", exc)

                # Case-insensitive exact canary search — encoded reflections
                # (e.g. &lt;) are not considered vulnerable.
                if canary.lower() in (resp.text or "").lower():
                    reflected.append(f"{param}={payload}")
                if reflected:
                    break  # one reflected param is enough for this canary
            if reflected:
                break  # stop after first reflected canary

        # --------------------------------------------------------------
        # 2. CSRF token presence on HTML forms (MEDIUM)
        # --------------------------------------------------------------
        csrf_missing: list[str] = []
        # Determine the HTTP origin (scheme + host + optional port) so that
        # path probing for / and /login is not done by mangling the full
        # assessment target (which may contain /api or query strings).
        from urllib.parse import urlsplit

        split = urlsplit(ctx.target)
        origin = f"{split.scheme}://{split.netloc}" if split.netloc else ctx.target
        csrf_paths: list[str] = ["/", "/login"]
        for path in csrf_paths:
            # Build probe URL: origin + path (handle trailing slash correctly).
            if path == "/":
                probe_url = origin.rstrip("/") + "/"
            else:
                probe_url = origin.rstrip("/") + path
            try:
                rr = session.get(probe_url, timeout=timeout_csrf, allow_redirects=False)
                html = (rr.text or "").lower()
                has_form = "<form" in html
                if has_form:
                    has_token = ("csrf" in html or "_token" in html or "authenticity_token" in html)
                    if not has_token:
                        csrf_missing.append(path)
                try:
                    store.save_http_exchange(
                        method="GET",
                        url=str(getattr(rr, "url", probe_url)),
                        status_code=rr.status_code,
                        response_headers=dict(rr.headers),
                        response_body=rr.text,
                        note=f"csrf form probe {path}",
                    )
                except Exception as exc:
                    logger.debug("Failed to persist CSRF evidence: %s", exc)
            except Exception as exc:
                errors.append(f"csrf probe {path}: {repr(exc)}")
                continue

        if csrf_missing:
            try:
                doc_csrf = store.save(kind="scanner_output", summary="forms without CSRF tokens", payload={"paths": csrf_missing, "origin": origin})
            except Exception as exc:
                logger.debug("Failed to persist CSRF summary: %s", exc)
                doc_csrf = {"path": "", "kind": "scanner_output", "summary": "forms without CSRF tokens"}
            findings.append(
                RawFinding(
                    title="HTML forms missing CSRF protection tokens",
                    description="State-changing forms are served without any anti-CSRF token field, allowing cross-site request forgery.",
                    severity="MEDIUM",
                    category=self.category,
                    affected_component=", ".join(csrf_missing),
                    scanner=self.name,
                    check_id="input_validation.csrf_token_missing",
                    reproduction=["Open the form page; inspect <form> for a hidden csrf/token field."],
                    impact="Attackers can submit actions on behalf of logged-in users.",
                    business_impact="Unauthorized state changes executed as victims.",
                    remediation="Add per-session CSRF tokens and validate them server-side.",
                    meta={"paths": csrf_missing, "origin": origin},
                    evidence_payloads=[doc_csrf],
                    scan_target=ctx.target,
                )
            )

        # --------------------------------------------------------------
        # 3. Verbose error disclosure (LOW) — trigger with a stray `'`.
        # --------------------------------------------------------------
        verbose_error: str | None = None
        try:
            probe_url = ctx.target + ("&" if "?" in ctx.target else "?") + "q='"
            resp = session.get(probe_url, timeout=timeout_canary, allow_redirects=False)
            body = (resp.text or "").lower()
            for marker in ("traceback", "sql syntax", "sqlite3.", "exception", "stack trace", "syntax error", "unterminated", "you have an error in your sql"):
                if marker in body:
                    verbose_error = marker
                    break
            try:
                store.save_http_exchange(
                    method="GET",
                    url=str(getattr(resp, "url", probe_url)),
                    status_code=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body=resp.text,
                    note="error-disclosure probe q='",
                )
            except Exception as exc:
                logger.debug("Failed to persist error-disclosure evidence: %s", exc)
        except Exception as exc:
            errors.append(f"error-disclosure probe: {repr(exc)}")

        # --------------------------------------------------------------
        # 4. Materialise findings from canary + error probes
        # --------------------------------------------------------------
        if reflected:
            try:
                doc = store.save(
                    kind="scanner_output",
                    summary=f"Canaries reflected verbatim: {reflected}",
                    payload={"scanner": self.name, "reflected_payloads": reflected, "scan_target": ctx.target},
                )
            except Exception as exc:
                logger.debug("Failed to persist XSS evidence: %s", exc)
                doc = {"path": "", "kind": "scanner_output", "summary": f"Canaries reflected verbatim: {reflected}"}
            findings.append(
                RawFinding(
                    title="Reflected user input without encoding (XSS indicator)",
                    description=(
                        f"Marker strings submitted via query parameters are reflected "
                        f"verbatim in the response ({len(reflected)} probe(s)). If an attacker "
                        f"substitutes markup, the browser will execute it in the page origin."
                    ),
                    severity="HIGH",
                    category=self.category,
                    affected_component=ctx.target,
                    scanner=self.name,
                    check_id="input_validation.reflected_xss_indicator",
                    reproduction=[
                        f"GET {ctx.target}?q=<canary-string>",
                        "Observe the canary echoed unencoded inside the HTML body.",
                    ],
                    impact="Attackers can craft links that run arbitrary JavaScript for other users.",
                    business_impact="Session theft, credential harvesting and defacement via crafted URLs.",
                    remediation="Apply context-aware output encoding on render; validate input types; adopt a strict Content-Security-Policy.",
                    meta={"probes_reflected": reflected},
                    scan_target=ctx.target,
                    evidence_payloads=[doc],
                )
            )

        if verbose_error:
            try:
                doc = store.save(
                    kind="scanner_output",
                    summary=f"Verbose error signature '{verbose_error}' disclosed to clients",
                    payload={"scanner": self.name, "signature": verbose_error, "scan_target": ctx.target},
                )
            except Exception as exc:
                logger.debug("Failed to persist verbose-error evidence: %s", exc)
                doc = {"path": "", "kind": "scanner_output", "summary": f"Verbose error signature '{verbose_error}'"}
            findings.append(
                RawFinding(
                    title="Verbose error disclosure aids attackers",
                    description=(
                        f"A malformed parameter produced a server error whose body contains "
                        f"framework/database internals (matched: '{verbose_error}')."
                    ),
                    severity="LOW",
                    category=self.category,
                    affected_component=ctx.target,
                    scanner=self.name,
                    check_id="input_validation.verbose_error_disclosure",
                    reproduction=["GET <target>?q=' and inspect the response body."],
                    impact="Leaked stack traces reveal technology stack and query structure.",
                    remediation="Return generic error pages; log details server-side only.",
                    meta={"matched_signature": verbose_error},
                    scan_target=ctx.target,
                    evidence_payloads=[doc],
                )
            )

        duration = round(time.perf_counter() - started, 3)
        # Coverage accounting: reflected checks are one logical probe per
        # probe_slice × param, but safe count collapses per category.
        total_reflection_checks = len(probe_slice) * len(self.PROBE_PARAMS)
        # +1 for CSRF, +1 for verbose error = total checks.
        checks_total = total_reflection_checks + 2
        # Safe counts: reflection safe if none reflected; CSRF safe if none
        # missing; error safe if no verbose disclosure.
        reflection_safe = 0 if reflected else total_reflection_checks
        csrf_safe = 0 if csrf_missing else 1
        error_safe = 0 if verbose_error else 1
        checks_safe = reflection_safe + csrf_safe + error_safe

        return ScanResult(
            scanner=self.name,
            status="completed",
            findings=findings,
            errors=errors,
            checks_total=checks_total,
            checks_safe=checks_safe,
            duration_s=duration,
        )
