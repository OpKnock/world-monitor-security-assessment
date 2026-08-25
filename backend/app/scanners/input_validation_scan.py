"""Input-validation module: vendored SQLi scanner + native reflected-XSS probe.

The XSS probe sends only inert, clearly-marked canary strings and checks for
their reflection — no script execution, no destructive payloads.
"""
from __future__ import annotations

import random
import string
import time

import httpx
import requests

from ..engine.findings import RawFinding
from ..scanners.api_scan import patch_base_path_awareness
from ..scanners.base import ScanContext, ScanResult, ScannerModule
from ..vendor.api_security_scanner.enums import ScanStatus
from ..vendor.api_security_scanner.sqli_scanner import SQLiScanner


class SqliModule(ScannerModule):
    name = "sqli"
    category = "INPUT_VALIDATION"

    def run(self, ctx: ScanContext) -> ScanResult:
        store = ctx.require_evidence()
        instance = SQLiScanner(ctx.target)
        patch_base_path_awareness(instance)
        try:
            result = instance.scan()
        except Exception as exc:
            return ScanResult(scanner=self.name, status="failed", errors=[repr(exc)])
        findings: list[RawFinding] = []
        safe = 0
        if result.status == ScanStatus.VULNERABLE:
            low = result.details.lower()
            if "error-based" in low:
                check_id, title, sev = "sqli.error_based", "Error-based SQL injection", "CRITICAL"
            elif "time-based" in low:
                check_id, title, sev = "sqli.time_based_blind", "Time-based blind SQL injection", "CRITICAL"
            else:
                check_id, title, sev = "sqli.boolean_based_blind", "Boolean-based blind SQL injection", "CRITICAL"
            evidence_meta = store.save_scanner_output(self.name, result.evidence_json or {}, note=result.details)
            findings.append(
                RawFinding(
                    title=title,
                    description=result.details,
                    severity=sev,
                    category=self.category,
                    affected_component=ctx.target,
                    scanner=self.name,
                    check_id=check_id,
                    reproduction=[f"Target: {ctx.target} (authorized local lab)",
                                  "Scanner sent paired true/false conditions and compared responses; see evidence."],
                    remediation="\n".join(result.recommendations_json),
                    meta={"upstream_test": result.test_name.value},
                    scan_target=ctx.target,
                    evidence_payloads=[evidence_meta],
                )
            )
        elif result.status == ScanStatus.SAFE:
            safe = 1
        else:
            return ScanResult(scanner=self.name, status="failed",
                              errors=[str(result.details)], checks_total=1)
        return ScanResult(scanner=self.name, status="completed", findings=findings,
                          checks_total=1, checks_safe=safe)


def _canary(length: int = 8) -> str:
    return "wm" + "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


class ReflectedXssModule(ScannerModule):
    name = "input_validation"
    category = "INPUT_VALIDATION"

    PROBES = [
        ('"{c}"', "{v}"),
        ("<b>{c}</b>", "{v}"),
        ("'><svg/onload={c}>", "<svg/onload={v}>"),
    ]

    def run(self, ctx: ScanContext) -> ScanResult:
        store = ctx.require_evidence()
        findings: list[RawFinding] = []
        errors: list[str] = []
        reflected: list[str] = []
        probe_params = ("q", "name", "search")

        session = requests.Session()
        session.headers.update({"User-Agent": "world-monitor-scanner/1.0"})
        for fmt, _ in self.PROBES[:2]:  # reflection probes only (no executable markup)
            canary = _canary()
            payload = fmt.format(c=canary)
            for param in probe_params:
                from urllib.parse import urlencode

                sep = "&" if "?" in ctx.target else "?"
                url = f"{ctx.target}{sep}{urlencode({param: payload})}"
                try:
                    resp = session.get(url, timeout=15)
                except Exception as exc:
                    errors.append(repr(exc))
                    continue
                store.save_http_exchange(
                    method="GET", url=url, status_code=resp.status_code,
                    request_headers=dict(session.headers), response_headers=dict(resp.headers),
                    response_body=resp.text, note=f"reflection probe param={param} canary={canary}",
                )
                if canary.lower() in resp.text.lower():
                    reflected.append(f"{param}={payload}")
                if reflected:
                    break
            if reflected:
                break

        # CSRF token presence probe on HTML forms (defensive check)
        csrf_missing = []
        try:
            for path in ("/", "/login"):
                u = ctx.target.rstrip('/') + path if path != '/' else ctx.target
                rr = session.get(u if u.startswith('http') else 'http://' + u,
                                 timeout=10)
                html = rr.text.lower()
                if '<form' in html and ('csrf' not in html
                                        and '_token' not in html):
                    csrf_missing.append(path or '/')
                store.save_http_exchange(
                    method='GET', url=str(rr.url), status_code=rr.status_code,
                    response_headers=dict(rr.headers), response_body=rr.text,
                    note=f'csrf form probe {path}')
        except Exception as exc:
            errors.append(repr(exc))
        if csrf_missing:
            doc_csrf = store.save(kind='scanner_output',
                                  summary='forms without CSRF tokens',
                                  payload={'paths': csrf_missing})
            findings.append(RawFinding(
                title='HTML forms missing CSRF protection tokens',
                description=(
                    'State-changing forms are served without any anti-CSRF '
                    'token field, allowing cross-site request forgery.'),
                severity='MEDIUM', category=self.category,
                affected_component=', '.join(csrf_missing),
                scanner=self.name,
                check_id='input_validation.csrf_token_missing',
                reproduction=['Open the form page; inspect <form> for a hidden '
                              'csrf/token field.'],
                impact='Attackers can submit actions on behalf of logged-in users.',
                business_impact='Unauthorized state changes executed as victims.',
                remediation='Add per-session CSRF tokens and validate them server-side.',
                meta={'paths': csrf_missing},
                evidence_payloads=[doc_csrf],
                scan_target=ctx.target,
            ))

        # verbose error disclosure probe
        verbose_error: str | None = None
        try:
            resp = session.get(ctx.target + ("&" if "?" in ctx.target else "?") + "q='", timeout=15)
            body = resp.text.lower()
            for marker in ("traceback", "sql syntax", "sqlite3.", "exception", "stack trace", "syntax error"):
                if marker in body:
                    verbose_error = marker
                    break
            store.save_http_exchange(
                method="GET", url=resp.url, status_code=resp.status_code,
                response_headers=dict(resp.headers), response_body=resp.text,
                note="error-disclosure probe q='",
            )
        except Exception as exc:
            errors.append(repr(exc))

        if reflected:
            doc = store.save(
                kind="scanner_output",
                summary=f"Canaries reflected verbatim: {reflected}",
                payload={"scanner": self.name, "reflected_payloads": reflected},
            )
            findings.append(
                RawFinding(
                    title="Reflected user input without encoding (XSS indicator)",
                    description=(
                        f"Marker strings submitted via query parameters are reflected "
                        f"verbatim in the response ({len(reflected)} probes). If an attacker "
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
                    remediation=(
                        "Apply context-aware output encoding on render; validate input types; "
                        "adopt a strict Content-Security-Policy."
                    ),
                    meta={"probes_reflected": reflected},
                    scan_target=ctx.target,
                    evidence_payloads=[doc],
                )
            )

        if verbose_error:
            doc = store.save(
                kind="scanner_output",
                summary=f"Verbose error signature '{verbose_error}' disclosed to clients",
                payload={"scanner": self.name, "signature": verbose_error},
            )
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

        return ScanResult(
            scanner=self.name,
            status="completed",
            findings=findings,
            errors=errors,
            checks_total=len(self.PROBES[:2]) * 3 + 3,
            checks_safe=(len(self.PROBES[:2]) * 3 - len(reflected)) + (0 if verbose_error else 1) + (1 if not csrf_missing else 0),
        )
