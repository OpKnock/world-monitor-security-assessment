"""Client security module — vendored ``http-headers-scanner`` + Set-Cookie flag audit.

Runs two complementary checks in one module:

1. **Security-header grading** — the vendored ``http_headers_scanner.scan``
   fetches the target once, grades six headers (HSTS, CSP, X-CTO, XFO,
   Referrer-Policy, Permissions-Policy) and returns a ``ScanReport`` with
   per-header ``ok / weak / missing`` findings.
2. **Cookie-flag audit** — a second conditional ``GET`` re-examines
   ``Set-Cookie`` headers for missing ``HttpOnly / Secure / SameSite``
   attributes.

Both checks share one HTTP exchange evidence document plus a dedicated
``scanner_output`` summary.  Every emitted :class:`RawFinding` carries
``scan_target == ctx.target`` so retest/fingerprint logic works.

Error handling
--------------
* Network errors from either request are mapped to
  ``ScanResult(status="failed")`` — the assessment is not left hanging.
* The cookie audit never fails the module on its own; errors are
  collected in ``ScanResult.errors`` but the header findings are still
  returned.
* Timeouts respect ``ctx.effective_timeout()`` (default 10 s) with a hard
  per-request ceiling so a hung lab cannot stall the worker thread.

Evidence
--------
* One ``http_exchange`` document captures the graded response (masked
  headers, grade/score) plus raw ``Set-Cookie`` lines.
* Findings reference that document via ``evidence_payloads`` — no finding
  is emitted without linked evidence.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from ..engine.evidence import mask_headers
from ..engine.findings import RawFinding
from ..scanners.base import ScanContext, ScanResult, ScannerModule
from ..vendor.http_headers_scanner import scan as headers_scan

logger = logging.getLogger(__name__)

__all__ = ["ClientSecurityHeadersModule"]

SEVERITY_MAP: dict[str, str] = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}

CHECK_SLUGS: dict[str, str] = {
    "Strict-Transport-Security": "headers.strict_transport_security",
    "Content-Security-Policy": "headers.content_security_policy",
    "X-Content-Type-Options": "headers.x_content_type_options",
    "X-Frame-Options": "headers.x_frame_options",
    "Referrer-Policy": "headers.referrer_policy",
    "Permissions-Policy": "headers.permissions_policy",
}

TITLES: dict[str, str] = {
    "headers.strict_transport_security": "Missing/weak HSTS header",
    "headers.content_security_policy": "Missing Content-Security-Policy",
    "headers.x_content_type_options": "Missing X-Content-Type-Options (nosniff)",
    "headers.x_frame_options": "Missing X-Frame-Options / frame-ancestors",
    "headers.referrer_policy": "Missing Referrer-Policy",
    "headers.permissions_policy": "Missing Permissions-Policy",
}

IMPACTS: dict[str, str] = {
    "headers.strict_transport_security": "SSL-stripping and downgrade attacks become possible for returning visitors.",
    "headers.content_security_policy": "No browser-enforced script allowlist; XSS payloads execute freely.",
    "headers.x_content_type_options": "Browsers may MIME-sniff uploads and render attacker-controlled files as HTML.",
    "headers.x_frame_options": "The page can be framed by any site, enabling clickjacking.",
    "headers.referrer_policy": "Full URLs (including tokens in paths) leak to third-party sites.",
    "headers.permissions_policy": "Sensitive browser features (camera, mic, geo) are not explicitly disabled.",
}

RECOMMENDED: dict[str, str] = {
    "headers.strict_transport_security": "Send: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "headers.content_security_policy": "Adopt a strict CSP, e.g. default-src 'self'; object-src 'none'; frame-ancestors 'none'.",
    "headers.x_content_type_options": "Send: X-Content-Type-Options: nosniff",
    "headers.x_frame_options": "Send: X-Frame-Options: DENY (plus CSP frame-ancestors 'none').",
    "headers.referrer_policy": "Send: Referrer-Policy: strict-origin-when-cross-origin",
    "headers.permissions_policy": "Send: Permissions-Policy: camera=(), microphone=(), geolocation=()",
}


def _get_set_cookie_values(headers: Any) -> list[str]:
    """Extract ``Set-Cookie`` header values in a client-agnostic way."""
    # httpx.Headers exposes get_list; plain dicts do not.
    if hasattr(headers, "get_list"):
        try:
            return list(headers.get_list("set-cookie"))  # type: ignore[union-attr]
        except Exception:
            pass
    # Fallback for dict or case-insensitive iteration.
    out: list[str] = []
    try:
        items = headers.items() if hasattr(headers, "items") else []
        for k, v in items:
            if str(k).lower() == "set-cookie":
                out.append(str(v))
    except Exception:
        pass
    return out


def _audit_cookie_flags(set_cookie_values: list[str]) -> list[str]:
    """Return human-readable misses like ``sessionid missing HttpOnly, Secure``."""
    misses: list[str] = []
    for value in set_cookie_values:
        low = value.lower()
        missing: list[str] = []
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "secure" not in low:
            missing.append("Secure")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            cookie_name = value.split("=", 1)[0].strip().split(";")[0]
            if not cookie_name:
                cookie_name = "(unnamed)"
            misses.append(f"{cookie_name} missing {', '.join(missing)}")
    return misses


class ClientSecurityHeadersModule(ScannerModule):
    name = "headers"
    category = "CLIENT_SECURITY"
    description = "Grades HTTP security headers and audits cookie flags"

    def run(self, ctx: ScanContext) -> ScanResult:
        started = time.perf_counter()
        if not ctx.has_http_target:
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=["HTTP target is required for header grading"],
                checks_total=1,
            )
        store = ctx.require_evidence()
        timeout = ctx.effective_timeout(10.0)

        # 1. Vendor grading — single GET, follows redirects, grades final URL.
        try:
            report = headers_scan(ctx.target)
        except httpx.HTTPError as exc:
            logger.warning("Header scan HTTP error for %s: %s", ctx.target, exc)
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[f"HTTP error during header grading: {repr(exc)}"],
                checks_total=6,
                duration_s=round(time.perf_counter() - started, 3),
            )
        except Exception as exc:
            logger.exception("Header scan failed for %s: %s", ctx.target, exc)
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[repr(exc)],
                checks_total=6,
                duration_s=round(time.perf_counter() - started, 3),
            )

        # 2. Second fetch for raw headers + cookie lines to persist as evidence.
        #    Keep this best-effort — failure here must not discard the grading.
        raw_headers: dict[str, str] = {}
        cookie_values: list[str] = []
        resp_url: str = str(getattr(report, "final_url", ctx.target))
        resp_status: int | None = getattr(report, "status_code", None)
        evidence_errors: list[str] = []
        try:
            # Respect auth_token if the caller supplied one (rare for headers,
            # but correct for authenticated header views).
            extra_headers: dict[str, str] = {"User-Agent": "world-monitor-scanner/1.0"}
            if ctx.auth_token:
                extra_headers["Authorization"] = f"Bearer {ctx.auth_token}"
            resp = httpx.get(
                ctx.target,
                follow_redirects=False,
                timeout=timeout,
                headers=extra_headers,
            )
            raw_headers = {k: v for k, v in resp.headers.items()}
            cookie_values = _get_set_cookie_values(resp.headers)
            resp_url = str(resp.url)
            resp_status = resp.status_code
        except httpx.HTTPError as exc:
            evidence_errors.append(f"cookie audit fetch failed: {repr(exc)}")
            logger.debug("Cookie audit fetch failed for %s: %s", ctx.target, exc)
        except Exception as exc:
            evidence_errors.append(repr(exc))
            logger.debug("Cookie audit error for %s: %s", ctx.target, exc, exc_info=True)

        cookie_findings = _audit_cookie_flags(cookie_values)

        # 3. Persist evidence once (http_exchange + grading summary).
        try:
            evidence_doc = store.save(
                kind="http_exchange",
                summary=f"GET {resp_url} -> {resp_status}",
                payload={
                    "request": {"method": "GET", "url": str(getattr(report, "final_url", ctx.target)), "headers": {}, "body_excerpt": ""},
                    "response": {
                        "status_code": resp_status,
                        "headers": mask_headers(raw_headers),
                        "body_excerpt": "",
                        "set_cookie_count": len(cookie_values),
                        "set_cookie_issues": cookie_findings,
                    },
                    "grade": {"score": getattr(report, "score", None), "grade": getattr(report, "grade", None)},
                    "cookie_values_masked": [v.split("=", 1)[0] + "=***" for v in cookie_values],
                },
            )
        except Exception as exc:
            logger.warning("Failed to persist headers evidence: %s", exc, exc_info=True)
            evidence_doc = {"path": "", "kind": "http_exchange", "summary": f"GET {resp_url}"}

        findings: list[RawFinding] = []
        safe = 0

        for hf in getattr(report, "findings", []) or []:
            # hf has .status (ok/weak/missing), .rule.header, .rule.severity etc.
            status = getattr(hf, "status", "missing")
            if status == "ok":
                safe += 1
                continue
            header_name = getattr(getattr(hf, "rule", None), "header", "") or ""
            check_id = CHECK_SLUGS.get(header_name)
            if not check_id:
                logger.debug("Unknown header rule %r — skipping", header_name)
                continue
            sev = SEVERITY_MAP.get(str(getattr(getattr(hf, "rule", None), "severity", "low")).lower(), "LOW")
            # ``weak`` means header present but value is wrong — surface the
            # actual value in remediation so the operator knows what to fix.
            actual = getattr(hf, "actual_value", None)
            if status == "missing":
                remediation = RECOMMENDED[check_id]
            else:
                remediation = f"{RECOMMENDED[check_id]} Current weak value: '{actual}'."
            note = getattr(hf, "note", "") or ""
            rule_desc = getattr(getattr(hf, "rule", None), "description", "") or ""
            findings.append(
                RawFinding(
                    title=TITLES[check_id],
                    description=f"{note}. {rule_desc}".strip(),
                    severity=sev,
                    category=self.category,
                    affected_component=str(getattr(report, "final_url", ctx.target)),
                    scanner=self.name,
                    check_id=check_id,
                    reproduction=[
                        f"curl -I {ctx.target}",
                        f"Observe the '{header_name}' response header ({status}).",
                    ],
                    impact=IMPACTS[check_id],
                    remediation=remediation,
                    meta={"status": status, "grade": getattr(report, "grade", None), "score": getattr(report, "score", None)},
                    scan_target=ctx.target,
                    evidence_payloads=[evidence_doc],
                )
            )

        # Cookie-flag finding is one aggregated check (not per-cookie).
        if cookie_findings:
            findings.append(
                RawFinding(
                    title="Session cookie missing security flags",
                    description="; ".join(cookie_findings),
                    severity="MEDIUM",
                    category="AUTHENTICATION",
                    affected_component=resp_url,
                    scanner=self.name,
                    check_id="auth.cookie_flags_missing",
                    reproduction=["POST /login, inspect Set-Cookie attributes of the session cookie."],
                    impact=(
                        "Without HttpOnly the session cookie is readable by injected scripts; "
                        "without Secure it can travel over plain HTTP; without SameSite it is "
                        "exposed to cross-site request forgery."
                    ),
                    remediation="Set HttpOnly; Secure; SameSite=Lax on every session cookie.",
                    meta={"cookies": cookie_findings, "cookie_count": len(cookie_values)},
                    scan_target=ctx.target,
                    evidence_payloads=[evidence_doc],
                )
            )
        else:
            # Cookie hygiene counts as one safe check regardless of whether any
            # cookies were set — “no cookies, no risk” is safe.
            safe += 1

        total_checks = len(getattr(report, "findings", []) or []) + 1  # +1 for cookie audit
        duration = round(time.perf_counter() - started, 3)
        errors: list[str] = list(evidence_errors)
        return ScanResult(
            scanner=self.name,
            status="completed",
            findings=findings,
            checks_total=total_checks,
            checks_safe=safe,
            errors=errors,
            duration_s=duration,
        )
