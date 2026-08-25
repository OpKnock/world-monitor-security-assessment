"""Client security module — vendored http-headers-scanner + Set-Cookie flag audit."""
from __future__ import annotations

import httpx

from ..engine.evidence import mask_headers
from ..engine.findings import RawFinding
from ..scanners.base import ScanContext, ScanResult, ScannerModule
from ..vendor.http_headers_scanner import scan as headers_scan

SEVERITY_MAP = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
CHECK_SLUGS = {
    "Strict-Transport-Security": "headers.strict_transport_security",
    "Content-Security-Policy": "headers.content_security_policy",
    "X-Content-Type-Options": "headers.x_content_type_options",
    "X-Frame-Options": "headers.x_frame_options",
    "Referrer-Policy": "headers.referrer_policy",
    "Permissions-Policy": "headers.permissions_policy",
}
TITLES = {
    "headers.strict_transport_security": "Missing/weak HSTS header",
    "headers.content_security_policy": "Missing Content-Security-Policy",
    "headers.x_content_type_options": "Missing X-Content-Type-Options (nosniff)",
    "headers.x_frame_options": "Missing X-Frame-Options / frame-ancestors",
    "headers.referrer_policy": "Missing Referrer-Policy",
    "headers.permissions_policy": "Missing Permissions-Policy",
}
IMPACTS = {
    "headers.strict_transport_security":
        "SSL-stripping and downgrade attacks become possible for returning visitors.",
    "headers.content_security_policy":
        "No browser-enforced script allowlist; XSS payloads execute freely.",
    "headers.x_content_type_options":
        "Browsers may MIME-sniff uploads and render attacker-controlled files as HTML.",
    "headers.x_frame_options":
        "The page can be framed by any site, enabling clickjacking.",
    "headers.referrer_policy":
        "Full URLs (including tokens in paths) leak to third-party sites.",
    "headers.permissions_policy":
        "Sensitive browser features (camera, mic, geo) are not explicitly disabled.",
}
RECOMMENDED = {
    "headers.strict_transport_security":
        "Send: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "headers.content_security_policy":
        "Adopt a strict CSP, e.g. default-src 'self'; object-src 'none'; frame-ancestors 'none'.",
    "headers.x_content_type_options": "Send: X-Content-Type-Options: nosniff",
    "headers.x_frame_options": "Send: X-Frame-Options: DENY (plus CSP frame-ancestors 'none').",
    "headers.referrer_policy": "Send: Referrer-Policy: strict-origin-when-cross-origin",
    "headers.permissions_policy":
        "Send: Permissions-Policy: camera=(), microphone=(), geolocation=()",
}


class ClientSecurityHeadersModule(ScannerModule):
    name = "headers"
    category = "CLIENT_SECURITY"

    def run(self, ctx: ScanContext) -> ScanResult:
        store = ctx.require_evidence()
        try:
            report = headers_scan(ctx.target)
        except httpx.HTTPError as exc:
            return ScanResult(scanner=self.name, status="failed", errors=[repr(exc)])

        findings: list[RawFinding] = []
        safe = 0
        # re-fetch once to capture raw headers + cookies as evidence
        resp = httpx.get(ctx.target, follow_redirects=True, timeout=10.0,
                         headers={"User-Agent": "world-monitor-scanner/1.0"})
        raw_headers = {k: v for k, v in resp.headers.items()}
        cookie_findings: list[str] = []
        for value in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]:
            low = value.lower()
            missing_flags = [
                flag for flag, ok in (("HttpOnly", "httponly" in low),
                                      ("Secure", "secure" in low),
                                      ("SameSite", "samesite" in low)) if not ok
            ]
            if missing_flags:
                cookie_name = value.split("=", 1)[0]
                cookie_findings.append(f"{cookie_name} missing {', '.join(missing_flags)}")

        evidence_doc = store.save(
            kind="http_exchange",
            summary=f"GET {report.final_url} -> {report.status_code}",
            payload={
                "request": {"method": "GET", "url": str(report.final_url), "headers": {}, "body_excerpt": ""},
                "response": {
                    "status_code": report.status_code,
                    "headers": mask_headers(raw_headers),
                    "body_excerpt": "",
                },
                "grade": {"score": report.score, "grade": report.grade},
            },
        )

        for hf in report.findings:
            if hf.status == "ok":
                safe += 1
                continue
            check_id = CHECK_SLUGS[hf.rule.header]
            sev = SEVERITY_MAP[hf.rule.severity]
            findings.append(
                RawFinding(
                    title=TITLES[check_id],
                    description=f"{hf.note}. {hf.rule.description}",
                    severity=sev,
                    category=self.category,
                    affected_component=str(report.final_url),
                    scanner=self.name,
                    check_id=check_id,
                    reproduction=[
                        f"curl -I {ctx.target}",
                        f"Observe the '{hf.rule.header}' response header ({hf.status}).",
                    ],
                    impact=IMPACTS[check_id],
                    remediation=RECOMMENDED[check_id] if hf.status == "missing"
                    else f"{RECOMMENDED[check_id]} Current weak value: '{hf.actual_value}'.",
                    meta={"status": hf.status, "grade": report.grade, "score": report.score},
                    scan_target=ctx.target,
                    evidence_payloads=[evidence_doc],
                )
            )

        if cookie_findings:
            findings.append(
                RawFinding(
                    title="Session cookie missing security flags",
                    description="; ".join(cookie_findings),
                    severity="MEDIUM",
                    category="AUTHENTICATION",
                    affected_component=str(resp.url),
                    scanner=self.name,
                    check_id="auth.cookie_flags_missing",
                    reproduction=["POST /login, inspect Set-Cookie attributes of the session cookie."],
                    impact=(
                        "Without HttpOnly the session cookie is readable by injected scripts; "
                        "without Secure it can travel over plain HTTP; without SameSite it is "
                        "exposed to cross-site request forgery."
                    ),
                    remediation="Set HttpOnly; Secure; SameSite=Lax on every session cookie.",
                    meta={"cookies": cookie_findings},
                    scan_target=ctx.target,
                    evidence_payloads=[evidence_doc],
                )
            )
        else:
            safe += 1

        return ScanResult(scanner=self.name, status="completed", findings=findings,
                          checks_total=len(report.findings) + 1, checks_safe=safe)
