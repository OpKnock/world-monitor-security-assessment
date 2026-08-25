"""API security module — wraps vendored api-security-scanner scanners."""
from __future__ import annotations

import re

from ..engine.evidence import EvidenceStore
from ..engine.findings import RawFinding
from ..scanners.base import ScanContext, ScanResult, ScannerModule
from ..vendor.api_security_scanner.auth_scanner import AuthScanner
from ..vendor.api_security_scanner.enums import ScanStatus
from ..vendor.api_security_scanner.idor_scanner import IDORScanner
from ..vendor.api_security_scanner.rate_limit_scanner import RateLimitScanner
from ..vendor.api_security_scanner.sqli_scanner import SQLiScanner  # noqa: F401 (exposed for sqli module)
from ..vendor.api_security_scanner.test_result_schemas import TestResultCreate


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def patch_base_path_awareness(instance) -> None:
    """Upstream scanners join endpoints with urljoin(target, '/x'), which
    discards the target's base path ('/api' + '/{id}' -> '/{id}'). This shim
    rewrites relative endpoints onto the target's own path so assessments of
    path-scoped targets (…/api, …/api/reports) probe the right URLs."""
    from urllib.parse import urlsplit

    split = urlsplit(instance.target_url)
    base = split.path.rstrip("/")
    if not base:  # host-root target: upstream behaviour already correct
        return

    original = instance.make_request

    def make_request(method, endpoint, **kwargs):
        if isinstance(endpoint, str) and endpoint.startswith("/"):
            if endpoint == "/":
                # bare "/" means "the scoped collection root" (no trailing
                # slash, so Flask strict-slash routes match)
                endpoint = base
            elif endpoint.startswith("/?"):
                # "/?query=..." means "this exact path with a query string"
                endpoint = base + endpoint[1:]
            else:
                endpoint = base + endpoint
        return original(method, endpoint, **kwargs)

    instance.make_request = make_request


CHECK_BY_AUTH = [
    ("JWT None Algorithm", "auth.jwt_none_algorithm_accepted"),
    ("JWT Signature Not Verified", "auth.jwt_signature_not_verified"),
]

TITLES = {
    "auth.missing_authentication": "Endpoint accessible without authentication",
    "auth.invalid_tokens_accepted": "Invalid/malformed tokens accepted by API",
    "auth.jwt_none_algorithm_accepted": "JWT 'none' algorithm accepted",
    "auth.jwt_signature_not_verified": "JWT signature not verified",
    "idor.numeric_id_enumeration": "Broken object-level authorization (numeric ID enumeration)",
    "idor.string_id_manipulation": "Broken object-level authorization (string ID manipulation)",
    "idor.predictable_id_patterns": "Predictable sequential resource IDs",
    "rate_limit.no_rate_limiting": "No rate limiting on target endpoint",
    "rate_limit.headers_without_enforcement": "Rate-limit headers present but not enforced",
    "rate_limit.bypass_ip_header_spoofing": "Rate limiting bypassed via IP-header spoofing",
    "rate_limit.bypass_endpoint_variant": "Rate limiting bypassed via endpoint-path variations",
    "sqli.error_based": "Error-based SQL injection",
    "sqli.boolean_based_blind": "Boolean-based blind SQL injection",
    "sqli.time_based_blind": "Time-based blind SQL injection",
}


def _derive_check_id(scanner: str, result: TestResultCreate) -> str:
    ev = result.evidence_json or {}
    vt = str(ev.get("vulnerability_type") or "")
    if scanner == "authentication":
        for marker, cid in CHECK_BY_AUTH:
            if marker.lower() == vt.lower():
                return cid
        if "without authentication" in result.details.lower():
            return "auth.missing_authentication"
        return "auth.invalid_tokens_accepted"
    if scanner == "authorization":
        low = vt.lower()
        if "numeric" in low:
            return "idor.numeric_id_enumeration"
        if "string" in low:
            return "idor.string_id_manipulation"
        return "idor.predictable_id_patterns"
    if scanner == "api":
        if result.severity.value == "medium":
            return "rate_limit.headers_without_enforcement"
        method = str(ev.get("bypass_details", {}).get("bypass_method") or ev.get("bypass_method") or "")
        if "header" in method.lower() or "x-" in method.lower():
            return "rate_limit.bypass_ip_header_spoofing"
        if method:
            return "rate_limit.bypass_endpoint_variant"
        return "rate_limit.no_rate_limiting"
    # sqli
    if "error-based" in result.details.lower():
        return "sqli.error_based"
    if "time-based" in result.details.lower():
        return "sqli.time_based_blind"
    return "sqli.boolean_based_blind"


class _UpstreamModule(ScannerModule):
    upstream_cls: type
    module_key: str = ""

    def run(self, ctx: ScanContext) -> ScanResult:
        store: EvidenceStore = ctx.require_evidence()
        instance = self.upstream_cls(ctx.target, auth_token=ctx.auth_token)
        patch_base_path_awareness(instance)
        try:
            result = instance.scan()
        except Exception as exc:  # defensive: upstream raises on network issues
            return ScanResult(scanner=self.name, status="failed", errors=[repr(exc)])
        findings: list[RawFinding] = []
        checks_safe = 0
        if result.status == ScanStatus.VULNERABLE:
            check_id = _derive_check_id(self.module_key, result)
            evidence_meta = store.save_scanner_output(
                self.name, result.evidence_json or {}, note=result.details
            )
            severity = result.severity.value.upper()
            findings.append(
                RawFinding(
                    title=TITLES.get(check_id, result.details),
                    description=result.details,
                    severity=severity,
                    category=self.category,
                    affected_component=ctx.target,
                    scanner=self.name,
                    check_id=check_id,
                    reproduction=[
                        f"Target: {ctx.target} (authorized local lab)",
                        *result.recommendations_json[:0],
                        f"Scanner '{self.name}' reproduced the condition; see evidence document.",
                    ],
                    remediation="\n".join(result.recommendations_json),
                    meta={"upstream_test": result.test_name.value},
                    scan_target=ctx.target,
                    evidence_payloads=[evidence_meta],
                )
            )
        elif result.status == ScanStatus.SAFE:
            checks_safe = 1
        else:
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[str(result.details)],
                checks_total=1,
                checks_safe=checks_safe,
            )
        return ScanResult(
            scanner=self.name,
            status="completed",
            findings=findings,
            checks_total=1,
            checks_safe=checks_safe,
        )


class AuthenticationModule(_UpstreamModule):
    name = "authentication"
    category = "AUTHENTICATION"
    module_key = "authentication"
    upstream_cls = AuthScanner


class AuthorizationModule(_UpstreamModule):
    name = "authorization"
    category = "AUTHORIZATION"
    module_key = "authorization"
    upstream_cls = IDORScanner


class ApiSecurityModule(_UpstreamModule):
    name = "api_rate_limit"
    category = "API_SECURITY"
    module_key = "api"
    upstream_cls = RateLimitScanner
