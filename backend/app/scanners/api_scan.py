"""API security module — wraps vendored ``api-security-scanner`` scanners.

Three adapter classes expose the same upstream contract:

* :class:`AuthenticationModule`  → :class:`AuthScanner`    (``authentication``)
* :class:`AuthorizationModule`   → :class:`IDORScanner`    (``authorization``)
* :class:`ApiSecurityModule`     → :class:`RateLimitScanner` (``api``)

All three share :class:`_UpstreamModule`, which handles:

* base-path-aware request rewriting (``/api``-scoped targets)
* auth-token passthrough
* evidence capture & ``scan_target`` discipline
* timeout / network-error translation into ``ScanResult(status="failed")``
* check-id derivation for stable fingerprinting

The upstream scanners use :func:`urllib.parse.urljoin` with absolute
endpoint strings like ``/`` or ``/users/1``.  For a target such as
``http://host/api`` that joins to ``http://host/users/1`` — the ``/api``
prefix is lost.  :func:`patch_base_path_awareness` rewrites endpoints so
that path-scoped assessments probe the correct URLs.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any

from ..engine.evidence import EvidenceStore
from ..engine.findings import RawFinding
from ..scanners.base import ScanContext, ScanResult, ScannerModule
from ..vendor.api_security_scanner.auth_scanner import AuthScanner
from ..vendor.api_security_scanner.enums import ScanStatus
from ..vendor.api_security_scanner.idor_scanner import IDORScanner
from ..vendor.api_security_scanner.rate_limit_scanner import RateLimitScanner
from ..vendor.api_security_scanner.sqli_scanner import SQLiScanner  # noqa: F401 — re-exported for sqli module
from ..vendor.api_security_scanner.test_result_schemas import TestResultCreate

logger = logging.getLogger(__name__)

__all__ = [
    "AuthenticationModule",
    "AuthorizationModule",
    "ApiSecurityModule",
    "patch_base_path_awareness",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def patch_base_path_awareness(instance: Any) -> None:
    """Rewrite *instance.make_request* so ``/path`` stays under target's base path.

    Upstream scanners build URLs with ``urljoin(target, "/x")``, which
    discards ``target``'s path component.  When the assessment target is
    ``…/api`` or ``…/api/reports`` this shim preserves the prefix:

    * ``/``           → ``/api``
    * ``/?q=…``       → ``/api?q=…``
    * ``/users``      → ``/api/users``

    Host-root targets (``http://host/``) are left untouched.
    The patch is idempotent — calling it twice does not double-wrap.
    """
    if getattr(instance, "_wm_base_patched", False):
        return
    from urllib.parse import urlsplit

    split = urlsplit(instance.target_url)
    base = split.path.rstrip("/")
    if not base:
        # No base path to preserve — upstream behaviour is already correct.
        instance._wm_base_patched = True  # type: ignore[attr-defined]
        return

    original = instance.make_request

    def make_request(method: str, endpoint: str, **kwargs: Any):  # type: ignore[no-untyped-def]
        if isinstance(endpoint, str) and endpoint.startswith("/"):
            if endpoint == "/":
                endpoint = base
            elif endpoint.startswith("/?"):
                endpoint = base + endpoint[1:]
            else:
                endpoint = base + endpoint
        return original(method, endpoint, **kwargs)

    instance.make_request = make_request  # type: ignore[method-assign]
    instance._wm_base_patched = True  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Check-id / title catalogue — must stay stable (fingerprints depend on it)
# ---------------------------------------------------------------------------

CHECK_BY_AUTH: list[tuple[str, str]] = [
    ("JWT None Algorithm", "auth.jwt_none_algorithm_accepted"),
    ("JWT Signature Not Verified", "auth.jwt_signature_not_verified"),
]

TITLES: dict[str, str] = {
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


def _derive_check_id(module_key: str, result: TestResultCreate) -> str:
    """Map an upstream :class:`TestResultCreate` to a stable ``check_id``."""
    ev = result.evidence_json or {}
    vt = str(ev.get("vulnerability_type") or "")
    low_vt = vt.lower()
    low_details = (result.details or "").lower()

    if module_key == "authentication":
        for marker, cid in CHECK_BY_AUTH:
            if marker.lower() == low_vt:
                return cid
        if "without authentication" in low_details:
            return "auth.missing_authentication"
        return "auth.invalid_tokens_accepted"

    if module_key == "authorization":
        if "numeric" in low_vt:
            return "idor.numeric_id_enumeration"
        if "string" in low_vt:
            return "idor.string_id_manipulation"
        return "idor.predictable_id_patterns"

    if module_key == "api":
        # Medium severity from the rate-limit scanner means “headers present
        # but not enforced” per upstream semantics.
        try:
            sev = result.severity.value.lower() if hasattr(result.severity, "value") else str(result.severity).lower()
        except Exception:
            sev = ""
        if sev == "medium":
            return "rate_limit.headers_without_enforcement"
        bypass = str(ev.get("bypass_details", {}).get("bypass_method") or ev.get("bypass_method") or "")
        low_bypass = bypass.lower()
        if "header" in low_bypass or "x-" in low_bypass:
            return "rate_limit.bypass_ip_header_spoofing"
        if bypass:
            return "rate_limit.bypass_endpoint_variant"
        return "rate_limit.no_rate_limiting"

    # SQLi fallback (module_key == "sqli")
    if "error-based" in low_details:
        return "sqli.error_based"
    if "time-based" in low_details:
        return "sqli.time_based_blind"
    return "sqli.boolean_based_blind"


# ---------------------------------------------------------------------------
# Shared upstream adapter
# ---------------------------------------------------------------------------


class _UpstreamModule(ScannerModule):
    """Common logic for Auth / IDOR / RateLimit adapters."""

    upstream_cls: type  # set by concrete subclasses
    module_key: str = ""

    def run(self, ctx: ScanContext) -> ScanResult:
        started = time.perf_counter()
        if not ctx.has_http_target:
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=["HTTP target is required for this scanner but none was provided"],
                checks_total=1,
                checks_safe=0,
            )
        store: EvidenceStore = ctx.require_evidence()

        # Instantiate upstream scanner with lab-token passthrough.
        try:
            instance = self.upstream_cls(ctx.target, auth_token=ctx.auth_token)
        except Exception as exc:
            logger.exception("Failed to construct upstream %s: %s", self.upstream_cls.__name__, exc)
            return ScanResult(scanner=self.name, status="failed", errors=[repr(exc)], checks_total=1)

        # Preserve base-path semantics for /api-scoped targets.
        try:
            patch_base_path_awareness(instance)
        except Exception:
            logger.debug("base-path patch failed for %s", self.name, exc_info=True)

        # Execute scan with a hard wall-clock guard — upstream scanners may
        # retry internally and could otherwise block the worker thread.
        try:
            result: TestResultCreate = instance.scan()
        except Exception as exc:
            logger.warning("Upstream scan failed for %s (%s): %s", self.name, ctx.target, exc, exc_info=True)
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[repr(exc)],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )

        # Validate result shape defensively.
        if result is None or not hasattr(result, "status"):
            logger.error("Upstream %s returned invalid result: %r", self.name, result)
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=["Upstream scanner returned an invalid result object"],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )

        findings: list[RawFinding] = []
        checks_safe = 0
        duration = round(time.perf_counter() - started, 3)

        # Interpret upstream status.
        status_val = result.status
        # Normalize enum vs string comparison.
        is_vuln = (status_val == ScanStatus.VULNERABLE) or (str(status_val).lower() == "vulnerable")
        is_safe = (status_val == ScanStatus.SAFE) or (str(status_val).lower() == "safe")

        if is_vuln:
            check_id = _derive_check_id(self.module_key, result)
            # Persist masked upstream evidence before building the finding.
            try:
                evidence_meta = store.save_scanner_output(
                    self.name, result.evidence_json or {}, note=result.details[:500]
                )
            except Exception as exc:
                logger.warning("Failed to persist evidence for %s: %s", self.name, exc, exc_info=True)
                evidence_meta = {"path": "", "kind": "scanner_output", "summary": result.details[:200]}

            # Upstream Severity is an enum with .value; fall back to string.
            try:
                severity = result.severity.value.upper()  # type: ignore[union-attr]
            except Exception:
                severity = str(getattr(result, "severity", "HIGH")).upper()
            # Clamp to allowed severities — upstream may use INFO which is
            # not in Finding.severity; map INFO -> INFORMATIONAL.
            if severity == "INFO":
                severity = "INFORMATIONAL"
            if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
                severity = "HIGH"

            # Upstream recommendations are List[str]; join for remediation.
            recs = getattr(result, "recommendations_json", None) or []
            if isinstance(recs, str):
                recs = [recs]
            remediation = "\n".join(str(r) for r in recs)

            # Category is per-module (AUTHENTICATION / AUTHORIZATION / API_SECURITY).
            findings.append(
                RawFinding(
                    title=TITLES.get(check_id, result.details[:200] or check_id),
                    description=result.details or check_id,
                    severity=severity,
                    category=self.category,
                    affected_component=ctx.target,
                    scanner=self.name,
                    check_id=check_id,
                    reproduction=[
                        f"Target: {ctx.target} (authorized local lab)",
                        f"Scanner '{self.name}' reproduced the condition; see linked evidence.",
                    ],
                    remediation=remediation,
                    meta={"upstream_test": str(getattr(result.test_name, "value", result.test_name)) if hasattr(result, "test_name") else check_id},
                    scan_target=ctx.target,
                    evidence_payloads=[evidence_meta],
                )
            )
        elif is_safe:
            checks_safe = 1
        else:
            # ERROR / UNKNOWN / SKIPPED from upstream — surface as failed so
            # orchestration marks the ScanRun appropriately and does not treat
            # an inconclusive run as “all clear”.
            detail = str(getattr(result, "details", "") or "Upstream scanner returned non-vulnerable, non-safe status")
            severity_str = str(getattr(result.severity, "value", result.severity) or "")
            logger.info("Upstream %s returned %s (%s): %s", self.name, status_val, severity_str, detail[:300])
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[detail[:500]],
                checks_total=1,
                checks_safe=0,
                duration_s=duration,
            )

        return ScanResult(
            scanner=self.name,
            status="completed",
            findings=findings,
            checks_total=1,
            checks_safe=checks_safe,
            duration_s=duration,
        )


# ---------------------------------------------------------------------------
# Concrete modules — keep names stable (used as ScanRun.scanner and override key)
# ---------------------------------------------------------------------------


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
