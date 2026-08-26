"""TLS / secure-communication module (native, non-destructive).

Probes performed

1. **TLS handshake on the target's own port** — respects explicit port in
   ``ctx.target`` (``https://host:8443`` probes ``host:8443``, not ``host:443``).
   Derives certificate expiry, days-to-expiry, and persists a masked PEM
   excerpt as ``tls_inspection`` evidence.
2. **Plain-HTTP exposure** — if the target is served over ``http://`` and no
   TLS listener is reachable on the canonical HTTPS port, emits
   ``tls.no_https_available`` (HIGH).
3. **HTTP→HTTPS redirect** — when a TLS listener *is* reachable but the
   application is accessed over plain HTTP, probes ``http://host[:port]``
   for a 3xx ``Location: https://…`` redirect.  Missing redirect →
   ``tls.no_https_redirect`` (MEDIUM).
4. **Certificate expiry window** — ``days_left < 30`` triggers
   ``tls.certificate_expiring_soon`` (MEDIUM <15 days, LOW 15-29).

The module is intentionally non-invasive: it never sends malformed
ClientHellos, never enumerates ciphers, and never performs a full
``testssl.sh``-style sweep (that would be flagged as intrusive by the lab
gate).  Evidence documents are always emitted, even on failure, so
operators can distinguish “probed and safe” from “probe failed”.

Thread/interrupt safety: all socket work is bounded by connect + TLS
timeouts; no unbounded blocking.
"""
from __future__ import annotations

import logging
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from ..engine.findings import RawFinding
from ..scanners.base import ScanContext, ScanResult, ScannerModule

logger = logging.getLogger(__name__)

__all__ = ["TlsModule"]

_CONNECT_TIMEOUT = 5.0
_TLS_TIMEOUT = 5.0
_HTTP_PROBE_TIMEOUT = 5.0


def _parse_host_port(target: str) -> tuple[str, int, str]:
    """Return ``(host, tls_port, scheme)`` from an HTTP target URL."""
    parsed = urlparse(target)
    host = parsed.hostname or "127.0.0.1"
    scheme = (parsed.scheme or "http").lower()
    # If the URL already specifies a port, that *is* the TLS port for
    # ``https`` targets.  For ``http`` targets the canonical TLS port is
    # always 443 (or the explicit port + 100-ish is not assumed).
    if parsed.port is not None:
        port = parsed.port if scheme == "https" else 443
    else:
        port = 443 if scheme == "https" else 443
    # For https://host:8443 we must probe host:8443, not host:443.
    if scheme == "https" and parsed.port is not None:
        port = parsed.port
    return host, port, scheme


class TlsModule(ScannerModule):
    name = "tls"
    category = "SECURE_COMMUNICATION"
    description = "Checks TLS availability, certificate expiry and HTTP→HTTPS redirect"

    def run(self, ctx: ScanContext) -> ScanResult:
        started = time.perf_counter()
        if not ctx.has_http_target:
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=["HTTP target is required for TLS checks"],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )
        store = ctx.require_evidence()
        parsed = urlparse(ctx.target)
        host = parsed.hostname or "127.0.0.1"
        # Canonical host for finding titles/meta is the hostname, but
        # the probe target for TLS is derived with port awareness.
        probe_host, probe_port, scheme = _parse_host_port(ctx.target)
        # For http targets we still probe <host>:443 even when ctx.target
        # carries an explicit http port (e.g. http://127.0.0.1:5000 → probe 443).
        # For https targets with explicit port we already use that port.
        tls_host = probe_host
        tls_port = probe_port

        findings: list[RawFinding] = []
        errors: list[str] = []
        checks = 0

        # ------------------------------------------------------------------
        # 1. TLS handshake probe
        # ------------------------------------------------------------------
        https_ok = False
        cert_info: dict = {}
        expires_raw: str | None = None
        days_left: int | None = None
        cert_pem_excerpt: str = ""

        # httpx timeout for secondary HTTP probe may be overridden via options.
        http_timeout = ctx.effective_timeout(_HTTP_PROBE_TIMEOUT)

        try:
            ssl_ctx = ssl.create_default_context()
            # No extra options — use system defaults; we are not testing
            # cipher downgrades here.
            with socket.create_connection((tls_host, tls_port), timeout=_CONNECT_TIMEOUT) as sock:
                sock.settimeout(_TLS_TIMEOUT)
                with ssl_ctx.wrap_socket(sock, server_hostname=tls_host) as tls:
                    # Keep the PEM excerpt short — never persist full chains verbatim.
                    try:
                        der = tls.getpeercert(binary_form=True)  # type: ignore[call-arg]
                        if der:
                            cert_pem_excerpt = ssl.DER_cert_to_PEM_cert(der)[:500]
                    except Exception:
                        cert_pem_excerpt = ""
                    peer = tls.getpeercert()  # dict form
                    if isinstance(peer, dict):
                        expires_raw = peer.get("notAfter")  # type: ignore[assignment]
                    # ``tls.version()`` and cipher are useful diagnostics.
                    cert_info["tls_version"] = tls.version() or ""
                    try:
                        cert_info["cipher"] = str(tls.cipher() or "")
                    except Exception:
                        pass
            https_ok = True
            checks += 1

            # Parse expiry if present.
            if expires_raw:
                try:
                    # Format per RFC 5280: "Jun  1 00:00:00 2026 GMT" — day may be space-padded.
                    expires_dt = datetime.strptime(expires_raw.strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expires_dt - datetime.now(timezone.utc)).days
                    cert_info.update({"https": True, "expires": expires_raw, "days_left": days_left, "host": tls_host, "port": tls_port})
                except Exception as exc:
                    logger.debug("Failed to parse notAfter %r: %s", expires_raw, exc)
                    cert_info.update({"https": True, "host": tls_host, "port": tls_port, "expires": expires_raw})
                    days_left = None
            else:
                cert_info.update({"https": True, "host": tls_host, "port": tls_port})

            try:
                store.save(
                    kind="tls_inspection",
                    summary=f"TLS certificate for {tls_host}:{tls_port}" if tls_port != 443 else f"TLS certificate for {tls_host}",
                    payload={"host": tls_host, "port": tls_port, "certificate_pem_excerpt": cert_pem_excerpt[:400], **cert_info},
                )
            except Exception as exc:
                logger.warning("Failed to persist TLS evidence: %s", exc, exc_info=True)

            # Expiry finding (only if we could parse days_left)
            if days_left is not None and days_left < 30:
                sev = "MEDIUM" if days_left < 15 else "LOW"
                if days_left < 0:
                    sev = "MEDIUM"
                    title = "TLS certificate expired"
                else:
                    title = "TLS certificate expiring soon"
                findings.append(
                    RawFinding(
                        title=title,
                        description=f"Certificate for {tls_host} expires in {days_left} days ({expires_raw}).",
                        severity=sev,
                        category=self.category,
                        affected_component=f"https://{tls_host}" + (f":{tls_port}" if tls_port != 443 else ""),
                        scanner=self.name,
                        check_id="tls.certificate_expiring_soon",
                        reproduction=["Inspect certificate validity via: openssl s_client -connect {0}:{1} -servername {0} </dev/null | openssl x509 -noout -dates".format(tls_host, tls_port)],
                        impact="Expired certificates break clients and train users to ignore warnings.",
                        remediation="Automate renewal (ACME/Let's Encrypt) before the 30-day window.",
                        scan_target=ctx.target,
                        meta=dict(cert_info),
                    )
                )
        except Exception as exc:
            # Any failure here means “no usable TLS on that port”.
            checks += 1
            logger.debug("TLS probe failed for %s:%s — %s", tls_host, tls_port, exc)
            try:
                store.save(
                    kind="tls_inspection",
                    summary=f"No usable TLS on {tls_host}:{tls_port}",
                    payload={"host": tls_host, "port": tls_port, "https": False, "error": repr(exc)[:500]},
                )
            except Exception:
                pass

        # ------------------------------------------------------------------
        # 1b. Plain-HTTP exposure (HIGH) — only when no TLS listener is
        #     reachable and the assessment target itself is http://.
        # ------------------------------------------------------------------
        if not https_ok and scheme == "http":
            findings.append(
                RawFinding(
                    title="Service served over plain HTTP without TLS",
                    description=(
                        f"{ctx.target} does not present a TLS listener on {tls_host}:{tls_port}; all traffic "
                        f"(including credentials and session cookies) traverses the network in cleartext."
                    ),
                    severity="HIGH",
                    category=self.category,
                    affected_component=ctx.target,
                    scanner=self.name,
                    check_id="tls.no_https_available",
                    reproduction=[
                        f"Attempt TLS handshake against {tls_host}:{tls_port} — connection refused/failed.",
                        "Observe that http:// serves the application directly.",
                    ],
                    impact="Network attackers can read and modify all traffic (MITM).",
                    business_impact="Credential interception and session hijacking on any shared network.",
                    remediation="Terminate TLS everywhere (even internally); redirect HTTP->HTTPS permanently.",
                    scan_target=ctx.target,
                    meta={"host": host, "tls_host": tls_host, "tls_port": tls_port},
                )
            )

        # ------------------------------------------------------------------
        # 2. HTTP → HTTPS redirect check — only meaningful when TLS *is*
        #    reachable but the target is still accessed over http://.
        # ------------------------------------------------------------------
        if https_ok and scheme == "http":
            checks += 1
            try:
                # Probe the *http* origin that corresponds to the tls_host.
                # For a target like http://127.0.0.1:5000 we probe
                # http://127.0.0.1:5000 (not bare http://127.0.0.1).
                http_origin = f"http://{host}"
                # Preserve explicit port when present (lab on :5000 etc.)
                if parsed.port is not None:
                    http_origin = f"http://{host}:{parsed.port}"
                # Also preserve base path?  Redirect is expected at host root
                # for full-site TLS, so probe origin root regardless of deep
                # target path — deep paths may 404 and mask the redirect.
                resp = httpx.head(http_origin, follow_redirects=False, timeout=http_timeout)
                location = resp.headers.get("location", "") or resp.headers.get("Location", "")
                is_redirect = (300 <= resp.status_code < 400) and location.lower().startswith("https://")
                if not is_redirect:
                    findings.append(
                        RawFinding(
                            title="HTTP traffic not redirected to HTTPS",
                            description=f"{http_origin} answers {resp.status_code} without an HTTPS redirect (Location: {location or '—'}).",
                            severity="MEDIUM",
                            category=self.category,
                            affected_component=http_origin,
                            scanner=self.name,
                            check_id="tls.no_https_redirect",
                            reproduction=[f"curl -I {http_origin}"],
                            impact="Users can land on the insecure origin and be downgraded.",
                            remediation="301-redirect every HTTP request to the HTTPS host + enable HSTS.",
                            scan_target=ctx.target,
                            meta={"status_code": resp.status_code, "location": location, "probed": http_origin},
                        )
                    )
            except Exception as exc:
                # Probe failure is not a finding — record it for diagnostics.
                errors.append(f"HTTP→HTTPS redirect probe failed: {repr(exc)}")
                logger.debug("HTTP redirect probe failed for %s: %s", host, exc)
                try:
                    store.save(kind="tls_inspection", summary="HTTP probe failed", payload={"host": host, "error": repr(exc)[:500]})
                except Exception:
                    pass

        duration = round(time.perf_counter() - started, 3)
        total = max(checks, 1)
        safe = max(total - len(findings), 0)
        return ScanResult(
            scanner=self.name,
            status="completed",
            findings=findings,
            checks_total=total,
            checks_safe=safe,
            errors=errors,
            duration_s=duration,
        )
