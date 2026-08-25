"""TLS / secure-communication module (native, non-destructive)."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from ..engine.findings import RawFinding
from ..scanners.base import ScanContext, ScanResult, ScannerModule


class TlsModule(ScannerModule):
    name = "tls"
    category = "SECURE_COMMUNICATION"

    def run(self, ctx: ScanContext) -> ScanResult:
        store = ctx.require_evidence()
        parsed = urlparse(ctx.target)
        host = parsed.hostname or "127.0.0.1"
        findings: list[RawFinding] = []
        checks = 0

        # 1. is HTTPS reachable at all?
        https_ok = False
        cert_info: dict = {}
        try:
            ctx_sock = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx_sock.wrap_socket(sock, server_hostname=host) as tls:
                    der = tls.getpeercert(True)
                    cert = ssl.DER_cert_to_PEM_cert(der)
                    not_after = tls.getpeercert()["notAfter"]
            https_ok = True
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            cert_info = {"https": True, "expires": not_after, "days_left": days_left}
            store.save(kind="tls_inspection", summary=f"TLS certificate for {host}",
                       payload={"host": host, "certificate_pem_excerpt": cert[:400], **cert_info})
            checks += 1
            if days_left < 30:
                sev = "MEDIUM" if days_left < 15 else "LOW"
                findings.append(RawFinding(
                    title="TLS certificate expiring soon" if days_left > 0 else "TLS certificate expired",
                    description=f"Certificate for {host} expires in {days_left} days ({not_after}).",
                    severity=sev, category=self.category, affected_component=f"https://{host}",
                    scanner=self.name, check_id="tls.certificate_expiring_soon",
                    reproduction=["Inspect certificate validity via openssl s_client."],
                    impact="Expired certificates break clients and train users to ignore warnings.",
                    remediation="Automate renewal (ACME/Let's Encrypt) before the 30-day window.",
                    scan_target=ctx.target,
                    meta=cert_info))
        except Exception:
            checks += 1
            store.save(kind="tls_inspection", summary=f"No usable TLS on {host}:443",
                       payload={"host": host, "https": False})

        if not https_ok and parsed.scheme == "http":
            findings.append(RawFinding(
                title="Service served over plain HTTP without TLS",
                description=(
                    f"{ctx.target} does not present a TLS listener on port 443; all traffic "
                    f"(including credentials and session cookies) traverses the network in cleartext."
                ),
                severity="HIGH", category=self.category, affected_component=ctx.target,
                scanner=self.name, check_id="tls.no_https_available",
                reproduction=[f"Attempt TLS handshake against {host}:443 — connection refused/failed.",
                              "Observe that http:// serves the application directly."],
                impact="Network attackers can read and modify all traffic (MITM).",
                business_impact="Credential interception and session hijacking on any shared network.",
                remediation="Terminate TLS everywhere (even internally); redirect HTTP->HTTPS permanently.",
                scan_target=ctx.target,
                meta={"host": host}))

        # 2. does HTTP redirect to HTTPS?
        if https_ok and parsed.scheme == "http":
            checks += 1
            try:
                resp = httpx.head(f"http://{host}", follow_redirects=False, timeout=5)
                location = resp.headers.get("location", "")
                if not (resp.status_code // 100 == 3 and location.startswith("https://")):
                    findings.append(RawFinding(
                        title="HTTP traffic not redirected to HTTPS",
                        description=f"http://{host} answers {resp.status_code} without an HTTPS redirect.",
                        severity="MEDIUM", category=self.category, affected_component=f"http://{host}",
                        scanner=self.name, check_id="tls.no_https_redirect",
                        reproduction=[f"curl -I http://{host}"],
                        impact="Users can land on the insecure origin and be downgraded.",
                        remediation="301-redirect every HTTP request to the HTTPS host + enable HSTS.",
                        scan_target=ctx.target,
                        meta={"status_code": resp.status_code, "location": location}))
            except Exception as exc:
                store.save(kind="tls_inspection", summary="HTTP probe failed",
                           payload={"error": repr(exc)})

        return ScanResult(scanner=self.name, status="completed", findings=findings,
                          checks_total=max(checks, 1), checks_safe=max(checks, 1) - len(findings))
