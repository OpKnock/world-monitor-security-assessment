import socket
import ssl
from datetime import datetime, timezone

from . import Finding, Plugin


def default_tls_probe(target, timeout):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((target.host, target.port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=target.host) as tls:
            cert = tls.getpeercert()
            if not cert:
                cert_bin = tls.getpeercert(binary_form=True)
                cert = _parse_cert_der(cert_bin) or _self_verify(cert_bin, target, timeout)
            return {"protocol": tls.version(), "cert": cert}


def _parse_cert_der(cert_bin):
    if not cert_bin:
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        parsed = x509.load_der_x509_certificate(cert_bin)
        return {"notAfter": parsed.not_valid_after_utc.isoformat(), "subject": str(parsed.subject)}
    except Exception:
        return None


def _self_verify(cert_bin, target, timeout):
    if not cert_bin:
        return None
    pem = ssl.DER_cert_to_PEM_cert(cert_bin)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=pem)
    try:
        with socket.create_connection((target.host, target.port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target.host) as tls:
                return tls.getpeercert()
    except (OSError, ssl.SSLError):
        return None


def _parse_not_after(cert):
    not_after = cert.get("notAfter")
    if not not_after:
        return None
    try:
        return datetime.fromisoformat(not_after.replace("Z", "+00:00"))
    except ValueError:
        pass
    try:
        return datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class TLSConfigPlugin(Plugin):
    """Checks TLS protocol version and certificate expiry via ssl."""

    name = "tls"

    def scan(self, target, ctx):
        probe = ctx.get("tls_probe") or default_tls_probe
        try:
            result = probe(target, ctx.get("tls_timeout", 1.0))
        except (OSError, ssl.SSLError, socket.timeout):
            return [
                Finding(
                    plugin=self.name,
                    severity="low",
                    title="TLS not supported on port",
                    detail=f"No TLS handshake could be completed on {target.host}:{target.port}.",
                )
            ]
        findings = []
        protocol = result.get("protocol", "")
        if protocol in ("TLSv1", "TLSv1.1", "TLSv1.2"):
            findings.append(
                Finding(
                    plugin=self.name,
                    severity="high",
                    title=f"outdated TLS protocol: {protocol}",
                    detail="Enable TLS 1.3 or newer minimum protocol version.",
                )
            )
        cert = result.get("cert")
        if cert:
            expiry = _parse_not_after(cert)
            if expiry is not None and expiry < datetime.now(timezone.utc):
                findings.append(
                    Finding(
                        plugin=self.name,
                        severity="medium",
                        title="TLS certificate expired",
                        detail=f"certificate expired {expiry.isoformat()}",
                    )
                )
        else:
            findings.append(
                Finding(
                    plugin=self.name,
                    severity="low",
                    title="TLS server sent no certificate",
                    detail="Cannot validate certificate identity.",
                )
            )
        return findings
