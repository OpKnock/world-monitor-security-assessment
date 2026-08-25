import socket

from . import Finding, Plugin


class OpenPortPlugin(Plugin):
    """Checks which configured ports are open on the target."""

    name = "ports"

    def scan(self, target, ctx):
        findings = []
        ports = ctx.get("ports") or [22, 80, 443, 3306, 5432, 8080, 8443]
        timeout = ctx.get("port_timeout", 0.3)
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                try:
                    sock.connect((target.host, port))
                except OSError:
                    continue
            findings.append(
                Finding(
                    plugin=self.name,
                    severity="medium" if port not in (80, 443) else "low",
                    title=f"open port {port}",
                    detail=f"TCP port {port} accepts connections on {target.host}.",
                )
            )
        return findings
