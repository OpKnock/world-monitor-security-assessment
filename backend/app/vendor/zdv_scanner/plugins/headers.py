import re

from . import Finding, Plugin
from ..netutil import http_get
from ..patterns import SECURITY_HEADERS


class HeaderPlugin(Plugin):
    """Checks for missing HTTP security headers."""

    name = "headers"

    def scan(self, target, ctx):
        fetched = ctx.get("fetched", {})
        if "root" not in fetched:
            fetched["root"] = http_get(target, timeout=ctx["timeout"])
        response = fetched["root"]
        if response is None:
            return []
        findings = []
        headers = {key.lower(): value for key, value in response["headers"].items()}
        for header, required_value in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(
                    Finding(
                        plugin=self.name,
                        severity="medium",
                        title=f"missing security header: {header}",
                        detail="The response does not include the recommended HTTP security header.",
                    )
                )
            elif required_value and headers[header].strip().lower() != required_value:
                findings.append(
                    Finding(
                        plugin=self.name,
                        severity="low",
                        title=f"weak security header value: {header}",
                        detail=f"expected {required_value!r}, got {headers[header]!r}",
                    )
                )
        if "strict-transport-security" not in headers and target.scheme == "https":
            findings.append(
                Finding(
                    plugin=self.name,
                    severity="high",
                    title="missing HSTS on HTTPS service",
                    detail="TLS without HSTS allows protocol-downgrade attacks.",
                )
            )
        return findings
