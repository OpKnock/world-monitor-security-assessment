import re

from . import Finding, Plugin
from ..netutil import http_get
from ..patterns import DEFAULT_CREDENTIAL_PATTERNS


class DefaultCredentialPlugin(Plugin):
    """Scans HTTP responses for default-credential patterns."""

    name = "credentials"

    def scan(self, target, ctx):
        fetched = ctx.setdefault("fetched", {})
        if "root" not in fetched:
            fetched["root"] = http_get(target, timeout=ctx["timeout"])
        response = fetched["root"]
        if response is None:
            return []
        body = response["body"].decode("utf-8", errors="replace")
        findings = []
        for pattern in DEFAULT_CREDENTIAL_PATTERNS:
            matches = list(re.finditer(pattern, body, re.IGNORECASE))
            if matches:
                evidence = matches[0].group(0)[:120]
                findings.append(
                    Finding(
                        plugin=self.name,
                        severity="high",
                        title="possible default credentials in response",
                        detail=f"response body matches default-credential pattern {pattern!r}",
                        evidence=evidence,
                    )
                )
        return findings
