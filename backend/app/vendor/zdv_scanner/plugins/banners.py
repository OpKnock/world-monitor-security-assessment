from . import Finding, Plugin
from ..advisories import match_advisory
from ..netutil import http_get
from ..patterns import parse_banner


class BannerPlugin(Plugin):
    """Matches software banners against the built-in advisory database."""

    name = "banners"

    def scan(self, target, ctx):
        fetched = ctx.setdefault("fetched", {})
        if "root" not in fetched:
            fetched["root"] = http_get(target, timeout=ctx["timeout"])
        response = fetched["root"]
        if response is None:
            return []
        banners = []
        server = response["headers"].get("Server")
        if server:
            banners.append(server)
        for header_name, header_value in response["headers"].items():
            if header_name.lower() in ("x-powered-by", "x-generator", "via"):
                banners.append(header_value)
        body_head = response["body"][:2048].decode("utf-8", errors="replace")
        for marker in ("<meta name=\"generator\"", "<!-- Server", "Powered by"):
            index = body_head.lower().find(marker.lower())
            if index >= 0:
                banners.append(body_head[index : index + 160])

        findings = []
        for banner in banners:
            parsed = parse_banner(banner)
            if parsed is None:
                continue
            product, version = parsed
            matched = match_advisory(product, version)
            for advisory in matched:
                findings.append(
                    Finding(
                        plugin=self.name,
                        severity=advisory.severity,
                        title=f"vulnerable software version: {product} {version}",
                        detail=f"{advisory.cve_id}: {advisory.description}",
                        score=advisory.cvss_score,
                        evidence=banner,
                    )
                )
        return findings
