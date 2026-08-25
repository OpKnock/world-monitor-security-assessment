import time
from dataclasses import dataclass, field

from .plugins import default_plugins

DEFAULT_CONFIG = {
    "timeout": 5.0,
    "ports": [22, 80, 443, 3306, 5432, 8080, 8443],
    "port_timeout": 0.3,
    "tls_timeout": 1.0,
    "tls_probe": None,
}


@dataclass
class ScanResult:
    target: object
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def by_plugin(self):
        grouped = {}
        for finding in self.findings:
            grouped.setdefault(finding.plugin, []).append(finding)
        return grouped

    def to_dict(self):
        return {
            "target": {
                "name": self.target.name,
                "host": self.target.host,
                "port": self.target.port,
                "scheme": self.target.scheme,
            },
            "elapsed": round(self.elapsed, 3),
            "errors": list(self.errors),
            "findings": [f.to_dict() for f in self.findings],
        }


class ScanEngine:
    def __init__(self, plugins=None, config=None):
        self.plugins = list(plugins if plugins is not None else default_plugins())
        self.config = dict(DEFAULT_CONFIG)
        if config:
            self.config.update(config)

    def scan(self, target):
        started = time.monotonic()
        ctx = {"fetched": {}, **self.config}
        result = ScanResult(target=target)
        for plugin in self.plugins:
            try:
                findings = plugin.scan(target, ctx)
                result.findings.extend(findings or [])
            except Exception as exc:
                result.errors.append(f"{plugin.name}: {exc}")
        result.elapsed = time.monotonic() - started
        return result

    def scan_all(self, targets):
        return [self.scan(target) for target in targets]
