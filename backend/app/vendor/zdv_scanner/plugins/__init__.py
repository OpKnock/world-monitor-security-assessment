from dataclasses import dataclass, field

from ..patterns import DEFAULT_CREDENTIAL_PATTERNS, SECURITY_HEADERS, check_banner_advisories
from ..netutil import http_get
from ..target import Target


@dataclass
class Finding:
    plugin: str
    severity: str
    title: str
    detail: str = ""
    score: float = 0.0
    evidence: str = ""

    def to_dict(self):
        return {
            "plugin": self.plugin,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "score": self.score,
            "evidence": self.evidence,
        }


class Plugin:
    name = "base"

    def scan(self, target, ctx):
        raise NotImplementedError

    @property
    def description(self):
        return self.__doc__ or ""


def default_plugins():
    from .banners import BannerPlugin
    from .credentials import DefaultCredentialPlugin
    from .headers import HeaderPlugin
    from .ports import OpenPortPlugin
    from .tls import TLSConfigPlugin

    return [
        HeaderPlugin(),
        TLSConfigPlugin(),
        OpenPortPlugin(),
        DefaultCredentialPlugin(),
        BannerPlugin(),
    ]
