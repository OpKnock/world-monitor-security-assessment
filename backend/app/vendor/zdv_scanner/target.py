from dataclasses import dataclass, field
from urllib.parse import urlparse

LOCALHOSTS = {"127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"}


class NonLocalhostTargetError(ValueError):
    pass


@dataclass
class Target:
    host: str = "127.0.0.1"
    port: int = 80
    scheme: str = "http"
    name: str = ""

    def __post_init__(self):
        if self.name == "":
            self.name = f"{self.host}:{self.port}"

    @property
    def base_url(self):
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def is_localhost(self):
        return self.host in LOCALHOSTS

    def require_localhost(self):
        if not self.is_localhost:
            raise NonLocalhostTargetError(
                f"refusing to target {self.host}: this scanner only runs against localhost targets"
            )

    @staticmethod
    def from_url(url):
        parsed = urlparse(url)
        scheme = parsed.scheme or "http"
        port = parsed.port or (443 if scheme == "https" else 80)
        return Target(host=parsed.hostname or "127.0.0.1", port=port, scheme=scheme, name=url)
