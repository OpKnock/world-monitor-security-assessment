import random
import socket
from dataclasses import dataclass, field

from .netutil import http_get
from .target import NonLocalhostTargetError

INTERESTING_VALUES = [
    "0", "1", "-1", "4294967295", "2147483647", "%00", "%0d%0a", "..%2f",
    "../", "{{7*7}}", "<script>alert(1)</script>", "' OR '1'='1", "${jndi:ldap://x}",
]


@dataclass
class FuzzFinding:
    plugin: str = "fuzzer"
    severity: str = "medium"
    title: str = ""
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


@dataclass
class FuzzResult:
    target: object
    requests: int = 0
    anomalies: list = field(default_factory=list)

    def to_dict(self):
        return {
            "target": {"name": self.target.name, "host": self.target.host, "port": self.target.port},
            "requests": self.requests,
            "anomalies": [a.to_dict() for a in self.anomalies],
        }


def mutate_path(seed_path, rng, interesting):
    if not interesting:
        interesting = INTERESTING_VALUES
    path = seed_path
    operation = rng.randrange(3)
    if operation == 0:
        index = rng.randrange(1, len(path) + 1)
        path = path[:index] + rng.choice(interesting) + path[index:]
    elif operation == 1 and path:
        index = rng.randrange(len(path))
        replacement = rng.choice(interesting)
        path = path[:index] + replacement
    else:
        path = path + rng.choice(interesting)
    return path


def generate_mutated_paths(seed_path="/", count=20, seed=1):
    rng = random.Random(seed)
    paths = []
    for _ in range(count):
        path = mutate_path(seed_path, rng, INTERESTING_VALUES)
        if not path.startswith("/"):
            path = "/" + path
        paths.append(path)
    return paths


class Fuzzer:
    """Sends mutated requests to localhost test servers only."""

    def __init__(self, timeout=5.0):
        self.timeout = timeout

    def fuzz(self, target, corpus, iterations=20, seed=1):
        target.require_localhost()
        rng = random.Random(seed)
        result = FuzzResult(target=target)
        paths = []
        for entry in corpus:
            seed = entry if entry.startswith("/") else "/" + entry
            paths.append(seed)
            paths.extend(generate_mutated_paths(seed, max(1, iterations // len(corpus)), seed=rng.randrange(2**32)))
        for path in paths[:iterations]:
            if not path.startswith("/"):
                path = "/" + path
            response = http_get(target, path=path, timeout=self.timeout)
            result.requests += 1
            if response is None:
                result.anomalies.append(
                    FuzzFinding(
                        title="connection failure during fuzzing",
                        detail="the server dropped or reset the connection while processing the mutated request",
                        evidence=path,
                    )
                )
            elif response["status"] >= 500:
                result.anomalies.append(
                    FuzzFinding(
                        severity="high",
                        title=f"server error status {response['status']}",
                        detail="the server returned a 5xx error for a mutated input - possible unhandled exception",
                        evidence=path,
                    )
                )
        return result
