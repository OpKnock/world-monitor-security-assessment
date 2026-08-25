"""Scanner contract (spec §11) and registry.

scan(context) -> ScanResult for every scanner; adapters translate third-party
outputs into RawFinding objects. Nothing here ever runs without a prior
authorization-gate pass performed by the orchestration engine.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .evidence import EvidenceStore
    from .findings import RawFinding


@dataclass
class ScanContext:
    target: str                    # authorized http(s) URL
    source_path: str = ""          # authorized filesystem scope (lab tree)
    auth_token: str | None = None  # lab test-account token, never a real secret
    options: dict = field(default_factory=dict)
    evidence: "EvidenceStore | None" = None

    def require_evidence(self) -> "EvidenceStore":
        assert self.evidence is not None, "EvidenceStore must be provided"
        return self.evidence


@dataclass
class ScanResult:
    scanner: str
    status: str = "completed"      # completed|failed|skipped
    findings: list["RawFinding"] = field(default_factory=list)
    duration_s: float = 0.0
    errors: list[str] = field(default_factory=list)
    checks_total: int = 0
    checks_safe: int = 0
    notes: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)           # checks executed that found no issue


class ScannerModule(ABC):
    name: str = "base"
    category: str = "API_SECURITY"

    @abstractmethod
    def run(self, ctx: ScanContext) -> ScanResult: ...


REGISTRY: dict[str, list[ScannerModule]] = {}


def register(module_key: str, scanner: ScannerModule) -> None:
    REGISTRY.setdefault(module_key, []).append(scanner)


def scanners_for(modules: list[str]) -> list[ScannerModule]:
    out: list[ScannerModule] = []
    for key in modules:
        out.extend(REGISTRY.get(key, []))
    return out


AVAILABLE_MODULES: dict[str, dict] = {
    "authentication": {"label": "Authentication", "needs": "http_target"},
    "authorization": {"label": "Authorization / IDOR", "needs": "http_target"},
    "api": {"label": "API Security", "needs": "http_target"},
    "input_validation": {"label": "Input Validation", "needs": "http_target"},
    "headers": {"label": "Client Security Headers", "needs": "http_target"},
    "tls": {"label": "TLS / Secure Communication", "needs": "http_target"},
    "secrets": {"label": "Secrets Exposure", "needs": "source_path"},
    "dependencies": {"label": "Dependencies / SBOM", "needs": "source_path"},
    "supply_chain": {"label": "Supply Chain Hygiene", "needs": "source_path"},
    "graphql": {"label": "GraphQL Security", "needs": "http_target"},
    "deep_scan": {"label": "Network Surface and Banners", "needs": "http_target"},
    "fuzzing": {"label": "Mutation Fuzzing", "needs": "http_target"},
}
