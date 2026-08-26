"""Scanner contract (spec §11) and registry.

Every scanner implements ``ScannerModule.run(ctx) -> ScanResult``.
Adapters translate third-party outputs into :class:`RawFinding` objects.
Nothing here runs without a prior authorization-gate pass performed by
the orchestration engine — scanners themselves never widen the allowed
scope, they only probe the *already-authorized* target/path.

Design goals
------------
* **Zero surprise** — callers always get a ``ScanResult``; exceptions
  never leak across the orchestration boundary.
* **Evidence is mandatory** — :meth:`ScanContext.require_evidence` fails
  loud if forgotten, so findings are never orphaned.
* **Thread-safe registry** — ``register`` / ``scanners_for`` are guarded
  by a lock so ``load_registry`` is safe under the orchestration engine's
  thread-per-assessment model.
* **Stable module keys** — ``AVAILABLE_MODULES`` is the single source of
  truth for the ``/api/scanners`` endpoint and for orchestration
  validation.  Keys are never renamed.

Scan target discipline
----------------------
Every :class:`RawFinding` produced by a scanner **must** set
``scan_target`` to the exact URL/path that was probed.  The finding
engine fingerprints on ``(target, category, check_id, component)`` so a
missing ``scan_target`` silently breaks de-duplication and retest.
All adapters in this package enforce it at construction time.
"""
from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from ..engine.evidence import EvidenceStore
    from ..engine.findings import RawFinding

__all__ = [
    "ScanContext",
    "ScanResult",
    "ScannerModule",
    "REGISTRY",
    "AVAILABLE_MODULES",
    "register",
    "scanners_for",
]

# ---------------------------------------------------------------------------
# ScanContext / ScanResult
# ---------------------------------------------------------------------------

ScanStatus = Literal["completed", "failed", "skipped"]


@dataclass
class ScanContext:
    """Inputs for a single scanner invocation.

    Attributes:
        target:      Authorized http(s) URL — already validated by the
                     authorization gate.  Scanners must not modify it except
                     to append probe-specific paths/query params.
        source_path: Authorized filesystem scope for source-code scanners
                     (lab tree).  Empty for pure HTTP scanners.
        auth_token:  Lab demo-account bearer token (``alice:user123`` JWT).
                     Never a real secret; may be ``None`` for unauthenticated
                     probes.
        options:     Caller-supplied overrides (timeout, etc.).
        evidence:    Per-assessment :class:`EvidenceStore`.  Must be present
                     before any finding is emitted.
    """

    target: str  # authorized http(s) URL
    source_path: str = ""  # authorized filesystem scope (lab tree)
    auth_token: str | None = None  # lab test-account token, never a real secret
    options: dict = field(default_factory=dict)
    evidence: "EvidenceStore | None" = None

    def require_evidence(self) -> "EvidenceStore":
        """Return the evidence store or raise — findings must never be orphaned."""
        assert self.evidence is not None, "EvidenceStore must be provided via ScanContext(evidence=...)"
        return self.evidence

    @property
    def has_http_target(self) -> bool:
        return bool(self.target and self.target.strip())

    @property
    def has_source_path(self) -> bool:
        return bool(self.source_path and self.source_path.strip())

    def effective_timeout(self, default: float = 10.0) -> float:
        """Timeout override from ``options['timeout']`` or *default*."""
        try:
            return float(self.options.get("timeout", default))
        except (TypeError, ValueError):
            return default


@dataclass
class ScanResult:
    """Normalized result returned by every scanner.

    The orchestration engine aggregates these into ``ScanRun`` rows and
    persists findings.  ``status`` drives the ``ScanRun.status`` column:

    * ``completed`` — scanner finished (may have 0 findings).
    * ``failed``    — unrecoverable error; ``errors`` explains why.
    * ``skipped``   — scanner not applicable (e.g. binary missing,
      ``WM_ENABLE_FUZZING`` unset, no GraphQL surface).

    ``checks_total`` / ``checks_safe`` feed dashboard coverage metrics.
    ``meta`` is free-form per-scanner diagnostics.
    """

    scanner: str
    status: ScanStatus = "completed"  # completed|failed|skipped
    findings: list["RawFinding"] = field(default_factory=list)
    duration_s: float = 0.0
    errors: list[str] = field(default_factory=list)
    checks_total: int = 0
    checks_safe: int = 0
    notes: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def is_success(self) -> bool:
        return self.status == "completed"

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


# ---------------------------------------------------------------------------
# ScannerModule ABC
# ---------------------------------------------------------------------------


class ScannerModule(ABC):
    """Interface every scanner must implement.

    Subclasses declare ``name`` (stable, used as ``RawFinding.scanner`` and
    as the ``ScanRun.scanner`` key for per-instance target overrides) and
    ``category`` (finding taxonomy).  ``run`` must be pure with respect to
    the supplied :class:`ScanContext` — no global state, no direct DB access.
    """

    name: str = "base"
    category: str = "API_SECURITY"
    # Optional human-readable description for /api/scanners metadata.
    description: str = ""

    @abstractmethod
    def run(self, ctx: ScanContext) -> ScanResult:
        """Execute the probe and return a normalized result."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

REGISTRY: dict[str, list[ScannerModule]] = {}
_REGISTRY_LOCK = threading.Lock()
# Guard for idempotent load_registry() — also protects concurrent first-load
# under the orchestration engine's thread-per-assessment model.
_REGISTRY_LOADED = False


def register(module_key: str, scanner: ScannerModule) -> None:
    """Register *scanner* under *module_key*.

    Duplicate registrations of the same object are ignored so that
    ``load_registry`` can be called idempotently without growing the list.
    """
    with _REGISTRY_LOCK:
        bucket = REGISTRY.setdefault(module_key, [])
        # Identity check prevents double-registration on repeated load_registry()
        if scanner not in bucket and not any(s.name == scanner.name and type(s) is type(scanner) for s in bucket):
            bucket.append(scanner)


def scanners_for(modules: list[str]) -> list[ScannerModule]:
    """Return scanner instances for *modules* in request order.

    Unknown keys are silently ignored — callers (orchestration) validate
    membership upstream and have already turned unknowns into a 403.
    A shallow copy is returned so callers cannot mutate the global registry.
    """
    out: list[ScannerModule] = []
    with _REGISTRY_LOCK:
        for key in modules:
            out.extend(list(REGISTRY.get(key, [])))
    return out


def _reset_registry_for_tests() -> None:  # pragma: no cover — test helper
    """Clear the global registry.  Only used by unit tests that need isolation."""
    global _REGISTRY_LOADED
    with _REGISTRY_LOCK:
        REGISTRY.clear()
        _REGISTRY_LOADED = False


# ---------------------------------------------------------------------------
# Module catalogue — must stay stable (keys are API-contract).
# ---------------------------------------------------------------------------

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
