"""Scanner registry wiring (spec §10).

This module is the *only* place that knows the full scanner catalogue.
Importing it has no side-effects — :func:`load_registry` must be called
explicitly (orchestration does so on every assessment start).  The
function is idempotent and thread-safe, so repeated calls are cheap and
cannot double-register instances.

Module-to-scanner mapping mirrors ``AVAILABLE_MODULES`` in
``base.py``.  ``input_validation`` intentionally maps to **two**
instances (SQLi + reflected-XSS) — ``scanners_for(["input_validation"])``
therefore returns a list of length 2, each with a distinct ``name``.

Keep imports at top-level so that static analysers and ``/api/scanners``
can resolve the catalogue without triggering network or subprocess work.
"""
from __future__ import annotations

import logging
import threading

from ..scanners.api_scan import ApiSecurityModule, AuthenticationModule, AuthorizationModule
from ..scanners.base import AVAILABLE_MODULES, REGISTRY, register, scanners_for  # noqa: F401 — re-exported for callers
from ..scanners.deps_scan import DependenciesModule
from ..scanners.graphql_scan import GraphqlModule
from ..scanners.headers_scan import ClientSecurityHeadersModule
from ..scanners.input_validation_scan import ReflectedXssModule, SqliModule
from ..scanners.secrets_scan import SecretsModule
from ..scanners.supply_chain_scan import SupplyChainModule
from ..scanners.tls_scan import TlsModule
from ..scanners.zdv_scan import DeepScanModule, FuzzingModule

logger = logging.getLogger(__name__)

__all__ = ["load_registry", "AVAILABLE_MODULES", "REGISTRY", "scanners_for"]

_LOAD_LOCK = threading.Lock()
_LOADED = False

# Ordered catalogue — tuple order drives registration order (and therefore
# the order findings appear when ``scanners_for`` is called with multiple
# keys).  Keep this alphabetical within http_target / source_path groups
# for readability but preserve the historical registration order so that
# existing tests that assert on ``ScanRun`` order remain green.
_CATALOGUE: list[tuple[str, type]] = [
    ("authentication", AuthenticationModule),
    ("authorization", AuthorizationModule),
    ("api", ApiSecurityModule),
    ("input_validation", SqliModule),
    ("input_validation", ReflectedXssModule),
    ("headers", ClientSecurityHeadersModule),
    ("tls", TlsModule),
    ("secrets", SecretsModule),
    ("dependencies", DependenciesModule),
    ("supply_chain", SupplyChainModule),
    ("graphql", GraphqlModule),
    ("deep_scan", DeepScanModule),
    ("fuzzing", FuzzingModule),
]


def load_registry() -> None:
    """Populate :data:`REGISTRY` exactly once per process.

    Thread-safe and idempotent.  If the registry is already populated the
    function returns immediately.  Each entry in ``_CATALOGUE`` is
    instantiated exactly once.  A second call after a test-driven
    ``REGISTRY.clear()`` will repopulate correctly.
    """
    global _LOADED
    # Fast path without lock — matches original ``if not REGISTRY`` guard
    if _LOADED and REGISTRY:
        return
    with _LOAD_LOCK:
        if _LOADED and REGISTRY:
            return
        # If REGISTRY was cleared externally (tests) reset the flag
        if not REGISTRY:
            _LOADED = False
        if _LOADED:
            return
        for module_key, cls in _CATALOGUE:
            try:
                instance = cls()
            except Exception as exc:  # pragma: no cover — construction should never fail
                logger.exception("Failed to construct scanner %s for module %s: %s", cls.__name__, module_key, exc)
                continue
            register(module_key, instance)
        _LOADED = True
        logger.debug("Scanner registry loaded: %s", {k: [s.name for s in v] for k, v in REGISTRY.items()})


def reload_registry() -> None:  # pragma: no cover — test helper
    """Force a reload (clears then repopulates).  Useful for isolated tests."""
    global _LOADED
    with _LOAD_LOCK:
        REGISTRY.clear()
        _LOADED = False
    load_registry()
