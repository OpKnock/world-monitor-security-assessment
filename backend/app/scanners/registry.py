"""Scanner registry wiring (spec §10)."""
from ..scanners.api_scan import ApiSecurityModule, AuthenticationModule, AuthorizationModule
from ..scanners.base import AVAILABLE_MODULES, REGISTRY, register, scanners_for  # noqa: F401
from ..scanners.deps_scan import DependenciesModule
from ..scanners.headers_scan import ClientSecurityHeadersModule
from ..scanners.input_validation_scan import ReflectedXssModule, SqliModule
from ..scanners.secrets_scan import SecretsModule
from ..scanners.supply_chain_scan import SupplyChainModule
from ..scanners.graphql_scan import GraphqlModule
from ..scanners.tls_scan import TlsModule
from ..scanners.zdv_scan import DeepScanModule, FuzzingModule


def load_registry() -> None:
    if not REGISTRY:
        register("authentication", AuthenticationModule())
        register("authorization", AuthorizationModule())
        register("api", ApiSecurityModule())
        register("input_validation", SqliModule())
        register("input_validation", ReflectedXssModule())
        register("headers", ClientSecurityHeadersModule())
        register("tls", TlsModule())
        register("secrets", SecretsModule())
        register("dependencies", DependenciesModule())
        register("supply_chain", SupplyChainModule())
        register("graphql", GraphqlModule())
        register("deep_scan", DeepScanModule())
        register("fuzzing", FuzzingModule())
