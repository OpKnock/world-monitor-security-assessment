"""Configuration shim for the vendored api-security-scanner modules.

The upstream scanners read tuning knobs from a pydantic-settings object
(`from config import settings`) that required DATABASE_URL / SECRET_KEY to
exist. World Monitor vendors only the scanner layer, so this shim provides
the same attribute surface with safe defaults and no environment coupling.

Values mirror upstream backend/config.py defaults.
"""
from types import SimpleNamespace

settings = SimpleNamespace(
    APP_NAME="World Monitor Security Assessment Platform",
    VERSION="1.0.0",
    # Scanner behaviour
    DEFAULT_MAX_REQUESTS=600,
    DEFAULT_TIMEOUT_SECONDS=10,
    DEFAULT_RETRY_COUNT=1,
    DEFAULT_RETRY_WAIT_SECONDS=60,
    DEFAULT_BASELINE_SAMPLES=10,
    DEFAULT_JITTER_MS=100,
    SCANNER_RATE_LIMIT_THRESHOLD=100,
    SCANNER_RATE_LIMIT_WINDOW_SECONDS=60,
    SCANNER_MAX_CONCURRENT_REQUESTS=50,
    SCANNER_CONNECTION_TIMEOUT=45,
    SCANNER_READ_TIMEOUT=180,
)
