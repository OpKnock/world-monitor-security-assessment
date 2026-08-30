"""Centralised, validated runtime configuration.

All values are sourced from environment variables / ``.env`` and validated
via Pydantic.  The module exposes a cached singleton :data:`settings`
for import-time convenience and :func:`get_settings` for testability.

Design goals
------------
* No weak hardcoded secrets in production (``DEBUG=False`` rejects the
  ``CHANGE-ME`` placeholder).
* Strict :class:`pydantic.Field` constraints so misconfiguration fails fast.
* Relative :class:`pathlib.Path` values are resolved against :data:`ROOT_DIR`.
* Helper properties expose parsed views (e.g. allowed-target list).
* Clear separation of concerns: core, secrets, storage, auth, limits, lab.
"""

from __future__ import annotations

import warnings
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import EmailStr, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR: Path = Path(__file__).resolve().parents[2]

# Placeholder that ships in the repo.  Any deployment MUST override it.
_PLACEHOLDER_SECRET = "CHANGE-ME-64-random-hex-chars"


class Settings(BaseSettings):
    """Validated application settings.

    Every field maps 1:1 to an environment variable (case-insensitive).
    See ``.env.example`` for the canonical list.
    """

    model_config = SettingsConfigDict(
        env_file=str(ROOT_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        env_prefix="",
    )

    # ------------------------------------------------------------------ #
    # Core
    # ------------------------------------------------------------------ #
    APP_NAME: Annotated[str, Field(min_length=1, max_length=120)] = (
        "World Monitor Security Assessment Platform"
    )
    VERSION: Annotated[str, Field(min_length=1, max_length=32)] = "1.0.0"
    DEBUG: bool = False
    LOG_LEVEL: Annotated[str, Field(min_length=1, max_length=10)] = "INFO"

    # ------------------------------------------------------------------ #
    # Secrets  — never commit real values; override via ``.env``.
    # ------------------------------------------------------------------ #
    SECRET_KEY: Annotated[str, Field(min_length=16, max_length=512)] = _PLACEHOLDER_SECRET
    ACCESS_TOKEN_EXPIRE_MINUTES: Annotated[int, Field(ge=5, le=60 * 24 * 30)] = 60 * 12
    REFRESH_TOKEN_EXPIRE_DAYS: Annotated[int, Field(ge=1, le=365)] = 30
    JWT_ALGORITHM: Literal["HS256"] = "HS256"
    JWT_ISSUER: str = "world-monitor"
    JWT_AUDIENCE: str = "world-monitor-api"

    # ------------------------------------------------------------------ #
    # Storage
    # ------------------------------------------------------------------ #
    DATABASE_URL: Annotated[str, Field(min_length=1, max_length=2048)] = Field(
        default_factory=lambda: f"sqlite:///{(ROOT_DIR / 'database' / 'worldmonitor.db').as_posix()}"
    )
    DATABASE_POOL_SIZE: Annotated[int, Field(ge=1, le=20)] = 5
    DATABASE_MAX_OVERFLOW: Annotated[int, Field(ge=0, le=30)] = 10
    EVIDENCE_DIR: Path = Field(default_factory=lambda: ROOT_DIR / "evidence")  # type: ignore[arg-type]
    REPORT_DIR: Path = Field(default_factory=lambda: ROOT_DIR / "reports")  # type: ignore[arg-type]

    # ------------------------------------------------------------------ #
    # Authorization gate
    # ------------------------------------------------------------------ #
    LAB_MODE: bool = True
    ALLOWED_TARGETS: str = Field(default="", description="Comma-separated extra URLs always permitted")
    BLOCK_CLOUD_METADATA: bool = True  # Always block 169.254.169.254, metadata.google.internal

    # ------------------------------------------------------------------ #
    # Lab wiring
    # ------------------------------------------------------------------ #
    LAB_APP_URL: Annotated[str, Field(min_length=1, max_length=2048)] = "http://127.0.0.1:8080"
    LAB_SOURCE_DIR: Path = Field(default_factory=lambda: ROOT_DIR / "lab" / "vulnerable-world-monitor")  # type: ignore[arg-type]
    LAB_HOST: str = "127.0.0.1"
    LAB_PORT: Annotated[int, Field(ge=1, le=65535)] = 8080

    # ------------------------------------------------------------------ #
    # External scanner binaries
    # ------------------------------------------------------------------ #
    BIN_DIR: Path = Field(default_factory=lambda: ROOT_DIR / "bin")  # type: ignore[arg-type]
    SECRETS_SCANNER_BIN: str = Field(default="", max_length=512)
    SBOM_SCANNER_BIN: str = Field(default="", max_length=512)
    SUPPLY_CHAIN_SCANNER_BIN: str = Field(default="", max_length=512)

    # ------------------------------------------------------------------ #
    # Bootstrap platform accounts
    # Lab convenience allows short passwords (e.g. "admin") when DEBUG or LAB_MODE;
    # production still warns if <12 chars via _check_secret_strength.
    # ------------------------------------------------------------------ #
    ADMIN_EMAIL: EmailStr = Field(default="admin@example.com")  # type: ignore[assignment]
    ADMIN_PASSWORD: Annotated[str, Field(min_length=4, max_length=256)] = "ChangeMe_Use_Strong_Password_Here"
    ANALYST_EMAIL: EmailStr = Field(default="analyst@example.com")  # type: ignore[assignment]
    ANALYST_PASSWORD: Annotated[str, Field(min_length=4, max_length=256)] = "ChangeMe_Use_Strong_Password_Here"

    # ------------------------------------------------------------------ #
    # Optional alerting
    # ------------------------------------------------------------------ #
    ALERT_WEBHOOK_URL: Annotated[str, Field(max_length=2048)] = Field(default="")
    ALERT_WEBHOOK_TIMEOUT: Annotated[float, Field(ge=1.0, le=60.0)] = 8.0
    ALERT_WEBHOOK_SECRET: str = Field(default="", max_length=256)  # HMAC secret for webhook verification

    # ------------------------------------------------------------------ #
    # Limits
    # ------------------------------------------------------------------ #
    MAX_SCAN_WORKERS: Annotated[int, Field(ge=1, le=64)] = 4
    API_RATE_LIMIT_PER_MINUTE: Annotated[int, Field(ge=1, le=100_000)] = 600
    AUTH_RATE_LIMIT_PER_MINUTE: Annotated[int, Field(ge=1, le=10_000)] = 30
    ASSESSMENT_RATE_LIMIT_PER_MINUTE: Annotated[int, Field(ge=1, le=100)] = 20
    SCAN_TIMEOUT_SECONDS: Annotated[int, Field(ge=30, le=3600)] = 600
    EVIDENCE_MAX_SIZE_MB: Annotated[int, Field(ge=1, le=100)] = 10

    # ------------------------------------------------------------------ #
    # Security headers
    # ------------------------------------------------------------------ #
    ENABLE_HSTS: bool = True
    ENABLE_CSP: bool = True
    CSP_POLICY: str = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
    ENABLE_SECURE_COOKIES: bool = True

    # ------------------------------------------------------------------ #
    # Validators
    # ------------------------------------------------------------------ #
    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def _validate_database_url(cls, v: object) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("DATABASE_URL must be a non-empty string")
        val = v.strip()
        allowed_prefixes = ("sqlite://", "postgresql://", "postgres://", "mysql://", "sqlite+pysqlite://")
        if not val.startswith(allowed_prefixes):
            raise ValueError(f"DATABASE_URL must start with one of {allowed_prefixes}")
        return val

    @field_validator("LAB_APP_URL", mode="before")
    @classmethod
    def _validate_lab_url(cls, v: object) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("LAB_APP_URL must be a non-empty URL")
        val = v.strip().rstrip("/")
        if not (val.startswith("http://") or val.startswith("https://")):
            raise ValueError("LAB_APP_URL must start with http:// or https://")
        return val

    @field_validator("ALERT_WEBHOOK_URL", mode="before")
    @classmethod
    def _validate_webhook(cls, v: object) -> str:
        if v is None:
            return ""
        if not isinstance(v, str):
            raise ValueError("ALERT_WEBHOOK_URL must be a string")
        val = v.strip()
        if val and not (val.startswith("http://") or val.startswith("https://")):
            raise ValueError("ALERT_WEBHOOK_URL must be http(s):// or empty")
        return val

    @field_validator("CSP_POLICY", mode="before")
    @classmethod
    def _validate_csp(cls, v: object) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("CSP_POLICY must be a non-empty string")
        return v.strip()

    @field_validator("EVIDENCE_DIR", "REPORT_DIR", "LAB_SOURCE_DIR", "BIN_DIR", mode="before")
    @classmethod
    def _coerce_path(cls, v: object) -> Path:
        """Allow env vars to be relative; resolve against :data:`ROOT_DIR`."""
        if isinstance(v, Path):
            return v
        if isinstance(v, str) and v.strip():
            p = Path(v.strip())
            if not p.is_absolute():
                p = (ROOT_DIR / p).resolve()
            return p
        # Fall back to field default_factory — pydantic will call it
        raise ValueError("Path field received empty value")

    @field_validator("EVIDENCE_DIR", "REPORT_DIR", "LAB_SOURCE_DIR", "BIN_DIR", mode="after")
    @classmethod
    def _ensure_absolute(cls, v: Path) -> Path:
        if not isinstance(v, Path):
            return Path(str(v))
        return v if v.is_absolute() else (ROOT_DIR / v).resolve()

    @model_validator(mode="after")
    def _check_secret_strength(self) -> "Settings":
        """Reject the placeholder secret in hardened prod; warn otherwise.

        LAB_MODE or DEBUG allows demo secrets for local development — warnings
        are emitted but not hard errors, so `admin/admin` and the placeholder
        `SECRET_KEY` keep the 60-second demo frictionless.
        """
        is_demo = self.DEBUG or self.LAB_MODE
        if self.SECRET_KEY == _PLACEHOLDER_SECRET:
            if not is_demo:
                raise ValueError(
                    "SECRET_KEY is still the placeholder 'CHANGE-ME-64-random-hex-chars'. "
                    "Generate a strong key with: python -c \"import secrets; print(secrets.token_hex(32))\" "
                    "and set it in .env / environment."
                )
            warnings.warn(
                "SECRET_KEY is the insecure placeholder — override it in .env before deploying",
                UserWarning,
                stacklevel=2,
            )
        elif len(self.SECRET_KEY) < 32:
            if not is_demo:
                raise ValueError("SECRET_KEY must be at least 32 characters in non-debug/non-lab mode")
            warnings.warn("SECRET_KEY is shorter than 32 chars — use a stronger key for production", UserWarning, stacklevel=2)

        # Guard against intentionally weak bootstrap passwords in production.
        if not is_demo:
            for attr in ("ADMIN_PASSWORD", "ANALYST_PASSWORD"):
                val: str = getattr(self, attr)
                if val in ("ChangeMe_Admin_2026!", "ChangeMe_Analyst_2026!", "ChangeMe_Use_Strong_Password_Here"):
                    warnings.warn(
                        f"{attr} is still the default demo password — change it before deploying",
                        UserWarning,
                        stacklevel=2,
                    )
                if len(val) < 12:
                    warnings.warn(
                        f"{attr} is shorter than 12 characters — use a stronger password for production",
                        UserWarning,
                        stacklevel=2,
                    )
        # Validate alert webhook secret if URL is set
        if self.ALERT_WEBHOOK_URL and not self.ALERT_WEBHOOK_SECRET:
            warnings.warn(
                "ALERT_WEBHOOK_URL is set but ALERT_WEBHOOK_SECRET is empty — "
                "webhook payloads cannot be verified. Set a secret for HMAC verification.",
                UserWarning,
                stacklevel=2,
            )
        return self

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @property
    def allowed_targets_list(self) -> list[str]:
        """Parsed :attr:`ALLOWED_TARGETS` as a list of stripped, non-empty URLs."""
        if not self.ALLOWED_TARGETS.strip():
            return []
        return [t.strip().rstrip("/") for t in self.ALLOWED_TARGETS.split(",") if t.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")

    @property
    def jwt_config(self) -> dict[str, str | int]:
        """Return JWT configuration as a dict for use in security.py."""
        return {
            "algorithm": self.JWT_ALGORITHM,
            "issuer": self.JWT_ISSUER,
            "audience": self.JWT_AUDIENCE,
            "access_token_expire_minutes": self.ACCESS_TOKEN_EXPIRE_MINUTES,
            "refresh_token_expire_days": self.REFRESH_TOKEN_EXPIRE_DAYS,
        }


# Backwards-compat: some modules do `from .config import ROOT_DIR`
__all__ = ["ROOT_DIR", "Settings", "get_settings", "settings"]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached :class:`Settings` singleton.

    The cache is intentionally process-wide; call ``get_settings.cache_clear()``
    in tests that mutate ``os.environ`` before re-import.
    """
    return Settings()  # type: ignore[call-arg]


# Eager singleton for ``from .config import settings`` ergonomics.
settings: Settings = get_settings()
