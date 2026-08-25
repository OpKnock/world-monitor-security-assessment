from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(ROOT_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "World Monitor Security Assessment Platform"
    VERSION: str = "1.0.0"
    DEBUG: bool = False

    # --- secrets (never hardcode; .env only) ---
    SECRET_KEY: str = "CHANGE-ME-in-.env-64-random-hex-chars"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12

    # --- storage ---
    DATABASE_URL: str = f"sqlite:///{(ROOT_DIR / 'database' / 'worldmonitor.db').as_posix()}"
    EVIDENCE_DIR: Path = ROOT_DIR / "evidence"
    REPORT_DIR: Path = ROOT_DIR / "reports"

    # --- authorization gate ---
    LAB_MODE: bool = True
    ALLOWED_TARGETS: str = ""  # comma-separated extra URLs always permitted

    # --- lab ---
    LAB_APP_URL: str = "http://127.0.0.1:8080"
    LAB_SOURCE_DIR: Path = ROOT_DIR / "lab" / "vulnerable-world-monitor"

    # --- external scanner binaries ---
    BIN_DIR: Path = ROOT_DIR / "bin"
    SECRETS_SCANNER_BIN: str = ""
    SBOM_SCANNER_BIN: str = ""

    # --- platform auth bootstrap ---
    ADMIN_EMAIL: str = "admin@example.com"
    ADMIN_PASSWORD: str = "ChangeMe_Admin_2026!"
    ANALYST_EMAIL: str = "analyst@example.com"
    ANALYST_PASSWORD: str = "ChangeMe_Analyst_2026!"

    # --- alerting (optional) ---
    ALERT_WEBHOOK_URL: str = ""  # e.g. Slack incoming webhook; CRITICAL/HIGH findings POST here

    # --- limits ---
    MAX_SCAN_WORKERS: int = 4
    API_RATE_LIMIT_PER_MINUTE: int = 600
    AUTH_RATE_LIMIT_PER_MINUTE: int = 30


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
