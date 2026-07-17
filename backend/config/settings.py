"""
TrustGuard v2.0 — Configuration Management
All hardcoded values are centralised here via Pydantic BaseSettings.
Source: environment variables or .env file.

Standards: OWASP ASVS 2.10, NIST SSDF
"""

from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ───────────────────────────────────────────────────────
    app_name: str = "TrustGuard AI Security Gateway"
    app_version: str = "2.0.0"
    debug: bool = False
    environment: str = "production"  # development | staging | production

    @field_validator("debug", mode="before")
    @classmethod
    def parse_debug(cls, v) -> bool:
        if isinstance(v, bool):
            return v
        return str(v).lower() in ("true", "1", "yes")

    # ── Database ──────────────────────────────────────────────────────────
    database_url: str = "sqlite:///./storage/database/aisec.db"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_echo: bool = False

    # ── JWT ───────────────────────────────────────────────────────────────
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    jwt_access_expire_minutes: int = 60
    jwt_refresh_expire_days: int = 7

    # ── ML Engine ─────────────────────────────────────────────────────────
    injection_model: str = "deepset/deberta-v3-base-injection"
    toxic_model: str = "martin-ha/toxic-comment-model"
    injection_threshold: float = 0.75
    toxic_threshold: float = 0.80
    ml_max_length: int = 512

    # ── Scan Limits ───────────────────────────────────────────────────────
    max_repo_size_mb: int = 200
    max_files: int = 500
    scan_timeout_seconds: int = 60
    max_upload_mb: int = 200
    max_prompt_length: int = 10_000
    max_code_length: int = 500_000
    small_repo_threshold_mb: int = 10  # sync vs background

    # ── Rate Limiting ─────────────────────────────────────────────────────
    shield_rate_limit_per_minute: int = 100
    auth_rate_limit_per_minute: int = 60
    scan_rate_limit_per_minute: int = 20

    # ── CORS ──────────────────────────────────────────────────────────────
    cors_origins: List[str] = ["http://localhost:8000"]
    cors_allow_credentials: bool = True

    # ── Storage ───────────────────────────────────────────────────────────
    reports_dir: str = "storage/reports"
    uploads_dir: str = "storage/uploads"
    temp_dir: str = "storage/temp"
    logs_dir: str = "storage/logs"
    database_dir: str = "storage/database"

    # ── Security ──────────────────────────────────────────────────────────
    max_request_body_mb: int = 10
    allowed_upload_extensions: List[str] = [".zip"]
    bcrypt_rounds: int = 12

    # ── Logging ───────────────────────────────────────────────────────────
    log_level: str = "INFO"
    log_format: str = "json"  # json | text

    # ── Cache TTL (seconds) ───────────────────────────────────────────────
    cache_rules_ttl: int = 3600       # OWASP rules — 1 jam
    cache_compliance_ttl: int = 300   # compliance score — 5 minit
    cache_shield_ttl: int = 60        # shield result — 1 minit

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"environment mesti salah satu daripada: {allowed}")
        return v

    @field_validator("jwt_secret")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("jwt_secret mesti sekurang-kurangnya 32 aksara")
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached Settings instance. Call once per process."""
    return Settings()
