"""
Application configuration using Pydantic Settings.
All config is loaded from environment variables / .env file.
"""

from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──
    app_name: str = "vulnscan-orchestrator"
    app_env: str = "development"
    app_debug: bool = True
    app_version: str = "0.1.0"
    secret_key: str = "change-me-to-a-random-64-char-string"
    api_v1_prefix: str = "/api/v1"

    # ── Server ──
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # ── PostgreSQL ──
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "vulnscan"
    postgres_user: str = "vulnscan"
    postgres_password: str = "vulnscan_dev_password"
    database_url: str = (
        "postgresql+asyncpg://vulnscan:vulnscan_dev_password@localhost:5432/vulnscan"
    )

    # ── Redis ──
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str = ""
    redis_url: str = "redis://localhost:6379/0"

    # ── Celery ──
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # ── MinIO / S3 ──
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_bucket_reports: str = "reports"
    minio_bucket_artifacts: str = "scan-artifacts"
    minio_bucket_evidence: str = "evidence"
    minio_use_ssl: bool = False

    # ── JWT ──
    jwt_secret_key: str = "change-me-to-a-different-random-64-char-string"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60
    jwt_refresh_token_expire_minutes: int = 10080  # 7 days

    # ── CORS ──
    cors_origins: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8080",
    ]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            import json

            return json.loads(v)
        return v

    # ── Logging ──
    log_level: str = "INFO"
    log_format: str = "json"

    # ── Agent ──
    agent_heartbeat_interval_seconds: int = 30
    agent_heartbeat_timeout_seconds: int = 90
    lock_default_ttl_seconds: int = 7200  # 2 hours

    # ── Scheduler ──
    scheduler_poll_interval_seconds: int = 5
    scheduler_max_concurrent_jobs: int = 10

    # ── Report Retention ──
    report_retention_years: int = 3

    @property
    def sync_database_url(self) -> str:
        """Synchronous database URL for Alembic migrations."""
        return self.database_url.replace("postgresql+asyncpg", "postgresql+psycopg2")


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance."""
    return Settings()
