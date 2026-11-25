"""Environment-backed runtime configuration for the webhook worker service."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw is not None and raw.strip() != "" else default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    return float(raw) if raw is not None and raw.strip() != "" else default


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable service settings loaded from environment variables."""

    webhook_secret: str = "local-dev-hmac-signing-key-change-in-production"
    db_path: Path = Path("./webhooks.db")
    timestamp_tolerance_seconds: int = 300
    max_body_bytes: int = 262_144
    max_attempts: int = 4
    poll_interval_seconds: float = 0.2
    lease_seconds: float = 30.0
    backoff_base_seconds: float = 1.0
    backoff_cap_seconds: float = 60.0
    handler_timeout_seconds: float = 10.0

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from process environment variables with safe defaults."""
        secret = os.getenv("WEBHOOK_SECRET", "").strip()
        if not secret:
            secret = cls.webhook_secret
        db_raw = os.getenv("WEBHOOK_DB_PATH", "./webhooks.db").strip() or "./webhooks.db"
        return cls(
            webhook_secret=secret,
            db_path=Path(db_raw),
            timestamp_tolerance_seconds=_env_int("WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS", 300),
            max_body_bytes=_env_int("WEBHOOK_MAX_BODY_BYTES", 262_144),
            max_attempts=_env_int("WEBHOOK_MAX_ATTEMPTS", 4),
            poll_interval_seconds=_env_float("WEBHOOK_POLL_INTERVAL_SECONDS", 0.2),
            lease_seconds=_env_float("WEBHOOK_LEASE_SECONDS", 30.0),
            backoff_base_seconds=_env_float("WEBHOOK_BACKOFF_BASE_SECONDS", 1.0),
            backoff_cap_seconds=_env_float("WEBHOOK_BACKOFF_CAP_SECONDS", 60.0),
            handler_timeout_seconds=_env_float("WEBHOOK_HANDLER_TIMEOUT_SECONDS", 10.0),
        )
