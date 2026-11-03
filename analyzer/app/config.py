"""Runtime settings from env (NFR-4: secrets only via env / .env)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", "postgresql://scamsaathi:scamsaathi@postgres:5432/scamsaathi"))
    redis_url: str = field(default_factory=lambda: os.getenv("REDIS_URL", "redis://redis:6379/0"))
    sandbox_url: str = field(default_factory=lambda: os.getenv("SANDBOX_URL", "http://sandbox:9000"))
    bridge_health_url: str = field(default_factory=lambda: os.getenv("BRIDGE_HEALTH_URL", "http://wa-bridge:8080/api/health"))
    internal_token: str = field(default_factory=lambda: os.getenv("ANALYZER_TOKEN", ""))
    admin_token: str = field(default_factory=lambda: os.getenv("ADMIN_TOKEN", ""))
    sender_salt: str = field(default_factory=lambda: os.getenv("SENDER_SALT", "dev-salt"))
    media_dir: str = field(default_factory=lambda: os.getenv("MEDIA_DIR", "/media"))
    registry_dir: str = field(default_factory=lambda: os.getenv("REGISTRY_DIR", "/registry/seed"))
    migrations_dir: str = field(default_factory=lambda: os.getenv("MIGRATIONS_DIR", "/migrations"))
    gsb_api_key: str = field(default_factory=lambda: os.getenv("GSB_API_KEY", ""))
    vt_api_key: str = field(default_factory=lambda: os.getenv("VT_API_KEY", ""))
    urlhaus_auth_key: str = field(default_factory=lambda: os.getenv("URLHAUS_AUTH_KEY", ""))
    openphish_enabled: bool = field(default_factory=lambda: _bool("OPENPHISH_ENABLED", True))
    rdap_enabled: bool = field(default_factory=lambda: _bool("RDAP_ENABLED", True))
    crtsh_enabled: bool = field(default_factory=lambda: _bool("CRTSH_ENABLED", True))
    reputation_overlay: str = field(default_factory=lambda: os.getenv("REPUTATION_OVERLAY", ""))
    detonate_enabled: bool = field(default_factory=lambda: _bool("DETONATE_ENABLED", True))
    feed_timeout_s: float = field(default_factory=lambda: float(os.getenv("FEED_TIMEOUT_S", "5")))
    rate_limit_per_hour: int = field(default_factory=lambda: int(os.getenv("RATE_LIMIT_PER_HOUR", "20")))
    cache_ttl_hours: int = field(default_factory=lambda: int(os.getenv("CACHE_TTL_HOURS", "24")))
    raw_text_retention_days: int = field(default_factory=lambda: int(os.getenv("RAW_TEXT_RETENTION_DAYS", "7")))
    campaign_threshold: int = field(default_factory=lambda: int(os.getenv("CAMPAIGN_THRESHOLD", "5")))
    campaign_window_hours: int = field(default_factory=lambda: int(os.getenv("CAMPAIGN_WINDOW_HOURS", "6")))
    registry_include_unreviewed: bool = field(default_factory=lambda: _bool("REGISTRY_INCLUDE_UNREVIEWED", True))
    seed_on_start: bool = field(default_factory=lambda: _bool("SEED_ON_START", True))


settings = Settings()
