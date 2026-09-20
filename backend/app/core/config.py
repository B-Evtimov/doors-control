"""Configuration. Every value comes from the process environment.

There is no config file, no defaults directory and no secret with a fallback
value baked into the code. A missing secret is a startup failure, not a quiet
downgrade to something insecure.
"""

from __future__ import annotations

import base64
import functools
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ACS_",
        env_file=None,
        extra="ignore",
        frozen=True,
    )

    # ------------------------------------------------------------------ runtime
    env: Literal["production", "development", "test"] = "production"
    api_host: str = "0.0.0.0"  # noqa: S104 - the container is published to loopback
    api_port: int = 8080
    trusted_proxies: str = ""

    # ----------------------------------------------------------------- database
    db_dsn: str = "postgresql://acs_app@127.0.0.1/acs"
    audit_db_dsn: str = ""
    db_pool_min: int = 2
    db_pool_max: int = 10
    db_statement_timeout: int = 10

    # ------------------------------------------------------------------- tokens
    access_token_ttl: int = 900
    refresh_token_ttl: int = 2_592_000
    token_pepper: str = ""

    # ------------------------------------------------------------------ argon2
    argon2_time_cost: int = 3
    argon2_memory_kib: int = 65_536
    argon2_parallelism: int = 2

    # ---------------------------------------------------------- login hardening
    auth_fixed_response_ms: int = 350
    rate_window_seconds: int = 900
    rate_max_login_failures: int = 5
    rate_max_unlocks_per_minute: int = 6
    rate_base_delay_ms: int = 250
    rate_max_delay_ms: int = 8_000

    # ---------------------------------------------------------------- proximity
    beacon_rotation_seconds: int = 30
    proximity_max_age_seconds: int = 60

    # ------------------------------------------------------------------- signer
    signer_socket: str = "/run/acs-signer/signer.sock"
    signer_timeout_ms: int = 1_500
    signer_private_key: str = ""
    signer_public_key: str = ""
    signer_key_id: str = "signer-1"

    # ------------------------------------------------------------ controller ws
    ws_heartbeat_seconds: int = 25
    ws_heartbeat_timeout_seconds: int = 60
    ws_handshake_timeout_seconds: int = 10
    command_ttl_seconds: int = 10

    # -------------------------------------------------------------- attestation
    attestation_mode: Literal["strict", "log_only"] = "strict"
    play_integrity_credentials: str = ""
    play_integrity_package_name: str = ""
    android_cert_digest: str = ""
    attestation_roots_pem: str = ""

    # -------------------------------------------------------------------- admin
    admin_host: str = "127.0.0.1"
    admin_port: int = 8081
    admin_allowed_cidrs: str = "127.0.0.1/32"

    @field_validator("token_pepper")
    @classmethod
    def _pepper_present(cls, value: str) -> str:
        if not value:
            # Allowed only so that `import app` works in a bare checkout; the
            # pepper is required the moment a token is minted.
            return value
        raw = base64.b64decode(value, validate=True)
        if len(raw) < 32:
            raise ValueError("ACS_TOKEN_PEPPER must decode to at least 32 bytes")
        return value

    @property
    def pepper_bytes(self) -> bytes:
        if not self.token_pepper:
            raise RuntimeError(
                "ACS_TOKEN_PEPPER is not set. Refusing to hash tokens without a pepper."
            )
        return base64.b64decode(self.token_pepper, validate=True)

    @property
    def audit_dsn(self) -> str:
        return self.audit_db_dsn or self.db_dsn

    @property
    def trusted_proxy_list(self) -> list[str]:
        return [p.strip() for p in self.trusted_proxies.split(",") if p.strip()]

    @property
    def admin_cidr_list(self) -> list[str]:
        return [c.strip() for c in self.admin_allowed_cidrs.split(",") if c.strip()]


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Used by the test suite after it rewrites the environment."""
    get_settings.cache_clear()
