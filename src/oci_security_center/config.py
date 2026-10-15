"""Application settings. Loaded from environment variables prefixed ``OSC_``.

No secrets are stored here except the local encryption key, which must come from the
environment (or, in ``oci`` mode, should be injected from OCI Vault at startup).
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class DeploymentMode(StrEnum):
    WORKSTATION = "workstation"
    OCI = "oci"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OSC_", env_nested_delimiter="__", extra="ignore")

    deployment: DeploymentMode = DeploymentMode.WORKSTATION
    data_root: Path = Field(default_factory=lambda: Path.home() / ".osc")

    # Retention (docs/storage.md §5).
    # Per-dataset overrides: OSC_RETENTION_OVERRIDES__AUDIT_EVENTS=30
    retention_days: int = 90
    retention_overrides: dict[str, int] = Field(default_factory=dict)
    control_plane_event_retention_days: int = 365

    # IAM names used in generated policies (docs/control-plane.md §5)
    group_admins: str = "OSC-Admins"
    group_viewers: str = "OSC-Viewers"
    group_scanners: str = "OSC-Scanners"
    dynamic_group_scanner: str = "OSC-Scanner-DG"
    identity_domain_name: str = "Default"
    parent_alias: str = "osc_parent"

    # Web
    web_host: str = "127.0.0.1"
    web_port: int = 8000
    public_base_url: str = "http://localhost:8000"
    # Extra Host header values the web UI answers to (e.g. a load balancer name). The host of
    # public_base_url is always allowed, plus localhost / 127.0.0.1 in workstation mode.
    trusted_hosts: list[str] = Field(default_factory=list)
    session_idle_minutes: int = 30
    # Absolute session lifetime, however active the session is.
    session_max_hours: int = 12
    groups_claim: str = "groups"
    oidc_scopes: str = "openid profile email"

    # Fernet key (urlsafe base64, 32 bytes) used to encrypt local secrets and sessions.
    secret_key: SecretStr | None = None

    # Data collection (docs/collection.md §2, §9). Each tier includes the lower ones.
    collection_tier: int = Field(default=1, ge=1, le=5)
    scan_lease_seconds: int = Field(default=900, ge=60)
    # Scheduler intervals in minutes.
    schedule_audit_minutes: int = Field(default=15, ge=1)
    schedule_governance_minutes: int = Field(default=60, ge=5)
    schedule_identity_minutes: int = Field(default=360, ge=15)
    schedule_guardrails_minutes: int = Field(default=1440, ge=60)

    # Audit ingestion (docs/delta-fetching.md). Defaults are proposals to tune in the POC (Q2/Q3).
    audit_source: Literal["logging_search", "audit_api"] = "logging_search"
    audit_ingestion_delay_minutes: int = Field(default=5, ge=0)
    audit_overlap_hours: int = Field(default=24, ge=0)
    audit_chunk_minutes: int = Field(default=60, ge=1)
    audit_min_split_minutes: int = Field(default=1, ge=1)
    audit_initial_minutes: int = Field(default=60, ge=1)
    audit_forward_chunks_per_run: int = Field(default=48, ge=1)
    audit_backfill_chunks_per_run: int = Field(default=24, ge=0)
    audit_reconcile_chunks_per_run: int = Field(default=24, ge=0)
    audit_backfill_days: int | None = Field(default=None, ge=1)  # None = audit retention
    audit_search_result_cap: int | None = Field(default=None, ge=1)  # set once Q2 is known

    # Full backups (docs/storage.md §6.1): published backup sets older than this are expired.
    backup_retention_days: int = Field(default=30, ge=1)

    # Organization switch: how long to wait for in-flight collection before aborting (§6.1).
    switch_drain_seconds: float = Field(default=120.0, gt=0)

    # Concurrency
    max_workers: int = Field(default=8, ge=1, le=64)

    @property
    def db_path(self) -> Path:
        return self.data_root / "osc.db"

    @property
    def audit_root(self) -> Path:
        return self.data_root / "audit"

    @property
    def allowed_hosts(self) -> list[str]:
        """Host header values the web UI accepts (DNS-rebinding defence)."""
        hosts = [urlsplit(self.public_base_url).hostname or "", *self.trusted_hosts]
        if self.deployment is DeploymentMode.WORKSTATION:
            hosts += ["localhost", "127.0.0.1", "::1"]
        return sorted({h.lower() for h in hosts if h})

    @property
    def scanner_is_dynamic_group(self) -> bool:
        return self.deployment is DeploymentMode.OCI

    def retention_for(self, dataset: str) -> int:
        """Days to keep ``dataset`` ("audit.events" matches override key "audit_events")."""
        overrides = {k.lower().replace(".", "_"): v for k, v in self.retention_overrides.items()}
        return overrides.get(dataset.lower().replace(".", "_"), self.retention_days)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
