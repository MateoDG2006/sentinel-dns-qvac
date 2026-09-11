"""Typed runtime configuration. Thresholds and secrets are not hardcoded in services."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any, ClassVar, Self
from urllib.parse import urlparse

from pydantic import BaseModel, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.constants.clickhouse import DATABASE as CLICKHOUSE_DATABASE
from app.constants.clickhouse import QOE_TABLE as CLICKHOUSE_QOE_TABLE
from app.constants.kafka import TOPIC_DLQ, TOPIC_GROUNDTRUTH, TOPIC_NORMALIZED
from app.constants.network import LOCAL_DNS_SUFFIXES, LOCAL_SERVICE_HOSTS
from app.constants.qvac import SDK_PACKAGE_DIR
from app.domain.enums import RuntimeProfile
from app.utils.secrets import SecretFile


class LocalEndpointPolicy:
    """Classify configured hosts as local/private for no-egress mode."""

    @staticmethod
    def hostname_is_local(host: str) -> bool:
        candidate = host.strip().lower().strip("[]")
        if not candidate:
            return False
        if candidate in LOCAL_SERVICE_HOSTS:
            return True
        if candidate.endswith(LOCAL_DNS_SUFFIXES):
            return True
        if "." not in candidate:
            return True
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return bool(address.is_private or address.is_loopback or address.is_link_local)

    @staticmethod
    def hosts_from_bootstrap(bootstrap_servers: str) -> list[str]:
        hosts: list[str] = []
        for part in bootstrap_servers.split(","):
            item = part.strip()
            if not item:
                continue
            if "://" in item:
                parsed = urlparse(item)
                if parsed.hostname:
                    hosts.append(parsed.hostname)
                continue
            if item.startswith("[") and "]" in item:
                hosts.append(item[1 : item.index("]")])
                continue
            hosts.append(item.rsplit(":", 1)[0] if ":" in item else item)
        return hosts


class KafkaSettings(BaseModel):
    bootstrap_servers: str = "kafka:9092"
    topic_normalized: str = TOPIC_NORMALIZED
    topic_dlq: str = TOPIC_DLQ
    topic_groundtruth: str = TOPIC_GROUNDTRUTH
    consumer_group: str = "sentinel-dns"
    poll_max_records: int = Field(default=500, ge=1)


class WazuhSettings(BaseModel):
    base_url: str = "https://wazuh-manager:55000"
    events_path: str = "/events"
    authenticate_path: str = "/security/user/authenticate"
    verify_tls: bool = True
    ca_path: Path | None = None
    username: str | None = None
    password: SecretStr | None = None
    username_file: Path | None = None
    password_file: Path | None = None
    batch_max: int = Field(default=100, ge=1, le=100)
    flush_seconds: float = Field(default=2.0, gt=0.0)
    max_requests_per_minute: int = Field(default=30, ge=1)

    def resolved_username(self) -> str:
        if self.username_file is not None:
            return SecretFile.read(self.username_file)
        if self.username:
            return self.username
        raise ValueError("Wazuh username is not configured")

    def resolved_password(self) -> str:
        if self.password_file is not None:
            return SecretFile.read(self.password_file)
        if self.password is not None:
            return self.password.get_secret_value()
        raise ValueError("Wazuh password is not configured")


class ClickHouseSettings(BaseModel):
    host: str = "clickhouse"
    http_port: int = Field(default=8123, ge=1, le=65535)
    database: str = CLICKHOUSE_DATABASE
    qoe_table: str = CLICKHOUSE_QOE_TABLE
    username: str | None = None
    password: SecretStr | None = None
    username_file: Path | None = None
    password_file: Path | None = None
    secure: bool = False

    def resolved_username(self) -> str | None:
        if self.username_file is not None:
            return SecretFile.read(self.username_file)
        return self.username

    def resolved_password(self) -> str | None:
        if self.password_file is not None:
            return SecretFile.read(self.password_file)
        if self.password is not None:
            return self.password.get_secret_value()
        return None


class OutboxSettings(BaseModel):
    path: Path = Path("data/outbox/sentinel.db")
    claim_limit: int = Field(default=100, ge=1, le=100)
    max_bytes: int = Field(default=256 * 1024 * 1024, ge=1)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
        populate_by_name=True,
    )

    _instance: ClassVar[Settings | None] = None

    app_host: str = "127.0.0.1"
    app_port: int = Field(default=8000, ge=1, le=65535)
    detector_version: str = "1.0.0"
    runtime_profile: RuntimeProfile = RuntimeProfile.HACKATHON
    no_egress: bool = True
    require_synthetic: bool = True
    clock_skew_tolerance_seconds: int = Field(default=300, ge=0)
    internal_queue_max_events: int = Field(default=5_000, ge=1)
    heuristic_alert_threshold: float = Field(default=0.90, ge=0.0, le=1.0)
    heuristic_qvac_min_score: float = Field(default=0.45, ge=0.0, le=1.0)
    qoe_window_seconds: int = Field(default=60, ge=1)
    qoe_min_samples: int = Field(default=20, ge=1)
    qoe_calculation_version: str = "1.0"
    features_config_path: Path = Path("config/features.yaml")
    brands_config_path: Path = Path("config/brands.yaml")
    qoe_thresholds_path: Path = Path("config/qoe_thresholds.yaml")
    webhook_token: SecretStr | None = None
    webhook_token_file: Path | None = None
    qvac_enabled: bool = True
    qvac_cache_dir: Path = Path("data/qvac")
    qvac_worker_path: Path | None = None
    qvac_bare_path: Path | None = None
    qvac_sdk_dir: Path = SDK_PACKAGE_DIR
    qvac_timeout_seconds: float = Field(default=1.5, gt=0.0)
    qvac_concurrency: int = Field(default=1, ge=1)
    kafka: KafkaSettings = Field(default_factory=KafkaSettings)
    wazuh: WazuhSettings = Field(default_factory=WazuhSettings)
    clickhouse: ClickHouseSettings = Field(default_factory=ClickHouseSettings)
    outbox: OutboxSettings = Field(default_factory=OutboxSettings)

    @classmethod
    def get(cls) -> Settings:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def clear_cache(cls) -> None:
        cls._instance = None

    @model_validator(mode="before")
    @classmethod
    def apply_qvac_env_aliases(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        data = dict(data)
        if "qvac_cache_dir" not in data:
            cache_dir = os.environ.get("QVAC_CACHE_DIR")
            if cache_dir:
                data["qvac_cache_dir"] = cache_dir
        if "qvac_worker_path" not in data:
            worker_path = os.environ.get("QVAC_WORKER_PATH")
            if worker_path:
                data["qvac_worker_path"] = worker_path
        if "qvac_bare_path" not in data:
            bare_path = os.environ.get("QVAC_BARE_PATH")
            if bare_path:
                data["qvac_bare_path"] = bare_path
        if "qvac_sdk_dir" not in data:
            sdk_dir = os.environ.get("QVAC_SDK_DIR")
            if sdk_dir:
                data["qvac_sdk_dir"] = sdk_dir
        return data

    @model_validator(mode="after")
    def validate_runtime_policy(self) -> Self:
        if self.heuristic_qvac_min_score > self.heuristic_alert_threshold:
            raise ValueError("heuristic_qvac_min_score must be <= heuristic_alert_threshold")
        if self.runtime_profile is RuntimeProfile.HACKATHON and not self.require_synthetic:
            raise ValueError("hackathon profile only accepts synthetic=true events")
        if not self.wazuh.verify_tls and self.runtime_profile is not RuntimeProfile.LOCAL_INSECURE:
            raise ValueError(
                "disabling Wazuh TLS verification requires runtime_profile=local-insecure"
            )
        if self.no_egress:
            self._assert_no_egress()
        return self

    def resolved_webhook_token(self) -> str:
        if self.webhook_token_file is not None:
            return SecretFile.read(self.webhook_token_file)
        if self.webhook_token is not None:
            return self.webhook_token.get_secret_value()
        raise ValueError("webhook token is not configured")

    def _assert_no_egress(self) -> None:
        kafka_hosts = LocalEndpointPolicy.hosts_from_bootstrap(self.kafka.bootstrap_servers)
        if not kafka_hosts or any(
            not LocalEndpointPolicy.hostname_is_local(host) for host in kafka_hosts
        ):
            raise ValueError("no_egress requires local Kafka bootstrap servers")
        wazuh_host = urlparse(self.wazuh.base_url).hostname
        if wazuh_host is None or not LocalEndpointPolicy.hostname_is_local(wazuh_host):
            raise ValueError("no_egress requires a local Wazuh URL")
        if not LocalEndpointPolicy.hostname_is_local(self.clickhouse.host):
            raise ValueError("no_egress requires a local ClickHouse host")
        if str(self.qvac_cache_dir).startswith(("http://", "https://")):
            raise ValueError("QVAC_CACHE_DIR must be a local path")
        if str(self.qvac_sdk_dir).startswith(("http://", "https://")):
            raise ValueError("QVAC_SDK_DIR must be a local path")
