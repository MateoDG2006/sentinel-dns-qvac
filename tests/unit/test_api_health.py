"""HTTP tests for liveness, readiness, and Prometheus metrics."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.constants.api import HEALTH_LIVE_PATH, HEALTH_READY_PATH, METRICS_PATH
from app.constants.health import (
    KAFKA_DISABLED_DETAIL,
    OUTBOX_SQLITE_DETAIL,
)
from app.constants.metrics import (
    EVENTS_TOTAL,
    FORBIDDEN_LABELS,
    KAFKA_CONSUMER_LAG,
    OUTBOX_PENDING,
    PREDICTIONS_TOTAL,
    PROCESSING_SECONDS,
    QOE_FLUSH_TOTAL,
    QVAC_AVAILABLE,
    QVAC_SECONDS,
    WAZUH_DELIVERY_TOTAL,
)
from app.core.config import Settings
from app.domain.enums import DependencyStatus, ServiceState
from app.domain.schemas import DependencyHealth
from app.main import SentinelApp
from app.observability.health import HealthProbe
from app.utils.time import UtcDateTime

WEBHOOK_TOKEN = "unit-test-webhook-token"


def _client() -> TestClient:
    return TestClient(SentinelApp.create(Settings(webhook_token=WEBHOOK_TOKEN)))


def test_health_live_returns_ok() -> None:
    with _client() as client:
        response = client.get(HEALTH_LIVE_PATH)
    assert response.status_code == 200
    assert response.json()["status"] == "live"


def test_health_ready_uses_live_adapters() -> None:
    with _client() as client:
        response = client.get(HEALTH_READY_PATH)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    by_name = {item["name"]: item for item in body["dependencies"]}
    assert by_name["config"]["status"] == DependencyStatus.UP.value
    assert by_name["kafka"]["status"] == DependencyStatus.DEGRADED.value
    assert by_name["kafka"]["detail"] == KAFKA_DISABLED_DETAIL
    assert by_name["qvac"]["status"] == DependencyStatus.DEGRADED.value
    assert by_name["qvac"]["detail"] != "adapter_not_implemented_heuristic_fallback_active"
    assert by_name["outbox"]["status"] == DependencyStatus.UP.value
    assert by_name["outbox"]["detail"] == OUTBOX_SQLITE_DETAIL


async def test_health_ready_reports_qvac_and_kafka_up() -> None:
    checked_at = UtcDateTime.ensure(datetime.now(UTC))
    probe = HealthProbe(Settings(webhook_token=WEBHOOK_TOKEN))

    class _Up:
        def __init__(self, name: str) -> None:
            self._name = name

        async def health(self) -> DependencyHealth:
            return DependencyHealth(
                name=self._name,
                status=DependencyStatus.UP,
                detail=None,
                checked_at=checked_at,
            )

    status_code, body = await probe.readiness(
        service_state=ServiceState.READY,
        qvac=_Up("qvac"),
        kafka=_Up("kafka"),
        outbox=_Up("outbox"),
        kafka_enabled=True,
    )
    assert status_code == 200
    by_name = {item["name"]: item for item in body["dependencies"]}
    assert by_name["kafka"]["status"] == DependencyStatus.UP.value
    assert by_name["qvac"]["status"] == DependencyStatus.UP.value
    assert by_name["outbox"]["status"] == DependencyStatus.UP.value


async def test_health_ready_returns_503_when_outbox_is_down() -> None:
    checked_at = UtcDateTime.ensure(datetime.now(UTC))
    probe = HealthProbe(Settings(webhook_token=WEBHOOK_TOKEN))

    class _Down:
        async def health(self) -> DependencyHealth:
            return DependencyHealth(
                name="outbox",
                status=DependencyStatus.DOWN,
                detail="sqlite_unavailable",
                checked_at=checked_at,
            )

    status_code, body = await probe.readiness(
        service_state=ServiceState.READY,
        outbox=_Down(),
        kafka_enabled=False,
    )
    assert status_code == 503
    assert body["status"] == "not_ready"


def test_metrics_exposes_spec_names_without_identity_labels() -> None:
    with _client() as client:
        response = client.get(METRICS_PATH)
    assert response.status_code == 200
    text = response.text
    for name in (
        EVENTS_TOTAL,
        PREDICTIONS_TOTAL,
        PROCESSING_SECONDS,
        QVAC_SECONDS,
        QVAC_AVAILABLE,
        KAFKA_CONSUMER_LAG,
        OUTBOX_PENDING,
        WAZUH_DELIVERY_TOTAL,
        QOE_FLUSH_TOTAL,
    ):
        assert name in text
    for label in FORBIDDEN_LABELS:
        assert f"{label}=" not in text
