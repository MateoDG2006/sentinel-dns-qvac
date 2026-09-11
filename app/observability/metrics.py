"""Prometheus counters, histograms, and gauges with frozen metric names."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

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


class SentinelMetrics:
    """Aggregated runtime metrics. High-cardinality identity labels are rejected."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self._assert_safe_labels(("source", "status"))
        self._assert_safe_labels(("threat_type", "severity", "runtime"))
        self._assert_safe_labels(("status",))
        self.events_total = Counter(
            EVENTS_TOTAL,
            "DNS events processed by source and status",
            ("source", "status"),
            registry=self.registry,
        )
        self.predictions_total = Counter(
            PREDICTIONS_TOTAL,
            "Threat predictions by type, severity, and detector runtime",
            ("threat_type", "severity", "runtime"),
            registry=self.registry,
        )
        self.processing_seconds = Histogram(
            PROCESSING_SECONDS,
            "Batch processing latency in seconds",
            registry=self.registry,
        )
        self.qvac_seconds = Histogram(
            QVAC_SECONDS,
            "Local QVAC enrichment latency in seconds",
            registry=self.registry,
        )
        self.qvac_available = Gauge(
            QVAC_AVAILABLE,
            "Whether the local QVAC worker is available (1) or degraded (0)",
            registry=self.registry,
        )
        self.kafka_consumer_lag = Gauge(
            KAFKA_CONSUMER_LAG,
            "Kafka consumer lag in records",
            registry=self.registry,
        )
        self.outbox_pending = Gauge(
            OUTBOX_PENDING,
            "Pending outbox records",
            registry=self.registry,
        )
        self.wazuh_delivery_total = Counter(
            WAZUH_DELIVERY_TOTAL,
            "Wazuh delivery attempts by status",
            ("status",),
            registry=self.registry,
        )
        self.qoe_flush_total = Counter(
            QOE_FLUSH_TOTAL,
            "QoE window flush attempts by status",
            ("status",),
            registry=self.registry,
        )
        self.set_qvac_available(False)
        self.set_kafka_consumer_lag(0)
        self.set_outbox_pending(0)

    @staticmethod
    def _assert_safe_labels(labels: tuple[str, ...]) -> None:
        blocked = FORBIDDEN_LABELS.intersection(labels)
        if blocked:
            raise ValueError(f"forbidden prometheus labels: {sorted(blocked)}")

    def observe_processing(self, seconds: float) -> None:
        self.processing_seconds.observe(seconds)

    def increment_events(self, *, source: str, status: str, amount: int = 1) -> None:
        self.events_total.labels(source=source, status=status).inc(amount)

    def increment_prediction(self, *, threat_type: str, severity: str, runtime: str) -> None:
        self.predictions_total.labels(
            threat_type=threat_type,
            severity=severity,
            runtime=runtime,
        ).inc()

    def set_qvac_available(self, available: bool) -> None:
        self.qvac_available.set(1 if available else 0)

    def set_kafka_consumer_lag(self, lag: float) -> None:
        self.kafka_consumer_lag.set(lag)

    def set_outbox_pending(self, pending: float) -> None:
        self.outbox_pending.set(pending)

    def increment_wazuh_delivery(self, *, status: str, amount: int = 1) -> None:
        self.wazuh_delivery_total.labels(status=status).inc(amount)

    def increment_qoe_flush(self, *, status: str, amount: int = 1) -> None:
        self.qoe_flush_total.labels(status=status).inc(amount)

    def render(self) -> bytes:
        return generate_latest(self.registry)
