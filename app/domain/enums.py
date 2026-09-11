"""Shared enumerations for Sentinel-DNS contracts."""

from enum import StrEnum


class ThreatType(StrEnum):
    DGA = "dga"
    TYPOSQUATTING = "typosquatting"
    DNS_TUNNELING = "dns_tunneling"
    BEACONING = "beaconing"
    NONE = "none"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PredictionMode(StrEnum):
    QVAC = "qvac"
    HYBRID = "hybrid"
    HEURISTIC_FALLBACK = "heuristic_fallback"


class EventSource(StrEnum):
    KAFKA = "kafka"
    WEBHOOK = "webhook"


class WazuhEventType(StrEnum):
    DNS_THREAT = "dns_threat"
    SENTINEL_OPERATIONAL = "sentinel_operational"


class DetectorRuntime(StrEnum):
    QVAC_LOCAL = "qvac-local"
    HEURISTIC_FALLBACK = "heuristic-fallback"


class QoeStatus(StrEnum):
    GOOD = "good"
    WARNING = "warning"
    CRITICAL = "critical"
    INSUFFICIENT_DATA = "insufficient_data"


class QoePrimaryCause(StrEnum):
    LATENCIA_ALTA = "latencia_alta"
    NXDOMAIN_ELEVADO = "nxdomain_elevado"
    SATURACION_PROBABLE = "saturacion_probable"
    MUESTRAS_INSUFICIENTES = "muestras_insuficientes"


class OutboxStatus(StrEnum):
    PENDING = "pending"
    CLAIMED = "claimed"
    DELIVERED = "delivered"
    DEAD = "dead"


class DependencyStatus(StrEnum):
    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"


class ErrorClass(StrEnum):
    RECOVERABLE = "recoverable"
    PERMANENT = "permanent"


class RuntimeProfile(StrEnum):
    HACKATHON = "hackathon"
    LOCAL_INSECURE = "local-insecure"


class ServiceState(StrEnum):
    STARTING = "starting"
    READY = "ready"
    DEGRADED = "degraded"
    STOPPING = "stopping"
    STOPPED = "stopped"
