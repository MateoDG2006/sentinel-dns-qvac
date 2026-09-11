"""Kubernetes overlay paths and static policy tokens for C5 validation."""

from typing import Final

OVERLAY_LOCAL: Final[str] = "deploy/kubernetes/overlays/local"
FORBIDDEN_SERVICE_TYPES: Final[frozenset[str]] = frozenset({"LoadBalancer"})
LATEST_IMAGE_TAG: Final[str] = "latest"
KUBECTL_DRY_RUN_TIMEOUT_SECONDS: Final[int] = 12
KUBECTL_CLUSTER_PROBE_TIMEOUT_SECONDS: Final[int] = 5
KUBECTL_UNREACHABLE_MARKERS: Final[tuple[str, ...]] = (
    "couldn't get current server API group list",
    "connection refused",
    "no such host",
    "wsarecv",
    "dial tcp",
    "was refused",
    "i/o timeout",
)
WORKLOAD_KINDS: Final[frozenset[str]] = frozenset(
    {
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "Job",
        "CronJob",
        "ReplicaSet",
        "Pod",
    }
)
CONTAINER_LIST_KEYS: Final[tuple[str, ...]] = (
    "containers",
    "initContainers",
    "ephemeralContainers",
)
