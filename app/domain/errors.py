"""Recoverable vs permanent error taxonomy for Sentinel-DNS."""

from app.domain.enums import ErrorClass


class SentinelError(Exception):
    """Base error for classified Sentinel-DNS failures."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        error_class: ErrorClass,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.error_class = error_class

    @property
    def recoverable(self) -> bool:
        return self.error_class is ErrorClass.RECOVERABLE


class RecoverableError(SentinelError):
    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message, code=code, error_class=ErrorClass.RECOVERABLE)


class PermanentError(SentinelError):
    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message, code=code, error_class=ErrorClass.PERMANENT)


class DomainValidationError(PermanentError):
    def __init__(self, message: str, *, code: str = "domain_validation") -> None:
        super().__init__(message, code=code)


class QnameNormalizationError(PermanentError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="qname_normalization")


class ClockSkewError(PermanentError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="clock_skew")


class QvacTimeoutError(RecoverableError):
    def __init__(self, message: str = "QVAC enrichment timed out") -> None:
        super().__init__(message, code="qvac_timeout")


class QvacUnavailableError(RecoverableError):
    def __init__(self, message: str = "QVAC is unavailable") -> None:
        super().__init__(message, code="qvac_unavailable")


class QvacInvalidResponseError(RecoverableError):
    def __init__(self, message: str = "QVAC response was not valid JSON") -> None:
        super().__init__(message, code="qvac_invalid_response")


class WazuhAuthError(RecoverableError):
    def __init__(self, message: str = "Wazuh authentication failed") -> None:
        super().__init__(message, code="wazuh_auth")


class WazuhRateLimitError(RecoverableError):
    def __init__(
        self,
        message: str = "Wazuh rate limited the request",
        *,
        retry_after_seconds: float | None = None,
    ) -> None:
        super().__init__(message, code="wazuh_rate_limit")
        self.retry_after_seconds = retry_after_seconds


class WazuhUnavailableError(RecoverableError):
    def __init__(self, message: str = "Wazuh API is unavailable") -> None:
        super().__init__(message, code="wazuh_unavailable")


class WazuhPermanentPayloadError(PermanentError):
    def __init__(self, message: str = "Wazuh rejected the payload") -> None:
        super().__init__(message, code="wazuh_payload")


class OutboxUnavailableError(RecoverableError):
    def __init__(self, message: str = "Outbox is unavailable") -> None:
        super().__init__(message, code="outbox_unavailable")


class OutboxFullError(RecoverableError):
    def __init__(self, message: str = "Outbox is at capacity") -> None:
        super().__init__(message, code="outbox_full")


class ClickHouseUnavailableError(RecoverableError):
    def __init__(self, message: str = "ClickHouse is unavailable") -> None:
        super().__init__(message, code="clickhouse_unavailable")


class KafkaBackpressureError(RecoverableError):
    def __init__(self, message: str = "Internal queue exceeded backpressure limit") -> None:
        super().__init__(message, code="kafka_backpressure")
