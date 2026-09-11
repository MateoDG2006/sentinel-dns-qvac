"""Local Wazuh events API client. Implements domain.ports.WazuhEventPort.

Expects an httpx.AsyncClient already constructed with base_url set to
settings.base_url and verify configured from settings.verify_tls /
settings.ca_path -- that wiring happens at app composition time
(core/lifecycle.py), not here, since this module only sends requests,
it doesn't own the client's lifecycle or TLS configuration.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from collections.abc import Callable

import httpx

from app.core.config import WazuhSettings
from app.domain.schemas import DeliveryResult
from app.infrastructure.wazuh.auth import WazuhAuthenticator


class _RateLimiter:
    """Sliding-window limiter: at most `max_calls` calls per `period_seconds`."""

    def __init__(
        self,
        max_calls: int,
        period_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_calls = max_calls
        self._period = period_seconds
        self._clock = clock
        self._calls: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = self._clock()
            while self._calls and now - self._calls[0] >= self._period:
                self._calls.popleft()
            if len(self._calls) >= self._max_calls:
                wait_for = self._period - (now - self._calls[0])
                if wait_for > 0:
                    await asyncio.sleep(wait_for)
                now = self._clock()
                while self._calls and now - self._calls[0] >= self._period:
                    self._calls.popleft()
            self._calls.append(self._clock())


def _backoff_with_jitter(
    attempt: int, base_seconds: float = 1.0, cap_seconds: float = 30.0
) -> float:
    """Full-jitter exponential backoff: random(0, min(cap, base * 2^attempt))."""
    upper = min(cap_seconds, base_seconds * (2**attempt))
    return random.uniform(0.0, upper)


def compute_retry_delay(attempt: int, retry_after_seconds: float | None) -> float:
    """Delay before the next attempt. A server-specified Retry-After always wins."""
    if retry_after_seconds is not None:
        return retry_after_seconds
    return _backoff_with_jitter(attempt)


class WazuhClient:
    """Sends pre-serialized event JSON strings to Wazuh's local POST /events."""

    def __init__(self, settings: WazuhSettings, http_client: httpx.AsyncClient) -> None:
        self._settings = settings
        self._http = http_client
        self._auth = WazuhAuthenticator(settings, http_client)
        self._rate_limiter = _RateLimiter(
            max_calls=settings.max_requests_per_minute, period_seconds=60.0
        )

    async def send_events(self, events: list[str]) -> DeliveryResult:
        if not events:
            return DeliveryResult(accepted=0, rejected=0, retryable=False)
        if len(events) > self._settings.batch_max:
            raise ValueError(
                f"batch of {len(events)} exceeds configured batch_max={self._settings.batch_max}"
            )

        await self._rate_limiter.acquire()
        return await self._send_with_single_reauth_retry(events)

    async def _send_with_single_reauth_retry(self, events: list[str]) -> DeliveryResult:
        try:
            token = await self._auth.get_token()
            response = await self._post_events(token, events)
        except httpx.TimeoutException:
            return DeliveryResult(
                accepted=0, rejected=len(events), retryable=True, reason="timeout"
            )
        except httpx.TransportError:
            return DeliveryResult(
                accepted=0, rejected=len(events), retryable=True, reason="connection_error"
            )

        if response.status_code == 401:
            # Spec (ADR-006, section 14): renew the JWT once, retry once.
            # A 401 that persists after renewal is an operational problem
            # (bad credentials, revoked account) -- not a payload problem --
            # so it stays retryable rather than dead. An operator needs to
            # fix the credential; the alert data shouldn't be discarded
            # over it.
            self._auth.invalidate()
            try:
                token = await self._auth.get_token(force_refresh=True)
                response = await self._post_events(token, events)
            except httpx.TimeoutException:
                return DeliveryResult(
                    accepted=0, rejected=len(events), retryable=True, reason="timeout"
                )
            except httpx.TransportError:
                return DeliveryResult(
                    accepted=0, rejected=len(events), retryable=True, reason="connection_error"
                )
            if response.status_code == 401:
                return DeliveryResult(
                    accepted=0,
                    rejected=len(events),
                    retryable=True,
                    status_code=401,
                    reason="auth_failed_after_renewal",
                )

        return self._classify_response(response, len(events))

    async def _post_events(self, token: str, events: list[str]) -> httpx.Response:
        return await self._http.post(
            self._settings.events_path,
            headers={"Authorization": f"Bearer {token}"},
            json={"events": events},
        )

    def _classify_response(self, response: httpx.Response, batch_size: int) -> DeliveryResult:
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            return DeliveryResult(
                accepted=0,
                rejected=batch_size,
                retryable=True,
                status_code=429,
                retry_after_seconds=float(retry_after) if retry_after else None,
                reason="rate_limited",
            )
        if 500 <= response.status_code < 600:
            return DeliveryResult(
                accepted=0,
                rejected=batch_size,
                retryable=True,
                status_code=response.status_code,
                reason="server_error",
            )
        if 200 <= response.status_code < 300:
            accepted, rejected = self._parse_success_counts(response, batch_size)
            return DeliveryResult(
                accepted=accepted,
                rejected=rejected,
                retryable=False,
                status_code=response.status_code,
            )
        # Any other 4xx: a permanent request/payload problem (Wazuh's own
        # docs show this shape for a malformed request: {"error": "3013",
        # "message": {"title": ..., "detail": ...}}). The bulk endpoint
        # validates the whole request, so there's no per-event detail here.
        return DeliveryResult(
            accepted=0,
            rejected=batch_size,
            retryable=False,
            status_code=response.status_code,
            reason=self._extract_error_reason(response),
        )

    def _parse_success_counts(self, response: httpx.Response, batch_size: int) -> tuple[int, int]:
        """Best-effort read of a granular accept/reject split.

        Wazuh's public docs confirm the request shape and the general
        {"error": 0, "data": {...}} success envelope, but do not document
        an accepted/rejected breakdown specifically for this endpoint.
        Default to "whole batch accepted" on any 2xx; only trust a more
        granular count if the response actually exposes one.
        """
        try:
            body = response.json()
        except ValueError:
            return batch_size, 0
        data = body.get("data") if isinstance(body, dict) else None
        if isinstance(data, dict):
            accepted = data.get("accepted")
            rejected = data.get("rejected")
            if isinstance(accepted, int) and isinstance(rejected, int):
                return accepted, rejected
        return batch_size, 0

    def _extract_error_reason(self, response: httpx.Response) -> str:
        try:
            body = response.json()
        except ValueError:
            return f"http_{response.status_code}"
        if not isinstance(body, dict):
            return f"http_{response.status_code}"
        message = body.get("message")
        if isinstance(message, dict):
            detail = message.get("detail") or message.get("title")
            if detail:
                return str(detail)[:200]
        elif isinstance(message, str) and message:
            return message[:200]
        error_code = body.get("error")
        if error_code is not None:
            return f"wazuh_error_{error_code}"
        return f"http_{response.status_code}"
