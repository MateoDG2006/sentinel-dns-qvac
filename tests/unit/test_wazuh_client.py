from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import httpx
import pytest

from app.core.config import WazuhSettings
from app.infrastructure.wazuh.client import WazuhClient, _backoff_with_jitter, _RateLimiter


def _fake_jwt(exp_seconds_from_now: float = 900.0) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    exp = int(datetime.now(UTC).timestamp() + exp_seconds_from_now)
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


def _settings(**overrides) -> WazuhSettings:
    defaults = dict(
        base_url="https://wazuh-test.local",
        username="sentinel_ingest",
        password="test-password",
        max_requests_per_minute=1000,  # keep the rate limiter out of the way by default
    )
    defaults.update(overrides)
    return WazuhSettings(**defaults)


def _client_with_handler(settings: WazuhSettings, handler) -> WazuhClient:
    transport = httpx.MockTransport(handler)
    http_client = httpx.AsyncClient(base_url=settings.base_url, transport=transport)
    return WazuhClient(settings, http_client)


@pytest.mark.asyncio
async def test_successful_send_all_accepted():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": _fake_jwt()}})
        assert request.url.path == "/events"
        assert request.headers["authorization"].startswith("Bearer ")
        body = json.loads(request.content)
        assert body == {"events": ["{}", "{}"]}
        return httpx.Response(200, json={"error": 0, "data": {}})

    client = _client_with_handler(_settings(), handler)
    result = await client.send_events(["{}", "{}"])
    assert result.accepted == 2
    assert result.rejected == 0
    assert result.retryable is False


@pytest.mark.asyncio
async def test_cached_token_is_reused_across_calls():
    call_count = {"auth": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            call_count["auth"] += 1
            return httpx.Response(200, json={"data": {"token": _fake_jwt()}})
        return httpx.Response(200, json={"error": 0})

    client = _client_with_handler(_settings(), handler)
    await client.send_events(["{}"])
    await client.send_events(["{}"])
    assert call_count["auth"] == 1


@pytest.mark.asyncio
async def test_401_triggers_single_reauth_then_succeeds():
    state = {"events_calls": 0, "auth_calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            state["auth_calls"] += 1
            return httpx.Response(200, json={"data": {"token": _fake_jwt()}})
        state["events_calls"] += 1
        if state["events_calls"] == 1:
            return httpx.Response(401, json={"error": "900", "message": "token expired"})
        return httpx.Response(200, json={"error": 0})

    client = _client_with_handler(_settings(), handler)
    result = await client.send_events(["{}"])
    assert result.accepted == 1
    assert result.retryable is False
    assert state["auth_calls"] == 2
    assert state["events_calls"] == 2


@pytest.mark.asyncio
async def test_401_persists_after_reauth_is_retryable_not_dead():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": _fake_jwt()}})
        return httpx.Response(401, json={"error": "900", "message": "invalid credentials"})

    client = _client_with_handler(_settings(), handler)
    result = await client.send_events(["{}"])
    assert result.retryable is True
    assert result.status_code == 401
    assert result.reason == "auth_failed_after_renewal"


@pytest.mark.asyncio
async def test_429_is_retryable_and_parses_retry_after():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": _fake_jwt()}})
        return httpx.Response(429, headers={"Retry-After": "13"})

    client = _client_with_handler(_settings(), handler)
    result = await client.send_events(["{}"])
    assert result.retryable is True
    assert result.status_code == 429
    assert result.retry_after_seconds == 13.0


@pytest.mark.asyncio
async def test_5xx_is_retryable():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": _fake_jwt()}})
        return httpx.Response(503)

    client = _client_with_handler(_settings(), handler)
    result = await client.send_events(["{}"])
    assert result.retryable is True
    assert result.status_code == 503


@pytest.mark.asyncio
async def test_permanent_400_is_not_retryable_and_extracts_detail():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": _fake_jwt()}})
        return httpx.Response(
            400,
            json={
                "error": "3013",
                "message": {"title": "Bad Request", "detail": "'events' is not of type 'array'"},
            },
        )

    client = _client_with_handler(_settings(), handler)
    result = await client.send_events(["not valid"])
    assert result.retryable is False
    assert result.status_code == 400
    assert result.rejected == 1
    assert result.reason == "'events' is not of type 'array'"


@pytest.mark.asyncio
async def test_timeout_is_retryable():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": _fake_jwt()}})
        raise httpx.ReadTimeout("simulated timeout", request=request)

    client = _client_with_handler(_settings(), handler)
    result = await client.send_events(["{}"])
    assert result.retryable is True
    assert result.reason == "timeout"


@pytest.mark.asyncio
async def test_batch_over_max_is_rejected_before_any_request():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("should never reach the network for an oversized batch")

    client = _client_with_handler(_settings(batch_max=2), handler)
    with pytest.raises(ValueError):
        await client.send_events(["{}", "{}", "{}"])


@pytest.mark.asyncio
async def test_rate_limiter_delays_calls_beyond_the_limit(monkeypatch):
    clock = {"t": 0.0}

    def fake_clock() -> float:
        return clock["t"]

    limiter = _RateLimiter(max_calls=2, period_seconds=10.0, clock=fake_clock)
    await limiter.acquire()
    await limiter.acquire()

    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        clock["t"] += seconds

    monkeypatch.setattr("app.infrastructure.wazuh.client.asyncio.sleep", fake_sleep)
    await limiter.acquire()

    assert len(slept) == 1
    assert slept[0] == pytest.approx(10.0)


def test_backoff_with_jitter_is_bounded_and_capped():
    for attempt in range(10):
        delay = _backoff_with_jitter(attempt, base_seconds=1.0, cap_seconds=30.0)
        assert 0.0 <= delay <= 30.0