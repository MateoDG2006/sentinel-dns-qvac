from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.domain.enums import OutboxStatus, WazuhEventType
from app.domain.schemas import DeliveryResult, OutboxRecord
from app.infrastructure.persistence.sqlite import SqliteOutbox
from app.infrastructure.wazuh.dispatcher import WazuhOutboxDispatcher


def _make_record() -> OutboxRecord:
    return OutboxRecord(
        id=uuid4(),
        event_id=uuid4(),
        prediction_id=None,
        created_at=datetime.now(timezone.utc),
        payload='{"threat_type": "dga"}',
        status=OutboxStatus.PENDING,
        attempts=0,
        next_retry_at=None,
        last_reason=None,
        record_type=WazuhEventType.DNS_THREAT,
    )


class _FakeWazuhClient:
    def __init__(self, result: DeliveryResult) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    async def send_events(self, events: list[str]) -> DeliveryResult:
        self.calls.append(events)
        return self.result


@pytest.mark.asyncio
async def test_full_success_marks_delivered(tmp_path):
    outbox = SqliteOutbox(tmp_path / "outbox.db")
    await outbox.start()
    try:
        record = _make_record()
        await outbox.enqueue(record)

        wazuh = _FakeWazuhClient(DeliveryResult(accepted=1, rejected=0, retryable=False))
        dispatcher = WazuhOutboxDispatcher(outbox, wazuh)
        processed = await dispatcher.run_once()

        assert processed == 1
        assert wazuh.calls == [[record.payload]]
        assert await outbox.claim_batch(10) == []
    finally:
        await outbox.close()


@pytest.mark.asyncio
async def test_retryable_failure_reschedules(tmp_path, monkeypatch):
    # Fix the backoff delay so this test never races real wall-clock time
    # against a randomly-tiny jitter value -- the jitter math itself is
    # already covered by test_backoff_with_jitter_is_bounded_and_capped.
    monkeypatch.setattr(
        "app.infrastructure.wazuh.dispatcher.compute_retry_delay",
        lambda attempt, retry_after: 100.0,
    )
    outbox = SqliteOutbox(tmp_path / "outbox.db")
    await outbox.start()
    try:
        await outbox.enqueue(_make_record())
        wazuh = _FakeWazuhClient(
            DeliveryResult(accepted=0, rejected=1, retryable=True, reason="server_error")
        )
        dispatcher = WazuhOutboxDispatcher(outbox, wazuh)
        await dispatcher.run_once()

        assert await outbox.claim_batch(10) == []
    finally:
        await outbox.close()


@pytest.mark.asyncio
async def test_permanent_failure_marks_dead(tmp_path):
    outbox = SqliteOutbox(tmp_path / "outbox.db")
    await outbox.start()
    try:
        await outbox.enqueue(_make_record())
        wazuh = _FakeWazuhClient(
            DeliveryResult(accepted=0, rejected=1, retryable=False, reason="malformed_payload")
        )
        dispatcher = WazuhOutboxDispatcher(outbox, wazuh)
        await dispatcher.run_once()

        assert await outbox.claim_batch(10) == []
    finally:
        await outbox.close()


@pytest.mark.asyncio
async def test_idle_outbox_returns_zero_without_calling_wazuh(tmp_path):
    outbox = SqliteOutbox(tmp_path / "outbox.db")
    await outbox.start()
    try:
        wazuh = _FakeWazuhClient(DeliveryResult(accepted=0, rejected=0, retryable=False))
        dispatcher = WazuhOutboxDispatcher(outbox, wazuh)
        processed = await dispatcher.run_once()
        assert processed == 0
        assert wazuh.calls == []
    finally:
        await outbox.close()