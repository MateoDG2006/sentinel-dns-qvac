from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from app.domain.enums import OutboxStatus, WazuhEventType
from app.domain.schemas import OutboxRecord
from app.infrastructure.persistence.sqlite import SqliteOutbox


def _make_record(event_id: UUID | None = None) -> OutboxRecord:
    return OutboxRecord(
        id=uuid4(),
        event_id=event_id or uuid4(),
        prediction_id=None,
        created_at=datetime.now(timezone.utc),
        payload="{}",
        status=OutboxStatus.PENDING,
        attempts=0,
        next_retry_at=None,
        last_reason=None,
        record_type=WazuhEventType.DNS_THREAT,
    )


@pytest.mark.asyncio
async def test_enqueue_dedupes_by_event_id(tmp_path):
    outbox = SqliteOutbox(tmp_path / "outbox.db")
    await outbox.start()
    try:
        shared_event_id = uuid4()
        assert await outbox.enqueue(_make_record(shared_event_id)) is True
        assert await outbox.enqueue(_make_record(shared_event_id)) is False
    finally:
        await outbox.close()


@pytest.mark.asyncio
async def test_restart_preserves_pending(tmp_path):
    db_path = tmp_path / "outbox.db"

    outbox = SqliteOutbox(db_path)
    await outbox.start()
    await outbox.enqueue(_make_record())
    await outbox.close()  # simulate process stopping

    restarted = SqliteOutbox(db_path)  # brand-new instance, same file
    await restarted.start()
    try:
        claimed = await restarted.claim_batch(limit=10)
        assert len(claimed) == 1
    finally:
        await restarted.close()


@pytest.mark.asyncio
async def test_claimed_but_undelivered_recovers_on_restart(tmp_path):
    db_path = tmp_path / "outbox.db"

    outbox = SqliteOutbox(db_path)
    await outbox.start()
    await outbox.enqueue(_make_record())
    await outbox.claim_batch(limit=10)  # claimed, then "crashes"
    await outbox.close()               # before mark_delivered ever runs

    restarted = SqliteOutbox(db_path)
    await restarted.start()  # must reset the stuck CLAIMED row
    try:
        reclaimed = await restarted.claim_batch(limit=10)
        assert len(reclaimed) == 1
    finally:
        await restarted.close()


@pytest.mark.asyncio
async def test_reschedule_increments_attempts_and_reopens_for_claim(tmp_path):
    outbox = SqliteOutbox(tmp_path / "outbox.db")
    await outbox.start()
    try:
        await outbox.enqueue(_make_record())
        claimed = await outbox.claim_batch(limit=10)
        already_due = datetime.now(timezone.utc)
        await outbox.reschedule([claimed[0].id], already_due, reason="wazuh_503")

        reclaimed = await outbox.claim_batch(limit=10)
        assert len(reclaimed) == 1
        assert reclaimed[0].attempts == 1
        assert reclaimed[0].last_reason == "wazuh_503"
    finally:
        await outbox.close()


@pytest.mark.asyncio
async def test_mark_dead_excludes_record_from_future_claims(tmp_path):
    outbox = SqliteOutbox(tmp_path / "outbox.db")
    await outbox.start()
    try:
        await outbox.enqueue(_make_record())
        claimed = await outbox.claim_batch(limit=10)
        await outbox.mark_dead([claimed[0].id], reason="wazuh_422_invalid_payload")

        assert await outbox.claim_batch(limit=10) == []
    finally:
        await outbox.close()