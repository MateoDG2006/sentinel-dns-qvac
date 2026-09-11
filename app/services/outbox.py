"""Initial outbox dispatcher (B1). Wazuh HTTP semantics are B2's scope."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from app.domain.ports import OutboxPort
from app.domain.schemas import OutboxRecord

DeliverFn = Callable[[list[OutboxRecord]], Awaitable[list[bool]]]
"""Given a batch, return one success/failure bool per record, same order.

NOTE for whoever builds B2: this signature only distinguishes success
from "retry later." It cannot express "this is permanently invalid,
call mark_dead instead" (spec section 14: a permanent 4xx must not
retry forever). When B2's real Wazuh client exists, either widen this
to return a three-way result (delivered / retry / dead) or have B2
call mark_dead directly on its own dead-lettered ids before invoking
this dispatcher. Flagging this now rather than guessing B2's shape.
"""


class OutboxDispatcher:
    def __init__(
        self,
        outbox: OutboxPort,
        deliver: DeliverFn,
        batch_size: int = 100,
        base_backoff_seconds: float = 2.0,
    ) -> None:
        self._outbox = outbox
        self._deliver = deliver
        self._batch_size = batch_size
        self._base_backoff_seconds = base_backoff_seconds

    async def run_once(self) -> int:
        """Claim one batch and resolve outcomes. Returns batch size (0 = idle)."""
        batch = await self._outbox.claim_batch(self._batch_size)
        if not batch:
            return 0

        results = await self._deliver(batch)
        delivered_ids = [r.id for r, ok in zip(batch, results, strict=True) if ok]
        failed = [r for r, ok in zip(batch, results, strict=True) if not ok]

        if delivered_ids:
            await self._outbox.mark_delivered(delivered_ids)
        if failed:
            retry_at = datetime.now(UTC) + timedelta(seconds=self._base_backoff_seconds)
            await self._outbox.reschedule(
                [r.id for r in failed], retry_at, reason="delivery_failed"
            )
        return len(batch)
