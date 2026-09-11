"""Wazuh-specific outbox dispatcher. Wires OutboxPort + WazuhEventPort together.

Distinct from app.services.outbox.OutboxDispatcher (B1's generic
claim/deliver loop, which assumes a per-record bool[] result): Wazuh's
bulk /events API only returns aggregate accepted/rejected counts for
the whole batch, with no per-event breakdown. This dispatcher resolves
each claimed batch as a whole -- delivered, retried, or dead-lettered
together -- rather than pretending to a per-record resolution the API
doesn't support.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.domain.ports import OutboxPort, WazuhEventPort
from app.infrastructure.wazuh.client import compute_retry_delay


class WazuhOutboxDispatcher:
    def __init__(self, outbox: OutboxPort, wazuh: WazuhEventPort, batch_size: int = 100) -> None:
        self._outbox = outbox
        self._wazuh = wazuh
        self._batch_size = batch_size

    async def run_once(self) -> int:
        """Claim one batch and resolve it against Wazuh. Returns batch size (0 = idle)."""
        batch = await self._outbox.claim_batch(self._batch_size)
        if not batch:
            return 0

        ids = [record.id for record in batch]
        events = [record.payload for record in batch]
        result = await self._wazuh.send_events(events)

        if result.rejected == 0 and not result.retryable:
            await self._outbox.mark_delivered(ids)
            return len(batch)

        if result.retryable:
            attempt = max((record.attempts for record in batch), default=0)
            delay = compute_retry_delay(attempt, result.retry_after_seconds)
            retry_at = datetime.now(UTC) + timedelta(seconds=delay)
            await self._outbox.reschedule(
                ids, retry_at, reason=result.reason or "retryable_delivery_failure"
            )
            return len(batch)

        # Not retryable, not a clean success: a permanent rejection.
        # No per-record detail from Wazuh's bulk API, so the whole
        # batch is dead-lettered together.
        await self._outbox.mark_dead(ids, reason=result.reason or "permanent_delivery_failure")
        return len(batch)