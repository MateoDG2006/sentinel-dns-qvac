"""SQLite-backed outbox (ADR-007). Implements domain.ports.OutboxPort."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import aiosqlite

from app.constants.health import OUTBOX_DEPENDENCY_NAME, OUTBOX_SQLITE_DETAIL
from app.domain.enums import DependencyStatus, OutboxStatus, WazuhEventType
from app.domain.schemas import DependencyHealth, OutboxRecord
from app.utils.time import UtcDateTime

_SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    prediction_id TEXT,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_reason TEXT,
    record_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    next_retry_at TEXT,
    claimed_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_outbox_event_id_type ON outbox(event_id, record_type);
CREATE INDEX IF NOT EXISTS ix_outbox_status_retry ON outbox(status, next_retry_at);
"""


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


class SqliteOutbox:
    """Durable, idempotent outbox backed by a local SQLite file.

    `updated_at` is internal bookkeeping only (not on the real
    OutboxRecord model) -- kept in the table for debugging, never
    exposed on the objects this class returns.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._conn: aiosqlite.Connection | None = None

    async def start(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(_SCHEMA)
        # VolatileOutbox and PredictionService key rows by (event_id, record_type)
        # so a dns_threat and a sentinel_operational alert can coexist. B1's first
        # unique index was event_id only; drop it on existing files.
        await self._conn.execute("DROP INDEX IF EXISTS ux_outbox_event_id")
        await self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_outbox_event_id_type "
            "ON outbox(event_id, record_type)"
        )
        # A row stuck in CLAIMED means the process died between
        # claim_batch() and mark_delivered()/reschedule()/mark_dead().
        # Reset it to PENDING on startup -- this is what makes
        # "reinicio no pierde pendientes" true in practice, not just
        # "rows survive on disk but are unreachable forever."
        await self._conn.execute(
            "UPDATE outbox SET status = ?, claimed_at = NULL WHERE status = ?",
            (OutboxStatus.PENDING.value, OutboxStatus.CLAIMED.value),
        )
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def enqueue(self, record: OutboxRecord) -> bool:
        assert self._conn is not None, "call start() first"
        cursor = await self._conn.execute(
            """
            INSERT OR IGNORE INTO outbox
                (id, event_id, prediction_id, payload, status, attempts,
                 last_reason, record_type, created_at, updated_at, next_retry_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(record.id),
                str(record.event_id),
                str(record.prediction_id) if record.prediction_id else None,
                record.payload,
                record.status.value,
                record.attempts,
                record.last_reason,
                record.record_type.value,
                record.created_at.isoformat(),
                _utcnow_iso(),
                record.next_retry_at.isoformat() if record.next_retry_at else None,
            ),
        )
        await self._conn.commit()
        # rowcount is 0 when UNIQUE(event_id, record_type) rejected the insert.
        return cursor.rowcount == 1

    async def pending_count(self) -> int:
        assert self._conn is not None, "call start() first"
        cursor = await self._conn.execute(
            "SELECT COUNT(*) FROM outbox WHERE status IN (?, ?)",
            (OutboxStatus.PENDING.value, OutboxStatus.CLAIMED.value),
        )
        row = await cursor.fetchone()
        return int(row[0]) if row is not None else 0

    async def health(self) -> DependencyHealth:
        checked_at = UtcDateTime.ensure(datetime.now(UTC))
        if self._conn is None:
            return DependencyHealth(
                name=OUTBOX_DEPENDENCY_NAME,
                status=DependencyStatus.DOWN,
                detail="not_started",
                checked_at=checked_at,
            )
        try:
            await self._conn.execute("SELECT 1")
        except aiosqlite.Error as exc:
            return DependencyHealth(
                name=OUTBOX_DEPENDENCY_NAME,
                status=DependencyStatus.DOWN,
                detail=type(exc).__name__,
                checked_at=checked_at,
            )
        return DependencyHealth(
            name=OUTBOX_DEPENDENCY_NAME,
            status=DependencyStatus.UP,
            detail=OUTBOX_SQLITE_DETAIL,
            checked_at=checked_at,
        )

    async def claim_batch(self, limit: int) -> list[OutboxRecord]:
        assert self._conn is not None, "call start() first"
        now = _utcnow_iso()
        cursor = await self._conn.execute(
            """
            UPDATE outbox
            SET status = ?, claimed_at = ?
            WHERE id IN (
                SELECT id FROM outbox
                WHERE status = ?
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                ORDER BY created_at
                LIMIT ?
            )
            RETURNING id, event_id, prediction_id, payload, status,
                      attempts, last_reason, record_type, created_at, next_retry_at
            """,
            (OutboxStatus.CLAIMED.value, now, OutboxStatus.PENDING.value, now, limit),
        )
        rows = await cursor.fetchall()
        await self._conn.commit()
        return [_row_to_record(row) for row in rows]

    async def mark_delivered(self, ids: list[UUID]) -> None:
        if not ids:
            return
        assert self._conn is not None, "call start() first"
        placeholders = ",".join("?" for _ in ids)
        await self._conn.execute(
            f"UPDATE outbox SET status = ?, updated_at = ? WHERE id IN ({placeholders})",
            (OutboxStatus.DELIVERED.value, _utcnow_iso(), *[str(i) for i in ids]),
        )
        await self._conn.commit()

    async def reschedule(self, ids: list[UUID], retry_at: datetime, reason: str) -> None:
        if not ids:
            return
        assert self._conn is not None, "call start() first"
        placeholders = ",".join("?" for _ in ids)
        await self._conn.execute(
            f"""
            UPDATE outbox
            SET status = ?, next_retry_at = ?, last_reason = ?,
                attempts = attempts + 1, updated_at = ?
            WHERE id IN ({placeholders})
            """,
            (
                OutboxStatus.PENDING.value,
                retry_at.isoformat(),
                reason,
                _utcnow_iso(),
                *[str(i) for i in ids],
            ),
        )
        await self._conn.commit()

    async def mark_dead(self, ids: list[UUID], reason: str) -> None:
        if not ids:
            return
        assert self._conn is not None, "call start() first"
        placeholders = ",".join("?" for _ in ids)
        await self._conn.execute(
            f"UPDATE outbox SET status = ?, last_reason = ?, updated_at = ? "
            f"WHERE id IN ({placeholders})",
            (OutboxStatus.DEAD.value, reason, _utcnow_iso(), *[str(i) for i in ids]),
        )
        await self._conn.commit()


def _row_to_record(row: aiosqlite.Row) -> OutboxRecord:
    return OutboxRecord(
        id=UUID(row["id"]),
        event_id=UUID(row["event_id"]),
        prediction_id=UUID(row["prediction_id"]) if row["prediction_id"] else None,
        created_at=datetime.fromisoformat(row["created_at"]),
        payload=row["payload"],
        status=OutboxStatus(row["status"]),
        attempts=row["attempts"],
        next_retry_at=(
            datetime.fromisoformat(row["next_retry_at"]) if row["next_retry_at"] else None
        ),
        last_reason=row["last_reason"],
        record_type=WazuhEventType(row["record_type"]),
    )
