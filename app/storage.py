"""SQLite WAL-backed durable webhook queue with atomic deduplication and lease claiming."""

from __future__ import annotations

import hashlib
import json
import random
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

EnqueueOutcome = Literal["accepted", "duplicate", "conflict"]

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS webhook_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'succeeded', 'dead_letter')),
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    next_run_at REAL NOT NULL,
    locked_until REAL,
    worker_id TEXT,
    last_error TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    completed_at REAL,
    UNIQUE (source, event_id)
);

CREATE INDEX IF NOT EXISTS idx_webhook_events_poll
    ON webhook_events (status, next_run_at, locked_until);
"""


@dataclass(frozen=True, slots=True)
class EnqueueResult:
    """Result of an atomic webhook enqueue attempt."""

    outcome: EnqueueOutcome
    source: str
    event_id: str
    status: str


@dataclass(frozen=True, slots=True)
class ClaimedEvent:
    """A webhook event leased to a specific worker instance for processing."""

    row_id: int
    source: str
    event_id: str
    event_type: str
    payload: dict[str, Any]
    attempts: int
    max_attempts: int
    worker_id: str


@dataclass(frozen=True, slots=True)
class EventRecord:
    """Read-only projection of a stored webhook event."""

    row_id: int
    source: str
    event_id: str
    event_type: str
    status: str
    attempts: int
    max_attempts: int
    next_run_at: float
    locked_until: float | None
    worker_id: str | None
    last_error: str | None
    created_at: float
    updated_at: float
    completed_at: float | None


def compute_backoff_seconds(
    attempts: int,
    *,
    base_seconds: float,
    cap_seconds: float,
    jitter_ratio: float = 0.2,
    rng: random.Random | None = None,
) -> float:
    """Compute capped exponential backoff with positive jitter for retry scheduling."""
    exponent = max(0, attempts - 1)
    delay = min(cap_seconds, base_seconds * (2**exponent))
    if jitter_ratio <= 0:
        return delay
    generator = rng if rng is not None else random
    return delay + generator.uniform(0.0, delay * jitter_ratio)


class WebhookStore:
    """Thread-safe SQLite store supporting WAL reads and atomic lease transitions."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)

    def _connect(self) -> sqlite3.Connection:
        # Use manual transaction boundaries so BEGIN IMMEDIATE acquires write locks upfront.
        conn = sqlite3.connect(self.db_path, timeout=5.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def init_db(self) -> None:
        """Create database parent directories, schema, and indexes if missing."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)

    def enqueue_event(
        self,
        *,
        source: str,
        event_id: str,
        event_type: str,
        payload: dict[str, Any],
        raw_body: bytes,
        max_attempts: int = 4,
        now: float | None = None,
    ) -> EnqueueResult:
        """Insert a webhook event atomically or detect a duplicate/conflicting replay."""
        ts = time.time() if now is None else now
        payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        payload_sha256 = hashlib.sha256(raw_body).hexdigest()

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                inserted = conn.execute(
                    """
                    INSERT INTO webhook_events (
                        source, event_id, event_type, payload_json, payload_sha256,
                        status, attempts, max_attempts, next_run_at,
                        created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?)
                    ON CONFLICT (source, event_id) DO NOTHING
                    RETURNING status;
                    """,
                    (
                        source,
                        event_id,
                        event_type,
                        payload_json,
                        payload_sha256,
                        max_attempts,
                        ts,
                        ts,
                        ts,
                    ),
                ).fetchone()

                if inserted is not None:
                    conn.execute("COMMIT;")
                    return EnqueueResult(
                        outcome="accepted",
                        source=source,
                        event_id=event_id,
                        status=inserted["status"],
                    )

                existing = conn.execute(
                    """
                    SELECT status, payload_sha256
                    FROM webhook_events
                    WHERE source = ? AND event_id = ?;
                    """,
                    (source, event_id),
                ).fetchone()
                conn.execute("COMMIT;")

                if existing is None:
                    raise RuntimeError("Conflict detected but existing webhook row disappeared.")

                if existing["payload_sha256"] != payload_sha256:
                    return EnqueueResult(
                        outcome="conflict",
                        source=source,
                        event_id=event_id,
                        status=existing["status"],
                    )

                return EnqueueResult(
                    outcome="duplicate",
                    source=source,
                    event_id=event_id,
                    status=existing["status"],
                )
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def claim_next_event(
        self,
        *,
        worker_id: str,
        lease_seconds: float = 30.0,
        now: float | None = None,
    ) -> ClaimedEvent | None:
        """Atomically claim one due pending event or reclaim an expired processing lease."""
        ts = time.time() if now is None else now
        lease_until = ts + lease_seconds

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                # Move crashed jobs that already spent their retry budget into dead_letter.
                conn.execute(
                    """
                    UPDATE webhook_events
                    SET status = 'dead_letter',
                        locked_until = NULL,
                        worker_id = NULL,
                        last_error = COALESCE(last_error, 'Worker lease expired at max_attempts.'),
                        updated_at = ?
                    WHERE status = 'processing'
                      AND locked_until IS NOT NULL
                      AND locked_until <= ?
                      AND attempts >= max_attempts;
                    """,
                    (ts, ts),
                )

                row = conn.execute(
                    """
                    WITH candidate AS (
                        SELECT id
                        FROM webhook_events
                        WHERE (
                            status = 'pending' AND next_run_at <= ? AND attempts < max_attempts
                        ) OR (
                            status = 'processing'
                            AND locked_until IS NOT NULL
                            AND locked_until <= ?
                            AND attempts < max_attempts
                        )
                        ORDER BY next_run_at ASC, id ASC
                        LIMIT 1
                    )
                    UPDATE webhook_events
                    SET status = 'processing',
                        attempts = attempts + 1,
                        locked_until = ?,
                        worker_id = ?,
                        updated_at = ?
                    WHERE id = (SELECT id FROM candidate)
                    RETURNING id, source, event_id, event_type, payload_json, attempts, max_attempts;
                    """,
                    (ts, ts, lease_until, worker_id, ts),
                ).fetchone()
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

        if row is None:
            return None

        return ClaimedEvent(
            row_id=row["id"],
            source=row["source"],
            event_id=row["event_id"],
            event_type=row["event_type"],
            payload=json.loads(row["payload_json"]),
            attempts=row["attempts"],
            max_attempts=row["max_attempts"],
            worker_id=worker_id,
        )

    def mark_succeeded(self, *, row_id: int, worker_id: str, now: float | None = None) -> bool:
        """Mark a leased event succeeded if the caller still owns the active lease."""
        ts = time.time() if now is None else now
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                cur = conn.execute(
                    """
                    UPDATE webhook_events
                    SET status = 'succeeded',
                        locked_until = NULL,
                        worker_id = NULL,
                        last_error = NULL,
                        completed_at = ?,
                        updated_at = ?
                    WHERE id = ? AND status = 'processing' AND worker_id = ?;
                    """,
                    (ts, ts, row_id, worker_id),
                )
                conn.execute("COMMIT;")
                return cur.rowcount == 1
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def mark_retry_or_dead_letter(
        self,
        *,
        row_id: int,
        worker_id: str,
        error_message: str,
        backoff_base_seconds: float,
        backoff_cap_seconds: float,
        jitter_ratio: float = 0.2,
        force_dead_letter: bool = False,
        now: float | None = None,
    ) -> str | None:
        """Schedule exponential backoff retry or move to dead_letter when attempts exhaust."""
        ts = time.time() if now is None else now
        trimmed_error = error_message[:1000]

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                row = conn.execute(
                    """
                    SELECT attempts, max_attempts
                    FROM webhook_events
                    WHERE id = ? AND status = 'processing' AND worker_id = ?;
                    """,
                    (row_id, worker_id),
                ).fetchone()
                if row is None:
                    conn.execute("COMMIT;")
                    return None

                if force_dead_letter or row["attempts"] >= row["max_attempts"]:
                    next_status = "dead_letter"
                    next_run_at = ts
                else:
                    next_status = "pending"
                    delay = compute_backoff_seconds(
                        row["attempts"],
                        base_seconds=backoff_base_seconds,
                        cap_seconds=backoff_cap_seconds,
                        jitter_ratio=jitter_ratio,
                    )
                    next_run_at = ts + delay

                conn.execute(
                    """
                    UPDATE webhook_events
                    SET status = ?,
                        next_run_at = ?,
                        locked_until = NULL,
                        worker_id = NULL,
                        last_error = ?,
                        updated_at = ?
                    WHERE id = ? AND status = 'processing' AND worker_id = ?;
                    """,
                    (next_status, next_run_at, trimmed_error, ts, row_id, worker_id),
                )
                conn.execute("COMMIT;")
                return next_status
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def get_event(self, *, source: str, event_id: str) -> EventRecord | None:
        """Fetch a single event record by `(source, event_id)`."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, source, event_id, event_type, status, attempts, max_attempts,
                       next_run_at, locked_until, worker_id, last_error,
                       created_at, updated_at, completed_at
                FROM webhook_events
                WHERE source = ? AND event_id = ?;
                """,
                (source, event_id),
            ).fetchone()
        return self._row_to_record(row) if row is not None else None

    def list_dead_letters(self, *, limit: int = 50) -> list[EventRecord]:
        """Return recent dead-lettered webhook events ordered newest first."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, source, event_id, event_type, status, attempts, max_attempts,
                       next_run_at, locked_until, worker_id, last_error,
                       created_at, updated_at, completed_at
                FROM webhook_events
                WHERE status = 'dead_letter'
                ORDER BY updated_at DESC, id DESC
                LIMIT ?;
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def requeue_dead_letter(
        self,
        *,
        source: str,
        event_id: str,
        reset_attempts: bool = True,
        now: float | None = None,
    ) -> bool:
        """Reset a dead-lettered event back to pending for immediate replay."""
        ts = time.time() if now is None else now
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                cur = conn.execute(
                    """
                    UPDATE webhook_events
                    SET status = 'pending',
                        attempts = CASE WHEN ? THEN 0 ELSE attempts END,
                        next_run_at = ?,
                        locked_until = NULL,
                        worker_id = NULL,
                        last_error = NULL,
                        updated_at = ?
                    WHERE source = ? AND event_id = ? AND status = 'dead_letter';
                    """,
                    (1 if reset_attempts else 0, ts, ts, source, event_id),
                )
                conn.execute("COMMIT;")
                return cur.rowcount == 1
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> EventRecord:
        return EventRecord(
            row_id=row["id"],
            source=row["source"],
            event_id=row["event_id"],
            event_type=row["event_type"],
            status=row["status"],
            attempts=row["attempts"],
            max_attempts=row["max_attempts"],
            next_run_at=row["next_run_at"],
            locked_until=row["locked_until"],
            worker_id=row["worker_id"],
            last_error=row["last_error"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            completed_at=row["completed_at"],
        )
