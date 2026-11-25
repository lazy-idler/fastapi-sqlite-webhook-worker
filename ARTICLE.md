# Building Idempotent, Retry-Safe Python Webhook Workers with FastAPI and SQLite

## Introduction

Webhook providers treat HTTP endpoints as unreliable transport. Stripe, GitHub, and Shopify all assume requests time out, drop mid-flight, or arrive twice when network links flap. If your FastAPI route runs billing updates or external API calls directly inside the request handler, one slow downstream dependency turns a routine timeout into duplicate side effects.

Separating HTTP ingestion from background execution fixes that failure mode without adding Redis, Celery, or RabbitMQ to your stack. You can verify the incoming request signature against raw payload bytes, persist the event atomically in SQLite with Write-Ahead Logging (WAL) enabled, and return `202 Accepted` in milliseconds. A background worker loop then claims rows with time-bounded leases, backs off exponentially on transient errors, and quarantines permanent failures in a dead-letter state.

In this tutorial, you will build and verify that complete webhook service using Python 3.12, FastAPI, and SQLite. By the end, your service will block signature tampering and replay attacks, deduplicate concurrent identical deliveries inside one transaction, and recover safely if a worker process crashes mid-job.

## Prerequisites

To run every code example and test in this guide, you need:

- Python 3.12 or newer (Python 3.12 bundles SQLite 3.45+, which provides the `ON CONFLICT ... DO NOTHING` and `RETURNING` clauses used below).
- A virtual environment tool such as `venv` or `uv`.
- Familiarity with FastAPI routes, HTTP status codes, and parameterized SQL.

Every command and test output below was verified on Python 3.12.7 with SQLite 3.45.3 and the dependency pins in `requirements.txt`.

## Step 1: Project Layout and Configuration

Organize the service into focused modules inside `sample_tutorial_01/` so cryptographic checks, database locking, worker scheduling, and HTTP routing stay decoupled:

```text
sample_tutorial_01/
├── .env.example
├── requirements.txt
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── main.py
│   ├── security.py
│   ├── storage.py
│   └── worker.py
├── scripts/
│   └── send_webhook.py
└── tests/
    └── test_webhook_worker.py
```

Pin exact dependencies in `requirements.txt`. Including `httpx2==2.16.2` alongside `httpx==0.28.1` silences a `StarletteDeprecationWarning` triggered by `TestClient` under Starlette 1.10.0 (installed with FastAPI 0.141.1), while `httpx` powers the standalone CLI test script:

```text
# requirements.txt
fastapi==0.141.1
uvicorn==0.41.0
pydantic==2.12.5
httpx==0.28.1
httpx2==2.16.2
pytest==9.1.1
```

Document runtime tuning knobs in `.env.example` so teammates never hardcode signing keys or queue timeouts:

```ini
# .env.example
WEBHOOK_SECRET=local-dev-hmac-signing-key-change-in-production
WEBHOOK_DB_PATH=./webhooks.db
WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS=300
WEBHOOK_MAX_BODY_BYTES=262144
WEBHOOK_MAX_ATTEMPTS=4
WEBHOOK_POLL_INTERVAL_SECONDS=0.2
WEBHOOK_LEASE_SECONDS=30.0
WEBHOOK_BACKOFF_BASE_SECONDS=1.0
WEBHOOK_BACKOFF_CAP_SECONDS=60.0
WEBHOOK_HANDLER_TIMEOUT_SECONDS=10.0
```

Create a clean virtual environment and install the pinned packages:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Next, define an immutable `Settings` dataclass in `app/config.py` so worker tasks cannot mutate shared retry thresholds at runtime:

```python
# app/config.py (excerpt)
@dataclass(frozen=True, slots=True)
class Settings:
    webhook_secret: str = "local-dev-hmac-signing-key-change-in-production"
    db_path: Path = Path("./webhooks.db")
    timestamp_tolerance_seconds: int = 300
    max_body_bytes: int = 262_144
    max_attempts: int = 4
    poll_interval_seconds: float = 0.2
    lease_seconds: float = 30.0
    backoff_base_seconds: float = 1.0
    backoff_cap_seconds: float = 60.0
    handler_timeout_seconds: float = 10.0
```

`Settings.from_env()` reads those ten variables from `os.environ` at startup and falls back to safe local defaults. In production, enforce a non-default `WEBHOOK_SECRET` at boot and load it from your secret manager.

## Step 2: Verifying Raw Webhook Signatures and Replay Windows

Two mistakes break custom webhook receivers in production. First, binding a Pydantic model directly in the route signature lets FastAPI parse JSON before HMAC verification, and re-serializing with `json.dumps()` alters whitespace or key order enough to fail valid signatures. Second, verifying only the payload without a signed timestamp allows an attacker to replay any captured request indefinitely.

Compute and verify signatures over the literal bytes returned by `await request.body()`, prefixed with the integer Unix timestamp (`"{timestamp}.".encode("utf-8") + raw_body`). Compare digests using `hmac.compare_digest` to block timing side channels.

Write `app/security.py`:

```python
# app/security.py
from __future__ import annotations

import hashlib
import hmac
import time


class SignatureVerificationError(ValueError):
    """Raised when webhook timestamp or signature headers fail validation."""


def compute_signature(secret: str, timestamp: int, raw_body: bytes) -> str:
    """Return a versioned HMAC-SHA256 signature (`v1=<hex>`) over timestamp and raw bytes."""
    signed_payload = f"{timestamp}.".encode("utf-8") + raw_body
    digest = hmac.new(
        key=secret.encode("utf-8"),
        msg=signed_payload,
        digestmod=hashlib.sha256,
    ).hexdigest()
    return f"v1={digest}"


def verify_webhook_signature(
    *,
    secret: str,
    raw_body: bytes,
    timestamp_header: str | None,
    signature_header: str | None,
    tolerance_seconds: int = 300,
    now: float | None = None,
) -> int:
    """Validate timestamp freshness and HMAC signature using constant-time comparison."""
    if not timestamp_header or not signature_header:
        raise SignatureVerificationError("Missing required webhook security headers.")

    try:
        timestamp = int(timestamp_header.strip())
    except ValueError as exc:
        raise SignatureVerificationError("Invalid X-Webhook-Timestamp header.") from exc

    current_time = time.time() if now is None else now
    if abs(current_time - timestamp) > tolerance_seconds:
        raise SignatureVerificationError("Webhook timestamp is outside the allowed tolerance window.")

    expected = compute_signature(secret=secret, timestamp=timestamp, raw_body=raw_body)
    if not hmac.compare_digest(expected, signature_header.strip()):
        raise SignatureVerificationError("Webhook signature mismatch.")

    return timestamp
```

Checking `abs(current_time - timestamp) > tolerance_seconds` tolerates minor clock skew while capping replay exposure at five minutes. Prefixing digests with `v1=` also gives you a clear upgrade path when rotating signing versions.

## Step 3: Implementing Atomic Deduplication and Leases in SQLite

Application-level deduplication fails under concurrent deliveries. When two identical webhooks arrive at the same millisecond, a `SELECT` followed by an `INSERT` lets both requests pass the read check before either commits.

SQLite eliminates that race when you combine three settings in `app/storage.py`:

1. A composite `UNIQUE (source, event_id)` constraint so identical IDs from separate providers (`billing` versus `github`) stay isolated while retries from the same source collide deterministically.
2. `PRAGMA journal_mode=WAL;` paired with `PRAGMA busy_timeout=5000;` so reads do not stall behind writes.
3. Explicit `BEGIN IMMEDIATE` transactions opened with `isolation_level=None` so SQLite acquires the write lock upfront, preventing write-upgrade deadlocks (`SQLITE_BUSY`).

The `webhook_events` table also stores `payload_sha256`. Identical retries return `200 OK` safely, whereas a reused `event_id` carrying altered body bytes returns `409 Conflict` instead of silently discarding changed data.

Define the schema inside `app/storage.py`:

```sql
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
```

Inside `WebhookStore`, every method opens a short-lived connection through `_connect()` with `timeout=5.0` and `isolation_level=None`. Opening a connection per operation avoids Python thread-affinity errors across FastAPI's worker thread pool while SQLite's page cache keeps connection cost negligible.

Look at how `enqueue_event` handles insertion and duplicate detection atomically inside one `BEGIN IMMEDIATE` block:

```python
# app/storage.py (enqueue_event excerpt)
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
    (source, event_id, event_type, payload_json, payload_sha256, max_attempts, ts, ts, ts),
).fetchone()

if inserted is not None:
    conn.execute("COMMIT;")
    return EnqueueResult(outcome="accepted", source=source, event_id=event_id, status=inserted["status"])

existing = conn.execute(
    "SELECT status, payload_sha256 FROM webhook_events WHERE source = ? AND event_id = ?;",
    (source, event_id),
).fetchone()
conn.execute("COMMIT;")

if existing["payload_sha256"] != payload_sha256:
    return EnqueueResult(outcome="conflict", source=source, event_id=event_id, status=existing["status"])
return EnqueueResult(outcome="duplicate", source=source, event_id=event_id, status=existing["status"])
```

Job claiming follows the same pattern in `claim_next_event`. First, a pre-claim `UPDATE` moves any crashed `processing` rows whose lease expired (`locked_until <= ts`) and whose `attempts >= max_attempts` directly into `dead_letter`, stopping poison-pill crashes from looping forever. Next, a `WITH candidate AS (...) UPDATE ... RETURNING` statement claims either the earliest due `pending` job or an expired lease with remaining retry budget:

```python
# app/storage.py (claim_next_event excerpt)
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
```

This single statement addresses three concurrency hazards cleanly:

| Failure scenario | Database protection | Resulting state |
| :--- | :--- | :--- |
| Concurrent worker polls | `BEGIN IMMEDIATE` serializes claims | Only one worker claims each row |
| Worker crashes mid-job | `locked_until <= now` reclaim filter | Another worker resumes after lease expiry |
| Poison job crashes workers repeatedly | Pre-claim sweep checks `attempts >= max_attempts` | Row moves to `dead_letter` |

Completion updates (`mark_succeeded`) and failure updates (`mark_retry_or_dead_letter`) both filter with `WHERE id = ? AND status = 'processing' AND worker_id = ?`. That `worker_id` fencing guard prevents a slow worker returning from a long pause after its lease expired from overwriting a second worker's newer state.

## Step 4: Building the Retry-Safe Background Worker

In `app/worker.py`, `WebhookWorker` offloads all SQLite disk calls using `asyncio.to_thread` so database writes never block FastAPI's event loop, and wraps each handler call with `asyncio.wait_for` using `handler_timeout_seconds`.

When a handler raises `NonRetryableError` (for instance, a missing required customer identifier), the worker sets `force_dead_letter=True` so bad payloads skip pointless retries. All other exceptions schedule capped exponential backoff (`min(cap, base * 2**(attempts - 1))`) plus random positive jitter (`0%` to `20%`) to avoid synchronized retry storms:

```python
# app/worker.py (process_once excerpt)
async def process_once(self) -> bool:
    claimed = await asyncio.to_thread(
        self.store.claim_next_event,
        worker_id=self.worker_id,
        lease_seconds=self.settings.lease_seconds,
    )
    if claimed is None:
        return False

    try:
        await asyncio.wait_for(
            self._invoke_handler(claimed),
            timeout=self.settings.handler_timeout_seconds,
        )
    except NonRetryableError as exc:
        await asyncio.to_thread(
            self.store.mark_retry_or_dead_letter,
            row_id=claimed.row_id,
            worker_id=self.worker_id,
            error_message=f"NonRetryableError: {exc}",
            backoff_base_seconds=self.settings.backoff_base_seconds,
            backoff_cap_seconds=self.settings.backoff_cap_seconds,
            jitter_ratio=0.0,
            force_dead_letter=True,
        )
        return True
    except Exception as exc:
        await asyncio.to_thread(
            self.store.mark_retry_or_dead_letter,
            row_id=claimed.row_id,
            worker_id=self.worker_id,
            error_message=f"{type(exc).__name__}: {exc}",
            backoff_base_seconds=self.settings.backoff_base_seconds,
            backoff_cap_seconds=self.settings.backoff_cap_seconds,
            jitter_ratio=self.jitter_ratio,
        )
        return True

    await asyncio.to_thread(
        self.store.mark_succeeded,
        row_id=claimed.row_id,
        worker_id=self.worker_id,
    )
    return True
```

Inside `_run_loop`, the worker drains back-to-back events immediately whenever `process_once` returns `True`, and waits on `self._stop_event.wait()` up to `poll_interval_seconds` when idle so shutdown signals wake the loop immediately.

## Step 5: Wiring FastAPI Endpoints and Graceful Lifespan Shutdown

FastAPI's `lifespan` context manager initializes the SQLite schema, starts `WebhookWorker`, and awaits `worker.stop()` during shutdown so active handlers finish before process exit. Keeping setup inside `create_app(settings=..., handler=...)` also lets tests swap in isolated temporary databases and deterministic fault handlers.

Write the ingestion route in `app/main.py` so validation runs in strict cost order: source path regex, body byte limit (`413`), HMAC signature (`401`), UTF-8 JSON decoding (`400`), Pydantic envelope (`422`), and atomic enqueue (`202`, `200`, or `409`):

```python
# app/main.py (ingest_webhook excerpt)
@app.post("/webhooks/{source}")
async def ingest_webhook(source: str, request: Request, response: Response) -> dict[str, str]:
    if not SOURCE_PATTERN.match(source):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid webhook source identifier.")

    raw_body = await request.body()
    if len(raw_body) > cfg.max_body_bytes:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="Payload exceeds maximum allowed byte size.")

    try:
        verify_webhook_signature(
            secret=cfg.webhook_secret,
            raw_body=raw_body,
            timestamp_header=request.headers.get("X-Webhook-Timestamp"),
            signature_header=request.headers.get("X-Webhook-Signature"),
            tolerance_seconds=cfg.timestamp_tolerance_seconds,
        )
    except SignatureVerificationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    try:
        parsed_json = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Request body must be valid UTF-8 JSON.") from exc

    try:
        envelope = WebhookEnvelope.model_validate(parsed_json)
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=exc.errors()) from exc

    result = store.enqueue_event(
        source=source,
        event_id=envelope.event_id,
        event_type=envelope.event_type,
        payload=envelope.payload,
        raw_body=raw_body,
        max_attempts=cfg.max_attempts,
    )
    if result.outcome == "conflict":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Event ID already exists with a different payload digest.")
    if result.outcome == "duplicate":
        response.status_code = status.HTTP_200_OK
        return {"outcome": "duplicate", "source": result.source, "event_id": result.event_id, "status": result.status}

    response.status_code = status.HTTP_202_ACCEPTED
    return {"outcome": "accepted", "source": result.source, "event_id": result.event_id, "status": result.status}
```

Checking signatures before JSON parsing ensures unauthenticated callers cannot trigger heavy parser work. Alongside `POST /webhooks/{source}`, `app/main.py` exposes `GET /health`, `GET /events/{source}/{event_id}`, `GET /dead-letters`, and `POST /dead-letters/{source}/{event_id}/requeue` for operational inspection and manual replay.

## Step 6: Running the Automated Test Suite and Live Verification

The companion test file `tests/test_webhook_worker.py` verifies five core invariants:

1. Missing headers, bad digests, expired timestamps, and whitespace-modified bodies all return `401`.
2. Firing eight identical signed requests concurrently via `ThreadPoolExecutor` yields exactly one `202 Accepted`, seven `200 OK` duplicates, one handler execution, and `409 Conflict` if the ID is reused with altered JSON bytes.
3. Simulated downstream exceptions retry with backoff, transition to `dead_letter` after `max_attempts`, and succeed after calling `/dead-letters/.../requeue`.
4. Expired leases after a simulated worker crash are reclaimed by another worker while stale `mark_succeeded` calls from the original worker return `False`.
5. Oversized payloads return `413`, malformed JSON returns `400`, and `NonRetryableError` skips retries immediately.

Run the test suite from `sample_tutorial_01/`:

```bash
pytest -v
```

Expected output from a clean virtual environment:

```text
============================= test session starts =============================
collecting ... collected 5 items

tests/test_webhook_worker.py::test_rejects_invalid_and_replayed_signatures PASSED [ 20%]
tests/test_webhook_worker.py::test_atomic_deduplication_under_concurrent_delivery PASSED [ 40%]
tests/test_webhook_worker.py::test_transient_retries_then_dead_letter_and_requeue PASSED [ 60%]
tests/test_webhook_worker.py::test_stale_lease_reclaimed_after_simulated_worker_crash PASSED [ 80%]
tests/test_webhook_worker.py::test_non_retryable_error_and_body_validation PASSED [100%]

============================== 5 passed in 2.07s ==============================
```

Now verify the full HTTP lifecycle against a running server. Launch Uvicorn in one terminal:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In a second terminal, check health and send a signed event with `scripts/send_webhook.py`:

```bash
curl -s http://127.0.0.1:8000/health
python scripts/send_webhook.py --url http://127.0.0.1:8000/webhooks/billing --event-id evt_demo_001
```

The health probe succeeds and the first delivery returns `202 Accepted`:

```text
{"status":"ok"}
HTTP 202: {"outcome":"accepted","source":"billing","event_id":"evt_demo_001","status":"pending"}
```

Send the exact same event again and query its status record:

```bash
python scripts/send_webhook.py --url http://127.0.0.1:8000/webhooks/billing --event-id evt_demo_001
curl -s http://127.0.0.1:8000/events/billing/evt_demo_001
```

Because the background worker already completed the event, the duplicate delivery returns `200 OK` without incrementing `attempts`:

```text
HTTP 200: {"outcome":"duplicate","source":"billing","event_id":"evt_demo_001","status":"succeeded"}
{"row_id":1,"source":"billing","event_id":"evt_demo_001","event_type":"invoice.paid","status":"succeeded","attempts":1,"max_attempts":4,"next_run_at":1795599353.497333,"locked_until":null,"worker_id":null,"last_error":null,"created_at":1795599353.497333,"updated_at":1795599353.5662038,"completed_at":1795599353.5662038}
```

Finally, verify signature rejection and conflict detection:

```bash
python scripts/send_webhook.py --url http://127.0.0.1:8000/webhooks/billing --event-id evt_demo_002 --secret wrong-secret
python scripts/send_webhook.py --url http://127.0.0.1:8000/webhooks/billing --event-id evt_demo_001 --payload '{"amount_cents":9999,"currency":"USD"}'
```

Both invalid requests fail before mutating queue state:

```text
HTTP 401: {"detail":"Webhook signature mismatch."}
HTTP 409: {"detail":"Event ID already exists with a different payload digest."}
```

## Production Tradeoffs and Next Steps

SQLite WAL handles single-node webhook queues cleanly up to several hundred events per second with zero broker maintenance. Keep three operational constraints in mind before deploying to production:

1. **Single-writer topology**: SQLite serializes writes per database file. Run Uvicorn with `--workers 1` when embedding `WebhookWorker` inside FastAPI lifespan, or split the worker into one dedicated OS process sharing local SSD storage. Never store SQLite files on NFS or EFS, where advisory file locks behave inconsistently.
2. **Idempotent downstream writes**: Worker leases guarantee at-least-once delivery across crashes, not transactional remote APIs. Forward `(source, event_id)` as an idempotency key to downstream billing calls or enforce local unique constraints on business tables.
3. **Endpoint access and retention**: Place `/events/*` and `/dead-letters/*` behind reverse-proxy authentication or bearer tokens before public exposure, and run a periodic cleanup job to prune completed `succeeded` rows older than your audit window.

When volume requires multiple horizontally scaled API containers across availability zones, keep the same `WebhookStore` method signatures and swap the SQLite backend for PostgreSQL using `INSERT ... ON CONFLICT DO NOTHING` and `SELECT ... FOR UPDATE SKIP LOCKED`.
