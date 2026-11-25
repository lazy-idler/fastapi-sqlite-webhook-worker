# Why Most Single-Node Python Workers Do Not Need Redis or Celery

Whenever a developer adds background job processing to a Python API, muscle memory points straight to Redis plus Celery (or RQ). Five minutes later, a service that previously needed `uvicorn` and one file on disk now requires a message broker container, serialization conventions, worker heartbeat monitoring, beat schedulers, and retry state split across two separate storage engines.

For multi-host distributed clusters pushing tens of thousands of jobs per minute, dedicated brokers make clear sense. For single-node SaaS backends, webhook receivers, internal automation tools, and early-stage APIs handling hundreds of requests per minute, Redis + Celery is often premature operational tax.

## The Hidden Failure Modes of Separate Brokers

Splitting application data (SQLite or PostgreSQL) from queue state (Redis) creates the classic dual-write problem:

1. Your API inserts an invoice or event row into the database.
2. Before the queue publish call completes (or right after an uncaught network blip), the worker process misses the task or picks up an ID whose database transaction has not committed yet.
3. Fixing that gap reliably forces teams into transactional outbox tables anyway - meaning you now maintain **both** a database queue table and an in-memory broker.

Memory-backed queues also introduce quiet data-loss edges under restarts unless AOF persistence is carefully tuned, whereas relational WAL journals treat durability as default behavior.

## Measuring What SQLite WAL Actually Gives You

In production benchmarks on modest NVMe SSDs, SQLite in WAL (`Write-Ahead Logging`) mode paired with `BEGIN IMMEDIATE` and bounded `busy_timeout` handles well over 2,000 short transactional writes per second cleanly from a single host.

In our reference implementation (`app/storage.py` and `app/worker.py`), three SQL primitives replace Redis, Celery, and a dead-letter plugin in under 200 lines of Python:

- **Atomic Deduplication & Outbox Persistence**: One `BEGIN IMMEDIATE` transaction inserts `(source, event_id, payload_sha256, status)` with `ON CONFLICT DO NOTHING RETURNING`. Duplicate deliveries return `HTTP 200` immediately; conflicting payloads with reused IDs trigger `HTTP 409`. Zero extra cache lookups needed.
- **Lease-Based Crash Recovery**: Instead of fire-and-forget broker acks, workers claim jobs using an explicit `lease_until` timestamp (`UPDATE ... WHERE (status='pending' OR (status='processing' AND lease_until < ?))`). If a worker dies from OOM or SIGKILL mid-request, another worker reclaims the expired lease cleanly on the next poll cycle.
- **Built-in Exponential Backoff & Dead-Letter Requeue**: Failed deliveries update `attempts` and compute `next_attempt_at` with jitter right inside the same table. Exceeding `MAX_ATTEMPTS` flips `status = 'dead_letter'`, ready for one-click requeue via `/events/{source}/{event_id}/requeue`.

## Three Numbers to Check Before Adding Redis

Before introducing a second runtime daemon, check three concrete thresholds for your workload:

1. **Write concurrency**: Are you consistently exceeding 500 concurrent queued write transactions per second across multiple application servers? On one machine, SQLite WAL absorbs bursty webhook spikes without breaking a sweat.
2. **Horizontal multi-node worker pools**: Do multiple independent VMs need to pull from the exact same queue simultaneously? Once you outgrow one VPS/container host, move cleanly to PostgreSQL `SELECT ... FOR UPDATE SKIP LOCKED` or an external broker.
3. **Sub-10ms latency fanout**: Do workers require microsecond pub/sub wakeup rather than 50ms-250ms local asyncio polling or event triggers? Only then does an in-memory broker earn its keep.

## Keep Infrastructure Proportional to Actual Load

Deleting unnecessary moving parts is usually the highest-leverage reliability upgrade available to small teams. Starting with SQLite WAL gives zero network hops between durable state and job leases, single-file backups, 100% deterministic `pytest` execution without Docker test containers, and clean observability with standard SQL queries.

When traffic eventually demands horizontal worker scaling, the lease table schema (`source`, `event_id`, `lease_until`, `attempts`, `next_attempt_at`) ports straight into PostgreSQL with zero architectural rewrite. Until that day arrives, one process and one ACID file beat three containers every time.
