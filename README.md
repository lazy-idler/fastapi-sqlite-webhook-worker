# Idempotent, Retry-Safe Python Webhook Worker (FastAPI + SQLite)

Reference implementation accompanying `ARTICLE.md` demonstrating production webhook ingestion:

- Raw-body HMAC-SHA256 verification with constant-time comparison and bounded timestamp replay checks
- SQLite WAL storage with `BEGIN IMMEDIATE` and `ON CONFLICT DO NOTHING ... RETURNING` atomic deduplication
- Payload digest conflict detection (`409 Conflict` when an existing `event_id` arrives with mutated bytes)
- Lease-based background worker with exponential backoff, jitter, stale-lease crash recovery, and dead-letter requeue endpoints

## Requirements

- Python 3.12+
- Dependencies in `requirements.txt` (`fastapi==0.141.1`, `uvicorn==0.41.0`, `pydantic==2.12.5`, `httpx==0.28.1`, `httpx2==2.16.2`, `pytest==9.1.1`)

## Quickstart

Create and activate a virtual environment, install dependencies, and run the test suite:

```bash
python -m venv .venv
. .venv/bin/activate  # On Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -v
```

Run the API server locally:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Send a signed webhook event and inspect its status:

```bash
python scripts/send_webhook.py --event-id evt_demo_001
curl http://127.0.0.1:8000/events/billing/evt_demo_001
```
