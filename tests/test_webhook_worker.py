"""Automated test suite for HMAC verification, concurrency dedupe, retries, and lease recovery."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.security import compute_signature
from app.storage import ClaimedEvent, WebhookStore
from app.worker import NonRetryableError


def _signed_headers(secret: str, raw_body: bytes, timestamp: int | None = None) -> dict[str, str]:
    ts = int(time.time()) if timestamp is None else timestamp
    return {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": str(ts),
        "X-Webhook-Signature": compute_signature(secret=secret, timestamp=ts, raw_body=raw_body),
    }


def _make_settings(tmp_path: Path, **overrides: object) -> Settings:
    defaults: dict[str, object] = {
        "webhook_secret": "unit-test-hmac-secret",
        "db_path": tmp_path / "webhooks.db",
        "timestamp_tolerance_seconds": 300,
        "max_body_bytes": 65_536,
        "max_attempts": 3,
        "poll_interval_seconds": 0.05,
        "lease_seconds": 1.0,
        "backoff_base_seconds": 0.05,
        "backoff_cap_seconds": 0.2,
        "handler_timeout_seconds": 2.0,
    }
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


def test_rejects_invalid_and_replayed_signatures(tmp_path: Path) -> None:
    cfg = _make_settings(tmp_path)
    app = create_app(cfg, run_worker=False)
    body = json.dumps({"event_id": "evt_auth_1", "event_type": "ping", "payload": {}}).encode("utf-8")

    with TestClient(app) as client:
        missing = client.post("/webhooks/billing", content=body)
        assert missing.status_code == 401

        bad_sig = client.post(
            "/webhooks/billing",
            content=body,
            headers={"X-Webhook-Timestamp": str(int(time.time())), "X-Webhook-Signature": "v1=deadbeef"},
        )
        assert bad_sig.status_code == 401

        stale_ts = int(time.time()) - 900
        expired = client.post(
            "/webhooks/billing",
            content=body,
            headers=_signed_headers(cfg.webhook_secret, body, timestamp=stale_ts),
        )
        assert expired.status_code == 401

        # Re-serializing JSON with whitespace changes the raw digest and must fail verification.
        valid_headers = _signed_headers(cfg.webhook_secret, body)
        tampered_whitespace = body.replace(b": ", b":  ")
        whitespace_mismatch = client.post("/webhooks/billing", content=tampered_whitespace, headers=valid_headers)
        assert whitespace_mismatch.status_code == 401


def test_atomic_deduplication_under_concurrent_delivery(tmp_path: Path) -> None:
    cfg = _make_settings(tmp_path)
    processed: list[str] = []

    def handler(event: ClaimedEvent) -> None:
        processed.append(event.event_id)

    app = create_app(cfg, handler=handler, run_worker=True)
    body = json.dumps(
        {
            "event_id": "evt_concurrent_01",
            "event_type": "order.created",
            "payload": {"customer": "홍길동", "note": "UTF-8 safe payload"},
        },
        ensure_ascii=False,
    ).encode("utf-8")

    with TestClient(app) as client:
        headers = _signed_headers(cfg.webhook_secret, body)

        def send_once() -> int:
            return client.post("/webhooks/shop", content=body, headers=headers).status_code

        with ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(lambda _: send_once(), range(8)))

        assert statuses.count(202) == 1
        assert statuses.count(200) == 7

        # Poll status endpoint briefly until worker marks the single queued job succeeded.
        deadline = time.time() + 2.0
        state = {}
        while time.time() < deadline:
            state = client.get("/events/shop/evt_concurrent_01").json()
            if state["status"] == "succeeded":
                break
            time.sleep(0.05)

        assert state["status"] == "succeeded"
        assert state["attempts"] == 1
        assert processed == ["evt_concurrent_01"]

        # Same event_id with altered payload bytes must trigger 409 Conflict.
        mutated = json.dumps(
            {"event_id": "evt_concurrent_01", "event_type": "order.created", "payload": {"customer": "other"}}
        ).encode("utf-8")
        conflict = client.post(
            "/webhooks/shop",
            content=mutated,
            headers=_signed_headers(cfg.webhook_secret, mutated),
        )
        assert conflict.status_code == 409


def test_transient_retries_then_dead_letter_and_requeue(tmp_path: Path) -> None:
    cfg = _make_settings(tmp_path, max_attempts=3, backoff_base_seconds=0.05, backoff_cap_seconds=0.1)
    attempts_seen = 0
    should_succeed = False

    def flaky_handler(event: ClaimedEvent) -> None:
        nonlocal attempts_seen
        attempts_seen += 1
        if not should_succeed:
            raise ConnectionError("Downstream ledger service unavailable")

    app = create_app(cfg, handler=flaky_handler, run_worker=True)
    body = json.dumps({"event_id": "evt_retry_99", "event_type": "payout.sent", "payload": {"amount": 250}}).encode(
        "utf-8"
    )

    with TestClient(app) as client:
        resp = client.post("/webhooks/payouts", content=body, headers=_signed_headers(cfg.webhook_secret, body))
        assert resp.status_code == 202

        deadline = time.time() + 3.0
        record = {}
        while time.time() < deadline:
            record = client.get("/events/payouts/evt_retry_99").json()
            if record["status"] == "dead_letter":
                break
            time.sleep(0.05)

        assert record["status"] == "dead_letter"
        assert record["attempts"] == 3
        assert attempts_seen == 3

        dlq = client.get("/dead-letters").json()
        assert dlq["count"] == 1
        assert dlq["items"][0]["event_id"] == "evt_retry_99"

        # Recover downstream and requeue via operator endpoint.
        should_succeed = True
        requeue_resp = client.post("/dead-letters/payouts/evt_retry_99/requeue")
        assert requeue_resp.status_code == 200

        deadline = time.time() + 2.0
        while time.time() < deadline:
            record = client.get("/events/payouts/evt_retry_99").json()
            if record["status"] == "succeeded":
                break
            time.sleep(0.05)

        assert record["status"] == "succeeded"
        assert attempts_seen == 4


def test_stale_lease_reclaimed_after_simulated_worker_crash(tmp_path: Path) -> None:
    store = WebhookStore(tmp_path / "crash.db")
    store.init_db()

    raw = b'{"event_id":"evt_crash_1","event_type":"sync.run","payload":{}}'
    enq = store.enqueue_event(
        source="sync",
        event_id="evt_crash_1",
        event_type="sync.run",
        payload={},
        raw_body=raw,
        max_attempts=3,
        now=1000.0,
    )
    assert enq.outcome == "accepted"

    # Worker A claims the event with a 10-second lease and disappears without acking.
    first_claim = store.claim_next_event(worker_id="worker-a", lease_seconds=10.0, now=1000.0)
    assert first_claim is not None
    assert first_claim.attempts == 1

    # Before lease expires, Worker B cannot steal the job.
    premature = store.claim_next_event(worker_id="worker-b", lease_seconds=10.0, now=1005.0)
    assert premature is None

    # After lease expires, Worker B reclaims and finishes the job, blocking late ack from Worker A.
    reclaimed = store.claim_next_event(worker_id="worker-b", lease_seconds=10.0, now=1011.0)
    assert reclaimed is not None
    assert reclaimed.attempts == 2
    assert store.mark_succeeded(row_id=first_claim.row_id, worker_id="worker-a", now=1012.0) is False
    assert store.mark_succeeded(row_id=reclaimed.row_id, worker_id="worker-b", now=1012.0) is True


def test_non_retryable_error_and_body_validation(tmp_path: Path) -> None:
    cfg = _make_settings(tmp_path, max_attempts=5, max_body_bytes=128)

    def strict_handler(event: ClaimedEvent) -> None:
        if "account_id" not in event.payload:
            raise NonRetryableError("Missing required account_id field")

    app = create_app(cfg, handler=strict_handler, run_worker=True)

    with TestClient(app) as client:
        oversized = b"{" + b"a" * 200 + b"}"
        too_big = client.post(
            "/webhooks/crm",
            content=oversized,
            headers=_signed_headers(cfg.webhook_secret, oversized),
        )
        assert too_big.status_code == 413

        bad_json = b"{not-json"
        malformed = client.post(
            "/webhooks/crm",
            content=bad_json,
            headers=_signed_headers(cfg.webhook_secret, bad_json),
        )
        assert malformed.status_code == 400

        bad_payload = json.dumps({"event_id": "evt_bad_1", "event_type": "user.sync", "payload": {}}).encode("utf-8")
        accepted = client.post(
            "/webhooks/crm",
            content=bad_payload,
            headers=_signed_headers(cfg.webhook_secret, bad_payload),
        )
        assert accepted.status_code == 202

        deadline = time.time() + 2.0
        rec = {}
        while time.time() < deadline:
            rec = client.get("/events/crm/evt_bad_1").json()
            if rec["status"] == "dead_letter":
                break
            time.sleep(0.05)

        assert rec["status"] == "dead_letter"
        assert rec["attempts"] == 1
        assert "NonRetryableError" in (rec["last_error"] or "")

