"""FastAPI HTTP receiver and status API for idempotent webhook ingestion."""

from __future__ import annotations

import json
import re
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, ValidationError

from app.config import Settings
from app.security import SignatureVerificationError, verify_webhook_signature
from app.storage import WebhookStore
from app.worker import EventHandler, WebhookWorker

SOURCE_PATTERN = re.compile(r"^[a-z0-9_-]{1,32}$")


class WebhookEnvelope(BaseModel):
    """Canonical JSON body schema required from webhook callers."""

    event_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)


def create_app(
    settings: Settings | None = None,
    handler: EventHandler | None = None,
    *,
    run_worker: bool = True,
) -> FastAPI:
    """Create a configured FastAPI application with durable SQLite storage and worker lifespan."""
    cfg = settings or Settings.from_env()
    store = WebhookStore(cfg.db_path)
    worker = WebhookWorker(store=store, settings=cfg, handler=handler)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store.init_db()
        app.state.settings = cfg
        app.state.store = store
        app.state.worker = worker
        if run_worker:
            worker.start()
        try:
            yield
        finally:
            if run_worker:
                await worker.stop()

    app = FastAPI(title="Idempotent Webhook Worker", version="1.0.0", lifespan=lifespan)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/webhooks/{source}")
    async def ingest_webhook(source: str, request: Request, response: Response) -> dict[str, str]:
        if not SOURCE_PATTERN.match(source):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid webhook source identifier.",
            )

        raw_body = await request.body()
        if len(raw_body) > cfg.max_body_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="Payload exceeds maximum allowed byte size.",
            )

        try:
            verify_webhook_signature(
                secret=cfg.webhook_secret,
                raw_body=raw_body,
                timestamp_header=request.headers.get("X-Webhook-Timestamp"),
                signature_header=request.headers.get("X-Webhook-Signature"),
                tolerance_seconds=cfg.timestamp_tolerance_seconds,
            )
        except SignatureVerificationError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
            ) from exc

        try:
            decoded = raw_body.decode("utf-8")
            parsed_json = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Request body must be valid UTF-8 JSON.",
            ) from exc

        try:
            envelope = WebhookEnvelope.model_validate(parsed_json)
        except ValidationError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=exc.errors(),
            ) from exc

        result = store.enqueue_event(
            source=source,
            event_id=envelope.event_id,
            event_type=envelope.event_type,
            payload=envelope.payload,
            raw_body=raw_body,
            max_attempts=cfg.max_attempts,
        )

        if result.outcome == "conflict":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Event ID already exists with a different payload digest.",
            )

        if result.outcome == "duplicate":
            response.status_code = status.HTTP_200_OK
            return {
                "outcome": "duplicate",
                "source": result.source,
                "event_id": result.event_id,
                "status": result.status,
            }

        response.status_code = status.HTTP_202_ACCEPTED
        return {
            "outcome": "accepted",
            "source": result.source,
            "event_id": result.event_id,
            "status": result.status,
        }

    @app.get("/events/{source}/{event_id}")
    def get_event_status(source: str, event_id: str) -> dict[str, Any]:
        record = store.get_event(source=source, event_id=event_id)
        if record is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")
        return asdict(record)

    @app.get("/dead-letters")
    def list_dead_letters(limit: int = 50) -> dict[str, Any]:
        bounded_limit = max(1, min(limit, 200))
        items = [asdict(rec) for rec in store.list_dead_letters(limit=bounded_limit)]
        return {"count": len(items), "items": items}

    @app.post("/dead-letters/{source}/{event_id}/requeue")
    def requeue_dead_letter(source: str, event_id: str) -> dict[str, str]:
        ok = store.requeue_dead_letter(source=source, event_id=event_id)
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Dead-lettered event not found.",
            )
        return {"status": "requeued", "source": source, "event_id": event_id}

    return app


app = create_app()
