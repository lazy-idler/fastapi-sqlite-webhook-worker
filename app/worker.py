"""Async background worker loop for processing leased SQLite webhook jobs."""

from __future__ import annotations

import asyncio
import inspect
import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from app.config import Settings
from app.storage import ClaimedEvent, WebhookStore

logger = logging.getLogger("webhook_worker")

EventHandler = Callable[[ClaimedEvent], Any | Awaitable[Any]]


class NonRetryableError(Exception):
    """Raised by handlers when an event payload is permanently invalid."""


async def default_event_handler(event: ClaimedEvent) -> None:
    """Default deterministic handler illustrating downstream business side effects."""
    logger.info(
        "Processed webhook source=%s event_id=%s type=%s attempt=%s/%s",
        event.source,
        event.event_id,
        event.event_type,
        event.attempts,
        event.max_attempts,
    )


class WebhookWorker:
    """Background worker that polls SQLite leases and isolates handler failures."""

    def __init__(
        self,
        *,
        store: WebhookStore,
        settings: Settings,
        handler: EventHandler | None = None,
        worker_id: str | None = None,
        jitter_ratio: float = 0.2,
    ) -> None:
        self.store = store
        self.settings = settings
        self.handler: EventHandler = handler or default_event_handler
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:12]}"
        self.jitter_ratio = jitter_ratio
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Launch the background polling loop if not already running."""
        if self._task is None or self._task.done():
            self._stop_event.clear()
            self._task = asyncio.create_task(self._run_loop(), name=self.worker_id)

    async def stop(self) -> None:
        """Signal shutdown and wait for any active handler iteration to finish cleanly."""
        self._stop_event.set()
        if self._task is not None:
            await self._task
            self._task = None

    async def process_once(self) -> bool:
        """Claim and process at most one due event. Returns True when work was claimed."""
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
            # Force dead_letter immediately when the failure cannot succeed on retry.
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
            logger.warning(
                "Permanent failure on event_id=%s (%s); moved to dead_letter",
                claimed.event_id,
                exc,
            )
            return True
        except Exception as exc:
            outcome = await asyncio.to_thread(
                self.store.mark_retry_or_dead_letter,
                row_id=claimed.row_id,
                worker_id=self.worker_id,
                error_message=f"{type(exc).__name__}: {exc}",
                backoff_base_seconds=self.settings.backoff_base_seconds,
                backoff_cap_seconds=self.settings.backoff_cap_seconds,
                jitter_ratio=self.jitter_ratio,
            )
            logger.warning(
                "Webhook attempt %s/%s failed for event_id=%s -> %s (%s)",
                claimed.attempts,
                claimed.max_attempts,
                claimed.event_id,
                outcome,
                exc,
            )
            return True

        await asyncio.to_thread(
            self.store.mark_succeeded,
            row_id=claimed.row_id,
            worker_id=self.worker_id,
        )
        return True

    async def _invoke_handler(self, claimed: ClaimedEvent) -> None:
        if inspect.iscoroutinefunction(self.handler):
            await self.handler(claimed)
        else:
            await asyncio.to_thread(self.handler, claimed)

    async def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            did_work = await self.process_once()
            if did_work:
                continue
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self.settings.poll_interval_seconds,
                )
            except TimeoutError:
                continue
