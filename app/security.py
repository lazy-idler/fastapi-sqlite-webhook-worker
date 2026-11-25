"""HMAC-SHA256 webhook signature creation and replay-safe verification."""

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
    """Validate timestamp freshness and HMAC signature using constant-time comparison.

    Returns the parsed integer timestamp when valid; raises SignatureVerificationError otherwise.
    """
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
    provided = signature_header.strip()
    if not hmac.compare_digest(expected, provided):
        raise SignatureVerificationError("Webhook signature mismatch.")

    return timestamp
