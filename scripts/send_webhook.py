"""CLI utility to sign and send deterministic test webhooks against a running server."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.security import compute_signature


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a signed webhook event.")
    parser.add_argument("--url", default="http://127.0.0.1:8000/webhooks/billing")
    parser.add_argument("--secret", default="local-dev-hmac-signing-key-change-in-production")
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--event-type", default="invoice.paid")
    parser.add_argument("--payload", default='{"amount_cents": 4900, "currency": "USD"}')
    args = parser.parse_args()

    body_dict = {
        "event_id": args.event_id,
        "event_type": args.event_type,
        "payload": json.loads(args.payload),
    }
    raw_body = json.dumps(body_dict, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    timestamp = int(time.time())
    signature = compute_signature(secret=args.secret, timestamp=timestamp, raw_body=raw_body)

    with httpx.Client(timeout=5.0) as client:
        resp = client.post(
            args.url,
            content=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Timestamp": str(timestamp),
                "X-Webhook-Signature": signature,
            },
        )
    print(f"HTTP {resp.status_code}: {resp.text}")
    return 0 if resp.status_code < 400 else 1


if __name__ == "__main__":
    raise SystemExit(main())
