"""
services/webhook_dispatcher.py — Webhook delivery, HMAC signing, and retry.

Security invariants:
- Webhook signing secrets are Fernet-encrypted in the DB. Decrypted in memory
  only for the duration of the HMAC computation, then discarded.
- The decrypted secret is NEVER logged.
- Payload bytes are signed; the signature header is sha256=<hex>.
- Delivery IDs are UUID4 — unique per attempt, not per alert.

Delivery flow:
  1. dispatch(alert, db) — called in the ingest request context
     • Finds all api_keys with webhook_url set for alert.tenant_id
     • Applies optional severity/service filters
     • Fires the first attempt synchronously (httpx, 10s timeout)
     • Records attempt to webhook_events
  2. retry_loop() — asyncio background task (every 30s)
     • Picks up failed webhook_events where next_retry_at <= now
     • Retries up to 3 total attempts (backoff: 2s, 4s, 8s)
     • Marks webhook_url=NULL after 10 consecutive failures
"""
import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Optional, Tuple

import httpx
from sqlalchemy.orm import Session

from database import SessionLocal

logger = logging.getLogger(__name__)

_MAX_ATTEMPTS = 3
_BACKOFF_BASE_S = 2        # seconds; attempt N retries after BACKOFF_BASE * 2^(N-1)
_TIMEOUT_S = 10
_AUTO_DISABLE_THRESHOLD = 10   # consecutive failures before disabling webhook_url


class WebhookDispatcher:
    """
    Stateful only for the session_factory reference and the retry background task.
    Instantiated once in main.py lifespan, attached to app.state.
    """

    def __init__(self, session_factory=None) -> None:
        self._session_factory = session_factory

    def set_session_factory(self, factory) -> None:
        self._session_factory = factory

    # ------------------------------------------------------------------
    # Primary dispatch (called from ingest path)
    # ------------------------------------------------------------------

    def dispatch(self, alert, db: Session) -> None:
        """
        Dispatch alert to all matching webhooks for alert.tenant_id.
        Synchronous but fast: httpx with 10s timeout per endpoint.
        Errors are logged and swallowed — never crash the ingest path.
        """
        from models.db import ApiKey, WebhookEvent

        try:
            keys = (
                db.query(ApiKey)
                .filter(
                    ApiKey.tenant_id == alert.tenant_id,
                    ApiKey.webhook_url.isnot(None),
                    ApiKey.revoked_at.is_(None),
                )
                .all()
            )

            if not keys:
                return

            payload_bytes = alert.full_payload.encode()

            for key in keys:
                # Apply optional per-key filters
                if not self._matches_filters(key, alert):
                    continue

                delivery_id = str(uuid.uuid4())
                sig_header = self._sign(payload_bytes, key.webhook_secret_enc)

                success, status_code, response_body, latency_ms = self._post(
                    key.webhook_url, payload_bytes, sig_header, delivery_id
                )

                backoff = _BACKOFF_BASE_S if not success else None
                next_retry = (
                    datetime.utcnow() + timedelta(seconds=backoff)
                    if not success and backoff
                    else None
                )

                event = WebhookEvent(
                    tenant_id=alert.tenant_id,
                    alert_id=alert.id,
                    api_key_id=key.id,
                    attempt_number=1,
                    target_url=key.webhook_url,
                    payload=alert.full_payload,
                    delivery_id=delivery_id,
                    response_status=status_code,
                    response_body=(response_body or "")[:500],
                    latency_ms=latency_ms,
                    success=success,
                    next_retry_at=next_retry,
                )
                db.add(event)

            db.flush()

        except Exception as exc:
            logger.error(
                "webhook_dispatcher.dispatch error",
                extra={"alert_id": alert.id, "error": str(exc)},
            )

    # ------------------------------------------------------------------
    # Background retry loop
    # ------------------------------------------------------------------

    async def retry_loop(self) -> None:
        """
        Asyncio background task.  Runs every 30 seconds.
        Retries failed deliveries up to _MAX_ATTEMPTS total.
        """
        while True:
            await asyncio.sleep(30)
            if self._session_factory is None:
                continue
            db = self._session_factory()
            try:
                self._process_retries(db)
                db.commit()
            except Exception as exc:
                db.rollback()
                logger.error(
                    "webhook retry_loop error", extra={"error": str(exc)}
                )
            finally:
                db.close()

    def _process_retries(self, db: Session) -> None:
        from models.db import ApiKey, WebhookEvent

        now = datetime.utcnow()
        pending = (
            db.query(WebhookEvent)
            .filter(
                WebhookEvent.success.is_(False),
                WebhookEvent.next_retry_at.isnot(None),
                WebhookEvent.next_retry_at <= now,
            )
            .all()
        )

        for event in pending:
            # Clear scheduling on this row regardless of outcome
            event.next_retry_at = None

            if event.attempt_number >= _MAX_ATTEMPTS:
                self._maybe_disable_webhook(event.api_key_id, db)
                continue

            key = db.query(ApiKey).filter(ApiKey.id == event.api_key_id).first()
            if not key or not key.webhook_url:
                continue

            payload_bytes = event.payload.encode()
            delivery_id = str(uuid.uuid4())
            sig_header = self._sign(payload_bytes, key.webhook_secret_enc)

            success, status_code, response_body, latency_ms = self._post(
                key.webhook_url, payload_bytes, sig_header, delivery_id
            )

            next_attempt = event.attempt_number + 1
            backoff_s = _BACKOFF_BASE_S * (2 ** (next_attempt - 1))  # 2, 4, 8 …
            next_retry = (
                None if (success or next_attempt >= _MAX_ATTEMPTS)
                else now + timedelta(seconds=backoff_s)
            )

            new_event = WebhookEvent(
                tenant_id=event.tenant_id,
                alert_id=event.alert_id,
                api_key_id=event.api_key_id,
                attempt_number=next_attempt,
                target_url=event.target_url,
                payload=event.payload,
                delivery_id=delivery_id,
                response_status=status_code,
                response_body=(response_body or "")[:500],
                latency_ms=latency_ms,
                success=success,
                next_retry_at=next_retry,
            )
            db.add(new_event)
            db.flush()

            if not success and next_attempt >= _MAX_ATTEMPTS:
                self._maybe_disable_webhook(event.api_key_id, db)

    def _maybe_disable_webhook(self, api_key_id: str, db: Session) -> None:
        """Disable webhook_url after _AUTO_DISABLE_THRESHOLD consecutive failures."""
        from models.db import ApiKey, WebhookEvent

        recent = (
            db.query(WebhookEvent.success)
            .filter(WebhookEvent.api_key_id == api_key_id)
            .order_by(WebhookEvent.created_at.desc())
            .limit(_AUTO_DISABLE_THRESHOLD)
            .all()
        )
        if len(recent) >= _AUTO_DISABLE_THRESHOLD and not any(r.success for r in recent):
            key = db.query(ApiKey).filter(ApiKey.id == api_key_id).first()
            if key and key.webhook_url:
                key.webhook_url = None
                key.webhook_secret_enc = None
                logger.warning(
                    "webhook auto-disabled after consecutive failures",
                    extra={"api_key_id": api_key_id},
                )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _matches_filters(key, alert) -> bool:
        """Return False if the key's webhook_filters exclude this alert."""
        if not key.webhook_filters:
            return True
        try:
            filters = json.loads(key.webhook_filters)
        except (json.JSONDecodeError, TypeError):
            return True
        if "severity" in filters and filters["severity"] != alert.severity:
            return False
        if "service_name" in filters and filters["service_name"] != alert.service_name:
            return False
        return True

    @staticmethod
    def _sign(payload_bytes: bytes, webhook_secret_enc: Optional[str]) -> str:
        """Return 'sha256=<hex>' signature, or empty string if no secret configured."""
        if not webhook_secret_enc:
            return ""
        from security import decrypt
        try:
            secret = decrypt(webhook_secret_enc)
            # SECURITY: secret lives only in this local scope
            sig = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
            return f"sha256={sig}"
        except Exception as exc:
            logger.error(
                "webhook HMAC signing failed",
                extra={"error": str(exc)},
            )
            return ""

    @staticmethod
    def _post(
        url: str,
        payload: bytes,
        sig_header: str,
        delivery_id: str,
    ) -> Tuple[bool, Optional[int], Optional[str], Optional[int]]:
        """
        POST payload to url.  Returns (success, status_code, response_body, latency_ms).
        success = True when HTTP 2xx received.
        """
        headers = {
            "Content-Type": "application/json",
            "X-Watchdog-Delivery-ID": delivery_id,
            "X-Watchdog-Event": "anomaly.detected",
        }
        if sig_header:
            headers["X-Watchdog-Signature"] = sig_header

        try:
            t0 = time.monotonic()
            with httpx.Client(timeout=_TIMEOUT_S) as client:
                resp = client.post(url, content=payload, headers=headers)
            latency_ms = int((time.monotonic() - t0) * 1000)
            success = resp.status_code < 400
            return success, resp.status_code, resp.text[:500], latency_ms
        except httpx.TimeoutException:
            return False, None, "timeout", None
        except Exception as exc:
            return False, None, str(exc)[:500], None
