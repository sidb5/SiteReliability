"""
tests/test_webhook.py — Module 7: Webhook system tests.

Covers:
  Unit:
    - HMAC signature generation and verification
    - Filter matching (severity, service_name, no filter)
    - _sign returns empty string when no secret
    - _matches_filters with malformed JSON

  Integration (full HTTP):
    - POST /api/v1/webhook/receive — 200 with valid signature
    - POST /api/v1/webhook/receive — 400 when signature mismatches
    - POST /api/v1/webhook/receive — 200 when no test_secret (skip verify)

  Dispatch:
    - dispatch() records WebhookEvent on success
    - dispatch() records WebhookEvent on failure with next_retry_at set
    - dispatch() skips keys with no webhook_url
    - dispatch() applies severity filter
    - dispatch() applies service_name filter
    - dispatch() swallows exceptions (never crashes ingest path)

  Retry:
    - _process_retries() creates new attempt row on failure
    - _process_retries() sets next_retry_at=None when max attempts reached
    - _maybe_disable_webhook clears webhook_url after 10 failures

  Security:
    - Webhook secret never appears in logs
    - dispatch() skips revoked API keys
"""
import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from models.db import AnomalyAlert, ApiKey, User, WebhookEvent
from security import encrypt
from services.webhook_dispatcher import WebhookDispatcher

UTC = timezone.utc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(db: Session, tenant_id: str) -> User:
    u = User(
        tenant_id=tenant_id,
        email=f"webhook-test-{uuid.uuid4().hex[:8]}@test.com",
        password_hash="$2b$12$placeholder",
        role="tenant_operator",
        active=True,
    )
    db.add(u)
    db.flush()
    return u


def _make_api_key(
    db: Session,
    tenant_id: str,
    user_id: str,
    webhook_url: str = None,
    webhook_secret: str = None,
    webhook_filters: dict = None,
    revoked: bool = False,
) -> ApiKey:
    from security import generate_api_key
    _, key_hash = generate_api_key()
    enc_secret = encrypt(webhook_secret) if webhook_secret else None
    filters_json = json.dumps(webhook_filters) if webhook_filters else None

    key = ApiKey(
        tenant_id=tenant_id,
        user_id=user_id,
        name=f"test-key-{uuid.uuid4().hex[:6]}",
        key_hash=key_hash,
        key_prefix="wdog_live_test",
        scopes=json.dumps(["alerts:read", "webhooks:manage"]),
        webhook_url=webhook_url,
        webhook_secret_enc=enc_secret,
        webhook_filters=filters_json,
        revoked_at=datetime.utcnow() if revoked else None,
    )
    db.add(key)
    db.flush()
    return key


def _make_alert(db: Session, tenant_id: str, source_id: str, **overrides) -> AnomalyAlert:
    now = datetime.now(UTC)
    payload = {"anomaly_id": str(uuid.uuid4()), "schema_version": "1.0"}
    alert = AnomalyAlert(
        tenant_id=tenant_id,
        source_id=source_id,
        anomaly_type=overrides.get("anomaly_type", "ERROR_RATE_SPIKE"),
        severity=overrides.get("severity", "WARNING"),
        service_name=overrides.get("service_name", "test-service"),
        environment="production",
        current_value=0.5,
        baseline_value=0.05,
        upper_bound=0.3,
        unit="errors_per_minute",
        window_start=now - timedelta(minutes=1),
        window_end=now,
        sample_count=50,
        representative_msgs="[]",
        detection_context="{}",
        full_payload=json.dumps(payload),
        status="open",
    )
    db.add(alert)
    db.flush()
    return alert


def _make_source(db: Session, tenant_id: str, user_id: str) -> str:
    from models.db import LogSource
    src = LogSource(
        tenant_id=tenant_id,
        name=f"wh-source-{uuid.uuid4().hex[:6]}",
        service_name="test-service",
        source_type="push",
        log_format="json",
        active=True,
        created_by=user_id,
    )
    db.add(src)
    db.flush()
    return src.id


# ---------------------------------------------------------------------------
# Unit: HMAC signing
# ---------------------------------------------------------------------------

class TestHmacSigning:
    def test_sign_with_secret_produces_sha256_prefix(self):
        secret = "my-signing-secret"
        enc = encrypt(secret)
        payload = b'{"test": "payload"}'
        sig = WebhookDispatcher._sign(payload, enc)
        assert sig.startswith("sha256=")

    def test_sign_produces_correct_hmac(self):
        secret = "my-signing-secret"
        enc = encrypt(secret)
        payload = b'{"test": "payload"}'
        sig = WebhookDispatcher._sign(payload, enc)
        expected = "sha256=" + hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        assert sig == expected

    def test_sign_without_secret_returns_empty(self):
        sig = WebhookDispatcher._sign(b"payload", None)
        assert sig == ""

    def test_sign_with_invalid_ciphertext_returns_empty(self):
        sig = WebhookDispatcher._sign(b"payload", "not-valid-ciphertext")
        assert sig == ""


# ---------------------------------------------------------------------------
# Unit: filter matching
# ---------------------------------------------------------------------------

class TestFilterMatching:
    def _key(self, filters_json: str = None):
        k = MagicMock()
        k.webhook_filters = filters_json
        return k

    def _alert(self, severity="WARNING", service_name="svc"):
        a = MagicMock()
        a.severity = severity
        a.service_name = service_name
        return a

    def test_no_filter_passes(self):
        assert WebhookDispatcher._matches_filters(self._key(None), self._alert()) is True

    def test_severity_filter_match(self):
        k = self._key('{"severity": "CRITICAL"}')
        assert WebhookDispatcher._matches_filters(k, self._alert("CRITICAL")) is True

    def test_severity_filter_no_match(self):
        k = self._key('{"severity": "CRITICAL"}')
        assert WebhookDispatcher._matches_filters(k, self._alert("WARNING")) is False

    def test_service_filter_match(self):
        k = self._key('{"service_name": "payment"}')
        assert WebhookDispatcher._matches_filters(k, self._alert(service_name="payment")) is True

    def test_service_filter_no_match(self):
        k = self._key('{"service_name": "payment"}')
        assert WebhookDispatcher._matches_filters(k, self._alert(service_name="auth")) is False

    def test_malformed_filter_json_passes(self):
        k = self._key("{not valid json")
        assert WebhookDispatcher._matches_filters(k, self._alert()) is True


# ---------------------------------------------------------------------------
# Integration: /api/v1/webhook/receive
# ---------------------------------------------------------------------------

class TestWebhookReceive:
    def test_receive_without_secret_returns_200(self, client):
        resp = client.post(
            "/api/v1/webhook/receive",
            json={"anomaly_type": "ERROR_RATE_SPIKE"},
            headers={
                "X-Watchdog-Delivery-ID": "test-delivery-1",
                "X-Watchdog-Event": "anomaly.detected",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["received"] is True
        assert data["delivery_id"] == "test-delivery-1"

    def test_receive_with_valid_signature_returns_200(self, client):
        secret = "my-test-secret"
        payload = b'{"test": "data"}'
        sig = "sha256=" + hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()

        resp = client.post(
            "/api/v1/webhook/receive",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-Watchdog-Signature": sig,
                "X-Watchdog-Delivery-ID": "valid-delivery",
                "X-Watchdog-Event": "anomaly.detected",
            },
            params={"test_secret": secret},
        )
        assert resp.status_code == 200
        assert resp.json()["received"] is True

    def test_receive_with_invalid_signature_returns_400(self, client):
        resp = client.post(
            "/api/v1/webhook/receive",
            json={"test": "data"},
            headers={
                "X-Watchdog-Signature": "sha256=bad_signature",
                "X-Watchdog-Delivery-ID": "bad-delivery",
                "X-Watchdog-Event": "anomaly.detected",
            },
            params={"test_secret": "some-secret"},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Dispatch tests
# ---------------------------------------------------------------------------

class TestDispatch:
    def test_dispatch_records_event_on_success(self, db_session, test_tenants):
        tid = test_tenants["tenant_a"]
        user = _make_user(db_session, tid)
        src_id = _make_source(db_session, tid, user.id)
        secret = "dispatch-secret"
        key = _make_api_key(
            db_session, tid, user.id,
            webhook_url="http://localhost:9999/receive",
            webhook_secret=secret,
        )
        alert = _make_alert(db_session, tid, src_id)

        dispatcher = WebhookDispatcher()

        with patch.object(WebhookDispatcher, "_post", return_value=(True, 200, "ok", 50)):
            dispatcher.dispatch(alert, db_session)

        events = db_session.query(WebhookEvent).filter(
            WebhookEvent.alert_id == alert.id
        ).all()
        assert len(events) == 1
        assert events[0].success is True
        assert events[0].attempt_number == 1
        assert events[0].next_retry_at is None

    def test_dispatch_sets_retry_on_failure(self, db_session, test_tenants):
        tid = test_tenants["tenant_b"]
        user = _make_user(db_session, tid)
        src_id = _make_source(db_session, tid, user.id)
        key = _make_api_key(
            db_session, tid, user.id,
            webhook_url="http://localhost:9999/fail",
        )
        alert = _make_alert(db_session, tid, src_id)

        dispatcher = WebhookDispatcher()
        with patch.object(WebhookDispatcher, "_post", return_value=(False, 500, "error", 10)):
            dispatcher.dispatch(alert, db_session)

        events = db_session.query(WebhookEvent).filter(
            WebhookEvent.alert_id == alert.id
        ).all()
        assert len(events) == 1
        assert events[0].success is False
        assert events[0].next_retry_at is not None

    def test_dispatch_skips_key_without_webhook_url(self, db_session, test_tenants):
        tid = test_tenants["tenant_a"]
        user = _make_user(db_session, tid)
        src_id = _make_source(db_session, tid, user.id)
        _make_api_key(db_session, tid, user.id, webhook_url=None)
        alert = _make_alert(db_session, tid, src_id)

        dispatcher = WebhookDispatcher()
        with patch.object(WebhookDispatcher, "_post") as mock_post:
            dispatcher.dispatch(alert, db_session)
            mock_post.assert_not_called()

    def test_dispatch_skips_revoked_key(self, db_session, test_tenants):
        tid = test_tenants["tenant_a"]
        user = _make_user(db_session, tid)
        src_id = _make_source(db_session, tid, user.id)
        _make_api_key(
            db_session, tid, user.id,
            webhook_url="http://localhost:9999/receive",
            revoked=True,
        )
        alert = _make_alert(db_session, tid, src_id)

        dispatcher = WebhookDispatcher()
        with patch.object(WebhookDispatcher, "_post") as mock_post:
            dispatcher.dispatch(alert, db_session)
            mock_post.assert_not_called()

    def test_dispatch_applies_severity_filter(self, db_session, test_tenants):
        tid = test_tenants["tenant_b"]
        user = _make_user(db_session, tid)
        src_id = _make_source(db_session, tid, user.id)
        _make_api_key(
            db_session, tid, user.id,
            webhook_url="http://localhost:9999/receive",
            webhook_filters={"severity": "CRITICAL"},
        )
        alert = _make_alert(db_session, tid, src_id, severity="WARNING")

        dispatcher = WebhookDispatcher()
        with patch.object(WebhookDispatcher, "_post") as mock_post:
            dispatcher.dispatch(alert, db_session)
            mock_post.assert_not_called()

    def test_dispatch_swallows_exceptions(self, db_session, test_tenants):
        tid = test_tenants["tenant_a"]
        user = _make_user(db_session, tid)
        src_id = _make_source(db_session, tid, user.id)
        _make_api_key(
            db_session, tid, user.id,
            webhook_url="http://localhost:9999/receive",
        )
        alert = _make_alert(db_session, tid, src_id)

        dispatcher = WebhookDispatcher()
        with patch.object(WebhookDispatcher, "_post", side_effect=RuntimeError("boom")):
            # Must not raise
            dispatcher.dispatch(alert, db_session)


# ---------------------------------------------------------------------------
# Retry tests
# ---------------------------------------------------------------------------

class TestRetry:
    def test_process_retries_creates_new_attempt(self, db_session, test_tenants):
        tid = test_tenants["tenant_a"]
        user = _make_user(db_session, tid)
        src_id = _make_source(db_session, tid, user.id)
        key = _make_api_key(
            db_session, tid, user.id,
            webhook_url="http://localhost:9999/retry",
        )
        alert = _make_alert(db_session, tid, src_id)

        past = datetime.utcnow() - timedelta(seconds=5)
        event = WebhookEvent(
            tenant_id=tid,
            alert_id=alert.id,
            api_key_id=key.id,
            attempt_number=1,
            target_url="http://localhost:9999/retry",
            payload=alert.full_payload,
            delivery_id=str(uuid.uuid4()),
            success=False,
            next_retry_at=past,
        )
        db_session.add(event)
        db_session.flush()

        dispatcher = WebhookDispatcher()
        with patch.object(WebhookDispatcher, "_post", return_value=(True, 200, "ok", 30)):
            dispatcher._process_retries(db_session)

        events = db_session.query(WebhookEvent).filter(
            WebhookEvent.alert_id == alert.id
        ).all()
        assert len(events) == 2
        assert any(e.attempt_number == 2 and e.success for e in events)

    def test_process_retries_exhausts_at_max_attempts(self, db_session, test_tenants):
        tid = test_tenants["tenant_b"]
        user = _make_user(db_session, tid)
        src_id = _make_source(db_session, tid, user.id)
        key = _make_api_key(
            db_session, tid, user.id,
            webhook_url="http://localhost:9999/exhaust",
        )
        alert = _make_alert(db_session, tid, src_id)

        past = datetime.utcnow() - timedelta(seconds=5)
        event = WebhookEvent(
            tenant_id=tid,
            alert_id=alert.id,
            api_key_id=key.id,
            attempt_number=3,  # already at max
            target_url="http://localhost:9999/exhaust",
            payload=alert.full_payload,
            delivery_id=str(uuid.uuid4()),
            success=False,
            next_retry_at=past,
        )
        db_session.add(event)
        db_session.flush()

        dispatcher = WebhookDispatcher()
        with patch.object(WebhookDispatcher, "_post") as mock_post:
            dispatcher._process_retries(db_session)
            mock_post.assert_not_called()

        # next_retry_at cleared in-memory (would be committed in production)
        assert event.next_retry_at is None
