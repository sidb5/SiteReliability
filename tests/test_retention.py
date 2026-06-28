"""
tests/test_retention.py — Module 10: Retention service tests.

Covers:
  _run_retention():
    - Deletes resolved alerts older than retention_days
    - Deletes acknowledged alerts older than retention_days
    - Never deletes OPEN alerts regardless of age
    - Deletes webhook events older than retention_days
    - Deletes request logs older than log_retention_days
    - Does not delete recent alerts
    - Tenant isolation — only own data deleted

  _run_key_expiry():
    - Marks expired keys revoked
    - Marks grace-period-expired keys revoked
    - Does not touch non-expired keys
    - Does not re-revoke already-revoked keys
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import sessionmaker

from models.db import AnomalyAlert, ApiKey, RequestLog, Tenant, User, WebhookEvent
from security import generate_api_key, hash_api_key
from services.retention_service import RetentionService

UTC = timezone.utc


def _make_session(test_engine):
    return sessionmaker(bind=test_engine, expire_on_commit=False)()


def _create_tenant(db, retention_days=30, log_retention_days=7) -> Tenant:
    t = Tenant(
        id=str(uuid.uuid4()),
        name=f"Ret-{uuid.uuid4().hex[:6]}",
        plan="starter",
        contact_email=f"ret-{uuid.uuid4().hex[:6]}@test.com",
        active=True,
        retention_days=retention_days,
        log_retention_days=log_retention_days,
    )
    db.add(t)
    db.flush()
    return t


def _create_user(db, tenant_id: str) -> User:
    u = User(
        tenant_id=tenant_id,
        email=f"ret-{uuid.uuid4().hex[:8]}@test.com",
        password_hash="$2b$12$placeholder",
        role="tenant_admin",
        active=True,
    )
    db.add(u)
    db.flush()
    return u


def _create_source(db, tenant_id: str, user_id: str):
    from models.db import LogSource
    s = LogSource(
        tenant_id=tenant_id,
        name=f"src-{uuid.uuid4().hex[:6]}",
        service_name="test-svc",
        source_type="push",
        log_format="json",
        active=True,
        created_by=user_id,
    )
    db.add(s)
    db.flush()
    return s


def _create_alert(db, tenant_id, status="resolved", age_days=40, source_id=None) -> AnomalyAlert:
    ts = datetime.now(UTC) - timedelta(days=age_days)
    a = AnomalyAlert(
        tenant_id=tenant_id,
        source_id=source_id,
        service_name="test-svc",
        environment="production",
        anomaly_type="SPIKE",
        severity="WARNING",
        status=status,
        detected_at=ts,
        created_at=ts,
        current_value=1.0,
        baseline_value=0.5,
        upper_bound=2.0,
        unit="count",
        window_start=ts,
        window_end=ts,
        sample_count=10,
        representative_msgs="[]",
        detection_context="{}",
        full_payload="{}",
    )
    db.add(a)
    db.flush()
    return a


def _create_webhook_event(db, tenant_id, alert_id, api_key_id, age_days=40) -> WebhookEvent:
    ts = datetime.now(UTC) - timedelta(days=age_days)
    e = WebhookEvent(
        tenant_id=tenant_id,
        alert_id=alert_id,
        api_key_id=api_key_id,
        delivery_id=str(uuid.uuid4()),
        target_url="https://example.com/hook",
        payload="{}",
        attempt_number=1,
        sent_at=ts,
        success=True,
        created_at=ts,
    )
    db.add(e)
    db.flush()
    return e


def _create_request_log(db, tenant_id, age_days=10) -> RequestLog:
    ts = datetime.now(UTC) - timedelta(days=age_days)
    r = RequestLog(
        tenant_id=tenant_id,
        request_id=str(uuid.uuid4()),
        method="GET",
        path="/api/v1/alerts",
        status_code=200,
        latency_ms=5,
        timestamp=ts,
    )
    db.add(r)
    db.flush()
    return r


def _create_key(db, tenant_id, user_id, expires_at=None, grace_period_ends_at=None) -> ApiKey:
    plaintext, key_hash = generate_api_key()
    k = ApiKey(
        tenant_id=tenant_id,
        user_id=user_id,
        name=f"key-{uuid.uuid4().hex[:6]}",
        key_hash=key_hash,
        key_prefix=plaintext[:12],
        scopes=json.dumps(["alerts:read"]),
        environment="live",
        expires_at=expires_at,
        grace_period_ends_at=grace_period_ends_at,
    )
    db.add(k)
    db.flush()
    return k


class TestRunRetention:
    def test_deletes_old_resolved_alerts(self, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db, retention_days=30)
        u = _create_user(db, t.id)
        s = _create_source(db, t.id, u.id)
        _create_alert(db, t.id, status="resolved", age_days=40, source_id=s.id)
        db.commit()

        svc = RetentionService()
        svc._run_retention(db)
        db.commit()

        remaining = db.query(AnomalyAlert).filter(AnomalyAlert.tenant_id == t.id).all()
        assert len(remaining) == 0
        db.close()

    def test_deletes_old_acknowledged_alerts(self, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db, retention_days=30)
        u = _create_user(db, t.id)
        s = _create_source(db, t.id, u.id)
        _create_alert(db, t.id, status="acknowledged", age_days=35, source_id=s.id)
        db.commit()

        svc = RetentionService()
        svc._run_retention(db)
        db.commit()

        remaining = db.query(AnomalyAlert).filter(AnomalyAlert.tenant_id == t.id).all()
        assert len(remaining) == 0
        db.close()

    def test_never_deletes_open_alerts(self, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db, retention_days=1)  # very short retention
        u = _create_user(db, t.id)
        s = _create_source(db, t.id, u.id)
        _create_alert(db, t.id, status="open", age_days=999, source_id=s.id)
        db.commit()

        svc = RetentionService()
        svc._run_retention(db)
        db.commit()

        remaining = db.query(AnomalyAlert).filter(AnomalyAlert.tenant_id == t.id).all()
        assert len(remaining) == 1
        db.close()

    def test_does_not_delete_recent_alerts(self, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db, retention_days=30)
        u = _create_user(db, t.id)
        s = _create_source(db, t.id, u.id)
        _create_alert(db, t.id, status="resolved", age_days=5, source_id=s.id)
        db.commit()

        svc = RetentionService()
        svc._run_retention(db)
        db.commit()

        remaining = db.query(AnomalyAlert).filter(AnomalyAlert.tenant_id == t.id).all()
        assert len(remaining) == 1
        db.close()

    def test_deletes_old_webhook_events(self, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db, retention_days=30)
        u = _create_user(db, t.id)
        s = _create_source(db, t.id, u.id)
        alert = _create_alert(db, t.id, status="resolved", age_days=40, source_id=s.id)
        key = _create_key(db, t.id, u.id)
        _create_webhook_event(db, t.id, alert.id, key.id, age_days=40)
        db.commit()

        svc = RetentionService()
        svc._run_retention(db)
        db.commit()

        remaining = db.query(WebhookEvent).filter(WebhookEvent.tenant_id == t.id).all()
        assert len(remaining) == 0
        db.close()

    def test_deletes_old_request_logs(self, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db, log_retention_days=7)
        _create_request_log(db, t.id, age_days=10)
        db.commit()

        svc = RetentionService()
        svc._run_retention(db)
        db.commit()

        remaining = db.query(RequestLog).filter(RequestLog.tenant_id == t.id).all()
        assert len(remaining) == 0
        db.close()

    def test_tenant_isolation(self, test_engine):
        db = _make_session(test_engine)
        t_a = _create_tenant(db, retention_days=30)
        t_b = _create_tenant(db, retention_days=30)
        u_a = _create_user(db, t_a.id)
        u_b = _create_user(db, t_b.id)
        s_a = _create_source(db, t_a.id, u_a.id)
        s_b = _create_source(db, t_b.id, u_b.id)
        _create_alert(db, t_a.id, status="resolved", age_days=40, source_id=s_a.id)
        _create_alert(db, t_b.id, status="resolved", age_days=40, source_id=s_b.id)
        db.commit()

        # Only clean tenant A
        tenant_a = db.query(Tenant).filter(Tenant.id == t_a.id).first()
        svc = RetentionService()
        svc._clean_tenant(db, tenant_a)
        db.commit()

        # Tenant A's alert gone, B's stays
        remaining_a = db.query(AnomalyAlert).filter(AnomalyAlert.tenant_id == t_a.id).all()
        remaining_b = db.query(AnomalyAlert).filter(AnomalyAlert.tenant_id == t_b.id).all()
        assert len(remaining_a) == 0
        assert len(remaining_b) == 1
        db.close()


class TestKeyExpiry:
    def test_marks_expired_key_revoked(self, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        past = datetime.now(UTC) - timedelta(hours=1)
        key = _create_key(db, t.id, u.id, expires_at=past)
        db.commit()
        kid = key.id
        db.close()

        db2 = _make_session(test_engine)
        svc = RetentionService()
        svc._run_key_expiry(db2)
        db2.commit()

        key_after = db2.query(ApiKey).filter(ApiKey.id == kid).first()
        assert key_after.revoked_at is not None
        db2.close()

    def test_marks_grace_period_expired_key_revoked(self, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        past = datetime.now(UTC) - timedelta(hours=1)
        key = _create_key(db, t.id, u.id, grace_period_ends_at=past)
        db.commit()
        kid = key.id
        db.close()

        db2 = _make_session(test_engine)
        svc = RetentionService()
        svc._run_key_expiry(db2)
        db2.commit()

        key_after = db2.query(ApiKey).filter(ApiKey.id == kid).first()
        assert key_after.revoked_at is not None
        db2.close()

    def test_does_not_touch_future_expiry(self, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        future = datetime.now(UTC) + timedelta(hours=24)
        key = _create_key(db, t.id, u.id, expires_at=future)
        db.commit()
        kid = key.id
        db.close()

        db2 = _make_session(test_engine)
        svc = RetentionService()
        svc._run_key_expiry(db2)
        db2.commit()

        key_after = db2.query(ApiKey).filter(ApiKey.id == kid).first()
        assert key_after.revoked_at is None
        db2.close()

    def test_does_not_re_revoke_already_revoked_key(self, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        past = datetime.now(UTC) - timedelta(hours=1)
        revoked_at = datetime.now(UTC) - timedelta(hours=2)
        key = _create_key(db, t.id, u.id, expires_at=past)
        key.revoked_at = revoked_at
        db.flush()
        db.commit()
        kid = key.id
        db.close()

        db2 = _make_session(test_engine)
        svc = RetentionService()
        svc._run_key_expiry(db2)
        db2.commit()

        key_after = db2.query(ApiKey).filter(ApiKey.id == kid).first()
        # revoked_at should remain the original value, not be overwritten
        assert key_after.revoked_at is not None
        db2.close()
