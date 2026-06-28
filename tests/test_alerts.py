"""
tests/test_alerts.py — Module 8: Alerts API tests.

Covers:
  Unit:
    - encode_cursor / decode_cursor roundtrip
    - decode_cursor returns None on invalid input

  Integration (full HTTP):
    - GET /api/v1/alerts — requires auth (401 without token)
    - GET /api/v1/alerts — returns empty list for new tenant
    - GET /api/v1/alerts — lists open alerts for tenant
    - GET /api/v1/alerts — cursor pagination (next_cursor present, consumed correctly)
    - GET /api/v1/alerts — filter by service / severity / anomaly_type / status
    - GET /api/v1/alerts/{id} — returns full alert
    - GET /api/v1/alerts/{id} — 404 for unknown id
    - POST /api/v1/alerts/{id}/acknowledge — transitions open→acknowledged
    - POST /api/v1/alerts/{id}/acknowledge — idempotent (already acknowledged)
    - POST /api/v1/alerts/{id}/acknowledge — 409 for resolved alert

  Security:
    - Tenant A cannot see Tenant B alerts
    - GET/POST for other tenant's alert ID returns 404
"""
import json
import uuid
from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy.orm import sessionmaker

from models.db import AnomalyAlert, LogSource, User, Tenant
from models.schemas.v1.alerts import decode_cursor, encode_cursor
from security import create_access_token, Role

UTC = timezone.utc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session(test_engine):
    """Session with expire_on_commit=False so IDs survive after commit+close."""
    return sessionmaker(bind=test_engine, expire_on_commit=False)()


def _jwt(user_id: str, tenant_id: str, role: str = "tenant_operator") -> dict:
    token = create_access_token(user_id, tenant_id, role)
    return {"Authorization": f"Bearer {token}"}


def _create_user(db, tenant_id: str) -> User:
    u = User(
        tenant_id=tenant_id,
        email=f"alerts-{uuid.uuid4().hex[:8]}@test.com",
        password_hash="$2b$12$placeholder",
        role=Role.TENANT_OPERATOR.value,
        active=True,
    )
    db.add(u)
    db.flush()
    return u


def _create_source(db, tenant_id: str, user_id: str, service_name: str = "svc") -> LogSource:
    src = LogSource(
        tenant_id=tenant_id,
        name=f"src-{uuid.uuid4().hex[:6]}",
        service_name=service_name,
        source_type="push",
        log_format="json",
        active=True,
        created_by=user_id,
    )
    db.add(src)
    db.flush()
    return src


def _create_alert(
    db,
    tenant_id: str,
    source_id: str,
    service_name: str = "svc",
    severity: str = "WARNING",
    anomaly_type: str = "ERROR_RATE_SPIKE",
    alert_status: str = "open",
    detected_at: datetime = None,
) -> AnomalyAlert:
    # Default to 1 hour ago so these committed alerts don't fall inside the
    # 5-minute cascade detection window used by TestCascade in test_anomaly_engine.py.
    now = detected_at or (datetime.now(UTC) - timedelta(hours=1))
    alert = AnomalyAlert(
        tenant_id=tenant_id,
        source_id=source_id,
        detected_at=now,
        anomaly_type=anomaly_type,
        severity=severity,
        service_name=service_name,
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
        full_payload=json.dumps({"schema_version": "1.0"}),
        status=alert_status,
    )
    db.add(alert)
    db.flush()
    return alert


# ---------------------------------------------------------------------------
# Unit: cursor encoding
# ---------------------------------------------------------------------------

class TestCursorEncoding:
    def test_roundtrip(self):
        now = datetime.now(UTC)
        alert_id = str(uuid.uuid4())
        cursor = encode_cursor(now, alert_id)
        decoded = decode_cursor(cursor)
        assert decoded is not None
        dt_str, aid = decoded
        assert aid == alert_id

    def test_invalid_cursor_returns_none(self):
        assert decode_cursor("not-valid-base64!!!") is None

    def test_empty_cursor_returns_none(self):
        assert decode_cursor("") is None


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

class TestListAlerts:
    def test_requires_auth(self, client):
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 401

    def test_empty_list_for_new_tenant(self, client, test_engine):
        db = _make_session(test_engine)
        tid = str(uuid.uuid4())
        db.add(Tenant(
            id=tid, name="Empty Tenant", plan="starter",
            contact_email="empty@test.com", active=True,
        ))
        user = _create_user(db, tid)
        db.commit()
        user_id = user.id
        db.close()

        resp = client.get("/api/v1/alerts", headers=_jwt(user_id, tid))
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total_returned"] == 0
        assert data["next_cursor"] is None

    def test_lists_alerts_for_tenant(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid = test_tenants["tenant_a"]
        user = _create_user(db, tid)
        src = _create_source(db, tid, user.id, service_name="list-svc")
        for i in range(3):
            _create_alert(db, tid, src.id, service_name="list-svc")
        db.commit()
        user_id = user.id
        db.close()

        resp = client.get(
            "/api/v1/alerts",
            headers=_jwt(user_id, tid),
            params={"service": "list-svc"},
        )
        assert resp.status_code == 200
        assert resp.json()["total_returned"] >= 3

    def test_filter_by_service(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid = test_tenants["tenant_b"]
        user = _create_user(db, tid)
        src = _create_source(db, tid, user.id)
        _create_alert(db, tid, src.id, service_name="payment-filter")
        _create_alert(db, tid, src.id, service_name="auth-filter")
        db.commit()
        user_id = user.id
        db.close()

        resp = client.get(
            "/api/v1/alerts",
            headers=_jwt(user_id, tid),
            params={"service": "payment-filter"},
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) >= 1
        assert all(a["service_name"] == "payment-filter" for a in items)

    def test_filter_by_severity(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid = test_tenants["tenant_a"]
        user = _create_user(db, tid)
        src = _create_source(db, tid, user.id, service_name="sev-svc")
        _create_alert(db, tid, src.id, service_name="sev-svc", severity="CRITICAL")
        _create_alert(db, tid, src.id, service_name="sev-svc", severity="WARNING")
        db.commit()
        user_id = user.id
        db.close()

        resp = client.get(
            "/api/v1/alerts",
            headers=_jwt(user_id, tid),
            params={"severity": "CRITICAL", "service": "sev-svc"},
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) >= 1
        assert all(a["severity"] == "CRITICAL" for a in items)

    def test_filter_by_anomaly_type(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid = test_tenants["tenant_b"]
        user = _create_user(db, tid)
        src = _create_source(db, tid, user.id, service_name="type-svc")
        _create_alert(db, tid, src.id, service_name="type-svc", anomaly_type="CASCADE")
        _create_alert(db, tid, src.id, service_name="type-svc", anomaly_type="SERVICE_SILENCE")
        db.commit()
        user_id = user.id
        db.close()

        resp = client.get(
            "/api/v1/alerts",
            headers=_jwt(user_id, tid),
            params={"anomaly_type": "CASCADE", "service": "type-svc"},
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) >= 1
        assert all(a["anomaly_type"] == "CASCADE" for a in items)

    def test_filter_by_status(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid = test_tenants["tenant_a"]
        user = _create_user(db, tid)
        src = _create_source(db, tid, user.id, service_name="stat-svc")
        _create_alert(db, tid, src.id, service_name="stat-svc", alert_status="open")
        _create_alert(db, tid, src.id, service_name="stat-svc", alert_status="resolved")
        db.commit()
        user_id = user.id
        db.close()

        resp = client.get(
            "/api/v1/alerts",
            headers=_jwt(user_id, tid),
            params={"status": "resolved", "service": "stat-svc"},
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) >= 1
        assert all(a["status"] == "resolved" for a in items)

    def test_cursor_pagination(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid = test_tenants["tenant_a"]
        user = _create_user(db, tid)
        src = _create_source(db, tid, user.id, service_name="page-svc")
        base = datetime.now(UTC) - timedelta(hours=2)
        for i in range(5):
            _create_alert(
                db, tid, src.id,
                service_name="page-svc",
                detected_at=base + timedelta(seconds=i),
            )
        db.commit()
        user_id = user.id
        db.close()

        # Page 1
        resp1 = client.get(
            "/api/v1/alerts",
            headers=_jwt(user_id, tid),
            params={"service": "page-svc", "limit": 3},
        )
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["total_returned"] == 3
        assert data1["next_cursor"] is not None

        # Page 2
        resp2 = client.get(
            "/api/v1/alerts",
            headers=_jwt(user_id, tid),
            params={"service": "page-svc", "limit": 3, "cursor": data1["next_cursor"]},
        )
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["total_returned"] == 2

        # No ID overlap between pages
        ids1 = {a["id"] for a in data1["items"]}
        ids2 = {a["id"] for a in data2["items"]}
        assert ids1.isdisjoint(ids2)


class TestGetAlert:
    def test_get_returns_full_alert(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid = test_tenants["tenant_a"]
        user = _create_user(db, tid)
        src = _create_source(db, tid, user.id)
        alert = _create_alert(db, tid, src.id)
        db.commit()
        user_id, alert_id = user.id, alert.id
        db.close()

        resp = client.get(f"/api/v1/alerts/{alert_id}", headers=_jwt(user_id, tid))
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == alert_id
        assert data["tenant_id"] == tid

    def test_get_unknown_returns_404(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid = test_tenants["tenant_a"]
        user = _create_user(db, tid)
        db.commit()
        user_id = user.id
        db.close()

        resp = client.get(
            f"/api/v1/alerts/{uuid.uuid4()}",
            headers=_jwt(user_id, tid),
        )
        assert resp.status_code == 404


class TestAcknowledgeAlert:
    def test_acknowledge_transitions_status(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid = test_tenants["tenant_b"]
        user = _create_user(db, tid)
        src = _create_source(db, tid, user.id)
        alert = _create_alert(db, tid, src.id, alert_status="open")
        db.commit()
        user_id, alert_id = user.id, alert.id
        db.close()

        resp = client.post(
            f"/api/v1/alerts/{alert_id}/acknowledge",
            headers=_jwt(user_id, tid),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "acknowledged"
        assert data["acknowledged_by"] == user_id

    def test_acknowledge_idempotent(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid = test_tenants["tenant_a"]
        user = _create_user(db, tid)
        src = _create_source(db, tid, user.id)
        alert = _create_alert(db, tid, src.id, alert_status="acknowledged")
        alert.acknowledged_by = user.id
        alert.acknowledged_at = datetime.now(UTC)
        db.commit()
        user_id, alert_id = user.id, alert.id
        db.close()

        resp = client.post(
            f"/api/v1/alerts/{alert_id}/acknowledge",
            headers=_jwt(user_id, tid),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "acknowledged"

    def test_acknowledge_resolved_returns_409(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid = test_tenants["tenant_b"]
        user = _create_user(db, tid)
        src = _create_source(db, tid, user.id)
        alert = _create_alert(db, tid, src.id, alert_status="resolved")
        db.commit()
        user_id, alert_id = user.id, alert.id
        db.close()

        resp = client.post(
            f"/api/v1/alerts/{alert_id}/acknowledge",
            headers=_jwt(user_id, tid),
        )
        assert resp.status_code == 409

    def test_acknowledge_unknown_returns_404(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid = test_tenants["tenant_a"]
        user = _create_user(db, tid)
        db.commit()
        user_id = user.id
        db.close()

        resp = client.post(
            f"/api/v1/alerts/{uuid.uuid4()}/acknowledge",
            headers=_jwt(user_id, tid),
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Security: tenant isolation
# ---------------------------------------------------------------------------

class TestTenantIsolation:
    def test_tenant_a_cannot_see_tenant_b_alerts(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid_a = test_tenants["tenant_a"]
        tid_b = test_tenants["tenant_b"]
        user_a = _create_user(db, tid_a)
        user_b = _create_user(db, tid_b)
        src_b = _create_source(db, tid_b, user_b.id, service_name="secret-svc-iso")
        secret_alert = _create_alert(db, tid_b, src_b.id, service_name="secret-svc-iso")
        db.commit()
        user_a_id = user_a.id
        secret_id = secret_alert.id
        db.close()

        resp = client.get(
            "/api/v1/alerts",
            headers=_jwt(user_a_id, tid_a),
            params={"service": "secret-svc-iso"},
        )
        assert resp.status_code == 200
        ids = {a["id"] for a in resp.json()["items"]}
        assert secret_id not in ids

    def test_get_other_tenant_alert_returns_404(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid_a = test_tenants["tenant_a"]
        tid_b = test_tenants["tenant_b"]
        user_a = _create_user(db, tid_a)
        user_b = _create_user(db, tid_b)
        src_b = _create_source(db, tid_b, user_b.id)
        alert_b = _create_alert(db, tid_b, src_b.id)
        db.commit()
        user_a_id = user_a.id
        alert_b_id = alert_b.id
        db.close()

        resp = client.get(
            f"/api/v1/alerts/{alert_b_id}",
            headers=_jwt(user_a_id, tid_a),
        )
        assert resp.status_code == 404

    def test_acknowledge_other_tenant_alert_returns_404(self, client, test_engine, test_tenants):
        db = _make_session(test_engine)
        tid_a = test_tenants["tenant_a"]
        tid_b = test_tenants["tenant_b"]
        user_a = _create_user(db, tid_a)
        user_b = _create_user(db, tid_b)
        src_b = _create_source(db, tid_b, user_b.id)
        alert_b = _create_alert(db, tid_b, src_b.id)
        db.commit()
        user_a_id = user_a.id
        alert_b_id = alert_b.id
        db.close()

        resp = client.post(
            f"/api/v1/alerts/{alert_b_id}/acknowledge",
            headers=_jwt(user_a_id, tid_a),
        )
        assert resp.status_code == 404
