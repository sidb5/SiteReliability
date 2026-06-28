"""
tests/test_dashboard.py — Module 12: Dashboard UI + data API tests.

HTML view tests (no auth required at HTTP level — Alpine.js handles it):
  - GET /            → 307 redirect to /dashboard
  - GET /login       → 200 HTML
  - GET /dashboard   → 200 HTML, contains Alpine.js CDN
  - GET /admin       → 200 HTML
  - GET /consumer    → 200 HTML
  - GET /platform-admin → 200 HTML

Data API tests (auth required):
  - GET /api/v1/dashboard/summary → 200 with expected keys
  - GET /api/v1/dashboard/trend   → 200 with labels + counts
  - GET /api/v1/dashboard/trend?hours=6 → 200, 6 buckets in labels
  - Unauthenticated summary → 401/403
  - Tenant isolation: summary scoped to own tenant only
"""
import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import sessionmaker

from models.db import AnomalyAlert, LogSource, Tenant, User
from security import create_access_token

UTC = timezone.utc


def _make_session(test_engine):
    return sessionmaker(bind=test_engine, expire_on_commit=False)()


def _jwt(user_id, tenant_id, role="tenant_operator"):
    token = create_access_token(user_id, tenant_id, role)
    return {"Authorization": f"Bearer {token}"}


def _setup_tenant(db):
    t = Tenant(
        id=str(uuid.uuid4()),
        name=f"Dash-{uuid.uuid4().hex[:6]}",
        plan="starter",
        contact_email=f"dash-{uuid.uuid4().hex[:6]}@test.com",
        active=True,
    )
    db.add(t)
    u = User(
        tenant_id=t.id,
        email=f"dash-{uuid.uuid4().hex[:8]}@test.com",
        password_hash="$2b$12$placeholder",
        role="tenant_operator",
        active=True,
    )
    db.add(u)
    db.flush()
    return t, u


class TestHtmlViews:
    def test_root_redirects(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code in (301, 302, 307, 308)
        assert "/dashboard" in resp.headers.get("location", "")

    def test_login_page_200(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_dashboard_page_200(self, client):
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        # Alpine.js should be referenced in the template
        assert "alpinejs" in resp.text

    def test_admin_page_200(self, client):
        resp = client.get("/admin")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_consumer_page_200(self, client):
        resp = client.get("/consumer")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_platform_page_200(self, client):
        resp = client.get("/platform-admin")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_chart_js_referenced(self, client):
        resp = client.get("/dashboard")
        assert "chart.js" in resp.text.lower()


class TestDashboardDataApi:
    def test_summary_requires_auth(self, client):
        resp = client.get("/api/v1/dashboard/summary")
        assert resp.status_code in (401, 403)

    def test_summary_returns_expected_keys(self, client, test_engine):
        db = _make_session(test_engine)
        t, u = _setup_tenant(db)
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.get("/api/v1/dashboard/summary", headers=_jwt(uid, tid))
        assert resp.status_code == 200
        data = resp.json()
        for key in ("total_alerts", "open", "resolved", "acknowledged", "critical_open", "warning_open", "active_sources"):
            assert key in data, f"missing key: {key}"

    def test_summary_counts_only_own_tenant(self, client, test_engine):
        db = _make_session(test_engine)
        t_a, u_a = _setup_tenant(db)
        t_b, u_b = _setup_tenant(db)
        # Create a source + alert in tenant B
        src = LogSource(
            tenant_id=t_b.id,
            name="svc-b",
            service_name="svc-b",
            source_type="push",
            log_format="json",
            active=True,
            created_by=u_b.id,
        )
        db.add(src)
        db.flush()
        now = datetime.now(UTC)
        alert = AnomalyAlert(
            tenant_id=t_b.id,
            source_id=src.id,
            service_name="svc-b",
            environment="production",
            anomaly_type="SPIKE",
            severity="CRITICAL",
            status="open",
            detected_at=now,
            created_at=now,
            current_value=1.0,
            baseline_value=0.5,
            upper_bound=2.0,
            unit="count",
            window_start=now,
            window_end=now,
            sample_count=1,
            representative_msgs="[]",
            detection_context="{}",
            full_payload="{}",
        )
        db.add(alert)
        db.commit()
        tid_a, uid_a = t_a.id, u_a.id
        db.close()

        # Tenant A should see 0 open alerts
        resp = client.get("/api/v1/dashboard/summary", headers=_jwt(uid_a, tid_a))
        assert resp.status_code == 200
        assert resp.json()["open"] == 0

    def test_trend_requires_auth(self, client):
        resp = client.get("/api/v1/dashboard/trend")
        assert resp.status_code in (401, 403)

    def test_trend_returns_labels_and_counts(self, client, test_engine):
        db = _make_session(test_engine)
        t, u = _setup_tenant(db)
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.get("/api/v1/dashboard/trend", headers=_jwt(uid, tid))
        assert resp.status_code == 200
        data = resp.json()
        assert "labels" in data
        assert "counts" in data
        assert len(data["labels"]) == len(data["counts"])

    def test_trend_hours_param(self, client, test_engine):
        db = _make_session(test_engine)
        t, u = _setup_tenant(db)
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.get("/api/v1/dashboard/trend?hours=6", headers=_jwt(uid, tid))
        assert resp.status_code == 200
        data = resp.json()
        assert data["hours"] == 6
        assert len(data["labels"]) == 6

    def test_trend_hours_capped_at_168(self, client, test_engine):
        db = _make_session(test_engine)
        t, u = _setup_tenant(db)
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.get("/api/v1/dashboard/trend?hours=9999", headers=_jwt(uid, tid))
        assert resp.status_code == 200
        assert resp.json()["hours"] == 168
