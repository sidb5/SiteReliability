"""
tests/test_platform.py — Module 13: Platform Admin API tests.

Covers:
  POST /api/v1/platform/tenants   — create tenant (platform admin only)
  GET  /api/v1/platform/tenants   — list all tenants
  GET  /api/v1/platform/tenants/{id} — get one tenant, 404 unknown
  PATCH /api/v1/platform/tenants/{id} — update active/plan
  GET  /api/v1/platform/health    — platform aggregate health

Security:
  - Non-platform-admin (tenant_admin) cannot access platform endpoints (403)
  - Unauthenticated requests return 401/403
"""
import uuid

import pytest
from sqlalchemy.orm import sessionmaker

from models.db import Tenant, User
from security import Role, create_access_token, hash_password

UTC_TENANT_ID = "00000000-0000-0000-0000-000000000001"


def _make_session(test_engine):
    return sessionmaker(bind=test_engine, expire_on_commit=False)()


def _platform_jwt(user_id: str) -> dict:
    token = create_access_token(user_id, UTC_TENANT_ID, Role.PLATFORM_ADMIN.value)
    return {"Authorization": f"Bearer {token}"}


def _tenant_jwt(user_id: str, tenant_id: str) -> dict:
    token = create_access_token(user_id, tenant_id, Role.TENANT_ADMIN.value)
    return {"Authorization": f"Bearer {token}"}


def _setup_platform_admin(db) -> User:
    # Platform system tenant may already exist from bootstrap; create user
    tenant = db.query(Tenant).filter(Tenant.id == UTC_TENANT_ID).first()
    if not tenant:
        tenant = Tenant(
            id=UTC_TENANT_ID,
            name="Platform",
            plan="platform",
            contact_email="platform@test.com",
            active=True,
        )
        db.add(tenant)
        db.flush()

    u = User(
        tenant_id=UTC_TENANT_ID,
        email=f"plat-{uuid.uuid4().hex[:8]}@test.com",
        password_hash=hash_password("TestPwd123!"),
        role=Role.PLATFORM_ADMIN.value,
        active=True,
    )
    db.add(u)
    db.flush()
    return u


def _setup_tenant_admin(db) -> tuple:
    t = Tenant(
        id=str(uuid.uuid4()),
        name=f"TA-{uuid.uuid4().hex[:6]}",
        plan="starter",
        contact_email=f"ta-{uuid.uuid4().hex[:6]}@test.com",
        active=True,
    )
    db.add(t)
    db.flush()
    u = User(
        tenant_id=t.id,
        email=f"ta-{uuid.uuid4().hex[:8]}@test.com",
        password_hash="$2b$12$placeholder",
        role=Role.TENANT_ADMIN.value,
        active=True,
    )
    db.add(u)
    db.flush()
    return t, u


class TestPlatformTenants:
    def test_create_tenant(self, client, test_engine):
        db = _make_session(test_engine)
        admin = _setup_platform_admin(db)
        db.commit()
        uid = admin.id
        db.close()

        resp = client.post(
            "/api/v1/platform/tenants",
            json={"name": "Acme Corp", "contact_email": "acme@example.com"},
            headers=_platform_jwt(uid),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Acme Corp"
        assert data["active"] is True

    def test_tenant_admin_cannot_create_tenant(self, client, test_engine):
        db = _make_session(test_engine)
        t, u = _setup_tenant_admin(db)
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.post(
            "/api/v1/platform/tenants",
            json={"name": "Sneaky", "contact_email": "sneaky@example.com"},
            headers=_tenant_jwt(uid, tid),
        )
        assert resp.status_code == 403

    def test_list_tenants(self, client, test_engine):
        db = _make_session(test_engine)
        admin = _setup_platform_admin(db)
        db.commit()
        uid = admin.id
        db.close()

        resp = client.get("/api/v1/platform/tenants", headers=_platform_jwt(uid))
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_tenant(self, client, test_engine):
        db = _make_session(test_engine)
        admin = _setup_platform_admin(db)
        t = Tenant(
            id=str(uuid.uuid4()),
            name="GetMe Corp",
            plan="pro",
            contact_email="getme@test.com",
            active=True,
        )
        db.add(t)
        db.commit()
        uid, tid = admin.id, t.id
        db.close()

        resp = client.get(f"/api/v1/platform/tenants/{tid}", headers=_platform_jwt(uid))
        assert resp.status_code == 200
        assert resp.json()["name"] == "GetMe Corp"

    def test_get_tenant_not_found(self, client, test_engine):
        db = _make_session(test_engine)
        admin = _setup_platform_admin(db)
        db.commit()
        uid = admin.id
        db.close()

        resp = client.get(f"/api/v1/platform/tenants/{uuid.uuid4()}", headers=_platform_jwt(uid))
        assert resp.status_code == 404

    def test_deactivate_tenant(self, client, test_engine):
        db = _make_session(test_engine)
        admin = _setup_platform_admin(db)
        t = Tenant(
            id=str(uuid.uuid4()),
            name="Deactivate Me",
            plan="starter",
            contact_email=f"deact-{uuid.uuid4().hex[:6]}@test.com",
            active=True,
        )
        db.add(t)
        db.commit()
        uid, tid = admin.id, t.id
        db.close()

        resp = client.patch(
            f"/api/v1/platform/tenants/{tid}",
            json={"active": False},
            headers=_platform_jwt(uid),
        )
        assert resp.status_code == 200
        assert resp.json()["active"] is False

    def test_unauthenticated_cannot_list_tenants(self, client):
        resp = client.get("/api/v1/platform/tenants")
        assert resp.status_code in (401, 403)


class TestPlatformHealth:
    def test_platform_health_returns_stats(self, client, test_engine):
        db = _make_session(test_engine)
        admin = _setup_platform_admin(db)
        db.commit()
        uid = admin.id
        db.close()

        resp = client.get("/api/v1/platform/health", headers=_platform_jwt(uid))
        assert resp.status_code == 200
        data = resp.json()
        for key in ("total_tenants", "active_tenants", "total_alerts", "open_alerts",
                    "active_sources", "active_users"):
            assert key in data, f"missing key: {key}"

    def test_tenant_admin_cannot_access_platform_health(self, client, test_engine):
        db = _make_session(test_engine)
        t, u = _setup_tenant_admin(db)
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.get("/api/v1/platform/health", headers=_tenant_jwt(uid, tid))
        assert resp.status_code == 403
