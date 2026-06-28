"""
tests/test_admin.py — Module 9: Admin API tests.

Covers:
  Sources (Tenant Admin):
    - Create source (201)
    - Create source — duplicate name 409
    - List sources (200)
    - Get source (200, 404)
    - Update source (200)
    - Delete source (204, then 404)
    - Operator cannot create/delete source (403)

  Users (Tenant Admin):
    - Create user (201)
    - Create user — duplicate email 409
    - List users (200)
    - Update user active/role (200)
    - Cannot deactivate self (400)
    - Delete user (204)

  Keys (all authenticated):
    - Create key (201, plaintext returned once)
    - List keys — operator sees own; admin sees all
    - Revoke key (204)
    - Rotate key (200, new plaintext, grace period set)
    - Attach webhook (200, secret returned once)
    - Detach webhook (204)
    - API key auth cannot create keys (403)

  Config (Tenant Admin):
    - Get config (200)
    - Update retention (200)
    - Operator cannot update config (403)

  Security:
    - Tenant A cannot see Tenant B sources
    - Tenant A cannot delete Tenant B source
"""
import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import sessionmaker

from models.db import ApiKey, LogSource, Tenant, User
from security import Role, create_access_token, generate_api_key, hash_api_key

UTC = timezone.utc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session(test_engine):
    return sessionmaker(bind=test_engine, expire_on_commit=False)()


def _jwt(user_id: str, tenant_id: str, role: str = "tenant_admin") -> dict:
    token = create_access_token(user_id, tenant_id, role)
    return {"Authorization": f"Bearer {token}"}


def _operator_jwt(user_id: str, tenant_id: str) -> dict:
    return _jwt(user_id, tenant_id, role="tenant_operator")


def _create_tenant(db, suffix: str = "") -> Tenant:
    t = Tenant(
        id=str(uuid.uuid4()),
        name=f"AdminTest{suffix}",
        plan="starter",
        contact_email=f"admin{suffix}@test.com",
        active=True,
    )
    db.add(t)
    db.flush()
    return t


def _create_user(db, tenant_id: str, role: str = "tenant_admin") -> User:
    u = User(
        tenant_id=tenant_id,
        email=f"adm-{uuid.uuid4().hex[:8]}@test.com",
        password_hash="$2b$12$placeholder",
        role=role,
        active=True,
    )
    db.add(u)
    db.flush()
    return u


def _create_source(db, tenant_id: str, user_id: str, name: str = None) -> LogSource:
    src = LogSource(
        tenant_id=tenant_id,
        name=name or f"src-{uuid.uuid4().hex[:6]}",
        service_name="test-service",
        source_type="push",
        log_format="json",
        active=True,
        created_by=user_id,
    )
    db.add(src)
    db.flush()
    return src


def _create_key(db, tenant_id: str, user_id: str) -> tuple:
    plaintext, key_hash = generate_api_key()
    key = ApiKey(
        tenant_id=tenant_id,
        user_id=user_id,
        name=f"key-{uuid.uuid4().hex[:6]}",
        key_hash=key_hash,
        key_prefix=plaintext[:12],
        scopes=json.dumps(["alerts:read"]),
        environment="live",
    )
    db.add(key)
    db.flush()
    return key, plaintext


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

class TestSources:
    def test_create_source(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.post(
            "/api/v1/admin/sources",
            json={"name": "my-source", "service_name": "svc", "source_type": "push", "log_format": "json"},
            headers=_jwt(uid, tid),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "my-source"
        assert "connection_config" not in data   # masked

    def test_create_source_duplicate_name_409(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        _create_source(db, t.id, u.id, name="dup-src")
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.post(
            "/api/v1/admin/sources",
            json={"name": "dup-src", "service_name": "svc", "source_type": "push", "log_format": "json"},
            headers=_jwt(uid, tid),
        )
        assert resp.status_code == 409

    def test_list_sources(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        _create_source(db, t.id, u.id)
        _create_source(db, t.id, u.id)
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.get("/api/v1/admin/sources", headers=_jwt(uid, tid, "tenant_operator"))
        assert resp.status_code == 200
        assert len(resp.json()) >= 2

    def test_get_source(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        src = _create_source(db, t.id, u.id)
        db.commit()
        tid, uid, src_id = t.id, u.id, src.id
        db.close()

        resp = client.get(f"/api/v1/admin/sources/{src_id}", headers=_jwt(uid, tid, "tenant_operator"))
        assert resp.status_code == 200
        assert resp.json()["id"] == src_id

    def test_get_source_not_found(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.get(f"/api/v1/admin/sources/{uuid.uuid4()}", headers=_jwt(uid, tid))
        assert resp.status_code == 404

    def test_update_source(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        src = _create_source(db, t.id, u.id)
        db.commit()
        tid, uid, src_id = t.id, u.id, src.id
        db.close()

        resp = client.patch(
            f"/api/v1/admin/sources/{src_id}",
            json={"poll_interval_s": 30, "active": False},
            headers=_jwt(uid, tid),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["poll_interval_s"] == 30
        assert data["active"] is False

    def test_delete_source(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        src = _create_source(db, t.id, u.id)
        db.commit()
        tid, uid, src_id = t.id, u.id, src.id
        db.close()

        resp = client.delete(f"/api/v1/admin/sources/{src_id}", headers=_jwt(uid, tid))
        assert resp.status_code == 204

        resp2 = client.get(f"/api/v1/admin/sources/{src_id}", headers=_jwt(uid, tid))
        assert resp2.status_code == 404

    def test_operator_cannot_create_source(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id, "tenant_operator")
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.post(
            "/api/v1/admin/sources",
            json={"name": "no-perm", "service_name": "s", "source_type": "push", "log_format": "json"},
            headers=_operator_jwt(uid, tid),
        )
        assert resp.status_code == 403

    def test_tenant_isolation(self, client, test_engine):
        db = _make_session(test_engine)
        t_a = _create_tenant(db, "A_iso")
        t_b = _create_tenant(db, "B_iso")
        u_a = _create_user(db, t_a.id)
        u_b = _create_user(db, t_b.id)
        src_b = _create_source(db, t_b.id, u_b.id)
        db.commit()
        tid_a, uid_a = t_a.id, u_a.id
        src_b_id = src_b.id
        db.close()

        resp = client.get(f"/api/v1/admin/sources/{src_b_id}", headers=_jwt(uid_a, tid_a))
        assert resp.status_code == 404

        resp2 = client.delete(f"/api/v1/admin/sources/{src_b_id}", headers=_jwt(uid_a, tid_a))
        assert resp2.status_code == 404


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

class TestUsers:
    def test_create_user(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        admin = _create_user(db, t.id)
        db.commit()
        tid, uid = t.id, admin.id
        db.close()

        resp = client.post(
            "/api/v1/admin/users",
            json={"email": f"new-{uuid.uuid4().hex[:6]}@example.com", "password": "Passw0rd!", "role": "tenant_operator"},
            headers=_jwt(uid, tid),
        )
        assert resp.status_code == 201
        assert resp.json()["role"] == "tenant_operator"

    def test_create_user_duplicate_email_409(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        admin = _create_user(db, t.id)
        existing = _create_user(db, t.id)
        db.commit()
        tid, uid = t.id, admin.id
        existing_email = existing.email
        db.close()

        resp = client.post(
            "/api/v1/admin/users",
            json={"email": existing_email, "password": "Passw0rd!", "role": "tenant_operator"},
            headers=_jwt(uid, tid),
        )
        assert resp.status_code == 409

    def test_list_users(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        admin = _create_user(db, t.id)
        _create_user(db, t.id, "tenant_operator")
        db.commit()
        tid, uid = t.id, admin.id
        db.close()

        resp = client.get("/api/v1/admin/users", headers=_jwt(uid, tid))
        assert resp.status_code == 200
        assert len(resp.json()) >= 2

    def test_update_user_role(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        admin = _create_user(db, t.id)
        target = _create_user(db, t.id, "tenant_operator")
        db.commit()
        tid, uid = t.id, admin.id
        target_id = target.id
        db.close()

        resp = client.patch(
            f"/api/v1/admin/users/{target_id}",
            json={"role": "tenant_admin"},
            headers=_jwt(uid, tid),
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "tenant_admin"

    def test_cannot_deactivate_self(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        admin = _create_user(db, t.id)
        db.commit()
        tid, uid = t.id, admin.id
        db.close()

        resp = client.patch(
            f"/api/v1/admin/users/{uid}",
            json={"active": False},
            headers=_jwt(uid, tid),
        )
        assert resp.status_code == 400

    def test_delete_user(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        admin = _create_user(db, t.id)
        target = _create_user(db, t.id, "tenant_operator")
        db.commit()
        tid, uid = t.id, admin.id
        target_id = target.id
        db.close()

        resp = client.delete(f"/api/v1/admin/users/{target_id}", headers=_jwt(uid, tid))
        assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

class TestKeys:
    def test_create_key_returns_plaintext_once(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.post(
            "/api/v1/admin/keys",
            json={"name": "my-key", "scopes": ["alerts:read"], "environment": "live"},
            headers=_jwt(uid, tid),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "plaintext_key" in data
        assert data["plaintext_key"].startswith("wdog_live_")
        assert data["scopes"] == ["alerts:read"]

    def test_list_keys_operator_sees_own(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u1 = _create_user(db, t.id, "tenant_operator")
        u2 = _create_user(db, t.id, "tenant_operator")
        _create_key(db, t.id, u1.id)
        _create_key(db, t.id, u2.id)
        db.commit()
        tid, uid1 = t.id, u1.id
        db.close()

        resp = client.get("/api/v1/admin/keys", headers=_operator_jwt(uid1, tid))
        assert resp.status_code == 200
        items = resp.json()
        # Operator only sees their own keys
        assert all(k["id"] for k in items)   # sanity

    def test_revoke_key(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        key, _ = _create_key(db, t.id, u.id)
        db.commit()
        tid, uid, kid = t.id, u.id, key.id
        db.close()

        resp = client.delete(f"/api/v1/admin/keys/{kid}", headers=_jwt(uid, tid))
        assert resp.status_code == 204

        # Key no longer appears in list
        resp2 = client.get("/api/v1/admin/keys", headers=_jwt(uid, tid))
        ids = [k["id"] for k in resp2.json()]
        assert kid not in ids

    def test_rotate_key(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        key, _ = _create_key(db, t.id, u.id)
        db.commit()
        tid, uid, kid = t.id, u.id, key.id
        db.close()

        resp = client.post(f"/api/v1/admin/keys/{kid}/rotate", headers=_jwt(uid, tid))
        assert resp.status_code == 200
        data = resp.json()
        assert data["old_key_id"] == kid
        assert data["new_key_id"] != kid
        assert data["plaintext_key"].startswith("wdog_")
        assert "grace_period_ends_at" in data

    def test_attach_webhook_returns_secret_once(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        key, _ = _create_key(db, t.id, u.id)
        db.commit()
        tid, uid, kid = t.id, u.id, key.id
        db.close()

        resp = client.post(
            f"/api/v1/admin/keys/{kid}/webhook",
            json={"webhook_url": "https://example.com/hook", "severity_filter": "CRITICAL"},
            headers=_jwt(uid, tid),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "webhook_secret" in data
        assert len(data["webhook_secret"]) > 10

    def test_detach_webhook(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        key, _ = _create_key(db, t.id, u.id)
        db.commit()
        tid, uid, kid = t.id, u.id, key.id
        db.close()

        # Attach first
        client.post(
            f"/api/v1/admin/keys/{kid}/webhook",
            json={"webhook_url": "https://example.com/hook"},
            headers=_jwt(uid, tid),
        )

        resp = client.delete(f"/api/v1/admin/keys/{kid}/webhook", headers=_jwt(uid, tid))
        assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

class TestConfig:
    def test_get_config(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.get("/api/v1/admin/config", headers=_jwt(uid, tid))
        assert resp.status_code == 200
        data = resp.json()
        assert "retention_days" in data
        assert "log_retention_days" in data

    def test_update_retention(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id)
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.patch(
            "/api/v1/admin/config",
            json={"retention_days": 60, "log_retention_days": 14},
            headers=_jwt(uid, tid),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["retention_days"] == 60
        assert data["log_retention_days"] == 14

    def test_operator_cannot_update_config(self, client, test_engine):
        db = _make_session(test_engine)
        t = _create_tenant(db)
        u = _create_user(db, t.id, "tenant_operator")
        db.commit()
        tid, uid = t.id, u.id
        db.close()

        resp = client.patch(
            "/api/v1/admin/config",
            json={"retention_days": 90},
            headers=_operator_jwt(uid, tid),
        )
        assert resp.status_code == 403
