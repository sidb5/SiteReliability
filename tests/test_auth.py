"""
tests/test_auth.py — Module 3: Auth endpoints and middleware.

Covers all 12 required test cases:
  1.  Login: valid credentials → 200, access_token, httpOnly refresh cookie
  2.  Login: wrong password → 401 (same error shape as unknown email)
  3.  Login: unknown email → 401 (same error shape as wrong password)
  4.  Login: rate limit — 11th request in 1 min → 429
  5.  Logout: refresh token row revoked in DB
  6.  Refresh: valid cookie → 200, new access token
  7.  Refresh: revoked cookie → 401
  8.  Platform Admin: POST /platform/tenants → 201
  9.  Platform Admin: Tenant Admin cannot create tenants → 403
  10. Middleware: X-Request-ID header on every response
  11. Middleware: every request produces a request_log row
  12. Middleware: X-API-Key and Authorization values absent from all log fields
"""
import logging
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from security import (
    Role,
    create_access_token,
    hash_password,
    hash_refresh_token,
)


# ---------------------------------------------------------------------------
# Module-level test data (users + platform admin account)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def auth_test_data(test_engine, test_tenants):
    """
    Insert module-scoped users for auth tests.
    Platform Admin is bootstrapped by the lifespan — we just need its creds
    from the env vars (already set in conftest.py).
    """
    tenant_a_id = test_tenants["tenant_a"]
    tenant_b_id = test_tenants["tenant_b"]

    op_id = str(uuid.uuid4())
    admin_id = str(uuid.uuid4())

    Session = sessionmaker(bind=test_engine, autocommit=False, autoflush=False,
                           expire_on_commit=False)
    session = Session()
    try:
        session.execute(text("""
            INSERT INTO users (id, tenant_id, email, password_hash, role, active, created_at)
            VALUES
              (:op_id,    :ta, 'op@tenant-a.com',    :op_hash,    'tenant_operator', 1, CURRENT_TIMESTAMP),
              (:admin_id, :ta, 'admin@tenant-a.com', :admin_hash, 'tenant_admin',    1, CURRENT_TIMESTAMP)
        """), {
            "op_id": op_id,
            "admin_id": admin_id,
            "ta": tenant_a_id,
            "op_hash": hash_password("OperatorPass1!"),
            "admin_hash": hash_password("AdminPass1!"),
        })
        session.commit()
    finally:
        session.close()

    return {
        "tenant_a_id": tenant_a_id,
        "tenant_b_id": tenant_b_id,
        "operator_id": op_id,
        "operator_email": "op@tenant-a.com",
        "operator_password": "OperatorPass1!",
        "admin_id": admin_id,
        "admin_email": "admin@tenant-a.com",
        "admin_password": "AdminPass1!",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, email, password):
    return client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )


def _access_token_for(user_id, tenant_id, role):
    return create_access_token(user_id, tenant_id, role)


# ---------------------------------------------------------------------------
# 1-4  Login
# ---------------------------------------------------------------------------

class TestLogin:
    def test_valid_credentials_returns_200_with_access_token(
        self, client, auth_test_data
    ):
        resp = _login(client, auth_test_data["operator_email"], auth_test_data["operator_password"])
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
        assert body["expires_in"] == 15 * 60

    def test_valid_credentials_sets_httponly_refresh_cookie(
        self, client, auth_test_data
    ):
        resp = _login(client, auth_test_data["operator_email"], auth_test_data["operator_password"])
        assert resp.status_code == 200
        cookie = resp.cookies.get("refresh_token")
        assert cookie is not None, "refresh_token cookie must be set"
        # httponly is enforced by the Set-Cookie header
        set_cookie = resp.headers.get("set-cookie", "")
        assert "httponly" in set_cookie.lower()

    def test_wrong_password_returns_401(self, client, auth_test_data):
        resp = _login(client, auth_test_data["operator_email"], "WRONG_PASSWORD")
        assert resp.status_code == 401
        body = resp.json()
        assert body["detail"]["code"] == "INVALID_CREDENTIALS"

    def test_unknown_email_returns_same_401_as_wrong_password(self, client):
        resp = _login(client, "nobody@nowhere.com", "AnyPassword1!")
        assert resp.status_code == 401
        body = resp.json()
        assert body["detail"]["code"] == "INVALID_CREDENTIALS"

    def test_unknown_email_and_wrong_password_have_identical_error_shapes(
        self, client, auth_test_data
    ):
        wrong_pw = _login(client, auth_test_data["operator_email"], "WRONG")
        unknown = _login(client, "ghost@test.com", "WRONG")
        # Same HTTP status
        assert wrong_pw.status_code == unknown.status_code == 401
        # Same error code — no enumeration possible
        assert wrong_pw.json()["detail"]["code"] == unknown.json()["detail"]["code"]

    def test_rate_limit_11th_request_returns_429(self, client):
        payload = {"email": "spam@test.com", "password": "pass"}
        for _ in range(10):
            client.post("/api/v1/auth/login", json=payload)
        resp = client.post("/api/v1/auth/login", json=payload)
        assert resp.status_code == 429


# ---------------------------------------------------------------------------
# 5  Logout
# ---------------------------------------------------------------------------

class TestLogout:
    def test_logout_revokes_refresh_token_in_db(
        self, client, auth_test_data, test_engine
    ):
        # Login to get a refresh cookie
        resp = _login(client, auth_test_data["operator_email"], auth_test_data["operator_password"])
        assert resp.status_code == 200
        raw_refresh = resp.cookies["refresh_token"]
        token_hash = hash_refresh_token(raw_refresh)

        # Verify the token is in the DB and not yet revoked
        with test_engine.connect() as conn:
            row = conn.execute(
                text("SELECT revoked_at FROM refresh_tokens WHERE token_hash = :h"),
                {"h": token_hash},
            ).fetchone()
        assert row is not None
        assert row.revoked_at is None

        # Logout
        logout_resp = client.post("/api/v1/auth/logout")
        assert logout_resp.status_code == 204

        # Token must now be revoked
        with test_engine.connect() as conn:
            row = conn.execute(
                text("SELECT revoked_at FROM refresh_tokens WHERE token_hash = :h"),
                {"h": token_hash},
            ).fetchone()
        assert row.revoked_at is not None

    def test_logout_without_cookie_returns_204(self, client):
        # Safe to call even with no cookie — no error
        resp = client.post("/api/v1/auth/logout")
        assert resp.status_code == 204


# ---------------------------------------------------------------------------
# 6-7  Refresh
# ---------------------------------------------------------------------------

class TestRefresh:
    def test_valid_refresh_cookie_returns_new_access_token(
        self, client, auth_test_data
    ):
        # Login to get cookie
        resp = _login(client, auth_test_data["operator_email"], auth_test_data["operator_password"])
        assert resp.status_code == 200

        # Use refresh endpoint (TestClient automatically sends the cookie)
        refresh_resp = client.post("/api/v1/auth/refresh")
        assert refresh_resp.status_code == 200
        body = refresh_resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"

    def test_revoked_refresh_cookie_returns_401(
        self, client, auth_test_data, test_engine
    ):
        # Login
        resp = _login(client, auth_test_data["operator_email"], auth_test_data["operator_password"])
        raw_refresh = resp.cookies["refresh_token"]
        token_hash = hash_refresh_token(raw_refresh)

        # Manually revoke in DB (simulating /logout on another device)
        Session = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)
        session = Session()
        try:
            session.execute(
                text("UPDATE refresh_tokens SET revoked_at = :now WHERE token_hash = :h"),
                {"now": datetime.utcnow(), "h": token_hash},
            )
            session.commit()
        finally:
            session.close()

        # Attempt refresh — must fail
        refresh_resp = client.post("/api/v1/auth/refresh")
        assert refresh_resp.status_code == 401
        assert refresh_resp.json()["detail"]["code"] == "REFRESH_TOKEN_INVALID"

    def test_missing_refresh_cookie_returns_401(self, client):
        # No prior login — no cookie in client jar
        resp = client.post("/api/v1/auth/refresh")
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "REFRESH_TOKEN_MISSING"


# ---------------------------------------------------------------------------
# 8-9  Platform Admin: create tenant
# ---------------------------------------------------------------------------

class TestPlatformAdminCreateTenant:
    def _platform_admin_token(self, test_engine):
        """Get tenant_id of the platform system tenant, build access token."""
        with test_engine.connect() as conn:
            row = conn.execute(
                text("SELECT id, tenant_id FROM users WHERE role = 'platform_admin' LIMIT 1")
            ).fetchone()
        assert row is not None, "Platform Admin not bootstrapped"
        return _access_token_for(row.id, row.tenant_id, Role.PLATFORM_ADMIN.value)

    def test_platform_admin_can_create_tenant(self, client, test_engine):
        token = self._platform_admin_token(test_engine)
        resp = client.post(
            "/api/v1/platform/tenants",
            json={
                "name": "New Corp",
                "contact_email": "admin@newcorp.com",
                "plan": "starter",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["name"] == "New Corp"
        assert body["contact_email"] == "admin@newcorp.com"
        assert body["active"] is True
        assert "id" in body

    def test_tenant_admin_cannot_create_tenant(self, client, auth_test_data):
        token = _access_token_for(
            auth_test_data["admin_id"],
            auth_test_data["tenant_a_id"],
            Role.TENANT_ADMIN.value,
        )
        resp = client.post(
            "/api/v1/platform/tenants",
            json={"name": "Sneaky Corp", "contact_email": "x@sneaky.com"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_unauthenticated_cannot_create_tenant(self, client):
        resp = client.post(
            "/api/v1/platform/tenants",
            json={"name": "Ghost Corp", "contact_email": "ghost@ghost.com"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 10-12  Middleware
# ---------------------------------------------------------------------------

class TestMiddleware:
    def test_x_request_id_present_on_200_response(self, client, auth_test_data):
        resp = _login(client, auth_test_data["operator_email"], auth_test_data["operator_password"])
        assert "x-request-id" in resp.headers

    def test_x_request_id_present_on_401_response(self, client):
        resp = _login(client, "nobody@test.com", "WRONG")
        assert "x-request-id" in resp.headers

    def test_x_request_id_propagated_when_client_sends_one(self, client, auth_test_data):
        my_id = str(uuid.uuid4())
        resp = _login(
            client,
            auth_test_data["operator_email"],
            auth_test_data["operator_password"],
        )
        # Send with our own ID
        resp2 = client.post(
            "/api/v1/auth/logout",
            headers={"X-Request-ID": my_id},
        )
        assert resp2.headers["x-request-id"] == my_id

    def test_every_request_produces_request_log_row(self, client, test_engine):
        before = _count_request_log(test_engine)
        client.post("/api/v1/auth/refresh")  # any endpoint
        after = _count_request_log(test_engine)
        assert after == before + 1

    def test_api_key_value_absent_from_all_log_fields(
        self, client, caplog
    ):
        sentinel = "wdog_live_SUPERSECRET_SHOULD_NOT_APPEAR"
        with caplog.at_level(logging.INFO, logger="middleware"):
            client.post(
                "/api/v1/auth/refresh",
                headers={"X-API-Key": sentinel},
            )

        for record in caplog.records:
            assert sentinel not in str(record.__dict__), (
                f"API key value leaked into log record: {record.__dict__}"
            )

    def test_authorization_value_absent_from_all_log_fields(
        self, client, auth_test_data, caplog
    ):
        token = _access_token_for(
            auth_test_data["operator_id"],
            auth_test_data["tenant_a_id"],
            Role.TENANT_OPERATOR.value,
        )
        with caplog.at_level(logging.INFO, logger="middleware"):
            client.post(
                "/api/v1/auth/logout",
                headers={"Authorization": f"Bearer {token}"},
            )

        for record in caplog.records:
            assert token not in str(record.__dict__), (
                f"Authorization token leaked into log record"
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _count_request_log(engine) -> int:
    with engine.connect() as conn:
        return conn.execute(text("SELECT COUNT(*) FROM request_log")).scalar()
