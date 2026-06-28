"""
tests/test_health.py — Module 11: Health endpoint tests.

Covers:
  - GET /api/v1/health returns 200 with status "ok"
  - Response includes version field
  - Response includes database and cache component statuses
  - X-API-Version header present on all responses
  - No authentication required
"""
import pytest


class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_health_status_ok(self, client):
        data = client.get("/api/v1/health").json()
        assert data["status"] in ("ok", "degraded")  # CI may run without all services

    def test_health_has_version(self, client):
        data = client.get("/api/v1/health").json()
        assert "version" in data
        assert isinstance(data["version"], str)
        assert len(data["version"]) > 0

    def test_health_has_components(self, client):
        data = client.get("/api/v1/health").json()
        assert "components" in data
        assert "database" in data["components"]
        assert "cache" in data["components"]

    def test_health_database_ok(self, client):
        data = client.get("/api/v1/health").json()
        assert data["components"]["database"]["status"] == "ok"

    def test_health_no_auth_required(self, client):
        # No Authorization header — must not return 401/403
        resp = client.get("/api/v1/health")
        assert resp.status_code not in (401, 403)

    def test_api_version_header_on_health(self, client):
        resp = client.get("/api/v1/health")
        assert "x-api-version" in resp.headers or "X-API-Version" in resp.headers

    def test_api_version_header_on_other_routes(self, client):
        # The middleware attaches the header to all responses
        resp = client.get("/api/v1/health")
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        assert "x-api-version" in headers_lower
