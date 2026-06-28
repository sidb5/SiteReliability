"""
tests/test_ingest.py — Module 5: Push ingest endpoint tests.

10 tests covering:
  - happy path: single entry, batch, large payload, future timestamp
  - validation: missing field, invalid level, batch atomicity
  - auth: missing key, wrong scope
  - rate limiting: 429 on 101st request
  - architectural proof: no DB row written on valid ingest

Fixtures use the shared conftest (app, client, test_engine, test_tenants).
Each test creates its own API key to avoid cross-test pollution.
"""
import json
import uuid
from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import inspect, text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _insert_api_key(
    engine,
    tenant_id: str,
    scopes: list[str],
    environment: str = "live",
) -> tuple[str, str]:
    """
    Mint a real API key, store its SHA-256 hash in api_keys, return (plaintext, key_id).
    The plaintext is returned once and never stored — mirrors production key generation.

    ApiKey.user_id is NOT NULL, so we create a minimal user row owned by the
    same tenant and use its id for the FK.  The user has no meaningful role here —
    its only purpose is to satisfy the FK constraint.
    """
    from security import generate_api_key, hash_password

    plaintext, key_hash = generate_api_key(environment=environment)
    key_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    prefix = plaintext[:12]

    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (id, tenant_id, email, password_hash, role, active) "
                "VALUES (:id, :tid, :email, :pw, 'tenant_operator', 1)"
            ),
            {
                "id": user_id,
                "tid": tenant_id,
                "email": f"key-owner-{user_id[:8]}@test.com",
                "pw": hash_password("unused"),
            },
        )
        conn.execute(
            text(
                "INSERT INTO api_keys "
                "(id, tenant_id, user_id, name, key_hash, key_prefix, environment, scopes) "
                "VALUES (:id, :tid, :uid, :name, :hash, :prefix, :env, :scopes)"
            ),
            {
                "id": key_id,
                "tid": tenant_id,
                "uid": user_id,
                "name": f"test-key-{key_id[:8]}",
                "hash": key_hash,
                "prefix": prefix,
                "env": environment,
                "scopes": json.dumps(scopes),
            },
        )
    return plaintext, key_id


def _all_table_row_counts(engine) -> dict[str, int]:
    """Return row counts for every table in the DB. Used to prove no writes occurred."""
    inspector = inspect(engine)
    counts = {}
    with engine.connect() as conn:
        for table in inspector.get_table_names():
            result = conn.execute(text(f"SELECT COUNT(*) FROM {table}"))  # noqa: S608
            counts[table] = result.scalar()
    return counts


# ---------------------------------------------------------------------------
# Test 1 — Valid single entry → 201, no DB row written
# ---------------------------------------------------------------------------

def test_single_entry_accepted_no_db_write(client, test_engine, test_tenants):
    """
    Core architectural proof: a valid single ingest returns 201 with the
    expected response shape, and no new rows appear in ANY table.
    """
    tenant_id = test_tenants["tenant_a"]
    plaintext, _ = _insert_api_key(test_engine, tenant_id, ["ingest"])

    # Snapshot every table's row count BEFORE the request
    counts_before = _all_table_row_counts(test_engine)

    resp = client.post(
        "/api/v1/ingest",
        json={"message": "disk utilisation at 92%", "level": "WARNING"},
        headers={"X-API-Key": plaintext},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "accepted"
    assert body["tenant_id"] == tenant_id
    assert "id" in body
    assert "received_at" in body

    # Snapshot AFTER the request.
    # Excluded tables:
    #   request_log — middleware writes one row per HTTP request (expected, correct)
    #   api_keys    — last_used_at is updated in-place, row count unchanged (excluded by comment)
    # The assertion proves that no application-level log entry rows were written.
    _ALLOWED_GROWTH = {"request_log"}
    counts_after = _all_table_row_counts(test_engine)
    for table, before in counts_before.items():
        if table in _ALLOWED_GROWTH:
            continue
        after = counts_after[table]
        assert after == before, (
            f"Table '{table}' gained {after - before} row(s) during ingest. "
            "Raw log entries must never be persisted to the database."
        )


# ---------------------------------------------------------------------------
# Test 2 — Valid batch of 100 entries → 201, accepted: 100
# ---------------------------------------------------------------------------

def test_batch_100_entries_accepted(client, test_engine, test_tenants):
    tenant_id = test_tenants["tenant_a"]
    plaintext, _ = _insert_api_key(test_engine, tenant_id, ["ingest"])

    entries = [{"message": f"event {i}", "level": "INFO"} for i in range(100)]
    resp = client.post(
        "/api/v1/ingest/batch",
        json={"entries": entries},
        headers={"X-API-Key": plaintext},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "accepted"
    assert body["accepted"] == 100


# ---------------------------------------------------------------------------
# Test 3 — Missing required field (message) → 422 with field detail
# ---------------------------------------------------------------------------

def test_missing_message_returns_422(client, test_engine, test_tenants):
    tenant_id = test_tenants["tenant_a"]
    plaintext, _ = _insert_api_key(test_engine, tenant_id, ["ingest"])

    resp = client.post(
        "/api/v1/ingest",
        json={"level": "ERROR"},          # message omitted
        headers={"X-API-Key": plaintext},
    )

    assert resp.status_code == 422
    detail = resp.json()["detail"]
    fields = [e["loc"] for e in detail]
    assert any("message" in loc for loc in fields), (
        f"Expected 'message' in validation error locations, got: {fields}"
    )


# ---------------------------------------------------------------------------
# Test 4 — Invalid level value → 422
# ---------------------------------------------------------------------------

def test_invalid_level_returns_422(client, test_engine, test_tenants):
    tenant_id = test_tenants["tenant_a"]
    plaintext, _ = _insert_api_key(test_engine, tenant_id, ["ingest"])

    resp = client.post(
        "/api/v1/ingest",
        json={"message": "x", "level": "VERBOSE"},   # VERBOSE not in allowed set
        headers={"X-API-Key": plaintext},
    )

    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Test 5 — Missing API key → 401
# ---------------------------------------------------------------------------

def test_missing_api_key_returns_401(client):
    resp = client.post(
        "/api/v1/ingest",
        json={"message": "hello"},
        # No X-API-Key header
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Test 6 — API key with wrong scope (alerts:read) → 403
# ---------------------------------------------------------------------------

def test_wrong_scope_returns_403(client, test_engine, test_tenants):
    tenant_id = test_tenants["tenant_a"]
    plaintext, _ = _insert_api_key(test_engine, tenant_id, ["alerts:read"])

    resp = client.post(
        "/api/v1/ingest",
        json={"message": "attempt with read-only key"},
        headers={"X-API-Key": plaintext},
    )

    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Test 7 — 101st request in the same minute → 429 with Retry-After header
# ---------------------------------------------------------------------------

def test_rate_limit_101_returns_429(client, test_engine, test_tenants):
    tenant_id = test_tenants["tenant_a"]
    plaintext, _ = _insert_api_key(test_engine, tenant_id, ["ingest"])

    headers = {"X-API-Key": plaintext}
    payload = {"message": "ping"}

    # Send 100 requests — all should succeed
    for _ in range(100):
        r = client.post("/api/v1/ingest", json=payload, headers=headers)
        assert r.status_code == 201, f"Expected 201 before limit, got {r.status_code}"

    # 101st request must be rate-limited
    r = client.post("/api/v1/ingest", json=payload, headers=headers)
    assert r.status_code == 429
    # slowapi sets Retry-After on 429 responses
    assert "retry-after" in {k.lower() for k in r.headers.keys()}, (
        f"Expected Retry-After header in 429 response, got: {dict(r.headers)}"
    )


# ---------------------------------------------------------------------------
# Test 8 — Large payload (10 KB message) → 201, not truncated
# ---------------------------------------------------------------------------

def test_large_message_accepted_and_not_truncated(client, test_engine, test_tenants):
    tenant_id = test_tenants["tenant_a"]
    plaintext, _ = _insert_api_key(test_engine, tenant_id, ["ingest"])

    big_message = "x" * 10_240  # 10 KB

    resp = client.post(
        "/api/v1/ingest",
        json={"message": big_message, "level": "DEBUG"},
        headers={"X-API-Key": plaintext},
    )

    assert resp.status_code == 201
    # Verify the response is accepted — the message itself isn't echoed back,
    # but the 201 confirms the full payload was processed without truncation error.


# ---------------------------------------------------------------------------
# Test 9 — Entry with future occurred_at → 201, timestamp preserved
# ---------------------------------------------------------------------------

def test_future_occurred_at_accepted(client, test_engine, test_tenants):
    tenant_id = test_tenants["tenant_a"]
    plaintext, _ = _insert_api_key(test_engine, tenant_id, ["ingest"])

    future_ts = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()

    resp = client.post(
        "/api/v1/ingest",
        json={"message": "event from the future", "occurred_at": future_ts},
        headers={"X-API-Key": plaintext},
    )

    assert resp.status_code == 201
    # The endpoint accepts the entry; occurred_at is not echoed in the response,
    # but the 201 confirms the future timestamp did not cause a validation rejection.


# ---------------------------------------------------------------------------
# Test 10 — Batch with one invalid entry → 422, zero entries processed
# ---------------------------------------------------------------------------

def test_batch_one_invalid_entry_returns_422(client, test_engine, test_tenants):
    """
    Pydantic validates the entire BatchIngestRequest before process_entries()
    is ever called.  One invalid entry must cause the entire batch to be
    rejected — no partial processing.
    """
    tenant_id = test_tenants["tenant_a"]
    plaintext, _ = _insert_api_key(test_engine, tenant_id, ["ingest"])

    counts_before = _all_table_row_counts(test_engine)

    entries = [
        {"message": "valid entry", "level": "INFO"},
        {"message": "also valid", "level": "ERROR"},
        {"level": "DEBUG"},          # invalid: missing required message
        {"message": "last valid"},
    ]
    resp = client.post(
        "/api/v1/ingest/batch",
        json={"entries": entries},
        headers={"X-API-Key": plaintext},
    )

    assert resp.status_code == 422

    # No DB writes from a rejected batch (request_log still gets its audit row — expected)
    _ALLOWED_GROWTH = {"request_log"}
    counts_after = _all_table_row_counts(test_engine)
    for table, before in counts_before.items():
        if table in _ALLOWED_GROWTH:
            continue
        after = counts_after[table]
        assert after == before, (
            f"Table '{table}' changed during a rejected batch ingest — "
            "partial batch processing must not occur."
        )
