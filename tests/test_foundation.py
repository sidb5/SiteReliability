"""
Module 1 — Foundation tests.

Covers: migration correctness, idempotency, config fast-fail,
config loading, get_db lifecycle, and two-tenant isolation baseline.
"""
import uuid

import pytest
from sqlalchemy import inspect, text
from pydantic import ValidationError


EXPECTED_TABLES = [
    "tenants",
    "users",
    "refresh_tokens",
    "api_keys",
    "log_sources",
    "source_state",
    "ewma_state",
    "anomaly_alerts",
    "webhook_events",
    "system_config",
    "request_log",
]


# ---------------------------------------------------------------------------
# Migration tests
# ---------------------------------------------------------------------------

class TestMigration:
    def test_all_tables_exist_after_migration(self, test_engine):
        inspector = inspect(test_engine)
        tables = set(inspector.get_table_names())
        missing = [t for t in EXPECTED_TABLES if t not in tables]
        assert not missing, f"Tables missing after migration: {missing}"

    def test_migration_idempotent(self, test_engine, test_db_url):
        """Running upgrade head a second time must not raise."""
        from alembic.config import Config as AlembicConfig
        from alembic import command as alembic_command

        cfg = AlembicConfig("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", test_db_url)
        # First run already applied by the test_engine fixture.
        # A second run must be a silent no-op.
        alembic_command.upgrade(cfg, "head")

        # Tables still present
        tables = set(inspect(test_engine).get_table_names())
        assert set(EXPECTED_TABLES).issubset(tables)


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

class TestConfig:
    def test_fails_fast_on_missing_required_var(self, monkeypatch):
        """Instantiating Settings without a required var raises ValidationError."""
        monkeypatch.delenv("FERNET_KEY", raising=False)
        from config import Settings
        with pytest.raises(ValidationError):
            Settings(_env_file=None)

    def test_loads_defaults_when_optional_vars_absent(self, monkeypatch):
        """Optional vars use documented defaults when not set."""
        from cryptography.fernet import Fernet
        from config import Settings

        fernet_key = Fernet.generate_key().decode()
        monkeypatch.setenv("FERNET_KEY", fernet_key)
        monkeypatch.setenv("JWT_PRIVATE_KEY", "dummy")
        monkeypatch.setenv("JWT_PUBLIC_KEY", "dummy")
        monkeypatch.setenv("PLATFORM_ADMIN_EMAIL", "admin@test.com")
        monkeypatch.setenv("PLATFORM_ADMIN_PASSWORD", "TestPass123!")
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        monkeypatch.delenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", raising=False)

        s = Settings(_env_file=None)
        assert s.LOG_LEVEL == "WARNING"
        assert s.JWT_ACCESS_TOKEN_EXPIRE_MINUTES == 15
        assert s.JWT_REFRESH_TOKEN_EXPIRE_DAYS == 7
        assert s.APP_VERSION == "1.0.0"

    def test_config_loads_fernet_key_correctly(self, monkeypatch):
        """Settings stores the exact FERNET_KEY value supplied."""
        from cryptography.fernet import Fernet
        from config import Settings

        key = Fernet.generate_key().decode()
        monkeypatch.setenv("FERNET_KEY", key)
        monkeypatch.setenv("JWT_PRIVATE_KEY", "dummy")
        monkeypatch.setenv("JWT_PUBLIC_KEY", "dummy")
        monkeypatch.setenv("PLATFORM_ADMIN_EMAIL", "admin@test.com")
        monkeypatch.setenv("PLATFORM_ADMIN_PASSWORD", "TestPass123!")

        s = Settings(_env_file=None)
        assert s.FERNET_KEY == key

    def test_invalid_fernet_key_raises(self, monkeypatch):
        """A garbage FERNET_KEY value must fail validation."""
        from config import Settings

        monkeypatch.setenv("FERNET_KEY", "not-a-valid-fernet-key")
        monkeypatch.setenv("JWT_PRIVATE_KEY", "dummy")
        monkeypatch.setenv("JWT_PUBLIC_KEY", "dummy")
        monkeypatch.setenv("PLATFORM_ADMIN_EMAIL", "admin@test.com")
        monkeypatch.setenv("PLATFORM_ADMIN_PASSWORD", "TestPass123!")

        with pytest.raises(ValidationError):
            Settings(_env_file=None)


# ---------------------------------------------------------------------------
# Database / get_db tests
# ---------------------------------------------------------------------------

class TestDatabase:
    def test_get_db_yields_session(self, test_engine):
        """get_db generator yields a non-None session object."""
        from sqlalchemy.orm import sessionmaker
        from database import get_db

        gen = get_db()
        session = next(gen)
        assert session is not None
        try:
            next(gen)
        except StopIteration:
            pass  # expected — finally block ran, session closed

    def test_db_session_executes_query(self, db_session):
        """Session from fixture can execute a basic SQL query."""
        result = db_session.execute(text("SELECT 1")).scalar()
        assert result == 1

    def test_db_session_rolls_back_on_fixture_teardown(self, test_engine):
        """Data written in a db_session fixture is not visible after rollback."""
        # This test verifies the rollback mechanism used in the fixture itself.
        # We perform the insert + rollback manually to mirror what the fixture does.
        connection = test_engine.connect()
        txn = connection.begin()
        row_id = str(uuid.uuid4())
        connection.execute(
            text(
                "INSERT INTO tenants (id, name, plan, contact_email, active, created_at) "
                "VALUES (:id, 'Rollback Tenant', 'starter', 'rb@test.com', 1, CURRENT_TIMESTAMP)"
            ),
            {"id": row_id},
        )
        txn.rollback()
        connection.close()

        # The row must not exist after rollback
        with test_engine.connect() as conn:
            count = conn.execute(
                text("SELECT COUNT(*) FROM tenants WHERE id = :id"), {"id": row_id}
            ).scalar()
        assert count == 0


# ---------------------------------------------------------------------------
# Tenant isolation baseline
# ---------------------------------------------------------------------------

class TestTenantIsolation:
    def test_tenant_a_data_not_visible_to_tenant_b(self, test_engine, test_tenants):
        """
        A system_config row written for Tenant A must not appear in a
        query filtered to Tenant B — the isolation pattern used everywhere.
        """
        a_id = test_tenants["tenant_a"]
        b_id = test_tenants["tenant_b"]
        row_id = str(uuid.uuid4())

        with test_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO system_config (id, tenant_id, key, value, updated_at) "
                    "VALUES (:id, :tid, 'isolation_test', 'sentinel', CURRENT_TIMESTAMP)"
                ),
                {"id": row_id, "tid": a_id},
            )

            # Querying as Tenant B must return nothing
            b_count = conn.execute(
                text(
                    "SELECT COUNT(*) FROM system_config "
                    "WHERE tenant_id = :tid AND key = 'isolation_test'"
                ),
                {"tid": b_id},
            ).scalar()
            assert b_count == 0, "Tenant B must not see Tenant A data"

            # Querying as Tenant A must return the row
            a_count = conn.execute(
                text(
                    "SELECT COUNT(*) FROM system_config "
                    "WHERE tenant_id = :tid AND key = 'isolation_test'"
                ),
                {"tid": a_id},
            ).scalar()
            assert a_count == 1, "Tenant A must see their own data"

            # Cleanup so session-scoped tenants stay clean
            conn.execute(
                text("DELETE FROM system_config WHERE id = :id"), {"id": row_id}
            )

    def test_both_tenants_exist_and_are_distinct(self, test_engine, test_tenants):
        """Two test tenants are created with different IDs and names."""
        a_id = test_tenants["tenant_a"]
        b_id = test_tenants["tenant_b"]
        assert a_id != b_id

        with test_engine.connect() as conn:
            names = conn.execute(
                text(
                    "SELECT name FROM tenants WHERE id IN (:a, :b) ORDER BY name"
                ),
                {"a": a_id, "b": b_id},
            ).scalars().all()
        assert set(names) == {"Tenant A", "Tenant B"}
