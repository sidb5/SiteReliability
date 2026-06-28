"""
Shared test fixtures for all modules.

env vars are set at module level so they are in place before any app module
is imported by pytest's collection phase.
"""
import base64
import os
import uuid

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ---------------------------------------------------------------------------
# Required env vars — must be set before config.py is imported.
# Generate real cryptographic material so JWT RS256 and Fernet work in tests.
# ---------------------------------------------------------------------------

_TEST_FERNET_KEY = Fernet.generate_key().decode()

_rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_rsa_private_pem = _rsa_private.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
_rsa_public_pem = _rsa_private.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

os.environ.setdefault("FERNET_KEY", _TEST_FERNET_KEY)
os.environ.setdefault("JWT_PRIVATE_KEY", base64.b64encode(_rsa_private_pem).decode())
os.environ.setdefault("JWT_PUBLIC_KEY", base64.b64encode(_rsa_public_pem).decode())
os.environ.setdefault("PLATFORM_ADMIN_EMAIL", "admin@test.com")
os.environ.setdefault("PLATFORM_ADMIN_PASSWORD", "TestPassword123!")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("LOG_LEVEL", "DEBUG")

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Session-scoped test database (file-based so Alembic migrations can run)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def test_db_url(tmp_path_factory):
    db_file = tmp_path_factory.mktemp("db") / "watchdog_test.db"
    return f"sqlite:///{db_file}"


@pytest.fixture(scope="session")
def test_engine(test_db_url):
    """Create a test DB, run all migrations, yield the engine."""
    from alembic.config import Config as AlembicConfig
    from alembic import command as alembic_command

    cfg = AlembicConfig("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", test_db_url)
    alembic_command.upgrade(cfg, "head")

    engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def test_tenants(test_engine):
    """Insert two isolated test tenants once per session; return their IDs."""
    tenant_a_id = str(uuid.uuid4())
    tenant_b_id = str(uuid.uuid4())

    with test_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenants (id, name, plan, contact_email, active, created_at) "
                "VALUES (:a, 'Tenant A', 'starter', 'a@test.com', 1, CURRENT_TIMESTAMP), "
                "       (:b, 'Tenant B', 'starter', 'b@test.com', 1, CURRENT_TIMESTAMP)"
            ),
            {"a": tenant_a_id, "b": tenant_b_id},
        )

    return {"tenant_a": tenant_a_id, "tenant_b": tenant_b_id}


@pytest.fixture(scope="function")
def db_session(test_engine):
    """
    Function-scoped DB session backed by a rolled-back transaction.
    Keeps the test DB clean without truncating tables between tests.
    """
    connection = test_engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection, autocommit=False, autoflush=False)
    session = Session()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


# ---------------------------------------------------------------------------
# FastAPI test client (used from Module 3 onward)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def app(test_engine):
    """
    Return the FastAPI app with two test-only overrides applied once per session:

    1. middleware._request_log_session_factory → test engine's SessionLocal
       so that middleware request_log writes land in the test DB, not the
       production SQLite (which has no schema in tests).

    2. The limiter reset fixture (below) resets per-function so rate limit
       state never bleeds between tests.
    """
    import middleware as _mw
    from sqlalchemy.orm import sessionmaker

    TestLocal = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)
    _mw._request_log_session_factory = TestLocal

    from main import app as fastapi_app
    return fastapi_app


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """
    Reset in-memory rate limit counters before every test function.
    Prevents a rate-limit test from poisoning subsequent tests that hit
    the same endpoint from the same TestClient IP ('testclient').
    """
    from limiter import limiter
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture(scope="function")
def client(app, test_engine):
    """
    HTTP test client with the production DB dependency overridden to use
    the test engine.  Cleared after each test function.
    """
    from database import get_db

    TestSession = sessionmaker(
        autocommit=False, autoflush=False, bind=test_engine
    )

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()
