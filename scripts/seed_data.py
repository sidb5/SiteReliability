"""
scripts/seed_data.py — Multi-tenant demo data with known anomaly events.

Usage:
    python scripts/seed_data.py

Creates:
  - 2 demo tenants (Acme Corp, Beta Inc)
  - 1 Tenant Admin + 1 Operator per tenant
  - 2 log sources per tenant (push connector)
  - 200 normal log entries per source
  - 10 anomaly-triggering bursts (known SPIKE and RATE_SPIKE events)
  - 1 API key per tenant (test environment, alerts:read scope)

Run against the production DB (DATABASE_URL in .env).
Idempotent — skip creation if objects already exist by name/email.
"""
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models.db import Base, Tenant, User, LogSource, AnomalyAlert
from security import hash_password, generate_api_key, hash_api_key
from models.db import ApiKey

UTC = timezone.utc


def _get_or_create_tenant(db: Session, name: str, email: str) -> Tenant:
    t = db.query(Tenant).filter(Tenant.name == name).first()
    if t:
        print(f"  tenant '{name}' already exists — skipping")
        return t
    t = Tenant(
        id=str(uuid.uuid4()),
        name=name,
        plan="starter",
        contact_email=email,
        max_sources=10,
        retention_days=30,
        log_retention_days=7,
        active=True,
    )
    db.add(t)
    db.flush()
    print(f"  created tenant '{name}' ({t.id})")
    return t


def _get_or_create_user(db: Session, tenant_id: str, email: str, role: str, password: str) -> User:
    u = db.query(User).filter(User.email == email).first()
    if u:
        print(f"  user '{email}' already exists — skipping")
        return u
    u = User(
        tenant_id=tenant_id,
        email=email,
        password_hash=hash_password(password),
        role=role,
        active=True,
    )
    db.add(u)
    db.flush()
    print(f"  created user '{email}' ({role})")
    return u


def _get_or_create_source(db: Session, tenant_id: str, user_id: str, name: str, service: str) -> LogSource:
    src = db.query(LogSource).filter(LogSource.tenant_id == tenant_id, LogSource.name == name).first()
    if src:
        print(f"  source '{name}' already exists — skipping")
        return src
    src = LogSource(
        tenant_id=tenant_id,
        name=name,
        service_name=service,
        environment="production",
        source_type="push",
        log_format="json",
        poll_interval_s=5,
        active=True,
        created_by=user_id,
    )
    db.add(src)
    db.flush()
    print(f"  created source '{name}' ({src.id})")
    return src


def _seed_normal_logs(db: Session, source: LogSource, count: int = 200) -> None:
    # Raw log entries are not persisted to the DB — they flow through the ingest
    # pipeline transiently and drive EWMA state.  Nothing to seed here.
    print(f"  (log entries for '{source.name}' are ingested at runtime via POST /api/v1/ingest)")


def _seed_spike_anomaly(
    db: Session,
    source: LogSource,
    alert_num: int,
    status: str = "resolved",
    severity: str = "WARNING",
) -> None:
    now = datetime.now(UTC) - timedelta(hours=alert_num)
    alert = AnomalyAlert(
        tenant_id=source.tenant_id,
        source_id=source.id,
        service_name=source.service_name,
        environment="production",
        anomaly_type="SPIKE",
        severity=severity,
        status=status,
        detected_at=now,
        current_value=float(150 + alert_num * 10),
        baseline_value=25.0,
        upper_bound=50.0,
        unit="req/min",
        window_start=now - timedelta(minutes=5),
        window_end=now,
        sample_count=60,
        representative_msgs=json.dumps([f"spike detected at t={alert_num}"]),
        detection_context=json.dumps({"ewma": 25.0, "std": 5.0}),
        full_payload=json.dumps({"source": source.name, "spike_factor": alert_num}),
        resolved_at=now + timedelta(minutes=15) if status == "resolved" else None,
        auto_resolved=status == "resolved",
        acknowledged_at=now + timedelta(minutes=5) if status == "acknowledged" else None,
        created_at=now,
    )
    db.add(alert)
    db.flush()


def _seed_api_key(db: Session, tenant_id: str, user_id: str, label: str) -> str:
    existing = db.query(ApiKey).filter(
        ApiKey.tenant_id == tenant_id, ApiKey.name == label, ApiKey.revoked_at.is_(None)
    ).first()
    if existing:
        print(f"  API key '{label}' already exists — skipping")
        return existing.key_prefix + "…"
    plaintext, key_hash = generate_api_key("test")
    key = ApiKey(
        tenant_id=tenant_id,
        user_id=user_id,
        name=label,
        key_hash=key_hash,
        key_prefix=plaintext[:12],
        environment="test",
        scopes=json.dumps(["alerts:read"]),
    )
    db.add(key)
    db.flush()
    print(f"  created API key '{label}': {plaintext}")
    return plaintext


def seed(db: Session) -> None:
    print("\n=== Watchdog Demo Seed ===\n")

    for tenant_name, tenant_email, admin_email, op_email, services in [
        ("Acme Corp", "acme@example.com", "admin@acme.example.com", "ops@acme.example.com",
         [("acme-api", "acme-api"), ("acme-worker", "acme-worker")]),
        ("Beta Inc", "beta@example.com", "admin@beta.example.com", "ops@beta.example.com",
         [("beta-web", "beta-web"), ("beta-payments", "beta-payments")]),
    ]:
        print(f"\n--- Tenant: {tenant_name} ---")
        tenant = _get_or_create_tenant(db, tenant_name, tenant_email)
        admin = _get_or_create_user(db, tenant.id, admin_email, "tenant_admin", "WatchdogDemo1!")
        op = _get_or_create_user(db, tenant.id, op_email, "tenant_operator", "WatchdogDemo1!")

        sources = []
        for src_name, svc_name in services:
            src = _get_or_create_source(db, tenant.id, admin.id, src_name, svc_name)
            sources.append(src)
            _seed_normal_logs(db, src)

        # Wipe existing alerts for this tenant so re-runs stay idempotent
        deleted = db.query(AnomalyAlert).filter(
            AnomalyAlert.tenant_id == tenant.id
        ).delete(synchronize_session=False)
        if deleted:
            print(f"  wiped {deleted} existing alert(s) for {tenant_name}")

        # Seed 10 alerts per tenant with a realistic status mix:
        #   4 open  (2 CRITICAL on source-0, 2 WARNING on source-1)
        #   3 acknowledged
        #   3 resolved
        alert_plan = [
            # (source_index, alert_num, status, severity)
            (0, 1,  "open",         "CRITICAL"),
            (0, 2,  "open",         "CRITICAL"),
            (1, 3,  "open",         "WARNING"),
            (1, 4,  "open",         "WARNING"),
            (0, 5,  "acknowledged", "CRITICAL"),
            (1, 6,  "acknowledged", "WARNING"),
            (0, 7,  "acknowledged", "WARNING"),
            (0, 8,  "resolved",     "WARNING"),
            (1, 9,  "resolved",     "CRITICAL"),
            (1, 10, "resolved",     "WARNING"),
        ]
        for src_idx, alert_num, status, severity in alert_plan:
            _seed_spike_anomaly(db, sources[src_idx], alert_num, status=status, severity=severity)
        print(f"  seeded 10 anomaly alerts for {tenant_name}: 4 open, 3 acknowledged, 3 resolved")

        plaintext = _seed_api_key(db, tenant.id, op.id, f"{tenant_name.lower().replace(' ', '-')}-test-key")

    db.commit()
    print("\n=== Seed complete ===\n")
    print("Credentials for both tenants:")
    print("  Admin password : WatchdogDemo1!")
    print("  Operator password: WatchdogDemo1!")
    print("  Run 'python scripts/seed_data.py' again to skip existing rows.\n")


if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed(db)
    finally:
        db.close()
