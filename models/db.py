"""
SQLAlchemy ORM models — populated incrementally per module.

Module 2:  Tenant, User, RefreshToken, ApiKey
Module 3:  RequestLog (needed by middleware)
Module 4:  LogSource, SourceState
Module 6:  EwmaState, AnomalyAlert
Module 7:  WebhookEvent
Module 10: SystemConfig
"""
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Integer, Text, UniqueConstraint,
)
from sqlalchemy.sql import func

from database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Module 2 models
# ---------------------------------------------------------------------------

class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Text, primary_key=True, default=_uuid)
    name = Column(Text, nullable=False)
    plan = Column(Text, nullable=False, default="starter")
    contact_email = Column(Text, nullable=False)
    max_sources = Column(Integer, nullable=False, default=10)
    retention_days = Column(Integer, nullable=False, default=30)
    log_retention_days = Column(Integer, nullable=False, default=7)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    deleted_at = Column(DateTime, nullable=True)


class User(Base):
    __tablename__ = "users"

    id = Column(Text, primary_key=True, default=_uuid)
    tenant_id = Column(Text, ForeignKey("tenants.id"), nullable=False)
    email = Column(Text, nullable=False, unique=True)
    password_hash = Column(Text, nullable=False)
    role = Column(Text, nullable=False)
    active = Column(Boolean, nullable=False, default=True)
    last_login_at = Column(DateTime, nullable=True)
    created_by = Column(Text, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    deleted_at = Column(DateTime, nullable=True)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Text, primary_key=True, default=_uuid)
    user_id = Column(Text, ForeignKey("users.id"), nullable=False)
    tenant_id = Column(Text, ForeignKey("tenants.id"), nullable=False)
    token_hash = Column(Text, nullable=False, unique=True)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Text, primary_key=True, default=_uuid)
    tenant_id = Column(Text, ForeignKey("tenants.id"), nullable=False)
    user_id = Column(Text, ForeignKey("users.id"), nullable=False)
    name = Column(Text, nullable=False)
    key_hash = Column(Text, nullable=False, unique=True)
    key_prefix = Column(Text, nullable=False)
    environment = Column(Text, nullable=False, default="live")
    scopes = Column(Text, nullable=False)          # JSON array string
    webhook_url = Column(Text, nullable=True)
    webhook_secret_enc = Column(Text, nullable=True)
    webhook_filters = Column(Text, nullable=True)       # JSON: {"severity": "CRITICAL", "service_name": "x"}
    rate_limit_rpm = Column(Integer, nullable=False, default=100)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    grace_period_ends_at = Column(DateTime, nullable=True)
    superseded_by = Column(Text, ForeignKey("api_keys.id"), nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


# ---------------------------------------------------------------------------
# Module 3 models (needed by middleware — brought forward from Module 10)
# ---------------------------------------------------------------------------

class RequestLog(Base):
    __tablename__ = "request_log"

    id = Column(Text, primary_key=True, default=_uuid)
    tenant_id = Column(Text, ForeignKey("tenants.id"), nullable=True)
    timestamp = Column(DateTime, server_default=func.now(), nullable=False)
    method = Column(Text, nullable=False)
    path = Column(Text, nullable=False)
    status_code = Column(Integer, nullable=False)
    latency_ms = Column(Integer, nullable=False)
    api_key_id = Column(Text, ForeignKey("api_keys.id"), nullable=True)
    user_id = Column(Text, ForeignKey("users.id"), nullable=True)
    ip_address = Column(Text, nullable=True)
    request_id = Column(Text, nullable=False)
    error_detail = Column(Text, nullable=True)


# ---------------------------------------------------------------------------
# Module 4 models
# ---------------------------------------------------------------------------

class LogSource(Base):
    __tablename__ = "log_sources"

    id = Column(Text, primary_key=True, default=_uuid)
    tenant_id = Column(Text, ForeignKey("tenants.id"), nullable=False)
    name = Column(Text, nullable=False)
    service_name = Column(Text, nullable=False)
    environment = Column(Text, nullable=False, default="production")
    source_type = Column(Text, nullable=False)           # file | postgres | mysql | sqlite | push
    connection_config_enc = Column(Text, nullable=True)  # Fernet-encrypted JSON; null for push
    poll_interval_s = Column(Integer, nullable=False, default=5)
    latency_field = Column(Text, nullable=True)
    log_format = Column(Text, nullable=False, default="json")  # json | logfmt | plaintext
    active = Column(Boolean, nullable=False, default=True)
    created_by = Column(Text, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
    deleted_at = Column(DateTime, nullable=True)

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_log_source_tenant_name"),
    )


class SourceState(Base):
    __tablename__ = "source_state"

    id = Column(Text, primary_key=True, default=_uuid)
    source_id = Column(Text, ForeignKey("log_sources.id"), nullable=False, unique=True)
    tenant_id = Column(Text, ForeignKey("tenants.id"), nullable=False)
    # File connector cursor
    byte_offset = Column(Integer, nullable=True, default=0)
    file_inode = Column(Integer, nullable=True)
    # DB connector high-water mark
    last_seen_id = Column(Text, nullable=True, default="0")
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)


# ---------------------------------------------------------------------------
# Module 6 models
# ---------------------------------------------------------------------------

class EwmaState(Base):
    """
    Persisted EWMA state per log source. Cached in-process at
    ewma:{tenant_id}:{source_id}. Written every 10 events and on shutdown.

    source_id FK to log_sources enforces that only registered sources have
    persisted state. Push-path sources without a log_sources row get cache-only
    state (persist silently no-ops on FK violation).
    """
    __tablename__ = "ewma_state"

    id = Column(Text, primary_key=True, default=_uuid)
    source_id = Column(Text, ForeignKey("log_sources.id"), nullable=False, unique=True)
    tenant_id = Column(Text, ForeignKey("tenants.id"), nullable=False)
    ewma_value = Column(Float, nullable=False, default=0.0)
    ewma_variance = Column(Float, nullable=False, default=0.0)
    alpha = Column(Float, nullable=False, default=0.3)
    sensitivity = Column(Float, nullable=False, default=2.5)
    warmup_count = Column(Integer, nullable=False, default=0)
    warmup_required = Column(Integer, nullable=False, default=10)
    error_fingerprints = Column(Text, nullable=False, default="[]")  # JSON list for NOVEL_ERROR bloom filter
    log_volume_ewma = Column(Float, nullable=False, default=0.0)     # baseline for SERVICE_SILENCE
    last_log_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)


class AnomalyAlert(Base):
    """
    Persisted anomaly alert with embedded evidence. Raw log entries are never
    stored — only this alert record with the top-3 representative messages.

    tenant_id is on every row: enforced at write time, enforced again in every
    query via .filter(AnomalyAlert.tenant_id == ctx.tenant_id).
    """
    __tablename__ = "anomaly_alerts"

    id = Column(Text, primary_key=True, default=_uuid)
    tenant_id = Column(Text, ForeignKey("tenants.id"), nullable=False)
    source_id = Column(Text, ForeignKey("log_sources.id"), nullable=False)
    detected_at = Column(DateTime, server_default=func.now(), nullable=False)
    anomaly_type = Column(Text, nullable=False)   # ERROR_RATE_SPIKE | SUSTAINED_ELEVATION | ...
    severity = Column(Text, nullable=False)        # WARNING | CRITICAL
    service_name = Column(Text, nullable=False)
    environment = Column(Text, nullable=False)
    current_value = Column(Float, nullable=False)
    baseline_value = Column(Float, nullable=False)
    upper_bound = Column(Float, nullable=False)
    unit = Column(Text, nullable=False)
    window_start = Column(DateTime, nullable=False)
    window_end = Column(DateTime, nullable=False)
    sample_count = Column(Integer, nullable=False)
    representative_msgs = Column(Text, nullable=False, default="[]")   # JSON top-3 messages
    detection_context = Column(Text, nullable=False)                   # JSON EWMA params
    cascade_context = Column(Text, nullable=True)                      # JSON only for CASCADE
    full_payload = Column(Text, nullable=False)                        # JSON v1.0 contract
    status = Column(Text, nullable=False, default="open")  # open | acknowledged | resolved
    acknowledged_by = Column(Text, ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    auto_resolved = Column(Boolean, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


# ---------------------------------------------------------------------------
# Module 7 models
# ---------------------------------------------------------------------------

class WebhookEvent(Base):
    """
    One row per webhook delivery attempt. Retries create new rows (append-only).
    Cleared on same retention schedule as anomaly_alerts.
    """
    __tablename__ = "webhook_events"

    id = Column(Text, primary_key=True, default=_uuid)
    tenant_id = Column(Text, ForeignKey("tenants.id"), nullable=False)
    alert_id = Column(Text, ForeignKey("anomaly_alerts.id"), nullable=False)
    api_key_id = Column(Text, ForeignKey("api_keys.id"), nullable=False)
    attempt_number = Column(Integer, nullable=False, default=1)
    sent_at = Column(DateTime, server_default=func.now(), nullable=False)
    target_url = Column(Text, nullable=False)
    payload = Column(Text, nullable=False)              # JSON alert body
    delivery_id = Column(Text, nullable=False)          # X-Watchdog-Delivery-ID
    response_status = Column(Integer, nullable=True)
    response_body = Column(Text, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    success = Column(Boolean, nullable=False, default=False)
    next_retry_at = Column(DateTime, nullable=True)     # NULL when exhausted or succeeded
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


# ---------------------------------------------------------------------------
# Module 10 models
# ---------------------------------------------------------------------------

class SystemConfig(Base):
    """
    Key-value config store. tenant_id=NULL means platform-level config.
    Per-tenant rows override platform defaults for the given key.
    """
    __tablename__ = "system_config"

    id = Column(Text, primary_key=True, default=_uuid)
    tenant_id = Column(Text, ForeignKey("tenants.id"), nullable=True)
    key = Column(Text, nullable=False)
    value = Column(Text, nullable=False)
    updated_by = Column(Text, ForeignKey("users.id"), nullable=True)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "key", name="uq_system_config_tenant_key"),
    )
