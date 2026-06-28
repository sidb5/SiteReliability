"""Initial schema — all tables and indexes

Revision ID: 001
Revises:
Create Date: 2026-06-27
"""
from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # tenants
    # ------------------------------------------------------------------
    op.create_table(
        "tenants",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("plan", sa.Text, nullable=False, server_default="starter"),
        sa.Column("contact_email", sa.Text, nullable=False),
        sa.Column("max_sources", sa.Integer, nullable=False, server_default="10"),
        sa.Column("retention_days", sa.Integer, nullable=False, server_default="30"),
        sa.Column("log_retention_days", sa.Integer, nullable=False, server_default="7"),
        sa.Column("active", sa.Boolean, nullable=False, server_default="1"),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("deleted_at", sa.DateTime, nullable=True),
    )

    # ------------------------------------------------------------------
    # users
    # ------------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("tenant_id", sa.Text, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("email", sa.Text, nullable=False, unique=True),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("role", sa.Text, nullable=False),
        sa.Column("active", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("last_login_at", sa.DateTime, nullable=True),
        sa.Column("created_by", sa.Text, sa.ForeignKey("users.id"), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("deleted_at", sa.DateTime, nullable=True),
    )
    op.create_index("idx_users_tenant", "users", ["tenant_id"])
    op.create_index("idx_users_email", "users", ["email"])

    # ------------------------------------------------------------------
    # refresh_tokens
    # ------------------------------------------------------------------
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("user_id", sa.Text, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("tenant_id", sa.Text, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("token_hash", sa.Text, nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("revoked_at", sa.DateTime, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_index("idx_refresh_tokens_user", "refresh_tokens", ["user_id"])
    op.create_index("idx_refresh_tokens_hash", "refresh_tokens", ["token_hash"])

    # ------------------------------------------------------------------
    # api_keys
    # ------------------------------------------------------------------
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("tenant_id", sa.Text, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("user_id", sa.Text, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("key_hash", sa.Text, nullable=False, unique=True),
        sa.Column("key_prefix", sa.Text, nullable=False),
        sa.Column("environment", sa.Text, nullable=False, server_default="live"),
        sa.Column("scopes", sa.Text, nullable=False),
        sa.Column("webhook_url", sa.Text, nullable=True),
        sa.Column("webhook_secret_enc", sa.Text, nullable=True),
        sa.Column("rate_limit_rpm", sa.Integer, nullable=False, server_default="100"),
        sa.Column("last_used_at", sa.DateTime, nullable=True),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column("grace_period_ends_at", sa.DateTime, nullable=True),
        sa.Column(
            "superseded_by",
            sa.Text,
            sa.ForeignKey("api_keys.id"),
            nullable=True,
        ),
        sa.Column("revoked_at", sa.DateTime, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_index("idx_api_keys_tenant", "api_keys", ["tenant_id"])
    op.create_index("idx_api_keys_hash", "api_keys", ["key_hash"])
    op.create_index("idx_api_keys_expiry", "api_keys", ["expires_at", "revoked_at"])

    # ------------------------------------------------------------------
    # log_sources
    # ------------------------------------------------------------------
    op.create_table(
        "log_sources",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("tenant_id", sa.Text, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("service_name", sa.Text, nullable=False),
        sa.Column("environment", sa.Text, nullable=False, server_default="production"),
        sa.Column("source_type", sa.Text, nullable=False),
        sa.Column("connection_config_enc", sa.Text, nullable=True),
        sa.Column("poll_interval_s", sa.Integer, nullable=False, server_default="5"),
        sa.Column("latency_field", sa.Text, nullable=True),
        sa.Column("log_format", sa.Text, nullable=False, server_default="json"),
        sa.Column("active", sa.Boolean, nullable=False, server_default="1"),
        sa.Column(
            "created_by", sa.Text, sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("deleted_at", sa.DateTime, nullable=True),
    )
    op.create_index("idx_log_sources_tenant", "log_sources", ["tenant_id"])
    op.create_index(
        "idx_log_sources_active", "log_sources", ["tenant_id", "active"]
    )

    # ------------------------------------------------------------------
    # source_state
    # ------------------------------------------------------------------
    op.create_table(
        "source_state",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column(
            "source_id",
            sa.Text,
            sa.ForeignKey("log_sources.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("tenant_id", sa.Text, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("last_seen_id", sa.Text, nullable=True),
        sa.Column("file_path", sa.Text, nullable=True),
        sa.Column("file_inode", sa.Integer, nullable=True),
        sa.Column("byte_offset", sa.Integer, nullable=True),
        sa.Column(
            "poll_state", sa.Text, nullable=False, server_default="active"
        ),
        sa.Column(
            "consecutive_empty", sa.Integer, nullable=False, server_default="0"
        ),
        sa.Column("last_polled_at", sa.DateTime, nullable=True),
        sa.Column("last_error", sa.Text, nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )

    # ------------------------------------------------------------------
    # ewma_state
    # ------------------------------------------------------------------
    op.create_table(
        "ewma_state",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column(
            "source_id",
            sa.Text,
            sa.ForeignKey("log_sources.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("tenant_id", sa.Text, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("ewma_value", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("ewma_variance", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("alpha", sa.Float, nullable=False, server_default="0.3"),
        sa.Column("sensitivity", sa.Float, nullable=False, server_default="2.5"),
        sa.Column("warmup_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "warmup_required", sa.Integer, nullable=False, server_default="10"
        ),
        sa.Column(
            "error_fingerprints", sa.Text, nullable=False, server_default="[]"
        ),
        sa.Column(
            "log_volume_ewma", sa.Float, nullable=False, server_default="0.0"
        ),
        sa.Column("last_log_at", sa.DateTime, nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_index("idx_ewma_state_tenant", "ewma_state", ["tenant_id"])

    # ------------------------------------------------------------------
    # anomaly_alerts
    # ------------------------------------------------------------------
    op.create_table(
        "anomaly_alerts",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("tenant_id", sa.Text, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column(
            "source_id", sa.Text, sa.ForeignKey("log_sources.id"), nullable=False
        ),
        sa.Column(
            "detected_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("anomaly_type", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("service_name", sa.Text, nullable=False),
        sa.Column("environment", sa.Text, nullable=False),
        sa.Column("current_value", sa.Float, nullable=False),
        sa.Column("baseline_value", sa.Float, nullable=False),
        sa.Column("upper_bound", sa.Float, nullable=False),
        sa.Column("unit", sa.Text, nullable=False),
        sa.Column("window_start", sa.DateTime, nullable=False),
        sa.Column("window_end", sa.DateTime, nullable=False),
        sa.Column("sample_count", sa.Integer, nullable=False),
        sa.Column(
            "representative_msgs", sa.Text, nullable=False, server_default="[]"
        ),
        sa.Column("detection_context", sa.Text, nullable=False),
        sa.Column("cascade_context", sa.Text, nullable=True),
        sa.Column("full_payload", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="open"),
        sa.Column(
            "acknowledged_by",
            sa.Text,
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column("acknowledged_at", sa.DateTime, nullable=True),
        sa.Column("resolved_at", sa.DateTime, nullable=True),
        sa.Column("auto_resolved", sa.Boolean, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_index(
        "idx_anomaly_alerts_tenant", "anomaly_alerts", ["tenant_id", "detected_at"]
    )
    op.create_index(
        "idx_anomaly_alerts_source",
        "anomaly_alerts",
        ["source_id", "detected_at"],
    )
    op.create_index("idx_anomaly_alerts_type", "anomaly_alerts", ["anomaly_type"])
    op.create_index(
        "idx_anomaly_alerts_severity",
        "anomaly_alerts",
        ["tenant_id", "severity", "status"],
    )
    op.create_index(
        "idx_anomaly_alerts_service",
        "anomaly_alerts",
        ["tenant_id", "service_name", "detected_at"],
    )
    op.create_index(
        "idx_anomaly_alerts_retention",
        "anomaly_alerts",
        ["tenant_id", "status", "created_at"],
    )

    # ------------------------------------------------------------------
    # webhook_events
    # ------------------------------------------------------------------
    op.create_table(
        "webhook_events",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("tenant_id", sa.Text, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column(
            "alert_id",
            sa.Text,
            sa.ForeignKey("anomaly_alerts.id"),
            nullable=False,
        ),
        sa.Column(
            "api_key_id", sa.Text, sa.ForeignKey("api_keys.id"), nullable=False
        ),
        sa.Column("attempt_number", sa.Integer, nullable=False, server_default="1"),
        sa.Column(
            "sent_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("target_url", sa.Text, nullable=False),
        sa.Column("payload", sa.Text, nullable=False),
        sa.Column("delivery_id", sa.Text, nullable=False),
        sa.Column("response_status", sa.Integer, nullable=True),
        sa.Column("response_body", sa.Text, nullable=True),
        sa.Column("latency_ms", sa.Integer, nullable=True),
        sa.Column("success", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("next_retry_at", sa.DateTime, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_index("idx_webhook_events_tenant", "webhook_events", ["tenant_id"])
    op.create_index("idx_webhook_events_alert", "webhook_events", ["alert_id"])
    op.create_index(
        "idx_webhook_events_retry", "webhook_events", ["success", "next_retry_at"]
    )
    op.create_index(
        "idx_webhook_events_retention", "webhook_events", ["tenant_id", "created_at"]
    )

    # ------------------------------------------------------------------
    # system_config
    # ------------------------------------------------------------------
    op.create_table(
        "system_config",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column(
            "tenant_id", sa.Text, sa.ForeignKey("tenants.id"), nullable=True
        ),
        sa.Column("key", sa.Text, nullable=False),
        sa.Column("value", sa.Text, nullable=False),
        sa.Column(
            "updated_by", sa.Text, sa.ForeignKey("users.id"), nullable=True
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("tenant_id", "key", name="uq_system_config_tenant_key"),
    )

    # ------------------------------------------------------------------
    # request_log
    # ------------------------------------------------------------------
    op.create_table(
        "request_log",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column(
            "tenant_id", sa.Text, sa.ForeignKey("tenants.id"), nullable=True
        ),
        sa.Column(
            "timestamp",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("method", sa.Text, nullable=False),
        sa.Column("path", sa.Text, nullable=False),
        sa.Column("status_code", sa.Integer, nullable=False),
        sa.Column("latency_ms", sa.Integer, nullable=False),
        sa.Column(
            "api_key_id", sa.Text, sa.ForeignKey("api_keys.id"), nullable=True
        ),
        sa.Column(
            "user_id", sa.Text, sa.ForeignKey("users.id"), nullable=True
        ),
        sa.Column("ip_address", sa.Text, nullable=True),
        sa.Column("request_id", sa.Text, nullable=False),
        sa.Column("error_detail", sa.Text, nullable=True),
    )
    op.create_index(
        "idx_request_log_tenant", "request_log", ["tenant_id", "timestamp"]
    )
    op.create_index(
        "idx_request_log_path", "request_log", ["path", "status_code"]
    )
    op.create_index(
        "idx_request_log_retention", "request_log", ["tenant_id", "timestamp"]
    )


def downgrade() -> None:
    # Drop in reverse FK dependency order
    op.drop_table("request_log")
    op.drop_table("system_config")
    op.drop_table("webhook_events")
    op.drop_table("anomaly_alerts")
    op.drop_table("ewma_state")
    op.drop_table("source_state")
    op.drop_table("log_sources")
    op.drop_table("api_keys")
    op.drop_table("refresh_tokens")
    op.drop_table("users")
    op.drop_table("tenants")
