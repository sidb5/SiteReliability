"""
models/schemas/v1/admin.py — Request/response schemas for admin operations.

Populated incrementally:
  Module 3:  CreateTenantRequest, TenantResponse
  Module 4:  SourceConfigRequest, SourceConfigResponse
  Module 9:  UserRequest, KeyRequest, WebhookRequest
"""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator


# ---------------------------------------------------------------------------
# Module 3 — Tenant management (Platform Admin)
# ---------------------------------------------------------------------------

class CreateTenantRequest(BaseModel):
    name: str
    contact_email: str
    plan: str = "starter"
    max_sources: int = 10
    retention_days: int = 30
    log_retention_days: int = 7

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("name must not be blank")
        return v.strip()

    @field_validator("max_sources")
    @classmethod
    def max_sources_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("max_sources must be at least 1")
        return v

    @field_validator("retention_days", "log_retention_days")
    @classmethod
    def retention_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("retention days must be at least 1")
        return v


class TenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    plan: str
    contact_email: str
    max_sources: int
    retention_days: int
    log_retention_days: int
    active: bool
    created_at: datetime


# ---------------------------------------------------------------------------
# Module 4 — Log source management (Tenant Admin)
# ---------------------------------------------------------------------------

_VALID_SOURCE_TYPES = {"file", "postgres", "mysql", "sqlite", "push"}
_VALID_LOG_FORMATS = {"json", "logfmt", "plaintext"}


class SourceConfigRequest(BaseModel):
    name: str
    service_name: str
    environment: str = "production"
    source_type: str
    connection_config: Optional[str] = None   # plaintext; encrypted at rest before save
    poll_interval_s: int = 5
    latency_field: Optional[str] = None
    log_format: str = "json"

    @field_validator("name", "service_name")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be blank")
        return v.strip()

    @field_validator("source_type")
    @classmethod
    def valid_source_type(cls, v: str) -> str:
        if v not in _VALID_SOURCE_TYPES:
            raise ValueError(f"source_type must be one of {sorted(_VALID_SOURCE_TYPES)}")
        return v

    @field_validator("log_format")
    @classmethod
    def valid_log_format(cls, v: str) -> str:
        if v not in _VALID_LOG_FORMATS:
            raise ValueError(f"log_format must be one of {sorted(_VALID_LOG_FORMATS)}")
        return v

    @field_validator("poll_interval_s")
    @classmethod
    def poll_interval_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("poll_interval_s must be at least 1")
        return v


class SourceConfigResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    service_name: str
    environment: str
    source_type: str
    poll_interval_s: int
    latency_field: Optional[str]
    log_format: str
    active: bool
    created_at: datetime
    # connection_config intentionally omitted — masked after save per security rules


class SourceUpdateRequest(BaseModel):
    name: Optional[str] = None
    poll_interval_s: Optional[int] = None
    latency_field: Optional[str] = None
    active: Optional[bool] = None

    @field_validator("poll_interval_s")
    @classmethod
    def poll_interval_positive(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v < 1:
            raise ValueError("poll_interval_s must be at least 1")
        return v


# ---------------------------------------------------------------------------
# Module 9 — User management (Tenant Admin)
# ---------------------------------------------------------------------------

_VALID_TENANT_ROLES = {"tenant_admin", "tenant_operator"}


class UserCreateRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def email_not_blank(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or len(v) < 3:
            raise ValueError("invalid email address")
        return v
    role: str = "tenant_operator"

    @field_validator("role")
    @classmethod
    def valid_role(cls, v: str) -> str:
        if v not in _VALID_TENANT_ROLES:
            raise ValueError(f"role must be one of {sorted(_VALID_TENANT_ROLES)}")
        return v

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        return v


class UserUpdateRequest(BaseModel):
    active: Optional[bool] = None
    role: Optional[str] = None

    @field_validator("role")
    @classmethod
    def valid_role(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in _VALID_TENANT_ROLES:
            raise ValueError(f"role must be one of {sorted(_VALID_TENANT_ROLES)}")
        return v


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    email: str
    role: str
    active: bool
    last_login_at: Optional[datetime]
    created_at: datetime


# ---------------------------------------------------------------------------
# Module 9 — API key management (self-service)
# ---------------------------------------------------------------------------

_VALID_SCOPES = {"ingest", "alerts:read", "webhooks:manage", "sources:read"}
_VALID_ENVS = {"live", "test"}


class KeyCreateRequest(BaseModel):
    name: str
    scopes: list[str]
    environment: str = "live"
    expires_at: Optional[datetime] = None

    @field_validator("name")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("name must not be blank")
        return v.strip()

    @field_validator("scopes")
    @classmethod
    def valid_scopes(cls, v: list[str]) -> list[str]:
        invalid = set(v) - _VALID_SCOPES
        if invalid:
            raise ValueError(f"invalid scopes: {sorted(invalid)}. Valid: {sorted(_VALID_SCOPES)}")
        if not v:
            raise ValueError("at least one scope required")
        return v

    @field_validator("environment")
    @classmethod
    def valid_environment(cls, v: str) -> str:
        if v not in _VALID_ENVS:
            raise ValueError(f"environment must be one of {sorted(_VALID_ENVS)}")
        return v


class KeyCreateResponse(BaseModel):
    """Returned exactly once at key creation.  plaintext_key never stored."""
    id: str
    name: str
    key_prefix: str
    plaintext_key: str          # SHOWN ONCE — never retrievable again
    scopes: list[str]
    environment: str
    expires_at: Optional[datetime]
    created_at: datetime


class KeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    key_prefix: str
    scopes: str                 # JSON string from DB; caller parses
    environment: str
    webhook_url: Optional[str]
    rate_limit_rpm: int
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    grace_period_ends_at: Optional[datetime]
    revoked_at: Optional[datetime]
    created_at: datetime


class KeyRotateResponse(BaseModel):
    new_key_id: str
    plaintext_key: str          # SHOWN ONCE — new key value
    key_prefix: str
    old_key_id: str
    grace_period_ends_at: datetime


# ---------------------------------------------------------------------------
# Module 9 — Webhook management (on API key)
# ---------------------------------------------------------------------------

class WebhookAttachRequest(BaseModel):
    webhook_url: str
    severity_filter: Optional[str] = None
    service_filter: Optional[str] = None

    @field_validator("webhook_url")
    @classmethod
    def valid_url(cls, v: str) -> str:
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("webhook_url must start with http:// or https://")
        return v

    @field_validator("severity_filter")
    @classmethod
    def valid_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in {"WARNING", "CRITICAL"}:
            raise ValueError("severity_filter must be WARNING or CRITICAL")
        return v


class WebhookAttachResponse(BaseModel):
    """Returned once at registration.  webhook_secret never retrievable again."""
    api_key_id: str
    webhook_url: str
    webhook_secret: str         # SHOWN ONCE — Fernet-encrypted in DB
    severity_filter: Optional[str]
    service_filter: Optional[str]


# ---------------------------------------------------------------------------
# Module 9 — Retention config (Tenant Admin)
# ---------------------------------------------------------------------------

class RetentionConfigResponse(BaseModel):
    tenant_id: str
    retention_days: int
    log_retention_days: int


class RetentionConfigRequest(BaseModel):
    retention_days: Optional[int] = None
    log_retention_days: Optional[int] = None

    @field_validator("retention_days", "log_retention_days")
    @classmethod
    def positive(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v < 1:
            raise ValueError("retention days must be at least 1")
        return v
