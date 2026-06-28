"""
routers/v1/admin/keys.py — API key self-service (all authenticated users).

POST   /api/v1/admin/keys              generate new API key
GET    /api/v1/admin/keys              list own keys (Admin sees all tenant keys)
DELETE /api/v1/admin/keys/{id}         revoke immediately
POST   /api/v1/admin/keys/{id}/rotate  zero-downtime rotation (24h grace)

Security invariants:
  - Plaintext key returned exactly once at generation — never stored.
  - Only SHA-256 hash persisted in DB — never the key value.
  - api_key_id (UUID) logged; plaintext key never appears in logs.
  - Tenant isolation: users can only manage keys in their own tenant.
  - Admin can see all tenant keys; Operator sees only their own.
"""
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db
from models.db import ApiKey
from models.schemas.v1.admin import (
    KeyCreateRequest,
    KeyCreateResponse,
    KeyResponse,
    KeyRotateResponse,
    WebhookAttachRequest,
    WebhookAttachResponse,
)
from security import (
    Role,
    TenantContext,
    encrypt,
    generate_api_key,
    hash_api_key,
    require_role,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/keys", tags=["admin-keys"])

UTC = timezone.utc
_GRACE_HOURS = 24


@router.post("", response_model=KeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_key(
    body: KeyCreateRequest,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_OPERATOR)),
) -> KeyCreateResponse:
    if ctx.user_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "JWT_REQUIRED", "message": "API key auth cannot create API keys"},
        )

    plaintext, key_hash = generate_api_key(body.environment)
    prefix = plaintext[:12]

    key = ApiKey(
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        name=body.name,
        key_hash=key_hash,
        key_prefix=prefix,
        environment=body.environment,
        scopes=json.dumps(body.scopes),
        expires_at=body.expires_at,
    )
    db.add(key)
    db.commit()
    db.refresh(key)

    # SECURITY: api_key_id only in logs — never plaintext
    logger.info("api key created", extra={"api_key_id": key.id, "tenant_id": ctx.tenant_id})

    import json as _json
    return KeyCreateResponse(
        id=key.id,
        name=key.name,
        key_prefix=prefix,
        plaintext_key=plaintext,  # shown once
        scopes=body.scopes,
        environment=key.environment,
        expires_at=key.expires_at,
        created_at=key.created_at,
    )


@router.get("", response_model=list[KeyResponse])
async def list_keys(
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_OPERATOR)),
) -> list[KeyResponse]:
    q = db.query(ApiKey).filter(
        ApiKey.tenant_id == ctx.tenant_id,
        ApiKey.revoked_at.is_(None),
    )
    # Operators see only their own keys; Admins see all
    if ctx.role == Role.TENANT_OPERATOR and ctx.user_id:
        q = q.filter(ApiKey.user_id == ctx.user_id)

    keys = q.order_by(ApiKey.created_at.desc()).all()
    return [KeyResponse.model_validate(k) for k in keys]


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_key(
    key_id: str,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_OPERATOR)),
) -> None:
    key = _get_or_403(key_id, ctx, db)
    key.revoked_at = datetime.now(UTC)
    db.commit()
    logger.info("api key revoked", extra={"api_key_id": key_id, "tenant_id": ctx.tenant_id})


@router.post("/{key_id}/rotate", response_model=KeyRotateResponse)
async def rotate_key(
    key_id: str,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_OPERATOR)),
) -> KeyRotateResponse:
    if ctx.user_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "JWT_REQUIRED", "message": "API key auth cannot rotate keys"},
        )

    old_key = _get_or_403(key_id, ctx, db)
    old_scopes = json.loads(old_key.scopes) if old_key.scopes else []

    plaintext, key_hash = generate_api_key(old_key.environment)
    prefix = plaintext[:12]
    grace_ends = datetime.now(UTC) + timedelta(hours=_GRACE_HOURS)

    new_key = ApiKey(
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        name=f"{old_key.name} (rotated)",
        key_hash=key_hash,
        key_prefix=prefix,
        environment=old_key.environment,
        scopes=old_key.scopes,
    )
    db.add(new_key)
    db.flush()

    old_key.superseded_by = new_key.id
    old_key.grace_period_ends_at = grace_ends

    db.commit()
    db.refresh(new_key)

    logger.info("api key rotated", extra={
        "old_key_id": key_id, "new_key_id": new_key.id, "tenant_id": ctx.tenant_id
    })

    return KeyRotateResponse(
        new_key_id=new_key.id,
        plaintext_key=plaintext,  # shown once
        key_prefix=prefix,
        old_key_id=key_id,
        grace_period_ends_at=grace_ends,
    )


@router.post("/{key_id}/webhook", response_model=WebhookAttachResponse)
async def attach_webhook(
    key_id: str,
    body: WebhookAttachRequest,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_OPERATOR)),
) -> WebhookAttachResponse:
    key = _get_or_403(key_id, ctx, db)

    # Generate per-webhook signing secret
    webhook_secret = secrets.token_urlsafe(32)
    secret_enc = encrypt(webhook_secret)

    filters = {}
    if body.severity_filter:
        filters["severity"] = body.severity_filter
    if body.service_filter:
        filters["service_name"] = body.service_filter

    key.webhook_url = body.webhook_url
    key.webhook_secret_enc = secret_enc
    key.webhook_filters = json.dumps(filters) if filters else None
    db.commit()

    logger.info("webhook attached", extra={"api_key_id": key_id, "tenant_id": ctx.tenant_id})

    return WebhookAttachResponse(
        api_key_id=key_id,
        webhook_url=body.webhook_url,
        webhook_secret=webhook_secret,  # shown once
        severity_filter=body.severity_filter,
        service_filter=body.service_filter,
    )


@router.delete("/{key_id}/webhook", status_code=status.HTTP_204_NO_CONTENT)
async def detach_webhook(
    key_id: str,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_OPERATOR)),
) -> None:
    key = _get_or_403(key_id, ctx, db)
    key.webhook_url = None
    key.webhook_secret_enc = None
    key.webhook_filters = None
    db.commit()


def _get_or_403(key_id: str, ctx: TenantContext, db: Session) -> ApiKey:
    """
    Load an API key, enforcing tenant isolation and ownership.
    Operators can only manage their own keys. Admins can manage all tenant keys.
    Returns 404 (not 403) when the key doesn't exist in this tenant to prevent enumeration.
    """
    q = db.query(ApiKey).filter(
        ApiKey.id == key_id,
        ApiKey.tenant_id == ctx.tenant_id,
        ApiKey.revoked_at.is_(None),
    )
    # Operators scoped to their own keys
    if ctx.role == Role.TENANT_OPERATOR and ctx.user_id:
        q = q.filter(ApiKey.user_id == ctx.user_id)

    key = q.first()
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "KEY_NOT_FOUND", "message": "API key not found"},
        )
    return key
