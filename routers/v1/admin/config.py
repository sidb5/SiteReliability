"""
routers/v1/admin/config.py — Tenant retention policy management (Tenant Admin only).

GET   /api/v1/admin/config   get current retention settings
PATCH /api/v1/admin/config   update retention settings
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db
from models.db import Tenant
from models.schemas.v1.admin import RetentionConfigRequest, RetentionConfigResponse
from security import Role, TenantContext, require_role

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/config", tags=["admin-config"])


@router.get("", response_model=RetentionConfigResponse)
async def get_config(
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_ADMIN)),
) -> RetentionConfigResponse:
    tenant = db.query(Tenant).filter(Tenant.id == ctx.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail={"code": "TENANT_NOT_FOUND"})
    return RetentionConfigResponse(
        tenant_id=tenant.id,
        retention_days=tenant.retention_days,
        log_retention_days=tenant.log_retention_days,
    )


@router.patch("", response_model=RetentionConfigResponse)
async def update_config(
    body: RetentionConfigRequest,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_ADMIN)),
) -> RetentionConfigResponse:
    tenant = db.query(Tenant).filter(Tenant.id == ctx.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail={"code": "TENANT_NOT_FOUND"})

    if body.retention_days is not None:
        tenant.retention_days = body.retention_days
    if body.log_retention_days is not None:
        tenant.log_retention_days = body.log_retention_days

    db.commit()
    logger.info("retention config updated", extra={
        "tenant_id": ctx.tenant_id,
        "retention_days": tenant.retention_days,
        "log_retention_days": tenant.log_retention_days,
    })
    return RetentionConfigResponse(
        tenant_id=tenant.id,
        retention_days=tenant.retention_days,
        log_retention_days=tenant.log_retention_days,
    )
