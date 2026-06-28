"""
routers/v1/platform/tenants.py — Platform Admin: tenant lifecycle management.

POST  /api/v1/platform/tenants       — create a new tenant (Platform Admin only)
GET   /api/v1/platform/tenants       — list all tenants
GET   /api/v1/platform/tenants/{id}  — get one tenant
PATCH /api/v1/platform/tenants/{id}  — update tenant (activate/deactivate, plan, limits)
GET   /api/v1/platform/health        — platform-wide health summary

Only Platform Admins can reach these endpoints.  Tenant Admins, Operators,
and API Consumers all receive 403.
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models.db import AnomalyAlert, LogSource, Tenant, User
from models.schemas.v1.admin import CreateTenantRequest, TenantResponse
from security import TenantContext, require_platform_admin

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/platform", tags=["platform-admin"])


class TenantUpdateRequest(BaseModel):
    active: Optional[bool] = None
    plan: Optional[str] = None
    max_sources: Optional[int] = None
    retention_days: Optional[int] = None
    log_retention_days: Optional[int] = None


@router.post(
    "/tenants",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_tenant(
    body: CreateTenantRequest,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_platform_admin()),
) -> TenantResponse:
    tenant = Tenant(
        name=body.name,
        contact_email=body.contact_email,
        plan=body.plan,
        max_sources=body.max_sources,
        retention_days=body.retention_days,
        log_retention_days=body.log_retention_days,
        active=True,
    )
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    logger.info("tenant created", extra={"tenant_id": tenant.id, "created_by": ctx.user_id})
    return TenantResponse.model_validate(tenant)


@router.get("/tenants", response_model=list[TenantResponse])
async def list_tenants(
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_platform_admin()),
) -> list[TenantResponse]:
    tenants = db.query(Tenant).order_by(Tenant.created_at.desc()).all()
    return [TenantResponse.model_validate(t) for t in tenants]


@router.get("/tenants/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
    tenant_id: str,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_platform_admin()),
) -> TenantResponse:
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail={"code": "TENANT_NOT_FOUND"})
    return TenantResponse.model_validate(tenant)


@router.patch("/tenants/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: str,
    body: TenantUpdateRequest,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_platform_admin()),
) -> TenantResponse:
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail={"code": "TENANT_NOT_FOUND"})

    if body.active is not None:
        tenant.active = body.active
    if body.plan is not None:
        tenant.plan = body.plan
    if body.max_sources is not None:
        tenant.max_sources = body.max_sources
    if body.retention_days is not None:
        tenant.retention_days = body.retention_days
    if body.log_retention_days is not None:
        tenant.log_retention_days = body.log_retention_days

    db.commit()
    db.refresh(tenant)
    logger.info("tenant updated", extra={"tenant_id": tenant_id, "updated_by": ctx.user_id})
    return TenantResponse.model_validate(tenant)


@router.get("/health")
async def platform_health(
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_platform_admin()),
) -> dict:
    """Platform-wide aggregate health: tenant counts, alert totals, source counts."""
    total_tenants = db.query(func.count(Tenant.id)).scalar()
    active_tenants = db.query(func.count(Tenant.id)).filter(Tenant.active.is_(True)).scalar()
    total_alerts = db.query(func.count(AnomalyAlert.id)).scalar()
    open_alerts = db.query(func.count(AnomalyAlert.id)).filter(AnomalyAlert.status == "open").scalar()
    active_sources = (
        db.query(func.count(LogSource.id))
        .filter(LogSource.active.is_(True), LogSource.deleted_at.is_(None))
        .scalar()
    )
    total_users = db.query(func.count(User.id)).filter(User.active.is_(True)).scalar()

    return {
        "total_tenants": total_tenants,
        "active_tenants": active_tenants,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "active_sources": active_sources,
        "active_users": total_users,
    }
