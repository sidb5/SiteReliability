"""
routers/v1/admin/sources.py — Log source CRUD (Tenant Admin only).

POST   /api/v1/admin/sources          create source
GET    /api/v1/admin/sources          list sources for tenant
GET    /api/v1/admin/sources/{id}     get source
PATCH  /api/v1/admin/sources/{id}     update source
DELETE /api/v1/admin/sources/{id}     soft-delete source

Security:
  - All queries scoped to ctx.tenant_id.
  - Tenant Admin role required on all mutating endpoints.
  - Connection strings encrypted at rest; never returned after save.
"""
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db
from models.db import LogSource
from models.schemas.v1.admin import (
    SourceConfigRequest,
    SourceConfigResponse,
    SourceUpdateRequest,
)
from security import Role, TenantContext, encrypt, require_role

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/sources", tags=["admin-sources"])

UTC = timezone.utc


@router.post("", response_model=SourceConfigResponse, status_code=status.HTTP_201_CREATED)
async def create_source(
    body: SourceConfigRequest,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_ADMIN)),
) -> SourceConfigResponse:
    existing = (
        db.query(LogSource)
        .filter(
            LogSource.tenant_id == ctx.tenant_id,
            LogSource.name == body.name,
            LogSource.deleted_at.is_(None),
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "SOURCE_NAME_EXISTS", "message": "A source with this name already exists"},
        )

    conn_enc = None
    if body.connection_config:
        conn_enc = encrypt(body.connection_config)

    src = LogSource(
        tenant_id=ctx.tenant_id,
        name=body.name,
        service_name=body.service_name,
        environment=body.environment,
        source_type=body.source_type,
        connection_config_enc=conn_enc,
        poll_interval_s=body.poll_interval_s,
        latency_field=body.latency_field,
        log_format=body.log_format,
        active=True,
        created_by=ctx.user_id,
    )
    db.add(src)
    db.commit()
    db.refresh(src)

    logger.info("source created", extra={
        "source_id": src.id, "tenant_id": ctx.tenant_id, "user_id": ctx.user_id
    })
    return SourceConfigResponse.model_validate(src)


@router.get("", response_model=list[SourceConfigResponse])
async def list_sources(
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_OPERATOR)),
) -> list[SourceConfigResponse]:
    sources = (
        db.query(LogSource)
        .filter(
            LogSource.tenant_id == ctx.tenant_id,
            LogSource.deleted_at.is_(None),
        )
        .order_by(LogSource.created_at.desc())
        .all()
    )
    return [SourceConfigResponse.model_validate(s) for s in sources]


@router.get("/{source_id}", response_model=SourceConfigResponse)
async def get_source(
    source_id: str,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_OPERATOR)),
) -> SourceConfigResponse:
    src = _get_or_404(source_id, ctx.tenant_id, db)
    return SourceConfigResponse.model_validate(src)


@router.patch("/{source_id}", response_model=SourceConfigResponse)
async def update_source(
    source_id: str,
    body: SourceUpdateRequest,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_ADMIN)),
) -> SourceConfigResponse:
    src = _get_or_404(source_id, ctx.tenant_id, db)

    if body.name is not None:
        src.name = body.name
    if body.poll_interval_s is not None:
        src.poll_interval_s = body.poll_interval_s
    if body.latency_field is not None:
        src.latency_field = body.latency_field
    if body.active is not None:
        src.active = body.active

    db.commit()
    db.refresh(src)
    return SourceConfigResponse.model_validate(src)


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_source(
    source_id: str,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_ADMIN)),
) -> None:
    src = _get_or_404(source_id, ctx.tenant_id, db)
    src.deleted_at = datetime.now(UTC)
    src.active = False
    db.commit()
    logger.info("source deleted", extra={
        "source_id": source_id, "tenant_id": ctx.tenant_id
    })


def _get_or_404(source_id: str, tenant_id: str, db: Session) -> LogSource:
    src = (
        db.query(LogSource)
        .filter(
            LogSource.id == source_id,
            LogSource.tenant_id == tenant_id,
            LogSource.deleted_at.is_(None),
        )
        .first()
    )
    if not src:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "SOURCE_NOT_FOUND", "message": "Source not found"},
        )
    return src
