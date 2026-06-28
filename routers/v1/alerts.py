"""
routers/v1/alerts.py — Alert management API.

GET  /api/v1/alerts              — list with filters + cursor pagination
GET  /api/v1/alerts/{id}         — get alert by ID
POST /api/v1/alerts/{id}/acknowledge — acknowledge open alert

Security:
  - All queries scoped to ctx.tenant_id — no cross-tenant leakage possible.
  - TenantContext derived from verified JWT/API key, never from request params.
  - Acknowledge requires alerts:read scope (or JWT role >= operator).
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from database import get_db
from models.db import AnomalyAlert, User
from models.schemas.v1.alerts import (
    AcknowledgeResponse,
    AnomalyAlertResponse,
    AnomalyListResponse,
    decode_cursor,
    encode_cursor,
)
from security import Role, TenantContext, require_role, require_scope

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts", tags=["alerts"])

_PAGE_DEFAULT = 20
_PAGE_MAX = 100

UTC = timezone.utc


@router.get("", response_model=AnomalyListResponse)
async def list_alerts(
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_OPERATOR)),
    service: Optional[str] = Query(default=None, description="Filter by service name"),
    severity: Optional[str] = Query(default=None, description="WARNING or CRITICAL"),
    anomaly_type: Optional[str] = Query(default=None, description="e.g. ERROR_RATE_SPIKE"),
    alert_status: Optional[str] = Query(
        default=None, alias="status", description="open | acknowledged | resolved"
    ),
    since: Optional[datetime] = Query(
        default=None, description="ISO datetime — only return alerts detected after this"
    ),
    until: Optional[datetime] = Query(
        default=None, description="ISO datetime — only return alerts detected before this"
    ),
    cursor: Optional[str] = Query(default=None, description="Pagination cursor from previous page"),
    limit: int = Query(default=_PAGE_DEFAULT, ge=1, le=_PAGE_MAX),
) -> AnomalyListResponse:
    """
    List anomaly alerts for the authenticated tenant.
    Results sorted by detected_at DESC, id DESC (newest first).
    Cursor-based pagination is stable under concurrent inserts.
    """
    q = (
        db.query(AnomalyAlert)
        .filter(AnomalyAlert.tenant_id == ctx.tenant_id)   # tenant isolation — mandatory
    )

    if service:
        q = q.filter(AnomalyAlert.service_name == service)
    if severity:
        q = q.filter(AnomalyAlert.severity == severity)
    if anomaly_type:
        q = q.filter(AnomalyAlert.anomaly_type == anomaly_type)
    if alert_status:
        q = q.filter(AnomalyAlert.status == alert_status)
    if since:
        q = q.filter(AnomalyAlert.detected_at >= since)
    if until:
        q = q.filter(AnomalyAlert.detected_at <= until)

    if cursor:
        decoded = decode_cursor(cursor)
        if decoded:
            cursor_dt_str, cursor_id = decoded
            cursor_dt = datetime.fromisoformat(cursor_dt_str)
            # Page condition: (detected_at, id) < (cursor_dt, cursor_id) in DESC order
            q = q.filter(
                (AnomalyAlert.detected_at < cursor_dt)
                | (
                    (AnomalyAlert.detected_at == cursor_dt)
                    & (AnomalyAlert.id < cursor_id)
                )
            )

    alerts = (
        q.order_by(AnomalyAlert.detected_at.desc(), AnomalyAlert.id.desc())
        .limit(limit + 1)   # fetch one extra to detect next page
        .all()
    )

    has_more = len(alerts) > limit
    page = alerts[:limit]

    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = encode_cursor(last.detected_at, last.id)

    return AnomalyListResponse(
        items=[AnomalyAlertResponse.model_validate(a) for a in page],
        next_cursor=next_cursor,
        total_returned=len(page),
    )


@router.get("/{alert_id}", response_model=AnomalyAlertResponse)
async def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_OPERATOR)),
) -> AnomalyAlertResponse:
    """Get a single alert by ID.  Returns 404 if the alert belongs to another tenant."""
    alert = (
        db.query(AnomalyAlert)
        .filter(
            AnomalyAlert.id == alert_id,
            AnomalyAlert.tenant_id == ctx.tenant_id,   # tenant isolation
        )
        .first()
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ALERT_NOT_FOUND", "message": "Alert not found"},
        )
    return AnomalyAlertResponse.model_validate(alert)


@router.post("/{alert_id}/acknowledge", response_model=AcknowledgeResponse)
async def acknowledge_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_OPERATOR)),
) -> AcknowledgeResponse:
    """
    Acknowledge an open alert.  Idempotent: acknowledging an already-acknowledged
    alert returns 200 with the existing acknowledgment metadata.
    """
    alert = (
        db.query(AnomalyAlert)
        .filter(
            AnomalyAlert.id == alert_id,
            AnomalyAlert.tenant_id == ctx.tenant_id,   # tenant isolation
        )
        .first()
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ALERT_NOT_FOUND", "message": "Alert not found"},
        )

    if alert.status == "resolved":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "ALERT_RESOLVED", "message": "Resolved alerts cannot be acknowledged"},
        )

    if alert.status != "acknowledged":
        now = datetime.now(UTC)
        alert.status = "acknowledged"
        alert.acknowledged_by = ctx.user_id
        alert.acknowledged_at = now
        db.commit()
        db.refresh(alert)

        logger.info(
            "alert acknowledged",
            extra={
                "alert_id": alert_id,
                "tenant_id": ctx.tenant_id,
                "user_id": ctx.user_id,
            },
        )

    return AcknowledgeResponse(
        id=alert.id,
        status=alert.status,
        acknowledged_at=alert.acknowledged_at,
        acknowledged_by=alert.acknowledged_by or "",
    )
