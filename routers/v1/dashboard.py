"""
routers/v1/dashboard.py — Dashboard data API + HTML view endpoints.

Data APIs (JSON, authenticated):
  GET /api/v1/dashboard/summary  — alert counts, severity breakdown, service statuses
  GET /api/v1/dashboard/trend    — per-service 24h alert rate for Chart.js

HTML views (serve templates, no auth enforced at HTTP layer — Alpine.js handles it):
  GET /             → redirect to /dashboard
  GET /dashboard    → operator dashboard
  GET /admin        → tenant admin panel
  GET /consumer     → consumer portal (keys, webhooks)
"""
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from models.db import AnomalyAlert, LogSource
from security import Role, TenantContext, require_role

logger = logging.getLogger(__name__)

router = APIRouter(tags=["dashboard"])

templates = Jinja2Templates(directory="templates")

UTC = timezone.utc


# ---------------------------------------------------------------------------
# HTML view endpoints
# ---------------------------------------------------------------------------

@router.get("/", include_in_schema=False)
async def root_redirect():
    return RedirectResponse(url="/dashboard")


@router.get("/login", include_in_schema=False)
async def login_view(request: Request):
    return templates.TemplateResponse(
        request=request, name="login.html",
        context={"app_version": settings.APP_VERSION, "page": "login"},
    )


@router.get("/dashboard", include_in_schema=False)
async def dashboard_view(request: Request):
    return templates.TemplateResponse(
        request=request, name="dashboard.html",
        context={"app_version": settings.APP_VERSION, "page": "dashboard"},
    )


@router.get("/admin", include_in_schema=False)
async def admin_view(request: Request):
    return templates.TemplateResponse(
        request=request, name="admin.html",
        context={"app_version": settings.APP_VERSION, "page": "admin"},
    )


@router.get("/consumer", include_in_schema=False)
async def consumer_view(request: Request):
    return templates.TemplateResponse(
        request=request, name="consumer.html",
        context={"app_version": settings.APP_VERSION, "page": "consumer"},
    )


@router.get("/platform-admin", include_in_schema=False)
async def platform_view(request: Request):
    return templates.TemplateResponse(
        request=request, name="platform.html",
        context={"app_version": settings.APP_VERSION, "page": "platform"},
    )


# ---------------------------------------------------------------------------
# Dashboard data APIs
# ---------------------------------------------------------------------------


@router.get("/api/v1/dashboard/summary")
async def dashboard_summary(
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_OPERATOR)),
) -> dict:
    """Alert counts by status + severity, plus active source count."""
    base = db.query(AnomalyAlert).filter(AnomalyAlert.tenant_id == ctx.tenant_id)

    total = base.count()
    open_count = base.filter(AnomalyAlert.status == "open").count()
    resolved_count = base.filter(AnomalyAlert.status == "resolved").count()
    acknowledged_count = base.filter(AnomalyAlert.status == "acknowledged").count()

    critical_open = (
        base.filter(AnomalyAlert.status == "open", AnomalyAlert.severity == "CRITICAL").count()
    )
    warning_open = (
        base.filter(AnomalyAlert.status == "open", AnomalyAlert.severity == "WARNING").count()
    )

    source_count = (
        db.query(func.count(LogSource.id))
        .filter(LogSource.tenant_id == ctx.tenant_id, LogSource.active.is_(True), LogSource.deleted_at.is_(None))
        .scalar()
    )

    return {
        "total_alerts": total,
        "open": open_count,
        "resolved": resolved_count,
        "acknowledged": acknowledged_count,
        "critical_open": critical_open,
        "warning_open": warning_open,
        "active_sources": source_count,
    }


@router.get("/api/v1/dashboard/trend")
async def dashboard_trend(
    hours: int = 24,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_OPERATOR)),
) -> dict:
    """
    Return per-hour alert counts for the past N hours.
    Used by Chart.js to render the trend line.
    """
    if hours < 1:
        hours = 1
    if hours > 168:
        hours = 168  # cap at 1 week

    since = datetime.now(UTC) - timedelta(hours=hours)
    alerts = (
        db.query(AnomalyAlert)
        .filter(
            AnomalyAlert.tenant_id == ctx.tenant_id,
            AnomalyAlert.detected_at >= since,
        )
        .all()
    )

    # Bucket by hour
    buckets: dict[str, int] = defaultdict(int)
    now = datetime.now(UTC)
    for h in range(hours):
        bucket_ts = now - timedelta(hours=(hours - 1 - h))
        label = bucket_ts.strftime("%Y-%m-%dT%H:00")
        buckets[label] = 0

    for alert in alerts:
        dt = alert.detected_at
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        label = dt.strftime("%Y-%m-%dT%H:00")
        buckets[label] = buckets.get(label, 0) + 1

    sorted_labels = sorted(buckets.keys())
    return {
        "labels": sorted_labels,
        "counts": [buckets[l] for l in sorted_labels],
        "hours": hours,
    }
