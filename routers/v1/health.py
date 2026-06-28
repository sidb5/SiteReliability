"""
routers/v1/health.py — Health and readiness check.

GET /api/v1/health   — no auth required; checks DB connectivity, cache liveness.

Returns overall "ok" / "degraded" / "down" based on component checks.
Always returns HTTP 200 so load balancers don't kill the instance on transient
hiccups; callers inspect the JSON status field.
"""
import logging
import time

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from models.schemas.v1.health import ComponentStatus, HealthResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=HealthResponse)
async def health_check(
    request: Request,
    db: Session = Depends(get_db),
) -> HealthResponse:
    components: dict[str, ComponentStatus] = {}

    # --- DB check ---
    db_ok = False
    db_latency = None
    try:
        t0 = time.monotonic()
        db.execute(text("SELECT 1"))
        db_latency = round((time.monotonic() - t0) * 1000, 2)
        db_ok = True
    except Exception as exc:
        logger.warning("health: DB check failed", extra={"error": str(exc)})

    components["database"] = ComponentStatus(
        status="ok" if db_ok else "down",
        latency_ms=db_latency,
    )

    # --- Cache check ---
    cache_ok = False
    try:
        cache = getattr(request.app.state, "cache", None)
        if cache is not None:
            cache.set("__health__", True, ttl=5)
            cache.get("__health__")
            cache_ok = True
        else:
            cache_ok = True  # no cache configured is acceptable
    except Exception as exc:
        logger.warning("health: cache check failed", extra={"error": str(exc)})

    components["cache"] = ComponentStatus(status="ok" if cache_ok else "degraded")

    # --- Anomaly engine check ---
    engine_ok = getattr(request.app.state, "anomaly_engine", None) is not None
    components["anomaly_engine"] = ComponentStatus(status="ok" if engine_ok else "degraded")

    # Overall status: down if DB is down, degraded if any other component is not ok
    if not db_ok:
        overall = "down"
    elif any(c.status != "ok" for c in components.values()):
        overall = "degraded"
    else:
        overall = "ok"

    return HealthResponse(
        status=overall,
        version=settings.APP_VERSION,
        components=components,
    )
