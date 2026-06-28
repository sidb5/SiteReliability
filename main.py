"""
main.py — FastAPI application entry point.

Responsibilities:
- Create the FastAPI app with versioned router prefix
- Register middleware (request logging, X-Request-ID)
- Register the slowapi rate-limiter and its 429 exception handler
- Lifespan startup: configure logging, set middleware session factory,
  bootstrap the Platform Admin account (idempotent), attach LogService
- Lifespan shutdown: graceful teardown
"""
import logging
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from config import settings
from database import SessionLocal
from limiter import limiter

logger = logging.getLogger(__name__)

# Fixed UUID for the platform system tenant that owns Platform Admin accounts.
# Chosen as a well-known nil-ish UUID to make it obvious in any DB dump.
_PLATFORM_SYSTEM_TENANT_ID = "00000000-0000-0000-0000-000000000001"


def _bootstrap_platform_admin(session_factory=None) -> None:
    """
    Ensure the platform system tenant and Platform Admin user exist.
    Safe to call on every startup — no-ops if already present.
    Accepts an optional session_factory so tests can direct writes to the
    test DB instead of the production SessionLocal.
    """
    from models.db import Tenant, User
    from security import hash_password, Role

    factory = session_factory or SessionLocal
    db = factory()
    try:
        # 1. Platform system tenant
        tenant = db.query(Tenant).filter(Tenant.id == _PLATFORM_SYSTEM_TENANT_ID).first()
        if not tenant:
            db.add(
                Tenant(
                    id=_PLATFORM_SYSTEM_TENANT_ID,
                    name="Platform",
                    plan="platform",
                    contact_email=settings.PLATFORM_ADMIN_EMAIL,
                    max_sources=0,
                    retention_days=365,
                    log_retention_days=30,
                    active=True,
                )
            )
            db.commit()
            logger.info("platform system tenant created")

        # 2. Platform Admin user
        user = (
            db.query(User)
            .filter(User.email == settings.PLATFORM_ADMIN_EMAIL)
            .first()
        )
        if not user:
            db.add(
                User(
                    tenant_id=_PLATFORM_SYSTEM_TENANT_ID,
                    email=settings.PLATFORM_ADMIN_EMAIL,
                    password_hash=hash_password(settings.PLATFORM_ADMIN_PASSWORD),
                    role=Role.PLATFORM_ADMIN.value,
                    active=True,
                )
            )
            db.commit()
            logger.info(
                "platform admin bootstrapped",
                extra={"email": settings.PLATFORM_ADMIN_EMAIL},
            )
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Wire middleware's session factory to the production DB.
    # If tests have already set _request_log_session_factory, this is a no-op.
    import middleware as _mw
    if _mw._request_log_session_factory is None:
        _mw._request_log_session_factory = SessionLocal

    # JSON structured logging — skipped if tests have already configured the root logger
    from middleware import configure_logging
    configure_logging(settings.LOG_LEVEL)

    # Bootstrap Platform Admin (idempotent).
    # Reuse _mw._request_log_session_factory so tests receive the bootstrap
    # in the test DB (already set by conftest.app fixture above).
    _bootstrap_platform_admin(session_factory=_mw._request_log_session_factory)

    # Attach stateless services to app.state so routers resolve them via
    # Depends without importing module-level singletons (easier to replace in tests).
    from services.cache import InProcessCache
    from services.anomaly_engine import AnomalyEngine
    from services.log_service import LogService
    from services.webhook_dispatcher import WebhookDispatcher
    from services.retention_service import RetentionService

    cache = InProcessCache()
    engine = AnomalyEngine(cache=cache, session_factory=_mw._request_log_session_factory)
    dispatcher = WebhookDispatcher(session_factory=_mw._request_log_session_factory)
    retention = RetentionService(session_factory=_mw._request_log_session_factory)
    log_service = LogService()
    log_service.set_engine(engine)
    log_service.set_dispatcher(dispatcher)

    app.state.cache = cache
    app.state.anomaly_engine = engine
    app.state.webhook_dispatcher = dispatcher
    app.state.retention_service = retention
    app.state.log_service = log_service

    import asyncio
    retry_task = asyncio.create_task(dispatcher.retry_loop())
    retention_task = asyncio.create_task(retention.retention_loop())
    key_expiry_task = asyncio.create_task(retention.key_expiry_loop())

    logger.info("watchdog startup complete", extra={"version": settings.APP_VERSION})

    yield

    # Cancel background tasks
    for task in (retry_task, retention_task, key_expiry_task):
        task.cancel()
    for task in (retry_task, retention_task, key_expiry_task):
        try:
            await task
        except asyncio.CancelledError:
            pass

    # Flush EWMA state on shutdown so no observations are lost
    try:
        db = (_mw._request_log_session_factory or SessionLocal)()
        engine.flush(db)
        db.commit()
        db.close()
    except Exception as exc:
        logger.warning("EWMA flush on shutdown failed", extra={"error": str(exc)})

    logger.info("watchdog shutdown")


# ---------------------------------------------------------------------------
# App construction
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Watchdog — Intelligent Observability & Event Watchdog",
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

def _rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """429 handler that always includes Retry-After so API clients know when to retry."""
    retry_after = 60  # matches the 100/minute window
    try:
        # exc.limit is a Limit object; its .limit attribute is a RateLimitItem
        retry_after = int(exc.limit.limit.get_expiry())
    except Exception:
        pass
    return JSONResponse(
        {"error": f"Rate limit exceeded: {exc.detail}"},
        status_code=429,
        headers={"Retry-After": str(retry_after)},
    )


# Rate limiter — must be on app.state before any request is processed
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# API-Version header on every response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

class ApiVersionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)
        response.headers["X-API-Version"] = settings.APP_VERSION
        return response

app.add_middleware(ApiVersionMiddleware)

# Request logging middleware
from middleware import RequestLoggingMiddleware
app.add_middleware(RequestLoggingMiddleware)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from routers.v1.dashboard import router as dashboard_router
from routers.v1.health import router as health_router
from routers.v1.auth import router as auth_router
from routers.v1.ingest import router as ingest_router
from routers.v1.alerts import router as alerts_router
from routers.v1.webhook import router as webhook_router
from routers.v1.admin.sources import router as admin_sources_router
from routers.v1.admin.users import router as admin_users_router
from routers.v1.admin.keys import router as admin_keys_router
from routers.v1.admin.config import router as admin_config_router
from routers.v1.platform.tenants import router as platform_tenants_router

app.include_router(dashboard_router)   # no prefix — serves /dashboard, /admin, /consumer, /login + /api/v1/dashboard/*
app.include_router(health_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")
app.include_router(ingest_router, prefix="/api/v1")
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(webhook_router, prefix="/api/v1")
app.include_router(admin_sources_router, prefix="/api/v1")
app.include_router(admin_users_router, prefix="/api/v1")
app.include_router(admin_keys_router, prefix="/api/v1")
app.include_router(admin_config_router, prefix="/api/v1")
app.include_router(platform_tenants_router, prefix="/api/v1")

import os as _os
if _os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")
