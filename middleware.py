"""
middleware.py — Request lifecycle: X-Request-ID, structured JSON logging,
latency measurement, sensitive header redaction, request_log persistence.

Security invariants enforced on every request:
- Authorization header VALUE is never logged (only presence as boolean)
- X-API-Key header VALUE is never logged (only presence as boolean)
- tenant_id, user_id, api_key_id are read only from verified TenantContext
  set by security.get_tenant_context() — never from raw request headers
"""
import logging
import time
import uuid
from logging.handlers import RotatingFileHandler

import json_log_formatter
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Session factory override — set by tests before the app starts so the
# middleware writes request_log rows to the test DB, not the production DB.
# main.py sets this to database.SessionLocal in the lifespan if still None.
# ---------------------------------------------------------------------------
_request_log_session_factory = None


def configure_logging(log_level: str = "WARNING") -> None:
    """
    Wire structured JSON logging onto the root logger.
    Called once from main.py's lifespan startup.
    Log level defaults to WARNING in production; use DEBUG locally.
    """
    formatter = json_log_formatter.JSONFormatter()

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    # 10 MB per file, keep 3 backups — handles log rotation on Windows
    file_handler = RotatingFileHandler(
        "watchdog.log", maxBytes=10 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(stream_handler)
    root.addHandler(file_handler)
    root.setLevel(getattr(logging, log_level.upper(), logging.WARNING))


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Starlette BaseHTTPMiddleware — runs around every request/response cycle:

    1. Inject or propagate X-Request-ID on every response
    2. Measure wall-clock latency
    3. Emit one structured JSON log line per request (no sensitive values)
    4. Persist request metadata to request_log table via its own DB session
       (independent of the route's get_db session, which is already closed)
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        start = time.perf_counter()
        response = await call_next(request)
        latency_ms = int((time.perf_counter() - start) * 1000)

        response.headers["X-Request-ID"] = request_id

        # Identity from verified TenantContext only — raw header values never used
        tc = getattr(request.state, "tenant_context", None)
        tenant_id = tc.tenant_id if tc else None
        user_id = tc.user_id if tc else None
        api_key_id = tc.api_key_id if tc else None

        # Structured log — header VALUES deliberately absent, presence only
        logger.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "latency_ms": latency_ms,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "api_key_id": api_key_id,
                "has_auth_header": bool(request.headers.get("Authorization")),
                "has_api_key_header": bool(request.headers.get("X-API-Key")),
                "client_ip": _get_client_ip(request),
            },
        )

        _persist_request_log(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            latency_ms=latency_ms,
            tenant_id=tenant_id,
            user_id=user_id,
            api_key_id=api_key_id,
            ip_address=_get_client_ip(request),
        )

        return response


def _get_client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _get_session():
    """Return a DB session from the active session factory."""
    if _request_log_session_factory is not None:
        return _request_log_session_factory()
    from database import SessionLocal
    return SessionLocal()


def _persist_request_log(
    *,
    request_id: str,
    method: str,
    path: str,
    status_code: int,
    latency_ms: int,
    tenant_id: str | None,
    user_id: str | None,
    api_key_id: str | None,
    ip_address: str | None,
) -> None:
    # Lazy import to break potential circular import at module load time
    from models.db import RequestLog

    db = _get_session()
    try:
        db.add(
            RequestLog(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                method=method,
                path=path,
                status_code=status_code,
                latency_ms=latency_ms,
                user_id=user_id,
                api_key_id=api_key_id,
                ip_address=ip_address,
                request_id=request_id,
                error_detail=None,
            )
        )
        db.commit()
    except Exception as exc:
        logger.error(
            "request_log write failed",
            extra={"request_id": request_id, "error": str(exc)},
        )
        db.rollback()
    finally:
        db.close()
