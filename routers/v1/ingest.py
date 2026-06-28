"""
routers/v1/ingest.py — POST /api/v1/ingest  (single) and /api/v1/ingest/batch

Auth: X-API-Key header, scope "ingest" required.
Rate limit: RATE_LIMIT_INGEST (default 100/min) from settings, applied per source IP.
No JWT path — ingest is machine-to-machine, API key only.

Raw entries are never persisted to the database.  They flow through LogService
to the anomaly engine stub (Module 6 wires the real engine).
"""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from config import settings
from database import get_db
from limiter import limiter
from models.schemas.v1.ingest import (
    BatchIngestRequest,
    BatchIngestResponse,
    LogEntryRequest,
    LogEntryResponse,
)
from security import TenantContext, get_tenant_context, require_scope
from services.log_service import LogService
from sqlalchemy.orm import Session

router = APIRouter(tags=["ingest"])


def _get_log_service(request: Request) -> LogService:
    return request.app.state.log_service


@router.post(
    "/ingest",
    response_model=LogEntryResponse,
    status_code=201,
    summary="Push a single log entry",
)
@limiter.limit(settings.RATE_LIMIT_INGEST)
async def ingest_single(
    request: Request,
    body: LogEntryRequest,
    ctx: TenantContext = Depends(require_scope("ingest")),
    log_service: LogService = Depends(_get_log_service),
    db: Session = Depends(get_db),
) -> LogEntryResponse:
    log_service.process_entries([body], ctx, db=db)
    return LogEntryResponse(
        id=str(uuid.uuid4()),
        tenant_id=ctx.tenant_id,
        received_at=datetime.now(timezone.utc),
    )


@router.post(
    "/ingest/batch",
    response_model=BatchIngestResponse,
    status_code=201,
    summary="Push a batch of log entries (1–500)",
)
@limiter.limit(settings.RATE_LIMIT_INGEST)
async def ingest_batch(
    request: Request,
    body: BatchIngestRequest,
    ctx: TenantContext = Depends(require_scope("ingest")),
    log_service: LogService = Depends(_get_log_service),
    db: Session = Depends(get_db),
) -> BatchIngestResponse:
    log_service.process_entries(body.entries, ctx, db=db)
    return BatchIngestResponse(accepted=len(body.entries))
