"""
services/log_service.py — Ingest pipeline: validate → normalise → route to anomaly engine.

Single chokepoint between both ingest paths (HTTP push and connector poll) and the
anomaly engine.  It is intentionally stateless so it can be attached to app.state
and shared across all request handlers without locks.

Raw log entries are NEVER written to the database.  The only DB writes in the
ingest path come from the anomaly engine when it detects an anomaly and persists
an AnomalyAlert row.

Session lifecycle:
  - Push path (routers/v1/ingest.py): the FastAPI get_db dependency owns the
    session and commits after this method returns (or rolls back on exception).
  - Connector path (ConnectorManager._dispatch): the ConnectorManager creates a
    short-lived session, passes it here, then commits.
  If neither caller provides a db session, process_entries() operates in
  cache-only mode (no DB persistence, anomaly engine still detects in-memory).
"""
import logging

from connectors.base import NormalizedLogEntry
from models.schemas.v1.ingest import LogEntryRequest
from security import TenantContext

logger = logging.getLogger(__name__)


class LogService:
    """
    Stateless ingest pipeline.  Instantiated once in main.py, attached to
    app.state.  Receives the AnomalyEngine reference after it is constructed
    (set_engine() called during lifespan startup).
    """

    def __init__(self) -> None:
        self._engine = None       # set by set_engine() in lifespan
        self._dispatcher = None   # set by set_dispatcher() in lifespan

    def set_engine(self, engine) -> None:
        """Wire the anomaly engine.  Called once during app startup."""
        self._engine = engine

    def set_dispatcher(self, dispatcher) -> None:
        """Wire the webhook dispatcher.  Called once during app startup."""
        self._dispatcher = dispatcher

    def process_entry(
        self, entry: LogEntryRequest, ctx: TenantContext
    ) -> NormalizedLogEntry:
        return NormalizedLogEntry(
            occurred_at=entry.occurred_at,
            level=entry.level,
            message=entry.message,
            source_id=ctx.api_key_id or "push",
            tenant_id=ctx.tenant_id,
            service_name=entry.service_name or "unknown",
            environment="production",
            latency_ms=entry.latency_ms,
            raw=entry.metadata or {},
        )

    def process_entries(
        self,
        entries: list[LogEntryRequest],
        ctx: TenantContext,
        db=None,
    ) -> list[NormalizedLogEntry]:
        """
        Convert and route a batch of validated LogEntryRequest objects.

        db: SQLAlchemy Session.  If None (tests without DB), engine runs in
        cache-only mode and skips DB persistence.
        """
        normalised = [self.process_entry(e, ctx) for e in entries]
        self._route_to_engine(normalised, db)
        return normalised

    def process_normalised(
        self,
        entries: list[NormalizedLogEntry],
        db=None,
    ) -> None:
        """
        Route already-normalised entries (connector poll path).
        Called by ConnectorManager._dispatch() which builds NormalizedLogEntry
        objects directly.
        """
        if not entries:
            return
        self._route_to_engine(entries, db)

    def _route_to_engine(
        self,
        entries: list[NormalizedLogEntry],
        db,
    ) -> None:
        if not entries:
            return
        if self._engine is None:
            logger.debug(
                "log_service: anomaly engine not wired (stub mode)",
                extra={"count": len(entries)},
            )
            return
        if db is None:
            logger.debug(
                "log_service: no DB session — engine running cache-only",
                extra={"count": len(entries)},
            )
            return
        try:
            alerts = self._engine.ingest(entries, db)
            if alerts:
                logger.info(
                    "anomaly alerts generated",
                    extra={
                        "count": len(alerts),
                        "tenant_id": entries[0].tenant_id,
                        "types": [a.anomaly_type for a in alerts],
                    },
                )
                if self._dispatcher is not None and db is not None:
                    for alert in alerts:
                        self._dispatcher.dispatch(alert, db)
        except Exception as exc:
            # Never let engine errors crash the ingest pipeline
            logger.error(
                "anomaly engine error during ingest",
                extra={
                    "tenant_id": entries[0].tenant_id if entries else "unknown",
                    "error": str(exc),
                },
            )
