"""
services/connector_manager.py — Lifecycle manager for all active connectors.

Responsibilities:
  - Start one asyncio task per active LogSource at app startup
  - Run each connector on an adaptive poll schedule (ACTIVE / IDLE / BACKOFF)
  - Persist SourceState cursor after every successful poll
  - Stop all tasks on graceful shutdown (FastAPI lifespan exit)

State machine per connector:
  ACTIVE  → polls every poll_interval_s seconds
           → transitions to IDLE after IDLE_AFTER_EMPTY consecutive empty polls
  IDLE    → polls every IDLE_POLL_INTERVAL_S seconds (reduced frequency)
           → transitions to ACTIVE immediately on first non-empty poll
  BACKOFF → entered after BACKOFF_AFTER_ERRORS consecutive poll errors
           → polls every BACKOFF_POLL_INTERVAL_S seconds
           → transitions to ACTIVE on first successful (non-error) poll

Tenant isolation:
  - Each asyncio.Task is tagged with (tenant_id, source_id)
  - A crash in one task does not affect other tasks
  - ConnectorManager tracks tasks in _tasks dict; one entry per source_id

Connector selection:
  source_type   connector class
  file          FileConnector
  postgres      DBConnector
  mysql         DBConnector
  sqlite        DBConnector
  push          PushConnector (no-op poll loop runs, harmlessly returns [])
"""
import asyncio
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from sqlalchemy.orm import Session

from connectors.base import LogSourceConnector, NormalizedLogEntry, SourceConfig
from connectors.db_connector import DBConnector
from connectors.file_connector import FileConnector
from connectors.push_connector import PushConnector

logger = logging.getLogger(__name__)

# Adaptive poll tuning constants
IDLE_AFTER_EMPTY = 5             # consecutive empty polls before entering IDLE
IDLE_POLL_INTERVAL_S = 30        # poll interval while IDLE
BACKOFF_AFTER_ERRORS = 3         # consecutive errors before entering BACKOFF
BACKOFF_POLL_INTERVAL_S = 60     # poll interval while in BACKOFF


class ConnectorState(str, Enum):
    ACTIVE = "active"
    IDLE = "idle"
    BACKOFF = "backoff"


@dataclass
class _ConnectorSlot:
    """Runtime state for one running connector task."""
    source_id: str
    tenant_id: str
    connector: LogSourceConnector
    config: SourceConfig
    state: ConnectorState = ConnectorState.ACTIVE
    consecutive_empty: int = 0
    consecutive_errors: int = 0
    task: Optional[asyncio.Task] = None


class ConnectorManager:
    """
    Manages the full lifecycle of all registered connectors.

    Usage (FastAPI lifespan):
        manager = ConnectorManager(session_factory=SessionLocal)
        await manager.start()      # call in lifespan startup
        yield
        await manager.stop()       # call in lifespan shutdown
    """

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory
        self._slots: dict[str, _ConnectorSlot] = {}   # keyed by source_id
        self._running = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Load all active sources from the DB and start their poll tasks."""
        self._running = True
        sources = await asyncio.to_thread(self._load_active_sources)
        for cfg in sources:
            await self._start_connector(cfg)
        logger.info(
            "connector manager started",
            extra={"connector_count": len(self._slots)},
        )

    async def stop(self) -> None:
        """Cancel all running tasks and close connectors gracefully."""
        self._running = False
        for slot in list(self._slots.values()):
            await self._stop_slot(slot)
        self._slots.clear()
        logger.info("connector manager stopped")

    async def add_source(self, cfg: SourceConfig, max_sources: Optional[int] = None) -> None:
        """
        Register and start a connector for a newly added source.
        Called by the admin API after creating a LogSource.

        max_sources: if provided, raise ValueError when the tenant already has
        that many active connectors.  The admin API reads this from Tenant.max_sources.
        """
        if cfg.source_id in self._slots:
            logger.warning(
                "add_source called for already-running source",
                extra={"source_id": cfg.source_id},
            )
            return
        if max_sources is not None:
            current = sum(1 for s in self._slots.values() if s.tenant_id == cfg.tenant_id)
            if current >= max_sources:
                raise ValueError(
                    f"Tenant {cfg.tenant_id} has reached the max_sources limit ({max_sources})"
                )
        await self._start_connector(cfg)

    async def remove_source(self, source_id: str) -> None:
        """Stop and deregister a connector. Called when a source is deleted."""
        slot = self._slots.pop(source_id, None)
        if slot:
            await self._stop_slot(slot)

    # ------------------------------------------------------------------
    # Internal: connector startup / shutdown
    # ------------------------------------------------------------------

    async def _start_connector(self, cfg: SourceConfig) -> None:
        connector = _make_connector(cfg.source_type)
        try:
            await connector.connect(cfg)
        except Exception as exc:
            logger.error(
                "connector failed to connect — not starting poll task",
                extra={"source_id": cfg.source_id, "error": str(exc)},
            )
            return

        slot = _ConnectorSlot(
            source_id=cfg.source_id,
            tenant_id=cfg.tenant_id,
            connector=connector,
            config=cfg,
        )
        slot.task = asyncio.create_task(
            self._poll_loop(slot),
            name=f"connector:{cfg.tenant_id}:{cfg.source_id}",
        )
        self._slots[cfg.source_id] = slot
        logger.debug(
            "connector started",
            extra={"source_id": cfg.source_id, "tenant_id": cfg.tenant_id, "type": cfg.source_type},
        )

    async def _stop_slot(self, slot: _ConnectorSlot) -> None:
        if slot.task and not slot.task.done():
            slot.task.cancel()
            try:
                await slot.task
            except asyncio.CancelledError:
                pass
        try:
            await slot.connector.close()
        except Exception as exc:
            logger.warning(
                "error closing connector",
                extra={"source_id": slot.source_id, "error": str(exc)},
            )

    # ------------------------------------------------------------------
    # Poll loop — one instance per connector
    # ------------------------------------------------------------------

    async def _poll_loop(self, slot: _ConnectorSlot) -> None:
        """
        Adaptive poll loop for one connector.  Runs until task is cancelled.
        """
        while self._running:
            interval = _poll_interval(slot)
            await asyncio.sleep(interval)

            try:
                entries: list[NormalizedLogEntry] = await slot.connector.poll()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                slot.consecutive_errors += 1
                slot.consecutive_empty = 0
                logger.warning(
                    "connector poll error",
                    extra={
                        "source_id": slot.source_id,
                        "tenant_id": slot.tenant_id,
                        "consecutive_errors": slot.consecutive_errors,
                        "error": str(exc),
                    },
                )
                if slot.consecutive_errors >= BACKOFF_AFTER_ERRORS:
                    if slot.state != ConnectorState.BACKOFF:
                        logger.info(
                            "connector entering BACKOFF",
                            extra={"source_id": slot.source_id, "consecutive_errors": slot.consecutive_errors},
                        )
                    slot.state = ConnectorState.BACKOFF
                continue

            # Successful poll (no exception)
            slot.consecutive_errors = 0
            if slot.state == ConnectorState.BACKOFF:
                logger.info(
                    "connector recovered from BACKOFF",
                    extra={"source_id": slot.source_id},
                )
                slot.state = ConnectorState.ACTIVE

            if not entries:
                slot.consecutive_empty += 1
                if (
                    slot.state == ConnectorState.ACTIVE
                    and slot.consecutive_empty >= IDLE_AFTER_EMPTY
                ):
                    logger.debug(
                        "connector entering IDLE",
                        extra={"source_id": slot.source_id, "consecutive_empty": slot.consecutive_empty},
                    )
                    slot.state = ConnectorState.IDLE
                continue

            # Non-empty result
            if slot.state == ConnectorState.IDLE:
                logger.debug(
                    "connector returning to ACTIVE",
                    extra={"source_id": slot.source_id},
                )
                slot.state = ConnectorState.ACTIVE
            slot.consecutive_empty = 0

            # Persist cursor state
            updated_cfg = await slot.connector.flush_state()
            slot.config = updated_cfg
            await asyncio.to_thread(self._persist_state, updated_cfg)

            # Dispatch entries to anomaly engine (injected in Module 6)
            await self._dispatch(slot, entries)

    async def _dispatch(self, slot: _ConnectorSlot, entries: list[NormalizedLogEntry]) -> None:
        """
        Forward entries to the anomaly engine.
        Placeholder until Module 6 wires in the engine.
        """
        logger.debug(
            "connector dispatching entries",
            extra={
                "source_id": slot.source_id,
                "tenant_id": slot.tenant_id,
                "count": len(entries),
            },
        )

    # ------------------------------------------------------------------
    # DB operations (all run in to_thread)
    # ------------------------------------------------------------------

    def _load_active_sources(self) -> list[SourceConfig]:
        """Load all active LogSource rows and build SourceConfig objects."""
        from models.db import LogSource, SourceState
        from security import decrypt

        db = self._session_factory()
        try:
            sources = (
                db.query(LogSource)
                .filter(LogSource.active == True)  # noqa: E712
                .all()
            )
            configs = []
            for src in sources:
                state = db.query(SourceState).filter(SourceState.source_id == src.id).first()
                cfg = _build_config(src, state, decrypt)
                configs.append(cfg)
            return configs
        finally:
            db.close()

    def _persist_state(self, cfg: SourceConfig) -> None:
        """Upsert SourceState with the latest cursor values."""
        from models.db import SourceState

        db = self._session_factory()
        if db is None:
            return
        try:
            state = db.query(SourceState).filter(SourceState.source_id == cfg.source_id).first()
            if state is None:
                state = SourceState(source_id=cfg.source_id, tenant_id=cfg.tenant_id)
                db.add(state)
            state.byte_offset = cfg.byte_offset
            state.file_inode = cfg.file_inode
            state.last_seen_id = cfg.last_seen_id
            db.commit()
        except Exception as exc:
            logger.error(
                "failed to persist connector state",
                extra={"source_id": cfg.source_id, "error": str(exc)},
            )
            try:
                db.rollback()
            except Exception:
                pass
        finally:
            try:
                db.close()
            except Exception:
                pass


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_connector(source_type: str) -> LogSourceConnector:
    if source_type == "file":
        return FileConnector()
    if source_type in ("postgres", "postgresql", "mysql", "sqlite"):
        return DBConnector()
    if source_type == "push":
        return PushConnector()
    raise ValueError(f"Unknown source_type: {source_type!r}")


def _poll_interval(slot: _ConnectorSlot) -> float:
    if slot.state == ConnectorState.IDLE:
        return float(IDLE_POLL_INTERVAL_S)
    if slot.state == ConnectorState.BACKOFF:
        return float(BACKOFF_POLL_INTERVAL_S)
    return float(slot.config.poll_interval_s)


def _build_config(src, state, decrypt_fn) -> SourceConfig:
    """
    Construct a SourceConfig from ORM rows.
    Decrypts connection_config_enc in-memory; never re-persists the plaintext.
    """
    connection_string: Optional[str] = None
    if src.connection_config_enc:
        try:
            connection_string = decrypt_fn(src.connection_config_enc)
        except Exception as exc:
            logger.error(
                "failed to decrypt connection config",
                extra={"source_id": src.id, "error": str(exc)},
            )

    file_path: Optional[str] = None
    if src.source_type == "file" and connection_string:
        # For file sources, connection_config_enc stores the file path (not a secret,
        # but encrypted for schema consistency with DB connectors)
        file_path = connection_string
        connection_string = None

    return SourceConfig(
        source_id=src.id,
        tenant_id=src.tenant_id,
        service_name=src.service_name,
        environment=src.environment,
        source_type=src.source_type,
        log_format=src.log_format,
        poll_interval_s=src.poll_interval_s,
        latency_field=src.latency_field,
        connection_string=connection_string,
        file_path=file_path,
        file_inode=state.file_inode if state else None,
        byte_offset=state.byte_offset if state else 0,
        last_seen_id=state.last_seen_id if state else "0",
    )
