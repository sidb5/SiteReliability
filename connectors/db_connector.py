"""
connectors/db_connector.py — High-water mark polling connector for SQL databases.

Polls an external table for rows with id > last_seen_id (high-water mark strategy).
Every synchronous SQLAlchemy Core call is wrapped in asyncio.to_thread() so the
event loop is never blocked.

Supported source types: sqlite | postgres | mysql
  sqlite   — built-in, no extra driver; used for tests and dev sources
  postgres — requires psycopg2-binary
  mysql    — requires PyMySQL

The connection string is decrypted by ConnectorManager before being placed in
SourceConfig.connection_string.  It is never re-persisted, logged, or returned.

High-water mark contract:
  - Rows are fetched WHERE id > last_seen_id ORDER BY id ASC LIMIT 500
  - On success: last_seen_id advances to the max id in the batch
  - On empty result: last_seen_id unchanged, returns []
  - On DB error: last_seen_id unchanged, raises (ConnectorManager handles backoff)
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import sqlalchemy as sa

from connectors.base import LogSourceConnector, NormalizedLogEntry, SourceConfig

logger = logging.getLogger(__name__)

_BATCH_LIMIT = 500
_REQUIRED_COLUMNS = {"id", "message"}
_LEVEL_COLUMNS = ("level", "lvl", "severity", "log_level")
_TS_COLUMNS = ("timestamp", "created_at", "occurred_at", "time", "ts")
_LATENCY_COLUMNS = ("latency_ms", "latency", "duration", "elapsed")


class DBConnector(LogSourceConnector):
    """
    Polls an external SQL table using a high-water mark on the primary key.
    All SQLAlchemy Core calls run in asyncio.to_thread() — never on the event loop.
    """

    def __init__(self) -> None:
        self._config: Optional[SourceConfig] = None
        self._engine: Optional[sa.Engine] = None
        self._table: Optional[sa.Table] = None
        self._last_seen_id: str = "0"   # string to accommodate UUID PKs
        self._level_col: Optional[str] = None
        self._ts_col: Optional[str] = None
        self._latency_col: Optional[str] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self, config: SourceConfig) -> None:
        self._config = config
        self._last_seen_id = config.last_seen_id or "0"
        await asyncio.to_thread(self._connect_sync)

    async def close(self) -> None:
        await asyncio.to_thread(self._close_sync)

    async def flush_state(self) -> SourceConfig:
        assert self._config is not None, "flush_state() called before connect()"
        self._config.last_seen_id = self._last_seen_id
        return self._config

    # ------------------------------------------------------------------
    # Poll
    # ------------------------------------------------------------------

    async def poll(self) -> list[NormalizedLogEntry]:
        return await asyncio.to_thread(self._poll_sync)

    # ------------------------------------------------------------------
    # Synchronous internals (run inside to_thread)
    # ------------------------------------------------------------------

    def _connect_sync(self) -> None:
        if not self._config.connection_string:
            raise ValueError(
                f"DBConnector source {self._config.source_id}: connection_string is empty"
            )

        conn_str = self._config.connection_string
        # Resolve source_type alias to SQLAlchemy URL prefix
        st = self._config.source_type
        if st in ("postgres", "postgresql") and not conn_str.startswith("postgresql"):
            conn_str = "postgresql+psycopg2://" + conn_str.split("://", 1)[-1]
        elif st == "mysql" and not conn_str.startswith("mysql"):
            conn_str = "mysql+pymysql://" + conn_str.split("://", 1)[-1]
        # sqlite and fully-qualified URLs pass through unchanged

        self._engine = sa.create_engine(conn_str, pool_pre_ping=True)

        # Reflect the target table; table name defaults to "logs" if not in path
        table_name = self._resolve_table_name()
        meta = sa.MetaData()
        try:
            self._table = sa.Table(table_name, meta, autoload_with=self._engine)
        except sa.exc.NoSuchTableError:
            raise ValueError(
                f"DBConnector source {self._config.source_id}: "
                f"table '{table_name}' not found in external database"
            )

        col_names = {c.name for c in self._table.columns}
        missing = _REQUIRED_COLUMNS - col_names
        if missing:
            raise ValueError(
                f"DBConnector source {self._config.source_id}: "
                f"table '{table_name}' missing required column(s): {missing}"
            )

        # Detect optional columns once at connect time
        self._level_col = next((c for c in _LEVEL_COLUMNS if c in col_names), None)
        self._ts_col = next((c for c in _TS_COLUMNS if c in col_names), None)

        # Prefer explicit latency_field config, fall back to well-known column names
        if self._config.latency_field and self._config.latency_field in col_names:
            self._latency_col = self._config.latency_field
        else:
            self._latency_col = next((c for c in _LATENCY_COLUMNS if c in col_names), None)

        logger.debug(
            "db connector connected",
            extra={
                "source_id": self._config.source_id,
                "table": table_name,
                "level_col": self._level_col,
                "ts_col": self._ts_col,
                "latency_col": self._latency_col,
            },
        )

    def _close_sync(self) -> None:
        if self._engine is not None:
            try:
                self._engine.dispose()
            except Exception:
                pass
            self._engine = None
        logger.debug(
            "db connector closed",
            extra={"source_id": self._config.source_id if self._config else "unknown"},
        )

    def _poll_sync(self) -> list[NormalizedLogEntry]:
        if self._engine is None or self._table is None:
            return []

        try:
            with self._engine.connect() as conn:
                rows = self._fetch_batch(conn)
        except Exception as exc:
            logger.warning(
                "db connector poll failed",
                extra={"source_id": self._config.source_id, "error": str(exc)},
            )
            raise   # ConnectorManager catches this and enters BACKOFF

        if not rows:
            return []

        entries = [self._row_to_entry(row) for row in rows]

        # Advance high-water mark to the highest id seen in this batch
        max_id = str(max(row["id"] for row in rows))
        self._last_seen_id = max_id

        return entries

    def _fetch_batch(self, conn: sa.Connection) -> list[dict]:
        """
        SELECT * FROM <table> WHERE id > :hwm ORDER BY id ASC LIMIT :limit

        Casts both sides of the comparison to TEXT for SQLite compatibility
        (SQLite has no native INTEGER PK type enforcement through reflection).
        For Postgres/MySQL the cast is a no-op on numeric PKs.
        """
        tbl = self._table
        stmt = (
            sa.select(tbl)
            .where(sa.cast(tbl.c.id, sa.Text) > sa.cast(sa.literal(self._last_seen_id), sa.Text))
            .order_by(tbl.c.id.asc())
            .limit(_BATCH_LIMIT)
        )
        result = conn.execute(stmt)
        keys = list(result.keys())
        return [dict(zip(keys, row)) for row in result.fetchall()]

    def _row_to_entry(self, row: dict) -> NormalizedLogEntry:
        level = "UNKNOWN"
        if self._level_col and self._level_col in row and row[self._level_col]:
            level = str(row[self._level_col]).upper()

        message = str(row.get("message") or "")

        occurred_at: Optional[datetime] = None
        if self._ts_col and self._ts_col in row and row[self._ts_col]:
            raw_ts = row[self._ts_col]
            if isinstance(raw_ts, datetime):
                occurred_at = raw_ts if raw_ts.tzinfo else raw_ts.replace(tzinfo=timezone.utc)
            elif isinstance(raw_ts, str):
                occurred_at = _parse_iso_timestamp(raw_ts)
        if occurred_at is None:
            occurred_at = datetime.now(timezone.utc)

        latency_ms: Optional[float] = None
        if self._latency_col and self._latency_col in row and row[self._latency_col] is not None:
            try:
                latency_ms = float(row[self._latency_col])
            except (TypeError, ValueError):
                pass

        return NormalizedLogEntry(
            occurred_at=occurred_at,
            level=level,
            message=message,
            source_id=self._config.source_id,
            tenant_id=self._config.tenant_id,
            service_name=self._config.service_name,
            environment=self._config.environment,
            latency_ms=latency_ms,
            raw={k: str(v) if v is not None else None for k, v in row.items()},
        )

    def _resolve_table_name(self) -> str:
        """Extract table name from connection string path, defaulting to 'logs'."""
        conn_str = self._config.connection_string or ""
        # sqlite:///./path/to/file.db -> table not in URL; use 'logs'
        # Some callers encode it as sqlite:///./file.db?table=app_logs
        if "?table=" in conn_str:
            return conn_str.split("?table=", 1)[1].split("&")[0]
        return "logs"


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _parse_iso_timestamp(raw: str) -> Optional[datetime]:
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
