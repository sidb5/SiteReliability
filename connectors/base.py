"""
connectors/base.py — Connector plugin contract.

All log source connectors implement LogSourceConnector.  Adding a new source
type (Kafka, CloudWatch, Loki) = one new file that subclasses this ABC.
Zero changes to existing code.

The ConnectorManager instantiates connectors, calls connect(), then calls
poll() on each adaptive schedule, and close() on graceful shutdown.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class SourceConfig:
    """
    All data a connector needs to operate, populated by ConnectorManager
    from the LogSource + SourceState ORM rows.

    connection_string is decrypted in memory by ConnectorManager before
    being placed here — it is NEVER re-persisted or logged.
    """
    source_id: str
    tenant_id: str
    service_name: str
    environment: str
    source_type: str            # file | postgres | mysql | sqlite | push
    log_format: str             # json | logfmt | plaintext
    poll_interval_s: int
    latency_field: Optional[str]         # field name for LATENCY_SPIKE, or None

    # File connector cursor (from source_state)
    file_path: Optional[str] = None
    file_inode: Optional[int] = None
    byte_offset: Optional[int] = None

    # DB connector high-water mark (from source_state)
    last_seen_id: Optional[str] = None

    # Connection string — decrypted Fernet plaintext, held in memory only.
    # ConnectorManager decrypts once at connect() time; never re-exposed.
    connection_string: Optional[str] = None


@dataclass
class NormalizedLogEntry:
    """
    Canonical representation of a single log event from any source type.
    This is what the anomaly engine receives — format details are erased here.
    """
    occurred_at: datetime          # when the log event happened (from payload)
    level: str                     # ERROR | WARNING | INFO | DEBUG | TRACE | UNKNOWN
    message: str                   # the log message text
    source_id: str                 # UUID of the originating LogSource
    tenant_id: str                 # UUID of the owning Tenant
    service_name: str              # from source config
    environment: str               # from source config
    latency_ms: Optional[float]    # extracted if latency_field is configured; else None
    raw: dict = field(default_factory=dict)  # original parsed fields for evidence


class LogSourceConnector(ABC):
    """
    Plugin interface for log source connectors.

    Lifecycle managed by ConnectorManager:
      1. Instantiate
      2. await connect(config)      — open connection / validate cursor
      3. await poll() repeatedly    — return new entries since last call
      4. await close()              — release resources on shutdown

    Each poll() call must be idempotent with respect to its cursor: if the
    same offset / high-water mark is polled twice, it returns the same set
    of entries (no skips, no duplicates).
    """

    @abstractmethod
    async def connect(self, config: SourceConfig) -> None:
        """
        Initialise the connector with the given source config.
        For file connectors: open the file, seek to the stored byte offset.
        For DB connectors: establish a connection to the external database.
        For push connectors: no-op (push path feeds entries via ingest endpoint).
        """

    @abstractmethod
    async def poll(self) -> list[NormalizedLogEntry]:
        """
        Return all new log entries since the last successful poll.
        Must update the internal cursor (byte offset / last_seen_id) on
        success so the next call does not replay the same entries.
        Must return [] rather than raising on an empty result.
        """

    @abstractmethod
    async def close(self) -> None:
        """Release all held resources (file handles, DB connections)."""

    @abstractmethod
    async def flush_state(self) -> SourceConfig:
        """
        Return the current SourceConfig with cursor fields updated to reflect
        the state after the most recent successful poll.  ConnectorManager
        calls this before persisting state to source_state.
        """
