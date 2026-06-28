"""
connectors/push_connector.py — Passive push connector.

External applications POST log entries directly to /api/v1/ingest using a
scoped API key.  The ingest endpoint (Module 5) routes those entries to the
anomaly engine without any polling loop.

PushConnector exists in the plugin hierarchy so ConnectorManager can register
push-type sources and track their state, but poll() always returns [] because
there is nothing to poll — the data arrives via the HTTP path.
"""
import logging

from connectors.base import LogSourceConnector, NormalizedLogEntry, SourceConfig

logger = logging.getLogger(__name__)


class PushConnector(LogSourceConnector):
    """
    No-op connector.  Satisfies the LogSourceConnector ABC for push-type
    sources so they participate in the ConnectorManager lifecycle without
    requiring special-case handling.
    """

    def __init__(self) -> None:
        self._config: SourceConfig | None = None

    async def connect(self, config: SourceConfig) -> None:
        self._config = config
        logger.debug(
            "push connector registered",
            extra={"source_id": config.source_id, "tenant_id": config.tenant_id},
        )

    async def poll(self) -> list[NormalizedLogEntry]:
        # Push sources deliver via /api/v1/ingest — nothing to poll.
        return []

    async def close(self) -> None:
        logger.debug(
            "push connector closed",
            extra={"source_id": self._config.source_id if self._config else "unknown"},
        )
        self._config = None

    async def flush_state(self) -> SourceConfig:
        # No cursor state to update for push sources.
        assert self._config is not None, "flush_state() called before connect()"
        return self._config
