"""
services/cache.py — CacheBackend ABC and InProcessCache implementation.

InProcessCache uses a plain dict with optional per-key TTL.  It is NOT thread-safe
for the general case, but is safe here because:
  - The anomaly engine runs on a single event loop thread
  - All push ingest calls are serialised through FastAPI's thread pool with
    the GIL protecting dict reads and writes

For multi-process deployments (future), swap InProcessCache for a Redis-backed
implementation that honours the same ABC.

Cache key conventions (enforced by callers, not by this module):
  EWMA state  : "ewma:{tenant_id}:{source_id}"    TTL=None (write-through)
  API key     : "apikey:{key_hash}"                TTL=60
  Dashboard   : "dash:{tenant_id}"                 TTL=5
"""
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

logger = logging.getLogger(__name__)


class CacheBackend(ABC):
    """Minimal key-value cache interface.  All implementations must be safe to
    call from a single asyncio event loop thread without explicit locking."""

    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Return the cached value for *key*, or None on miss / expiry."""

    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Store *value* under *key*.  *ttl* is seconds; None means no expiry."""

    @abstractmethod
    def delete(self, key: str) -> None:
        """Remove *key* from the cache.  No-op if not present."""

    @abstractmethod
    def clear(self) -> None:
        """Flush all entries.  Used in tests to reset state between runs."""


class InProcessCache(CacheBackend):
    """
    In-process dict cache with per-key TTL support.

    Entry layout: {key: (value, expires_at_monotonic_or_None)}
    expires_at = None means no expiry (permanent until evicted or cleared).
    """

    def __init__(self) -> None:
        self._store: dict[str, tuple[Any, Optional[float]]] = {}

    def get(self, key: str) -> Optional[Any]:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if expires_at is not None and time.monotonic() >= expires_at:
            del self._store[key]
            logger.debug("cache miss (expired)", extra={"key": key})
            return None
        return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        expires_at = (time.monotonic() + ttl) if ttl is not None else None
        self._store[key] = (value, expires_at)

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)
