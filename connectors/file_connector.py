"""
connectors/file_connector.py — Tail-follows a log file with rotation detection.

Poll strategy:
  1. Open the file at the stored byte offset.
  2. Read all new bytes since last poll; parse into NormalizedLogEntry items.
  3. Persist the new byte offset so the next poll starts exactly where this one ended.

Rotation detection (cross-platform):
  Primary:   current file size < last byte offset  → file was truncated or replaced
  Secondary: os.stat().st_ino != stored inode      → file was renamed/replaced
             (st_ino is non-zero on POSIX; on Windows it is 0, so this check
              is skipped, and the size-shrink check handles rotation instead)

On rotation:
  1. Drain remaining bytes from the old file descriptor (bytes between last offset
     and EOF that haven't been read yet).
  2. Close old descriptor.
  3. Open the new file from byte offset 0.
  4. Continue reading.

Supported log formats:
  json     — one JSON object per line; requires 'level' and 'message' keys
  logfmt   — key=value pairs; e.g. level=ERROR msg="something broke"
  plaintext — bare text lines; level inferred from keywords in the message
"""
import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

from connectors.base import LogSourceConnector, NormalizedLogEntry, SourceConfig

logger = logging.getLogger(__name__)

# Keyword → level map for plaintext format (checked in order, first match wins)
_PLAINTEXT_LEVEL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(CRITICAL|FATAL)\b", re.IGNORECASE), "CRITICAL"),
    (re.compile(r"\bERROR\b", re.IGNORECASE), "ERROR"),
    (re.compile(r"\bWARN(?:ING)?\b", re.IGNORECASE), "WARNING"),
    (re.compile(r"\bINFO\b", re.IGNORECASE), "INFO"),
    (re.compile(r"\bDEBUG\b", re.IGNORECASE), "DEBUG"),
]

# logfmt key aliases for level and message fields
_LOGFMT_LEVEL_KEYS = ("level", "lvl", "severity")
_LOGFMT_MSG_KEYS = ("msg", "message", "text")
_LOGFMT_TS_KEYS = ("time", "ts", "timestamp", "at")
_LOGFMT_LATENCY_CANDIDATES = ("latency", "latency_ms", "duration", "elapsed")


class FileConnector(LogSourceConnector):
    """
    Tail-follows a rotating log file.  State (byte offset + inode) is persisted
    via flush_state() so the connector can resume after a restart with no re-reads.
    """

    def __init__(self) -> None:
        self._config: Optional[SourceConfig] = None
        self._fh = None                    # open file handle
        self._current_path: Optional[str] = None
        self._current_inode: int = 0       # 0 on Windows (size-shrink is primary)
        self._byte_offset: int = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self, config: SourceConfig) -> None:
        self._config = config
        self._current_path = config.file_path
        self._byte_offset = config.byte_offset or 0
        self._current_inode = config.file_inode or 0

        if self._current_path and os.path.exists(self._current_path):
            await asyncio.to_thread(self._open_at_offset, self._byte_offset)
        else:
            logger.warning(
                "file connector: path not found at connect time, will retry on first poll",
                extra={"source_id": config.source_id, "path": self._current_path},
            )

    async def close(self) -> None:
        await asyncio.to_thread(self._close_handle)
        logger.debug(
            "file connector closed",
            extra={"source_id": self._config.source_id if self._config else "unknown"},
        )

    async def flush_state(self) -> SourceConfig:
        assert self._config is not None, "flush_state() called before connect()"
        self._config.file_path = self._current_path
        self._config.file_inode = self._current_inode
        self._config.byte_offset = self._byte_offset
        return self._config

    # ------------------------------------------------------------------
    # Poll — the core read loop
    # ------------------------------------------------------------------

    async def poll(self) -> list[NormalizedLogEntry]:
        return await asyncio.to_thread(self._poll_sync)

    def _poll_sync(self) -> list[NormalizedLogEntry]:
        """Synchronous body of poll(); runs in a thread pool executor."""
        if not self._current_path:
            return []

        if not os.path.exists(self._current_path):
            logger.debug(
                "file connector: path does not exist yet",
                extra={"source_id": self._config.source_id, "path": self._current_path},
            )
            return []

        # --- Rotation detection ---
        # Open a stat on the current on-disk file (before we potentially open it)
        try:
            stat = os.stat(self._current_path)
        except OSError:
            return []

        current_size = stat.st_size
        current_inode = stat.st_ino  # 0 on Windows — that is fine

        rotated = self._detect_rotation(current_size, current_inode)

        if rotated:
            entries = self._handle_rotation(current_inode)
        else:
            # No rotation — ensure handle is open and read new bytes
            if self._fh is None:
                self._open_at_offset(self._byte_offset)
            entries = self._read_new_lines()

        return entries

    # ------------------------------------------------------------------
    # Rotation detection
    # ------------------------------------------------------------------

    def _detect_rotation(self, current_size: int, current_inode: int) -> bool:
        """
        Return True if the file appears to have been rotated.

        Primary check (cross-platform):
            current file size < last known byte offset
            → the file on disk is smaller than where we left off, meaning it
              was truncated or replaced with a new (shorter) file.

        Secondary check (POSIX only, skipped when st_ino == 0):
            current inode != stored inode
            → the filename now points to a different file (renamed rotation).
        """
        if self._fh is None and self._byte_offset == 0:
            # First open — no rotation possible yet
            return False

        # Primary: size shrink
        if current_size < self._byte_offset:
            logger.info(
                "file rotation detected (size shrink)",
                extra={
                    "source_id": self._config.source_id,
                    "path": self._current_path,
                    "last_offset": self._byte_offset,
                    "current_size": current_size,
                },
            )
            return True

        # Secondary: inode change (POSIX only; current_inode == 0 skips this)
        if (
            current_inode != 0
            and self._current_inode != 0
            and current_inode != self._current_inode
        ):
            logger.info(
                "file rotation detected (inode change)",
                extra={
                    "source_id": self._config.source_id,
                    "path": self._current_path,
                    "old_inode": self._current_inode,
                    "new_inode": current_inode,
                },
            )
            return True

        return False

    # ------------------------------------------------------------------
    # Rotation handler
    # ------------------------------------------------------------------

    def _handle_rotation(self, new_inode: int) -> list[NormalizedLogEntry]:
        """
        Drain any unread bytes from the old file, then open the new file.
        Returns all entries from both old tail and new file.
        """
        entries: list[NormalizedLogEntry] = []

        # Drain remaining bytes from the old descriptor before it disappears
        if self._fh is not None:
            try:
                tail_bytes: bytes = self._fh.read()
                if tail_bytes:
                    tail = tail_bytes.decode("utf-8", errors="replace")
                    entries.extend(self._parse_lines(tail.splitlines()))
            except OSError:
                pass
            self._close_handle()

        # Reset cursor and open the new file from byte 0
        self._byte_offset = 0
        self._current_inode = new_inode
        self._open_at_offset(0)
        entries.extend(self._read_new_lines())
        return entries

    # ------------------------------------------------------------------
    # Low-level file I/O
    # ------------------------------------------------------------------

    def _open_at_offset(self, offset: int) -> None:
        """
        Open the current path in BINARY mode and seek to byte offset.

        Binary mode is required for reliable byte-level seeking on Windows.
        Text mode on Windows translates \\r\\n → \\n during reads, so the
        character count we store diverges from the true file byte position,
        causing seek() to land in the wrong place after a restart.
        Binary mode + explicit UTF-8 decode gives exact, portable byte offsets.
        """
        self._close_handle()
        try:
            self._fh = open(self._current_path, "rb")
            if offset > 0:
                self._fh.seek(offset)
            # Record the inode of the file we just opened (0 on Windows)
            self._current_inode = os.fstat(self._fh.fileno()).st_ino
            self._byte_offset = offset
        except OSError as exc:
            logger.warning(
                "file connector: could not open file",
                extra={"source_id": self._config.source_id, "path": self._current_path, "error": str(exc)},
            )
            self._fh = None

    def _close_handle(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None

    def _read_new_lines(self) -> list[NormalizedLogEntry]:
        """Read any new bytes since the last position and return parsed entries."""
        if self._fh is None:
            return []
        try:
            chunk_bytes: bytes = self._fh.read()
            if not chunk_bytes:
                return []
            self._byte_offset += len(chunk_bytes)
            chunk = chunk_bytes.decode("utf-8", errors="replace")
            return self._parse_lines(chunk.splitlines())
        except OSError as exc:
            logger.warning(
                "file connector: read error",
                extra={"source_id": self._config.source_id, "error": str(exc)},
            )
            return []

    # ------------------------------------------------------------------
    # Format parsers
    # ------------------------------------------------------------------

    def _parse_lines(self, lines: list[str]) -> list[NormalizedLogEntry]:
        entries = []
        fmt = self._config.log_format if self._config else "plaintext"
        parse_fn = {
            "json": self._parse_json_line,
            "logfmt": self._parse_logfmt_line,
            "plaintext": self._parse_plaintext_line,
        }.get(fmt, self._parse_plaintext_line)

        for line in lines:
            line = line.strip()
            if not line:
                continue
            entry = parse_fn(line)
            if entry is not None:
                entries.append(entry)
        return entries

    def _make_entry(
        self,
        *,
        level: str,
        message: str,
        occurred_at: Optional[datetime] = None,
        latency_ms: Optional[float] = None,
        raw: Optional[dict] = None,
    ) -> NormalizedLogEntry:
        return NormalizedLogEntry(
            occurred_at=occurred_at or datetime.now(timezone.utc),
            level=level.upper() if level else "UNKNOWN",
            message=message or "",
            source_id=self._config.source_id,
            tenant_id=self._config.tenant_id,
            service_name=self._config.service_name,
            environment=self._config.environment,
            latency_ms=latency_ms,
            raw=raw or {},
        )

    def _parse_json_line(self, line: str) -> Optional[NormalizedLogEntry]:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            # Malformed JSON — treat as plaintext
            return self._parse_plaintext_line(line)

        if not isinstance(obj, dict):
            return None

        level = obj.get("level") or obj.get("lvl") or obj.get("severity") or "UNKNOWN"
        message = obj.get("message") or obj.get("msg") or obj.get("text") or line
        ts_raw = obj.get("time") or obj.get("timestamp") or obj.get("ts")
        occurred_at = _parse_timestamp(ts_raw)

        latency_ms = None
        if self._config.latency_field and self._config.latency_field in obj:
            try:
                latency_ms = float(obj[self._config.latency_field])
            except (TypeError, ValueError):
                pass

        return self._make_entry(
            level=str(level),
            message=str(message),
            occurred_at=occurred_at,
            latency_ms=latency_ms,
            raw=obj,
        )

    def _parse_logfmt_line(self, line: str) -> Optional[NormalizedLogEntry]:
        pairs = _parse_logfmt(line)
        if not pairs:
            return self._parse_plaintext_line(line)

        level = next((pairs[k] for k in _LOGFMT_LEVEL_KEYS if k in pairs), "UNKNOWN")
        message = next((pairs[k] for k in _LOGFMT_MSG_KEYS if k in pairs), line)
        ts_raw = next((pairs[k] for k in _LOGFMT_TS_KEYS if k in pairs), None)
        occurred_at = _parse_timestamp(ts_raw)

        latency_ms = None
        if self._config.latency_field and self._config.latency_field in pairs:
            try:
                latency_ms = float(pairs[self._config.latency_field].rstrip("ms"))
            except (TypeError, ValueError):
                pass
        elif not self._config.latency_field:
            # Auto-detect common latency key names
            for candidate in _LOGFMT_LATENCY_CANDIDATES:
                if candidate in pairs:
                    try:
                        latency_ms = float(pairs[candidate].rstrip("ms"))
                        break
                    except (TypeError, ValueError):
                        pass

        return self._make_entry(
            level=str(level),
            message=str(message),
            occurred_at=occurred_at,
            latency_ms=latency_ms,
            raw=pairs,
        )

    def _parse_plaintext_line(self, line: str) -> Optional[NormalizedLogEntry]:
        level = "UNKNOWN"
        for pattern, lvl in _PLAINTEXT_LEVEL_PATTERNS:
            if pattern.search(line):
                level = lvl
                break
        return self._make_entry(level=level, message=line, raw={"raw_line": line})


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _parse_logfmt(line: str) -> dict[str, str]:
    """
    Parse a logfmt line into a dict.
    Handles quoted values: key="value with spaces" and unquoted: key=value.
    """
    result: dict[str, str] = {}
    # Regex: key= then either "quoted" or unquoted-value
    pattern = re.compile(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|(\S*))')
    for match in pattern.finditer(line):
        key = match.group(1)
        value = match.group(2) if match.group(2) is not None else match.group(3)
        result[key] = value
    return result


def _parse_timestamp(raw: Optional[str]) -> Optional[datetime]:
    """Best-effort timestamp parse; returns None rather than raising."""
    if not raw:
        return None
    # Try ISO 8601 (most common in structured logs)
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None
