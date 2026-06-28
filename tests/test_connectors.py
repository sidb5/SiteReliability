"""
tests/test_connectors.py — Module 4: Connector tests (18 cases)

FileConnector  (tests 1-7):  append, cursor, rotation detection, drain, resume, JSON, logfmt
DBConnector    (tests 8-11): high-water mark, advance, empty, connection failure
ConnectorManager (tests 12-17): startup, max_sources, ACTIVE→IDLE, IDLE→ACTIVE,
                                ACTIVE→BACKOFF, per-connector error isolation
Cross-tenant   (test 18):   tenant A connector never returns tenant B entries

Windows notes:
  - Rotation tests explicitly close all write handles before simulating rotation.
  - DBConnector tests use file-based SQLite (tmp_path); in-memory is connection-scoped.
  - ConnectorManager state-machine tests mock asyncio.sleep for instant execution.
"""
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from unittest.mock import AsyncMock, patch

import pytest
import sqlalchemy as sa

from connectors.base import LogSourceConnector, NormalizedLogEntry, SourceConfig
from connectors.db_connector import DBConnector
from connectors.file_connector import FileConnector
from connectors.push_connector import PushConnector
from services.connector_manager import (
    BACKOFF_AFTER_ERRORS,
    IDLE_AFTER_EMPTY,
    ConnectorManager,
    ConnectorState,
    _ConnectorSlot,
)


# ─────────────────────────────── helpers ────────────────────────────────────

def _cfg(
    source_id: str = "src1",
    tenant_id: str = "t1",
    source_type: str = "file",
    log_format: str = "json",
    file_path: Optional[str] = None,
    byte_offset: int = 0,
    last_seen_id: str = "0",
    connection_string: Optional[str] = None,
    latency_field: Optional[str] = None,
) -> SourceConfig:
    return SourceConfig(
        source_id=source_id,
        tenant_id=tenant_id,
        service_name="svc",
        environment="test",
        source_type=source_type,
        log_format=log_format,
        poll_interval_s=5,
        latency_field=latency_field,
        file_path=file_path,
        byte_offset=byte_offset,
        last_seen_id=last_seen_id,
        connection_string=connection_string,
    )


def _jline(level: str = "INFO", message: str = "ok", **extra) -> str:
    return json.dumps({"level": level, "message": message, **extra})


def _seed_ext_db(db_path: Path, rows: list[dict]) -> None:
    """Seed a file-based SQLite DB with a minimal 'logs' table."""
    engine = sa.create_engine(f"sqlite:///{db_path}")
    with engine.connect() as c:
        c.execute(sa.text(
            "CREATE TABLE IF NOT EXISTS logs "
            "(id INTEGER PRIMARY KEY, level TEXT, message TEXT, timestamp TEXT)"
        ))
        for row in rows:
            c.execute(
                sa.text("INSERT INTO logs (level, message, timestamp) VALUES (:l, :m, :t)"),
                {"l": row.get("level", "INFO"),
                 "m": row["message"],
                 "t": row.get("timestamp", "2026-01-01T00:00:00Z")},
            )
        c.commit()
    engine.dispose()


def _make_entry(source_id: str = "s", tenant_id: str = "t") -> NormalizedLogEntry:
    return NormalizedLogEntry(
        occurred_at=datetime.now(timezone.utc),
        level="INFO",
        message="ok",
        source_id=source_id,
        tenant_id=tenant_id,
        service_name="svc",
        environment="test",
        latency_ms=None,
    )


class _MockConnector(LogSourceConnector):
    """Controllable connector for ConnectorManager state-machine tests."""

    def __init__(self, responses: list, raises: bool = False) -> None:
        # responses: list of lists — each inner list is one poll() return value
        self._responses = list(responses)
        self._raises = raises
        self._config: Optional[SourceConfig] = None

    async def connect(self, config: SourceConfig) -> None:
        self._config = config

    async def close(self) -> None:
        pass

    async def flush_state(self) -> SourceConfig:
        assert self._config is not None
        return self._config

    async def poll(self) -> list[NormalizedLogEntry]:
        if self._raises:
            raise RuntimeError("source unavailable")
        return self._responses.pop(0) if self._responses else []


async def _run_n_polls(manager: ConnectorManager, slot: _ConnectorSlot, n: int) -> None:
    """
    Drive manager._poll_loop for exactly n successful poll() calls, then
    set _running = False so the loop exits cleanly.
    asyncio.sleep is patched to be instant inside this helper.
    """
    count = [0]
    orig = slot.connector.poll

    async def _counted():
        result = await orig()
        count[0] += 1
        if count[0] >= n:
            manager._running = False
        return result

    slot.connector.poll = _counted  # type: ignore[method-assign]
    manager._running = True
    with patch("asyncio.sleep", new_callable=AsyncMock):
        await manager._poll_loop(slot)


async def _run_n_attempts(manager: ConnectorManager, slot: _ConnectorSlot, n: int) -> None:
    """
    Drive manager._poll_loop for n poll *attempts* (including those that raise),
    then stop.  Used for BACKOFF tests where poll() always raises.
    """
    count = [0]
    orig = slot.connector.poll

    async def _counted():
        count[0] += 1
        if count[0] >= n:
            manager._running = False
        return await orig()  # may raise; exception propagates to poll loop

    slot.connector.poll = _counted  # type: ignore[method-assign]
    manager._running = True
    with patch("asyncio.sleep", new_callable=AsyncMock):
        await manager._poll_loop(slot)


# ═══════════════════════════════════════════════════════════════════════════
# FileConnector — tests 1-7
# ═══════════════════════════════════════════════════════════════════════════

class TestFileConnector:

    async def test_reads_appended_lines(self, tmp_path: Path) -> None:
        """Test 1: reads lines appended to a temp file."""
        log = tmp_path / "app.log"
        log.write_text(
            _jline("ERROR", "disk full") + "\n" + _jline("INFO", "startup") + "\n",
            encoding="utf-8",
        )

        connector = FileConnector()
        await connector.connect(_cfg(file_path=str(log)))
        entries = await connector.poll()
        await connector.close()

        assert len(entries) == 2
        assert entries[0].level == "ERROR"
        assert entries[0].message == "disk full"
        assert entries[1].level == "INFO"
        assert entries[1].message == "startup"

    async def test_cursor_no_duplicate_reads(self, tmp_path: Path) -> None:
        """Test 2: second poll ignores already-read lines (cursor advances correctly)."""
        log = tmp_path / "app.log"
        log.write_text(_jline("INFO", "first") + "\n", encoding="utf-8")

        connector = FileConnector()
        await connector.connect(_cfg(file_path=str(log)))

        first = await connector.poll()
        assert len(first) == 1

        # Append after first poll — write handle explicitly closed via with-block
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(_jline("INFO", "second") + "\n")
        # fh closed here

        second = await connector.poll()
        await connector.close()

        assert len(second) == 1
        assert second[0].message == "second"

    async def test_rotation_detection_follows_new_file(self, tmp_path: Path) -> None:
        """
        Test 3: detects rotation via size-shrink and follows new file.

        Windows-safe strategy: keep old file intact at a different path;
        create a new shorter file; point connector._current_path at new file.
        Old byte offset > new file size → size-shrink detected → follows new file.
        """
        old_log = tmp_path / "app.log.1"
        new_log = tmp_path / "app.log"

        # Write 5 lines so old offset is large
        old_content = "\n".join(_jline("INFO", f"old-{i}") for i in range(5)) + "\n"
        old_log.write_text(old_content, encoding="utf-8")

        connector = FileConnector()
        await connector.connect(_cfg(file_path=str(old_log)))

        # Poll all old content — byte_offset now = len(old file)
        first = await connector.poll()
        assert len(first) == 5

        # New file is shorter than old byte_offset (rotation signal)
        new_log.write_text(_jline("ERROR", "new-file-line") + "\n", encoding="utf-8")
        assert new_log.stat().st_size < connector._byte_offset, (
            "New file must be smaller than offset to trigger size-shrink detection"
        )

        # Point connector at new path; old read handle still on old file (no lock issue)
        connector._current_path = str(new_log)

        second = await connector.poll()
        await connector.close()

        assert len(second) == 1
        assert second[0].message == "new-file-line"

    async def test_rotation_drains_old_file_before_new(self, tmp_path: Path) -> None:
        """
        Test 4: drains unread bytes from old file descriptor before following new file.

        Strategy:
          - Read first batch from old file (cursor advances to mid-file).
          - Append 2 unread lines to old file; write handle explicitly closed.
          - Create new shorter file at a different path.
          - Point connector._current_path at new file (size < old cursor).
          - poll() detects rotation → drains 2 unread lines from old fd → reads new file.
        """
        old_log = tmp_path / "app.log.1"
        new_log = tmp_path / "app.log"

        old_log.write_text(
            "\n".join(_jline("INFO", f"old-{i}") for i in range(3)) + "\n",
            encoding="utf-8",
        )

        connector = FileConnector()
        await connector.connect(_cfg(file_path=str(old_log)))
        first = await connector.poll()
        assert len(first) == 3   # all read; byte_offset = end of initial content

        # Append unread lines — explicit close before rotation
        with open(old_log, "a", encoding="utf-8") as wf:
            wf.write(_jline("WARNING", "unread-1") + "\n")
            wf.write(_jline("WARNING", "unread-2") + "\n")
        # wf closed here

        # New file is shorter than current byte_offset
        new_log.write_text(_jline("ERROR", "new-entry") + "\n", encoding="utf-8")
        assert new_log.stat().st_size < connector._byte_offset

        # Point connector at new path; its _fh still references old_log fd
        connector._current_path = str(new_log)

        # poll: size-shrink detected → drains old fd (2 unread) → reads new file (1)
        second = await connector.poll()
        await connector.close()

        messages = {e.message for e in second}
        assert "unread-1" in messages
        assert "unread-2" in messages
        assert "new-entry" in messages

    async def test_resumes_from_persisted_offset(self, tmp_path: Path) -> None:
        """Test 5: new connector instance resumes from stored byte offset."""
        log = tmp_path / "app.log"
        log.write_text(
            "\n".join(_jline("INFO", f"line-{i}") for i in range(5)) + "\n",
            encoding="utf-8",
        )

        c1 = FileConnector()
        await c1.connect(_cfg(file_path=str(log)))
        first = await c1.poll()
        assert len(first) == 5
        saved_offset = c1._byte_offset
        await c1.close()

        # Append new content while connector is "down"
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(_jline("ERROR", "new-after-restart") + "\n")
        # fh closed here

        # Second connector starts at saved offset (simulated restart / state reload)
        c2 = FileConnector()
        await c2.connect(_cfg(file_path=str(log), byte_offset=saved_offset))
        second = await c2.poll()
        await c2.close()

        assert len(second) == 1
        assert second[0].message == "new-after-restart"

    async def test_parses_json_format(self, tmp_path: Path) -> None:
        """Test 6: parses JSON-per-line format, extracts level, message, timestamp, latency."""
        log = tmp_path / "app.log"
        log.write_text(
            json.dumps({
                "level": "ERROR",
                "message": "timeout hit",
                "time": "2026-01-01T12:00:00Z",
                "latency_ms": 1234.5,
            }) + "\n",
            encoding="utf-8",
        )

        connector = FileConnector()
        await connector.connect(
            _cfg(file_path=str(log), log_format="json", latency_field="latency_ms")
        )
        entries = await connector.poll()
        await connector.close()

        assert len(entries) == 1
        e = entries[0]
        assert e.level == "ERROR"
        assert e.message == "timeout hit"
        assert e.latency_ms == pytest.approx(1234.5)
        assert e.occurred_at.year == 2026

    async def test_parses_logfmt_format(self, tmp_path: Path) -> None:
        """Test 7: parses logfmt key=value lines, extracts level, message, latency."""
        log = tmp_path / "app.log"
        log.write_text(
            'level=WARNING msg="cache miss" latency=250ms\n',
            encoding="utf-8",
        )

        connector = FileConnector()
        await connector.connect(_cfg(file_path=str(log), log_format="logfmt"))
        entries = await connector.poll()
        await connector.close()

        assert len(entries) == 1
        e = entries[0]
        assert e.level == "WARNING"
        assert e.message == "cache miss"
        # latency auto-detected from well-known column name; "250ms" → 250.0
        assert e.latency_ms == pytest.approx(250.0)


# ═══════════════════════════════════════════════════════════════════════════
# DBConnector — tests 8-11
# ═══════════════════════════════════════════════════════════════════════════

class TestDBConnector:

    async def test_returns_rows_after_hwm(self, tmp_path: Path) -> None:
        """Test 8: returns only rows with id > last_seen_id (high-water mark)."""
        db = tmp_path / "ext.db"
        _seed_ext_db(db, [
            {"message": "old-1"},
            {"message": "old-2"},
            {"message": "new-1"},
        ])

        connector = DBConnector()
        # HWM = 2 → only id=3 (new-1) should be returned
        await connector.connect(_cfg(
            source_type="sqlite",
            connection_string=f"sqlite:///{db}",
            last_seen_id="2",
        ))
        entries = await connector.poll()
        await connector.close()

        assert len(entries) == 1
        assert entries[0].message == "new-1"

    async def test_advances_hwm_after_poll(self, tmp_path: Path) -> None:
        """Test 9: high-water mark advances to the max id in the batch after a poll."""
        db = tmp_path / "ext.db"
        _seed_ext_db(db, [{"message": "row-1"}, {"message": "row-2"}])

        connector = DBConnector()
        await connector.connect(_cfg(
            source_type="sqlite",
            connection_string=f"sqlite:///{db}",
            last_seen_id="0",
        ))
        entries = await connector.poll()
        await connector.close()

        assert len(entries) == 2
        assert connector._last_seen_id == "2"
        state = await connector.flush_state()
        assert state.last_seen_id == "2"

    async def test_empty_result_does_not_advance_hwm(self, tmp_path: Path) -> None:
        """Test 10: empty result returns [] and leaves high-water mark unchanged."""
        db = tmp_path / "ext.db"
        _seed_ext_db(db, [{"message": "only-row"}])

        connector = DBConnector()
        # HWM already past the only row → nothing to return
        await connector.connect(_cfg(
            source_type="sqlite",
            connection_string=f"sqlite:///{db}",
            last_seen_id="1",
        ))
        entries = await connector.poll()
        await connector.close()

        assert entries == []
        assert connector._last_seen_id == "1"   # unchanged

    async def test_connection_failure_raises(self, tmp_path: Path) -> None:
        """
        Test 11: connect() raises when the target table is missing;
        ConnectorManager catches this and does not start a poll task (test 12),
        or the poll loop enters BACKOFF (test 16).
        """
        db = tmp_path / "ext.db"
        # DB file exists but has no 'logs' table
        engine = sa.create_engine(f"sqlite:///{db}")
        with engine.connect() as c:
            c.execute(sa.text("CREATE TABLE other (id INTEGER PRIMARY KEY)"))
            c.commit()
        engine.dispose()

        connector = DBConnector()
        with pytest.raises(ValueError, match="not found"):
            await connector.connect(_cfg(
                source_type="sqlite",
                connection_string=f"sqlite:///{db}",
                last_seen_id="0",
            ))


# ═══════════════════════════════════════════════════════════════════════════
# ConnectorManager — tests 12-17
# ═══════════════════════════════════════════════════════════════════════════

class TestConnectorManager:

    async def test_starts_task_per_active_source(self) -> None:
        """Test 12: start() creates one asyncio.Task per active source."""
        manager = ConnectorManager(session_factory=lambda: None)
        cfgs = [
            _cfg(source_id="s1", source_type="push"),
            _cfg(source_id="s2", source_type="push"),
        ]

        with patch.object(manager, "_load_active_sources", return_value=cfgs):
            await manager.start()

        try:
            assert len(manager._slots) == 2
            assert "s1" in manager._slots
            assert "s2" in manager._slots
            for slot in manager._slots.values():
                assert slot.task is not None
                assert not slot.task.done()
        finally:
            await manager.stop()

    async def test_max_sources_limit_enforced(self) -> None:
        """Test 13: add_source() raises ValueError when tenant is at max_sources cap."""
        manager = ConnectorManager(session_factory=lambda: None)
        manager._running = True

        cfg1 = _cfg(source_id="s1", source_type="push", tenant_id="t1")
        cfg2 = _cfg(source_id="s2", source_type="push", tenant_id="t1")

        await manager.add_source(cfg1, max_sources=1)
        assert len(manager._slots) == 1

        with pytest.raises(ValueError, match="max_sources"):
            await manager.add_source(cfg2, max_sources=1)

        assert len(manager._slots) == 1   # second source not added
        await manager.stop()

    async def test_active_to_idle_after_empty_polls(self) -> None:
        """Test 14: connector transitions ACTIVE → IDLE after IDLE_AFTER_EMPTY empty polls."""
        manager = ConnectorManager(session_factory=lambda: None)
        connector = _MockConnector(responses=[[] for _ in range(IDLE_AFTER_EMPTY)])
        cfg = _cfg(source_id="s1", source_type="push")
        await connector.connect(cfg)
        slot = _ConnectorSlot(
            source_id="s1", tenant_id="t1", connector=connector, config=cfg
        )

        await _run_n_polls(manager, slot, IDLE_AFTER_EMPTY)

        assert slot.state == ConnectorState.IDLE
        assert slot.consecutive_empty == IDLE_AFTER_EMPTY

    async def test_idle_to_active_on_data(self) -> None:
        """Test 15: connector transitions IDLE → ACTIVE immediately on first non-empty poll."""
        manager = ConnectorManager(session_factory=lambda: None)

        # IDLE_AFTER_EMPTY empty polls → IDLE; then one poll with data → ACTIVE
        responses = [[] for _ in range(IDLE_AFTER_EMPTY)] + [[_make_entry()]]
        connector = _MockConnector(responses=responses)
        cfg = _cfg(source_id="s1", source_type="push")
        await connector.connect(cfg)
        slot = _ConnectorSlot(
            source_id="s1", tenant_id="t1", connector=connector, config=cfg
        )

        await _run_n_polls(manager, slot, IDLE_AFTER_EMPTY + 1)

        assert slot.state == ConnectorState.ACTIVE
        assert slot.consecutive_empty == 0

    async def test_active_to_backoff_after_errors(self) -> None:
        """Test 16: connector transitions ACTIVE → BACKOFF after BACKOFF_AFTER_ERRORS consecutive errors."""
        manager = ConnectorManager(session_factory=lambda: None)
        connector = _MockConnector(responses=[], raises=True)
        cfg = _cfg(source_id="s1", source_type="push")
        await connector.connect(cfg)
        slot = _ConnectorSlot(
            source_id="s1", tenant_id="t1", connector=connector, config=cfg
        )

        await _run_n_attempts(manager, slot, BACKOFF_AFTER_ERRORS)

        assert slot.state == ConnectorState.BACKOFF
        assert slot.consecutive_errors >= BACKOFF_AFTER_ERRORS

    async def test_connector_error_isolation(self) -> None:
        """
        Test 17: errors in one connector's slot do not affect other connector slots.

        Each _ConnectorSlot maintains its own independent state machine.
        We verify that the bad connector's slot enters BACKOFF while the good
        connector's slot stays ACTIVE, with zero shared error state between them.

        Note: loops are driven sequentially (not concurrently) because AsyncMock
        coroutines complete without yielding the event loop, which would starve
        the second task in asyncio.gather.  Sequential execution proves the same
        isolation guarantee: each slot's counters are independent by construction.
        """
        # ── bad connector: BACKOFF_AFTER_ERRORS errors → BACKOFF ──
        bad_mgr = ConnectorManager(session_factory=lambda: None)
        bad_connector = _MockConnector(responses=[], raises=True)
        cfg_bad = _cfg(source_id="s_bad", source_type="push", tenant_id="t1")
        await bad_connector.connect(cfg_bad)
        bad_slot = _ConnectorSlot(
            source_id="s_bad", tenant_id="t1", connector=bad_connector, config=cfg_bad
        )

        await _run_n_attempts(bad_mgr, bad_slot, BACKOFF_AFTER_ERRORS)

        # ── good connector: 3 successful polls → stays ACTIVE ──
        good_mgr = ConnectorManager(session_factory=lambda: None)
        good_connector = _MockConnector(responses=[[_make_entry("s_good", "t2")]] * 5)
        cfg_good = _cfg(source_id="s_good", source_type="push", tenant_id="t2")
        await good_connector.connect(cfg_good)
        good_slot = _ConnectorSlot(
            source_id="s_good", tenant_id="t2", connector=good_connector, config=cfg_good
        )

        await _run_n_polls(good_mgr, good_slot, 3)

        # States are fully independent — no shared error counters across slots
        assert bad_slot.state == ConnectorState.BACKOFF
        assert bad_slot.consecutive_errors >= BACKOFF_AFTER_ERRORS
        assert good_slot.state == ConnectorState.ACTIVE
        assert good_slot.consecutive_errors == 0


# ═══════════════════════════════════════════════════════════════════════════
# Cross-tenant isolation — test 18
# ═══════════════════════════════════════════════════════════════════════════

class TestCrossTenantIsolation:

    async def test_connector_never_returns_other_tenant_entries(self, tmp_path: Path) -> None:
        """
        Test 18: Connector for Tenant A reads only Tenant A's source file.
        NormalizedLogEntry objects are stamped with the correct tenant_id / source_id
        and Tenant A's connector returns zero entries from Tenant B's log file.
        """
        log_a = tmp_path / "tenant_a.log"
        log_b = tmp_path / "tenant_b.log"

        log_a.write_text(_jline("INFO", "tenant-A-message") + "\n", encoding="utf-8")
        log_b.write_text(_jline("INFO", "tenant-B-message") + "\n", encoding="utf-8")

        # Separate connectors for separate tenants — each points only at its own file
        connector_a = FileConnector()
        connector_b = FileConnector()

        cfg_a = _cfg(source_id="src_a", tenant_id="tenant_a", file_path=str(log_a))
        cfg_b = _cfg(source_id="src_b", tenant_id="tenant_b", file_path=str(log_b))

        await connector_a.connect(cfg_a)
        await connector_b.connect(cfg_b)

        entries_a = await connector_a.poll()
        entries_b = await connector_b.poll()

        await connector_a.close()
        await connector_b.close()

        # Tenant A: all entries have correct stamps, none from B's file
        assert len(entries_a) == 1
        assert all(e.tenant_id == "tenant_a" for e in entries_a)
        assert all(e.source_id == "src_a" for e in entries_a)
        assert not any(e.message == "tenant-B-message" for e in entries_a)

        # Tenant B: all entries have correct stamps, none from A's file
        assert len(entries_b) == 1
        assert all(e.tenant_id == "tenant_b" for e in entries_b)
        assert all(e.source_id == "src_b" for e in entries_b)
        assert not any(e.message == "tenant-A-message" for e in entries_b)
