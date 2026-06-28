"""
tests/test_anomaly_engine.py — Unit, integration, and security tests for Module 6.

Coverage targets: all 6 anomaly types, EWMA maths, cache/DB persistence,
cross-tenant isolation, auto-resolution, and the log_service wire-up.

Test design principles:
  - Each test creates its own AnomalyEngine with a fresh InProcessCache, so
    no EWMA state leaks between tests.
  - The conftest db_session fixture wraps each test in a rolled-back transaction,
    so anomaly_alerts and ewma_state rows are cleaned up automatically.
  - Pre-warmed states are injected via _prewarm() rather than running 10+ real
    ingest calls, keeping individual tests fast and deterministic.
  - All spike windows use error_rate = 1.0 (all entries ERROR), which is always
    well above the EWMA upper bound for any pre-warmed baseline.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest
from sqlalchemy import text

from connectors.base import NormalizedLogEntry
from models.db import AnomalyAlert, EwmaState
from services.anomaly_engine import (
    PERSIST_EVERY,
    AnomalyEngine,
    _EwmaState,
    _cache_key,
    _fingerprint,
    _normalize_message,
    _SILENCE_WINDOW_S,
    _SUSTAINED_WARNING_S,
    _SUSTAINED_CRITICAL_S,
    _CASCADE_MIN_SERVICES,
    _CASCADE_WINDOW_S,
    _FINGERPRINT_TTL_S,
)
from services.cache import InProcessCache

UTC = timezone.utc


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_engine() -> AnomalyEngine:
    return AnomalyEngine(cache=InProcessCache())


def _make_entry(
    source_id: str,
    tenant_id: str,
    *,
    level: str = "INFO",
    service_name: str = "svc",
    latency_ms: Optional[float] = None,
    occurred_at: Optional[datetime] = None,
    message: str = "log message",
) -> NormalizedLogEntry:
    return NormalizedLogEntry(
        occurred_at=occurred_at or datetime.now(UTC),
        level=level,
        message=message,
        source_id=source_id,
        tenant_id=tenant_id,
        service_name=service_name,
        environment="production",
        latency_ms=latency_ms,
        raw={},
    )


def _error_batch(
    source_id: str,
    tenant_id: str,
    service_name: str = "svc",
    n: int = 10,
    message: str = "database connection failed",
    occurred_at: Optional[datetime] = None,
) -> list[NormalizedLogEntry]:
    ts = occurred_at or datetime.now(UTC)
    return [
        _make_entry(source_id, tenant_id, level="ERROR",
                    service_name=service_name, message=message,
                    occurred_at=ts)
        for _ in range(n)
    ]


def _normal_batch(
    source_id: str,
    tenant_id: str,
    service_name: str = "svc",
    n: int = 10,
    occurred_at: Optional[datetime] = None,
) -> list[NormalizedLogEntry]:
    ts = occurred_at or datetime.now(UTC)
    return [_make_entry(source_id, tenant_id, level="INFO",
                        service_name=service_name, occurred_at=ts)
            for _ in range(n)]


def _prewarm(
    engine: AnomalyEngine,
    source_id: str,
    tenant_id: str,
    *,
    ewma_value: float = 0.02,
    ewma_variance: float = 1e-5,
    log_volume_ewma: float = 10.0,
    last_log_at: Optional[datetime] = None,
) -> _EwmaState:
    """
    Inject a pre-warmed state into the engine cache.
    Bypasses the 10-observation warmup so tests can focus on detector logic.
    Returns the live _EwmaState object stored in the cache.
    """
    state = _EwmaState(
        source_id=source_id,
        tenant_id=tenant_id,
        ewma_value=ewma_value,
        ewma_variance=ewma_variance,
        warmup_count=15,
        warmup_required=10,
        log_volume_ewma=log_volume_ewma,
        last_log_at=last_log_at,
    )
    engine._cache.set(_cache_key(tenant_id, source_id), state)
    return state


def _fresh_src() -> str:
    return f"src-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Warmup enforcement
# ---------------------------------------------------------------------------

class TestWarmup:
    def test_no_alerts_during_warmup(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        # Send 9 batches (one below warmup_required=10) all with 100% errors
        for _ in range(9):
            alerts = engine.ingest(_error_batch(src, tid, n=10), db_session)
            assert alerts == [], "alerts must not fire before warmup complete"

    def test_first_post_warmup_window_can_alert(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        # 10 warmup with 0% errors → stable zero baseline
        for _ in range(10):
            engine.ingest(_normal_batch(src, tid, n=10), db_session)
        # 11th window: 100% errors — should fire since warmup complete
        alerts = engine.ingest(_error_batch(src, tid, n=10), db_session)
        types = [a.anomaly_type for a in alerts]
        assert "ERROR_RATE_SPIKE" in types

    def test_ewma_updates_unconditionally_during_warmup(
        self, db_session, test_tenants
    ):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        # 5 observations of 100% error rate during warmup
        for _ in range(5):
            engine.ingest(_error_batch(src, tid, n=10), db_session)
        state: _EwmaState = engine._cache.get(_cache_key(tid, src))
        assert state is not None
        assert state.warmup_count == 5
        assert state.ewma_value > 0.0, "EWMA must update during warmup"


# ---------------------------------------------------------------------------
# Detector 1 — ERROR_RATE_SPIKE
# ---------------------------------------------------------------------------

class TestErrorRateSpike:
    def test_no_alert_below_threshold(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        _prewarm(engine, src, tid, ewma_value=0.5, ewma_variance=0.04)
        # Upper bound = 0.5 + 2.5 × sqrt(0.04) = 0.5 + 0.5 = 1.0
        # error_rate = 0.9 ≤ 1.0 → no alert
        entries = [
            _make_entry(src, tid, level="ERROR") if i < 9
            else _make_entry(src, tid, level="INFO")
            for i in range(10)
        ]
        alerts = engine.ingest(entries, db_session)
        assert not any(a.anomaly_type == "ERROR_RATE_SPIKE" for a in alerts)

    def test_warning_fires_above_warning_threshold(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        # Low baseline, tiny variance → very low upper bound
        _prewarm(engine, src, tid, ewma_value=0.02, ewma_variance=1e-5)
        # warn_bound ≈ 0.02 + 2.5 × sqrt(1e-5) ≈ 0.0279
        # error_rate = 1.0 >> 0.028 → WARNING
        alerts = engine.ingest(_error_batch(src, tid, n=10), db_session)
        spike = next((a for a in alerts if a.anomaly_type == "ERROR_RATE_SPIKE"), None)
        assert spike is not None
        assert spike.severity in ("WARNING", "CRITICAL")
        assert spike.tenant_id == tid

    def test_critical_fires_above_critical_threshold(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        # With zero variance, upper_bound = ewma_value, so 1.0 >> ewma for both thresholds
        _prewarm(engine, src, tid, ewma_value=0.0, ewma_variance=0.0)
        alerts = engine.ingest(_error_batch(src, tid, n=10), db_session)
        spike = next((a for a in alerts if a.anomaly_type == "ERROR_RATE_SPIKE"), None)
        assert spike is not None
        assert spike.severity == "CRITICAL"

    def test_auto_resolve_after_two_clean_windows(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        _prewarm(engine, src, tid, ewma_value=0.02, ewma_variance=1e-5)
        # Fire an alert
        alerts = engine.ingest(_error_batch(src, tid, n=10), db_session)
        assert any(a.anomaly_type == "ERROR_RATE_SPIKE" for a in alerts)

        # Two consecutive clean windows → auto-resolve
        engine.ingest(_normal_batch(src, tid, n=10), db_session)
        engine.ingest(_normal_batch(src, tid, n=10), db_session)

        open_count = (
            db_session.query(AnomalyAlert)
            .filter(
                AnomalyAlert.tenant_id == tid,
                AnomalyAlert.source_id == src,
                AnomalyAlert.anomaly_type == "ERROR_RATE_SPIKE",
                AnomalyAlert.status == "open",
            )
            .count()
        )
        assert open_count == 0, "alert should be auto-resolved after 2 clean windows"

    def test_alert_payload_shape(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        _prewarm(engine, src, tid, ewma_value=0.02, ewma_variance=1e-5)
        alerts = engine.ingest(_error_batch(src, tid, n=10), db_session)
        spike = next((a for a in alerts if a.anomaly_type == "ERROR_RATE_SPIKE"), None)
        assert spike is not None
        payload = json.loads(spike.full_payload)
        assert payload["schema_version"] == "1.0"
        assert payload["anomaly_type"] == "ERROR_RATE_SPIKE"
        assert "evidence" in payload
        assert "detection_context" in payload
        assert payload["evidence"]["unit"] == "error_fraction"

    @pytest.mark.parametrize("n_errors,n_total", [(0, 10), (1, 10), (2, 10)])
    def test_no_spike_at_low_error_rates(
        self, n_errors, n_total, db_session, test_tenants
    ):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        # Warmup at same low rate → EWMA converges to that rate
        rate = n_errors / n_total
        for _ in range(12):
            entries = [
                _make_entry(src, tid, level="ERROR") if i < n_errors
                else _make_entry(src, tid, level="INFO")
                for i in range(n_total)
            ]
            engine.ingest(entries, db_session)
        # After convergence at the true rate, same rate should not spike
        entries = [
            _make_entry(src, tid, level="ERROR") if i < n_errors
            else _make_entry(src, tid, level="INFO")
            for i in range(n_total)
        ]
        alerts = engine.ingest(entries, db_session)
        spike_alerts = [a for a in alerts if a.anomaly_type == "ERROR_RATE_SPIKE"]
        assert len(spike_alerts) == 0, f"stable rate={rate} should not spike at convergence"


# ---------------------------------------------------------------------------
# Detector 2 — SUSTAINED_ELEVATION
# ---------------------------------------------------------------------------

class TestSustainedElevation:
    def _setup_above_baseline(
        self,
        engine: AnomalyEngine,
        src: str,
        tid: str,
        db,
        seconds_above: int,
    ):
        """Pre-warms, sets above_baseline_since to simulate time above baseline."""
        state = _prewarm(engine, src, tid, ewma_value=0.05, ewma_variance=1e-5)
        # First observation above baseline sets above_baseline_since
        above_entries = [
            _make_entry(src, tid, level="ERROR") if i < 5
            else _make_entry(src, tid, level="INFO")
            for i in range(10)
        ]  # 50% errors > 5% baseline
        engine.ingest(above_entries, db)
        # Backdate the above_baseline_since to simulate sustained duration
        state = engine._cache.get(_cache_key(tid, src))
        if state.above_baseline_since is not None:
            state.above_baseline_since = datetime.now(UTC) - timedelta(seconds=seconds_above)

    def test_warning_fires_after_ten_minutes(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        self._setup_above_baseline(engine, src, tid, db_session, seconds_above=_SUSTAINED_WARNING_S + 1)
        # Next observation still above baseline → should fire WARNING
        above = [
            _make_entry(src, tid, level="ERROR") if i < 5
            else _make_entry(src, tid, level="INFO")
            for i in range(10)
        ]
        alerts = engine.ingest(above, db_session)
        sustained = [a for a in alerts if a.anomaly_type == "SUSTAINED_ELEVATION"]
        assert len(sustained) == 1
        assert sustained[0].severity == "WARNING"

    def test_critical_escalates_after_fifteen_minutes(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        # Set to >10 min, fire WARNING first
        self._setup_above_baseline(engine, src, tid, db_session, seconds_above=_SUSTAINED_WARNING_S + 1)
        above = [
            _make_entry(src, tid, level="ERROR") if i < 5
            else _make_entry(src, tid, level="INFO")
            for i in range(10)
        ]
        engine.ingest(above, db_session)

        # Now push to >15 min
        state = engine._cache.get(_cache_key(tid, src))
        if state.above_baseline_since is not None:
            state.above_baseline_since = datetime.now(UTC) - timedelta(seconds=_SUSTAINED_CRITICAL_S + 1)

        alerts = engine.ingest(above, db_session)
        critical = [
            a for a in alerts
            if a.anomaly_type == "SUSTAINED_ELEVATION" and a.severity == "CRITICAL"
        ]
        assert len(critical) == 1

    def test_resolves_when_rate_returns_to_baseline(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        self._setup_above_baseline(engine, src, tid, db_session, seconds_above=_SUSTAINED_WARNING_S + 1)
        above = [
            _make_entry(src, tid, level="ERROR") if i < 5
            else _make_entry(src, tid, level="INFO")
            for i in range(10)
        ]
        engine.ingest(above, db_session)  # fire WARNING
        # Return to baseline
        engine.ingest(_normal_batch(src, tid, n=10), db_session)
        state = engine._cache.get(_cache_key(tid, src))
        assert state.above_baseline_since is None
        assert state.sustained_severity_fired is None

    def test_no_alert_before_ten_minutes(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        self._setup_above_baseline(engine, src, tid, db_session, seconds_above=60)
        above = [
            _make_entry(src, tid, level="ERROR") if i < 5
            else _make_entry(src, tid, level="INFO")
            for i in range(10)
        ]
        alerts = engine.ingest(above, db_session)
        sustained = [a for a in alerts if a.anomaly_type == "SUSTAINED_ELEVATION"]
        assert len(sustained) == 0


# ---------------------------------------------------------------------------
# Detector 3 — SERVICE_SILENCE
# ---------------------------------------------------------------------------

class TestServiceSilence:
    def test_no_alert_for_new_source(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        # No pre-warms: no last_log_at, no volume baseline
        alerts = engine.ingest(_normal_batch(src, tid, n=5), db_session)
        assert not any(a.anomaly_type == "SERVICE_SILENCE" for a in alerts)

    def test_no_alert_without_volume_baseline(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        past = datetime.now(UTC) - timedelta(seconds=_SILENCE_WINDOW_S + 60)
        state = _prewarm(engine, src, tid, log_volume_ewma=0.0, last_log_at=past)
        alerts = engine.ingest(_normal_batch(src, tid), db_session)
        assert not any(a.anomaly_type == "SERVICE_SILENCE" for a in alerts)

    def test_fires_after_gap_exceeds_threshold(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        # Establish volume baseline + set last_log_at 3 min ago
        past = datetime.now(UTC) - timedelta(seconds=_SILENCE_WINDOW_S + 60)
        _prewarm(engine, src, tid, log_volume_ewma=10.0, last_log_at=past)
        # Current batch arrives NOW — gap = 3 min > 2 min threshold
        alerts = engine.ingest(_normal_batch(src, tid, n=5), db_session)
        silence = [a for a in alerts if a.anomaly_type == "SERVICE_SILENCE"]
        assert len(silence) == 1
        assert silence[0].severity == "CRITICAL"

    def test_auto_resolves_when_logs_resume(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        past = datetime.now(UTC) - timedelta(seconds=_SILENCE_WINDOW_S + 60)
        _prewarm(engine, src, tid, log_volume_ewma=10.0, last_log_at=past)
        alerts = engine.ingest(_normal_batch(src, tid, n=5), db_session)
        silence = next(a for a in alerts if a.anomaly_type == "SERVICE_SILENCE")
        # Should be immediately auto-resolved (logs resumed)
        assert silence.status == "resolved"
        assert silence.auto_resolved is True

    def test_no_refire_within_same_gap(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        past = datetime.now(UTC) - timedelta(seconds=_SILENCE_WINDOW_S + 60)
        _prewarm(engine, src, tid, log_volume_ewma=10.0, last_log_at=past)
        alerts1 = engine.ingest(_normal_batch(src, tid, n=5), db_session)
        # Update last_log_at to simulate logs received; but set silence_alerted=True via state
        # (silence auto-resolves on first batch; subsequent batches should not re-fire)
        alerts2 = engine.ingest(_normal_batch(src, tid, n=5), db_session)
        assert not any(a.anomaly_type == "SERVICE_SILENCE" for a in alerts2)

    def test_no_alert_for_short_gap(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        past = datetime.now(UTC) - timedelta(seconds=_SILENCE_WINDOW_S - 30)
        _prewarm(engine, src, tid, log_volume_ewma=10.0, last_log_at=past)
        alerts = engine.ingest(_normal_batch(src, tid, n=5), db_session)
        assert not any(a.anomaly_type == "SERVICE_SILENCE" for a in alerts)


# ---------------------------------------------------------------------------
# Detector 4 — LATENCY_SPIKE
# ---------------------------------------------------------------------------

class TestLatencySpike:
    def _prewarm_latency(
        self,
        engine: AnomalyEngine,
        src: str,
        tid: str,
        latency_ewma: float = 50.0,
        latency_variance: float = 1.0,
    ) -> _EwmaState:
        state = _prewarm(engine, src, tid)
        state.latency_ewma = latency_ewma
        state.latency_variance = latency_variance
        state.latency_warmup = 15
        return state

    def test_no_alert_during_latency_warmup(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        # Pre-warms error-rate EWMA but latency_warmup stays 0
        _prewarm(engine, src, tid)
        entries = [_make_entry(src, tid, latency_ms=999.0) for _ in range(10)]
        alerts = engine.ingest(entries, db_session)
        assert not any(a.anomaly_type == "LATENCY_SPIKE" for a in alerts)

    def test_warning_fires_on_latency_spike(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        # baseline: 50ms, variance: 1ms² → warn_bound = 50 + 2.5×1 = 52.5ms
        self._prewarm_latency(engine, src, tid, latency_ewma=50.0, latency_variance=1.0)
        # Send 10 entries with latency_ms = 200ms >> 52.5ms
        entries = [_make_entry(src, tid, latency_ms=200.0) for _ in range(10)]
        alerts = engine.ingest(entries, db_session)
        lat_spike = next((a for a in alerts if a.anomaly_type == "LATENCY_SPIKE"), None)
        assert lat_spike is not None
        assert lat_spike.severity in ("WARNING", "CRITICAL")
        assert lat_spike.unit == "ms"

    def test_critical_fires_above_critical_threshold(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        # baseline: 50ms, variance: 1ms² → crit_bound = 50 + 5×1 = 55ms
        self._prewarm_latency(engine, src, tid, latency_ewma=50.0, latency_variance=1.0)
        entries = [_make_entry(src, tid, latency_ms=500.0) for _ in range(10)]
        alerts = engine.ingest(entries, db_session)
        lat_spike = next((a for a in alerts if a.anomaly_type == "LATENCY_SPIKE"), None)
        assert lat_spike is not None
        assert lat_spike.severity == "CRITICAL"

    def test_no_alert_without_latency_data(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        self._prewarm_latency(engine, src, tid, latency_ewma=50.0, latency_variance=1.0)
        # Entries without latency_ms → no latency check runs
        entries = [_make_entry(src, tid, latency_ms=None) for _ in range(10)]
        alerts = engine.ingest(entries, db_session)
        assert not any(a.anomaly_type == "LATENCY_SPIKE" for a in alerts)

    def test_latency_auto_resolve_after_two_clean_windows(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        self._prewarm_latency(engine, src, tid, latency_ewma=50.0, latency_variance=1.0)
        entries = [_make_entry(src, tid, latency_ms=200.0) for _ in range(10)]
        alerts = engine.ingest(entries, db_session)
        assert any(a.anomaly_type == "LATENCY_SPIKE" for a in alerts)
        # Two clean latency windows
        clean = [_make_entry(src, tid, latency_ms=50.0) for _ in range(10)]
        engine.ingest(clean, db_session)
        engine.ingest(clean, db_session)
        open_count = (
            db_session.query(AnomalyAlert)
            .filter(
                AnomalyAlert.tenant_id == tid,
                AnomalyAlert.source_id == src,
                AnomalyAlert.anomaly_type == "LATENCY_SPIKE",
                AnomalyAlert.status == "open",
            )
            .count()
        )
        assert open_count == 0


# ---------------------------------------------------------------------------
# Detector 5 — NOVEL_ERROR
# ---------------------------------------------------------------------------

class TestNovelError:
    def test_new_pattern_fires_warning(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        _prewarm(engine, src, tid)
        entries = [_make_entry(src, tid, level="ERROR",
                               message="deadlock detected on table orders")]
        alerts = engine.ingest(entries, db_session)
        novel = [a for a in alerts if a.anomaly_type == "NOVEL_ERROR"]
        assert len(novel) == 1
        assert novel[0].severity == "WARNING"

    def test_known_pattern_no_alert(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        _prewarm(engine, src, tid)
        entries = [_make_entry(src, tid, level="ERROR",
                               message="timeout connecting to redis")]
        # First time: novel
        engine.ingest(entries, db_session)
        # Second time: known
        alerts = engine.ingest(entries, db_session)
        novel = [a for a in alerts if a.anomaly_type == "NOVEL_ERROR"]
        assert len(novel) == 0

    def test_numeric_normalization_deduplicates(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        _prewarm(engine, src, tid)
        # First occurrence: port 5432
        e1 = [_make_entry(src, tid, level="ERROR",
                           message="Connection refused port 5432")]
        engine.ingest(e1, db_session)
        # Second occurrence: port 9999 — same NORMALIZED fingerprint
        e2 = [_make_entry(src, tid, level="ERROR",
                           message="Connection refused port 9999")]
        alerts = engine.ingest(e2, db_session)
        novel = [a for a in alerts if a.anomaly_type == "NOVEL_ERROR"]
        assert len(novel) == 0, "port numbers differ but normalised pattern is same"

    def test_different_patterns_both_fire(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        _prewarm(engine, src, tid)
        entries = [
            _make_entry(src, tid, level="ERROR",
                        message="connection refused"),
            _make_entry(src, tid, level="ERROR",
                        message="disk full on device"),
        ]
        alerts = engine.ingest(entries, db_session)
        novel = [a for a in alerts if a.anomaly_type == "NOVEL_ERROR"]
        assert len(novel) == 2

    def test_expired_fingerprint_is_novel_again(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        state = _prewarm(engine, src, tid)
        # Inject a fingerprint that's 25 hours old (past 24h TTL)
        fp = _fingerprint("memory allocation failed")
        expired_time = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
        state.error_fingerprints = [{"fp": fp, "seen_at": expired_time}]

        entries = [_make_entry(src, tid, level="ERROR",
                               message="memory allocation failed")]
        alerts = engine.ingest(entries, db_session)
        novel = [a for a in alerts if a.anomaly_type == "NOVEL_ERROR"]
        assert len(novel) == 1, "expired fingerprint should be treated as novel"

    def test_non_error_levels_not_fingerprinted(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        _prewarm(engine, src, tid)
        entries = [
            _make_entry(src, tid, level="INFO",  message="query took too long"),
            _make_entry(src, tid, level="DEBUG", message="slow read detected"),
            _make_entry(src, tid, level="WARNING", message="memory pressure high"),
        ]
        alerts = engine.ingest(entries, db_session)
        novel = [a for a in alerts if a.anomaly_type == "NOVEL_ERROR"]
        assert len(novel) == 0, "only ERROR and CRITICAL levels fingerprinted"


# ---------------------------------------------------------------------------
# Detector 6 — CASCADE
# ---------------------------------------------------------------------------

class TestCascade:
    def test_cascade_fires_at_three_services(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        services = [(_fresh_src(), f"svc-{i}") for i in range(3)]

        for src, svc in services:
            _prewarm(engine, src, tid)

        # Service 1 spike: 1 service, no cascade
        a1 = engine.ingest(_error_batch(services[0][0], tid, services[0][1]), db_session)
        assert not any(a.anomaly_type == "CASCADE" for a in a1)
        # Service 2 spike: 2 services, no cascade
        a2 = engine.ingest(_error_batch(services[1][0], tid, services[1][1]), db_session)
        assert not any(a.anomaly_type == "CASCADE" for a in a2)
        # Service 3 spike: 3 services → CASCADE
        a3 = engine.ingest(_error_batch(services[2][0], tid, services[2][1]), db_session)
        cascade = [a for a in a3 if a.anomaly_type == "CASCADE"]
        assert len(cascade) == 1
        assert cascade[0].severity == "CRITICAL"
        assert cascade[0].tenant_id == tid

    def test_cascade_below_threshold_no_fire(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        services = [(_fresh_src(), f"svc-under-{i}") for i in range(2)]
        for src, svc in services:
            _prewarm(engine, src, tid)
        for src, svc in services:
            alerts = engine.ingest(_error_batch(src, tid, svc), db_session)
            assert not any(a.anomaly_type == "CASCADE" for a in alerts)

    def test_cascade_payload_includes_contributing_ids(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        services = [(_fresh_src(), f"svc-ctx-{i}") for i in range(3)]
        for src, svc in services:
            _prewarm(engine, src, tid)
        for src, svc in services:
            alerts = engine.ingest(_error_batch(src, tid, svc), db_session)
        cascade = next(
            (a for a in alerts if a.anomaly_type == "CASCADE"), None
        )
        assert cascade is not None
        ctx = json.loads(cascade.cascade_context)
        assert ctx["service_count"] == 3
        assert len(ctx["contributing_services"]) == 3
        for item in ctx["contributing_services"]:
            assert "service_name" in item
            assert "alert_id" in item
            assert item["alert_id"]  # non-empty UUID

    def test_cascade_dedup_no_refire_in_window(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        # Build up 3-service cascade
        services = [(_fresh_src(), f"svc-dedup-{i}") for i in range(3)]
        for src, svc in services:
            _prewarm(engine, src, tid)
        for src, svc in services:
            engine.ingest(_error_batch(src, tid, svc), db_session)
        # 4th service spike — should NOT fire another CASCADE (within same window)
        src4, svc4 = _fresh_src(), "svc-dedup-4"
        _prewarm(engine, src4, tid)
        alerts = engine.ingest(_error_batch(src4, tid, svc4), db_session)
        cascade = [a for a in alerts if a.anomaly_type == "CASCADE"]
        assert len(cascade) == 0, "CASCADE should not re-fire within 5-min window"

    def test_cascade_window_respects_five_minutes(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        # Manually insert old anomaly_alerts (>5 min ago) for 2 services
        old_time = datetime.now(UTC) - timedelta(seconds=_CASCADE_WINDOW_S + 60)
        for svc in ["old-svc-1", "old-svc-2"]:
            old_alert = AnomalyAlert(
                id=str(uuid.uuid4()),
                tenant_id=tid,
                source_id=_fresh_src(),
                detected_at=old_time,
                anomaly_type="ERROR_RATE_SPIKE",
                severity="WARNING",
                service_name=svc,
                environment="production",
                current_value=0.9,
                baseline_value=0.02,
                upper_bound=0.03,
                unit="error_fraction",
                window_start=old_time,
                window_end=old_time,
                sample_count=10,
                representative_msgs="[]",
                detection_context="{}",
                full_payload="{}",
                status="open",
            )
            db_session.add(old_alert)
        db_session.flush()

        # Only one new spike fires now — old alerts are outside the window
        src = _fresh_src()
        _prewarm(engine, src, tid)
        alerts = engine.ingest(_error_batch(src, tid, "new-svc"), db_session)
        cascade = [a for a in alerts if a.anomaly_type == "CASCADE"]
        assert len(cascade) == 0, "alerts older than 5 min must not count toward cascade"


# ---------------------------------------------------------------------------
# Security — cross-tenant isolation
# ---------------------------------------------------------------------------

class TestCrossTenantIsolation:
    def test_cascade_does_not_cross_tenants(self, db_session, test_tenants):
        """
        Tenant A spikes on 3 services. Tenant B spikes on 2 services.
        Tenant B must NOT cascade even though tenant A already has 3 open spikes.
        """
        engine = _make_engine()
        tid_a = test_tenants["tenant_a"]
        tid_b = test_tenants["tenant_b"]

        # Spike 3 services for tenant A
        for i in range(3):
            src = _fresh_src()
            _prewarm(engine, src, tid_a)
            engine.ingest(_error_batch(src, tid_a, f"shared-svc-{i}"), db_session)

        # Spike 2 services for tenant B — must NOT cascade (only 2 B-services)
        for i in range(2):
            src = _fresh_src()
            _prewarm(engine, src, tid_b)
            alerts = engine.ingest(_error_batch(src, tid_b, f"b-svc-{i}"), db_session)
            cascade = [a for a in alerts if a.anomaly_type == "CASCADE"]
            assert len(cascade) == 0, (
                f"tenant B cascade fired after spike {i+1} — "
                "tenant A spikes must not be visible to tenant B"
            )

    def test_alert_tenant_id_always_matches_source_tenant(
        self, db_session, test_tenants
    ):
        engine = _make_engine()
        tid = test_tenants["tenant_b"]
        src = _fresh_src()
        _prewarm(engine, src, tid, ewma_value=0.0, ewma_variance=0.0)
        alerts = engine.ingest(_error_batch(src, tid, n=10), db_session)
        for alert in alerts:
            assert alert.tenant_id == tid, (
                f"alert.tenant_id={alert.tenant_id!r} != source tenant {tid!r}"
            )

    def test_ewma_state_never_shared_between_tenants(
        self, db_session, test_tenants
    ):
        engine = _make_engine()
        tid_a = test_tenants["tenant_a"]
        tid_b = test_tenants["tenant_b"]
        src = "shared-source-name"  # same source_id, different tenants
        _prewarm(engine, src, tid_a, ewma_value=0.8)
        _prewarm(engine, src, tid_b, ewma_value=0.0)
        # Verify cache stores them separately
        state_a: _EwmaState = engine._cache.get(_cache_key(tid_a, src))
        state_b: _EwmaState = engine._cache.get(_cache_key(tid_b, src))
        assert state_a is not state_b
        assert state_a.ewma_value != state_b.ewma_value
        assert state_a.tenant_id == tid_a
        assert state_b.tenant_id == tid_b


# ---------------------------------------------------------------------------
# EWMA state persistence
# ---------------------------------------------------------------------------

class TestEwmaStatePersistence:
    def test_state_persisted_after_persist_every_events(
        self, db_session, test_tenants
    ):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        # Run exactly PERSIST_EVERY ingest calls
        for _ in range(PERSIST_EVERY):
            engine.ingest(_normal_batch(src, tid, n=5), db_session)
        row = (
            db_session.query(EwmaState)
            .filter(EwmaState.tenant_id == tid, EwmaState.source_id == src)
            .first()
        )
        assert row is not None
        assert row.tenant_id == tid
        assert row.warmup_count >= PERSIST_EVERY

    def test_state_loads_from_db_on_cold_start(self, db_session, test_tenants):
        engine_a = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        # Persist state via engine A
        for _ in range(PERSIST_EVERY):
            engine_a.ingest(_normal_batch(src, tid, n=5), db_session)
        warmed_count = engine_a._cache.get(_cache_key(tid, src)).warmup_count

        # Cold-start engine B (empty cache, same session)
        engine_b = _make_engine()
        engine_b.ingest(_normal_batch(src, tid, n=5), db_session)
        state_b = engine_b._cache.get(_cache_key(tid, src))
        assert state_b is not None
        assert state_b.warmup_count == warmed_count + 1, (
            "cold-start engine should have loaded warmup_count from DB and incremented it"
        )

    def test_state_not_persisted_before_threshold(self, db_session, test_tenants):
        engine = _make_engine()
        tid = test_tenants["tenant_a"]
        src = _fresh_src()
        for _ in range(PERSIST_EVERY - 1):
            engine.ingest(_normal_batch(src, tid, n=5), db_session)
        row = (
            db_session.query(EwmaState)
            .filter(EwmaState.tenant_id == tid, EwmaState.source_id == src)
            .first()
        )
        assert row is None, "state must not be persisted before PERSIST_EVERY events"

    def test_cache_key_format(self, test_tenants):
        tid = test_tenants["tenant_a"]
        src = "test-source"
        key = _cache_key(tid, src)
        assert key == f"ewma:{tid}:{src}"
        # tenant_id must appear before source_id in the key
        assert key.startswith(f"ewma:{tid}:")


# ---------------------------------------------------------------------------
# Fingerprint helpers
# ---------------------------------------------------------------------------

class TestFingerprintHelpers:
    @pytest.mark.parametrize("msg,expected", [
        ("timeout after 5s", "timeout after Ns"),
        ("connection refused port 5432", "connection refused port N"),
        ("error code 404", "error code N"),
        ("no numbers here", "no numbers here"),
    ])
    def test_normalize_message(self, msg, expected):
        assert _normalize_message(msg) == expected

    def test_fingerprint_is_16_hex_chars(self):
        fp = _fingerprint("some error message")
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)

    def test_fingerprint_deterministic(self):
        msg = "disk write failure on /dev/sda1"
        assert _fingerprint(msg) == _fingerprint(msg)

    def test_fingerprint_different_for_different_patterns(self):
        assert _fingerprint("connection reset by peer") != _fingerprint("null pointer dereference")


# ---------------------------------------------------------------------------
# LogService wire-up
# ---------------------------------------------------------------------------

class TestLogServiceIntegration:
    def test_log_service_stub_mode_no_error(self, test_tenants):
        """LogService without wired engine should silently no-op."""
        from services.log_service import LogService
        from models.schemas.v1.ingest import LogEntryRequest

        svc = LogService()  # engine not set
        from security import TenantContext
        ctx = TenantContext(
            tenant_id=test_tenants["tenant_a"],
            user_id="u1",
            role="tenant_operator",
            scopes=["ingest"],
            api_key_id="key1",
        )
        req = LogEntryRequest(message="test", level="INFO")
        result = svc.process_entries([req], ctx, db=None)
        assert len(result) == 1

    def test_log_service_routes_to_engine(self, db_session, test_tenants):
        from services.log_service import LogService
        from models.schemas.v1.ingest import LogEntryRequest
        from security import TenantContext

        tid = test_tenants["tenant_a"]
        cache = InProcessCache()
        engine = AnomalyEngine(cache=cache)
        src = _fresh_src()
        _prewarm_fn = lambda: _prewarm(engine, "push", tid,
                                        ewma_value=0.0, ewma_variance=0.0)
        _prewarm_fn()

        svc = LogService()
        svc.set_engine(engine)
        ctx = TenantContext(
            tenant_id=tid,
            user_id="u1",
            role="tenant_operator",
            scopes=["ingest"],
            api_key_id="push",
        )
        reqs = [LogEntryRequest(message="error", level="ERROR") for _ in range(10)]
        svc.process_entries(reqs, ctx, db=db_session)
        # Engine should have ingested and potentially raised an alert
        state = engine._cache.get(_cache_key(tid, "push"))
        assert state is not None
        assert state.warmup_count > 0
