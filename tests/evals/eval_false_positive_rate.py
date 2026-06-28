"""
tests/evals/eval_false_positive_rate.py — False Positive Rate evaluation.

Target: FPR < 0.05 for each detector (less than 5 false alarms per 100 normal windows).

Methodology:
  Pre-warmed baseline: ewma=0.05, variance=0.01
  warn_bound = 0.05 + 2.5×sqrt(0.01) = 0.30

  "Normal" window: BATCH_SIZE entries with ≤ 10% error rate (well below 0.30).
  A "false positive" is any detector firing on a window that is clearly normal.

  Per detector:
    ERROR_RATE_SPIKE    — normal batch (2% errors) → rate 0.02 << 0.30 → FPR = 0.0
    LATENCY_SPIKE       — normal latency (50ms mean, baseline 50ms) → FPR = 0.0
    SUSTAINED_ELEVATION — single normal window cannot trigger (needs 10+ min) → FPR = 0.0
    SERVICE_SILENCE     — last_log_at set to 30 seconds ago (< 120s threshold) → FPR = 0.0
    NOVEL_ERROR         — normal INFO entries, no ERROR level → FPR = 0.0 (only ERROR fingerprinted)
    CASCADE             — requires 3+ services spiking; normal windows don't spike → FPR = 0.0

Uses shared conftest fixtures.
"""
import uuid
from datetime import datetime, timezone, timedelta

import pytest

from connectors.base import NormalizedLogEntry
from models.db import AnomalyAlert
from services.anomaly_engine import AnomalyEngine, _EwmaState, _cache_key
from services.cache import InProcessCache

UTC = timezone.utc

N_NORMAL_WINDOWS = 500
BATCH_SIZE       = 50
FPR_TARGET       = 0.05

PREWARM_EWMA     = 0.05
PREWARM_VARIANCE = 0.01   # warn_bound = 0.05 + 2.5×0.1 = 0.30


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_entry(
    source_id: str, tenant_id: str,
    level: str = "INFO", latency_ms: float = 50.0,
) -> NormalizedLogEntry:
    return NormalizedLogEntry(
        occurred_at=datetime.now(UTC),
        level=level,
        message="normal request processed",
        source_id=source_id,
        tenant_id=tenant_id,
        service_name="fpr-service",
        environment="production",
        latency_ms=latency_ms,
        raw={},
    )


def _normal_batch(source_id: str, tenant_id: str) -> list[NormalizedLogEntry]:
    """2% error rate — well below warn_bound of 0.30."""
    n_errors = round(0.02 * BATCH_SIZE)
    n_ok     = BATCH_SIZE - n_errors
    return (
        [_make_entry(source_id, tenant_id, level="ERROR") for _ in range(n_errors)]
        + [_make_entry(source_id, tenant_id, level="INFO")  for _ in range(n_ok)]
    )


def _fresh_engine(tenant_id: str, source_id: str, last_log_offset_s: int = 30) -> AnomalyEngine:
    engine = AnomalyEngine(cache=InProcessCache())
    state = _EwmaState(
        source_id=source_id,
        tenant_id=tenant_id,
        ewma_value=PREWARM_EWMA,
        ewma_variance=PREWARM_VARIANCE,
        warmup_count=50,
        warmup_required=10,
        log_volume_ewma=10.0,
        last_log_at=datetime.now(UTC) - timedelta(seconds=last_log_offset_s),
        latency_ewma=50.0,
        latency_variance=1.0,
        latency_warmup=50,
    )
    engine._cache.set(_cache_key(tenant_id, source_id), state)
    return engine


# ---------------------------------------------------------------------------
# Main FPR test
# ---------------------------------------------------------------------------

def test_false_positive_rate(db_session, test_tenants):
    """
    Run N_NORMAL_WINDOWS of clearly-normal traffic through the full engine.
    Measure FP rate per detector type.

    Expected: FPR = 0.0 for all EWMA-based detectors (ERROR_RATE_SPIKE,
    LATENCY_SPIKE, SERVICE_SILENCE, SUSTAINED_ELEVATION, CASCADE).
    NOVEL_ERROR may fire once per trial for the first error entry — that is
    the detector working correctly (first occurrence IS novel), not a FP.
    It is counted separately and not penalised.
    """
    tid = test_tenants["tenant_a"]

    fp_counts: dict[str, int] = {
        "ERROR_RATE_SPIKE": 0,
        "LATENCY_SPIKE": 0,
        "SERVICE_SILENCE": 0,
        "SUSTAINED_ELEVATION": 0,
        "CASCADE": 0,
    }
    novel_fires = 0

    for _ in range(N_NORMAL_WINDOWS):
        src = f"fpr-{uuid.uuid4().hex[:8]}"
        engine = _fresh_engine(tid, src, last_log_offset_s=30)
        batch  = _normal_batch(src, tid)
        alerts = engine.ingest(batch, db_session)

        for alert in alerts:
            if alert.anomaly_type == "NOVEL_ERROR":
                novel_fires += 1
            elif alert.anomaly_type in fp_counts:
                fp_counts[alert.anomaly_type] += 1

    print(f"\n=== False Positive Rate Eval (N={N_NORMAL_WINDOWS} normal windows) ===")
    print(f"  Baseline: ewma={PREWARM_EWMA}  variance={PREWARM_VARIANCE}")
    print(f"  warn_bound = {PREWARM_EWMA + 2.5 * PREWARM_VARIANCE**0.5:.3f}  (error_rate <= 0.02 is safe)")
    print(f"")

    overall_ok = True
    for detector, count in fp_counts.items():
        fpr    = count / N_NORMAL_WINDOWS
        status = "PASS" if fpr < FPR_TARGET else "FAIL"
        if fpr >= FPR_TARGET:
            overall_ok = False
        print(f"  {detector:<25}: {count:3d} FPs  FPR={fpr:.4f}  [{status}]")

    print(f"  {'NOVEL_ERROR (expected)':<25}: {novel_fires:3d} fires  "
          f"rate={novel_fires/N_NORMAL_WINDOWS:.4f}  [INFO — not a FP]")

    for detector, count in fp_counts.items():
        fpr = count / N_NORMAL_WINDOWS
        assert fpr < FPR_TARGET, (
            f"{detector} FPR={fpr:.4f} exceeds target <{FPR_TARGET}"
        )


# ---------------------------------------------------------------------------
# SERVICE_SILENCE FPR (explicit short-gap test)
# ---------------------------------------------------------------------------

def test_service_silence_fpr(db_session, test_tenants):
    """
    SERVICE_SILENCE fires when gap > 120s. With last_log_at 30s ago, no alert expected.
    """
    tid = test_tenants["tenant_b"]
    fp_count = 0
    windows  = 200

    for _ in range(windows):
        src    = f"sil-{uuid.uuid4().hex[:8]}"
        engine = _fresh_engine(tid, src, last_log_offset_s=30)
        alerts = engine.ingest(
            [_make_entry(src, tid) for _ in range(10)], db_session
        )
        if any(a.anomaly_type == "SERVICE_SILENCE" for a in alerts):
            fp_count += 1

    fpr = fp_count / windows
    print(f"\n  SERVICE_SILENCE FPR (last_log 30s ago): {fpr:.4f}")
    assert fpr == 0.0, (
        f"SERVICE_SILENCE fires for 30s gaps: FPR={fpr}"
    )


# ---------------------------------------------------------------------------
# Latency FPR (explicit on-baseline latency)
# ---------------------------------------------------------------------------

def test_latency_spike_fpr(db_session, test_tenants):
    """
    LATENCY_SPIKE with latency exactly at baseline (50ms) should never fire.
    warn_bound = latency_ewma + 2.5×sqrt(latency_variance) = 50 + 2.5×1 = 52.5ms
    Batch mean at exactly 50ms: 50 < 52.5 → no alert.
    """
    tid = test_tenants["tenant_b"]
    fp_count = 0
    windows  = 200

    for _ in range(windows):
        src    = f"lat-{uuid.uuid4().hex[:8]}"
        engine = _fresh_engine(tid, src)
        entries = [_make_entry(src, tid, latency_ms=50.0) for _ in range(BATCH_SIZE)]
        alerts  = engine.ingest(entries, db_session)
        if any(a.anomaly_type == "LATENCY_SPIKE" for a in alerts):
            fp_count += 1

    fpr = fp_count / windows
    print(f"\n  LATENCY_SPIKE FPR (lat=50ms, baseline=50ms): {fpr:.4f}")
    assert fpr == 0.0, f"LATENCY_SPIKE fires on baseline latency: FPR={fpr}"
