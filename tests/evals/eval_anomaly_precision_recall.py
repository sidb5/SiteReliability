"""
tests/evals/eval_anomaly_precision_recall.py — Precision/Recall evaluation
for the anomaly engine detectors.

Targets (ARCHITECTURE.md):
  Precision  > 0.85
  Recall     > 0.90
  FPR        < 0.05

Methodology:
  Each trial resets the engine to a known pre-warmed baseline
  (ewma=0.05, variance=0.01) which reflects a turbulent service that has
  some historical volatility.

  With that baseline the upper-bound thresholds are:
    warn_bound  = 0.05 + 2.5 × sqrt(0.01) = 0.05 + 0.25 = 0.30
    crit_bound  = 0.05 + 5.0 × sqrt(0.01) = 0.05 + 0.50 = 0.55

  Spike window  : 90% error rate (0.90 > 0.30 → always detected)
  Normal window : 0–10% error rate (≤ 0.10 < 0.30 → never fires)

  The pre-update snapshot fix (Lesson 8) makes this detection reliable:
  the comparison is against EWMA_{t-1}, not EWMA_t after absorbing the spike.

Uses shared conftest fixtures (test_tenants, db_session) so the tenant rows
are valid in the test DB schema.
"""
import random
import uuid
from datetime import datetime, timezone
from typing import Optional

import pytest

from connectors.base import NormalizedLogEntry
from models.db import AnomalyAlert
from services.anomaly_engine import AnomalyEngine, _EwmaState, _cache_key
from services.cache import InProcessCache

UTC = timezone.utc

PRECISION_TARGET = 0.85
RECALL_TARGET    = 0.90
FPR_TARGET       = 0.05

# Pre-warmed state reflects a turbulent baseline.
# warn_bound = 0.05 + 2.5 × sqrt(0.01) = 0.30
# Any spike at 0.90 is always > 0.30; any normal at ≤ 0.10 is always < 0.30.
PREWARM_EWMA     = 0.05
PREWARM_VARIANCE = 0.01
SPIKE_ERROR_RATE = 0.90    # 90% errors → clearly anomalous
NORMAL_ERROR_RATE = 0.02   # 2% errors → clearly normal

BATCH_SIZE       = 50
N_SPIKE_TRIALS   = 100
N_NORMAL_TRIALS  = 200


# ---------------------------------------------------------------------------
# Helpers (no isolated DB needed — uses shared test_tenants fixture)
# ---------------------------------------------------------------------------

def _make_entry(
    source_id: str,
    tenant_id: str,
    level: str = "INFO",
    service_name: str = "eval-service",
) -> NormalizedLogEntry:
    return NormalizedLogEntry(
        occurred_at=datetime.now(UTC),
        level=level,
        message="eval log message",
        source_id=source_id,
        tenant_id=tenant_id,
        service_name=service_name,
        environment="production",
        latency_ms=None,
        raw={},
    )


def _batch(source_id: str, tenant_id: str, error_rate: float) -> list[NormalizedLogEntry]:
    n_errors = round(error_rate * BATCH_SIZE)
    n_ok     = BATCH_SIZE - n_errors
    return (
        [_make_entry(source_id, tenant_id, level="ERROR") for _ in range(n_errors)]
        + [_make_entry(source_id, tenant_id, level="INFO")  for _ in range(n_ok)]
    )


def _fresh_engine(tenant_id: str, source_id: str) -> AnomalyEngine:
    """Create a pre-warmed engine for one trial."""
    engine = AnomalyEngine(cache=InProcessCache())
    state = _EwmaState(
        source_id=source_id,
        tenant_id=tenant_id,
        ewma_value=PREWARM_EWMA,
        ewma_variance=PREWARM_VARIANCE,
        warmup_count=50,
        warmup_required=10,
        log_volume_ewma=10.0,
    )
    engine._cache.set(_cache_key(tenant_id, source_id), state)
    return engine


def _run_trial(tenant_id: str, db, error_rate: float) -> bool:
    """
    Run one independent trial: fresh engine, one batch, return True if spike fires.
    """
    source_id = f"eval-{uuid.uuid4().hex[:8]}"
    engine = _fresh_engine(tenant_id, source_id)
    alerts = engine.ingest(_batch(source_id, tenant_id, error_rate), db)
    return any(a.anomaly_type == "ERROR_RATE_SPIKE" for a in alerts)


# ---------------------------------------------------------------------------
# Eval 1 — Precision and Recall (ERROR_RATE_SPIKE)
# ---------------------------------------------------------------------------

def test_precision_recall(db_session, test_tenants):
    """
    Precision/Recall for ERROR_RATE_SPIKE.

    Expected result (with pre-update fix):
      All N_SPIKE_TRIALS fire  → Recall  = 1.00  (target > 0.90)
      No N_NORMAL_TRIALS fire  → FPR     = 0.00  (target < 0.05)
                                 Precision = 1.00  (target > 0.85)
    """
    tid = test_tenants["tenant_a"]

    tp = sum(_run_trial(tid, db_session, SPIKE_ERROR_RATE)  for _ in range(N_SPIKE_TRIALS))
    fp = sum(_run_trial(tid, db_session, NORMAL_ERROR_RATE) for _ in range(N_NORMAL_TRIALS))

    fn        = N_SPIKE_TRIALS  - tp
    tn        = N_NORMAL_TRIALS - fp
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr       = fp / N_NORMAL_TRIALS

    print(f"\n=== ERROR_RATE_SPIKE Precision/Recall ===")
    print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"  Precision={precision:.3f}  (target >{PRECISION_TARGET})")
    print(f"  Recall   ={recall:.3f}  (target >{RECALL_TARGET})")
    print(f"  FPR      ={fpr:.3f}  (target <{FPR_TARGET})")
    print(f"  warn_bound = ewma + 2.5*sqrt(var) = {PREWARM_EWMA} + 2.5*{PREWARM_VARIANCE**0.5:.4f}")

    assert recall    >= RECALL_TARGET,    f"Recall={recall:.3f} < {RECALL_TARGET}"
    assert precision >= PRECISION_TARGET, f"Precision={precision:.3f} < {PRECISION_TARGET}"
    assert fpr       <  FPR_TARGET,       f"FPR={fpr:.3f} >= {FPR_TARGET}"


# ---------------------------------------------------------------------------
# Eval 2 — Precision and Recall (LATENCY_SPIKE)
# ---------------------------------------------------------------------------

def test_latency_spike_precision_recall(db_session, test_tenants):
    """
    Precision/Recall for LATENCY_SPIKE.
    Baseline: latency_ewma=50ms, latency_variance=1ms²
    warn_bound = 50 + 2.5×√1 = 52.5ms
    Spike: 200ms batch mean (>> 52.5ms) → always detected.
    Normal: 50ms batch mean (at baseline) → never fires.
    """
    tid = test_tenants["tenant_b"]

    def _lat_trial(spike: bool) -> bool:
        source_id = f"lat-eval-{uuid.uuid4().hex[:8]}"
        engine = AnomalyEngine(cache=InProcessCache())
        state = _EwmaState(
            source_id=source_id,
            tenant_id=tid,
            ewma_value=PREWARM_EWMA,
            ewma_variance=PREWARM_VARIANCE,
            warmup_count=50,
            warmup_required=10,
            log_volume_ewma=10.0,
            latency_ewma=50.0,
            latency_variance=1.0,
            latency_warmup=50,
        )
        engine._cache.set(_cache_key(tid, source_id), state)
        lat_ms = 200.0 if spike else 50.0
        entries = [
            NormalizedLogEntry(
                occurred_at=datetime.now(UTC),
                level="INFO",
                message="req",
                source_id=source_id,
                tenant_id=tid,
                service_name="lat-svc",
                environment="production",
                latency_ms=lat_ms,
                raw={},
            )
            for _ in range(BATCH_SIZE)
        ]
        alerts = engine.ingest(entries, db_session)
        return any(a.anomaly_type == "LATENCY_SPIKE" for a in alerts)

    n_trials = 50
    tp = sum(_lat_trial(spike=True)  for _ in range(n_trials))
    fp = sum(_lat_trial(spike=False) for _ in range(n_trials))

    recall    = tp / n_trials
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    fpr       = fp / n_trials

    print(f"\n=== LATENCY_SPIKE Precision/Recall ===")
    print(f"  TP={tp}/{n_trials}  FP={fp}/{n_trials}")
    print(f"  Precision={precision:.3f}  Recall={recall:.3f}  FPR={fpr:.3f}")

    assert recall    >= RECALL_TARGET,    f"LATENCY_SPIKE Recall={recall:.3f} < {RECALL_TARGET}"
    assert precision >= PRECISION_TARGET, f"LATENCY_SPIKE Precision={precision:.3f} < {PRECISION_TARGET}"
    assert fpr       <  FPR_TARGET,       f"LATENCY_SPIKE FPR={fpr:.3f} >= {FPR_TARGET}"


# ---------------------------------------------------------------------------
# Eval 3 — Recall for SUSTAINED_ELEVATION
# ---------------------------------------------------------------------------

def test_sustained_elevation_recall(db_session, test_tenants):
    """
    SUSTAINED_ELEVATION fires when error_rate > ewma_value for >10 min.
    Injects one batch above baseline then backdates above_baseline_since by 11 min.
    Expected recall: 1.0 (always fires when time condition is met).
    """
    from datetime import timedelta

    tid = test_tenants["tenant_a"]
    n_trials = 50
    tp = 0
    fp_normal = 0

    for _ in range(n_trials):
        src = f"sust-eval-{uuid.uuid4().hex[:8]}"
        engine = AnomalyEngine(cache=InProcessCache())
        state = _EwmaState(
            source_id=src,
            tenant_id=tid,
            ewma_value=0.02,
            ewma_variance=1e-5,
            warmup_count=50,
            warmup_required=10,
            log_volume_ewma=10.0,
        )
        engine._cache.set(_cache_key(tid, src), state)

        # One batch above baseline — sets above_baseline_since
        above = [_make_entry(src, tid, level="ERROR") for _ in range(5)] + \
                [_make_entry(src, tid, level="INFO")  for _ in range(5)]
        engine.ingest(above, db_session)

        # Simulate 11 min elapsed
        state = engine._cache.get(_cache_key(tid, src))
        if state.above_baseline_since:
            state.above_baseline_since = datetime.now(UTC) - timedelta(seconds=661)

        alerts = engine.ingest(above, db_session)
        if any(a.anomaly_type == "SUSTAINED_ELEVATION" for a in alerts):
            tp += 1

    # Normal check: engine with stable baseline never fires SUSTAINED_ELEVATION
    for _ in range(50):
        src = f"sust-normal-{uuid.uuid4().hex[:8]}"
        engine = AnomalyEngine(cache=InProcessCache())
        state = _EwmaState(
            source_id=src, tenant_id=tid,
            ewma_value=0.02, ewma_variance=1e-5,
            warmup_count=50, warmup_required=10,
        )
        engine._cache.set(_cache_key(tid, src), state)
        normal = [_make_entry(src, tid, level="INFO") for _ in range(10)]
        alerts = engine.ingest(normal, db_session)
        if any(a.anomaly_type == "SUSTAINED_ELEVATION" for a in alerts):
            fp_normal += 1

    recall = tp / n_trials
    fpr    = fp_normal / 50

    print(f"\n=== SUSTAINED_ELEVATION Recall/FPR ===")
    print(f"  TP={tp}/{n_trials}  recall={recall:.3f}  FP={fp_normal}/50  fpr={fpr:.3f}")

    assert recall >= RECALL_TARGET, f"SUSTAINED_ELEVATION recall={recall:.3f} < {RECALL_TARGET}"
    assert fpr    <  FPR_TARGET,    f"SUSTAINED_ELEVATION FPR={fpr:.3f} >= {FPR_TARGET}"
