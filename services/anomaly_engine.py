"""
services/anomaly_engine.py — EWMA-based anomaly detection engine.

Six anomaly types (ARCHITECTURE.md §4):
  ERROR_RATE_SPIKE    — error fraction > EWMA upper bound (2.5×/5.0× sensitivity)
  SUSTAINED_ELEVATION — error rate > EWMA baseline for >10 min
  SERVICE_SILENCE     — 0 logs for >2 min from previously active source
  LATENCY_SPIKE       — latency_ms EWMA breaches threshold (2.5×/5.0×)
  NOVEL_ERROR         — error pattern not seen in past 24 h (bloom-filter via fingerprints)
  CASCADE             — 3+ services spiking within a 5-min window (same tenant)

Design invariants:
  • Cache key "ewma:{tenant_id}:{source_id}" — tenant_id first so no crafted
    source_id can collide across tenants (tasks/lessons.md Decision).
  • AnomalyAlert is written with tenant_id on every INSERT.
  • Every DB query in this file carries .filter(... tenant_id == ...) — belt +
    suspenders alongside the FK constraint.
  • The caller owns the session.  This engine calls db.flush() (not commit).

EWMA formulas:
  EWMA_t     = α × x_t + (1 − α) × EWMA_{t-1}
  Variance_t = α × (x_t − EWMA_{t-1})² + (1 − α) × Variance_{t-1}
  Upper_bound = EWMA_t + sensitivity × √Variance_t
"""
import hashlib
import json
import logging
import math
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from connectors.base import NormalizedLogEntry
from models.db import AnomalyAlert, EwmaState
from services.cache import CacheBackend

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PERSIST_EVERY: int = 10

_WARNING_SENSITIVITY: float = 2.5
_CRITICAL_SENSITIVITY: float = 5.0
_ERROR_LEVELS: frozenset[str] = frozenset({"ERROR", "CRITICAL"})

_SUSTAINED_WARNING_S: int  = 600   # 10 min in seconds
_SUSTAINED_CRITICAL_S: int = 900   # 15 min in seconds

_SILENCE_WINDOW_S: int = 120       # 2 min in seconds

_CASCADE_WINDOW_S: int = 300       # 5-min correlation window
_CASCADE_MIN_SERVICES: int = 3     # minimum distinct services for CASCADE

_FINGERPRINT_TTL_S: int = 86400    # 24 h in seconds
_MAX_FINGERPRINTS: int = 500       # cap bloom set to prevent unbounded growth

# ---------------------------------------------------------------------------
# In-memory EWMA state
# ---------------------------------------------------------------------------

@dataclass
class _EwmaState:
    """
    Full in-memory EWMA state for one (tenant_id, source_id) pair.

    Persisted fields correspond to ewma_state table columns.
    Transient fields live only in the in-process cache and reset on restart.
    """
    # Identifiers
    source_id: str
    tenant_id: str

    # Persisted — error-rate EWMA
    ewma_value: float = 0.0
    ewma_variance: float = 0.0
    alpha: float = 0.3
    sensitivity: float = 2.5
    warmup_count: int = 0
    warmup_required: int = 10

    # Persisted — NOVEL_ERROR bloom set + SERVICE_SILENCE gate
    error_fingerprints: list = field(default_factory=list)
    log_volume_ewma: float = 0.0
    last_log_at: Optional[datetime] = None

    # Transient — auto-resolve counters
    events_since_persist: int = 0
    clean_windows: int = 0                        # for ERROR_RATE_SPIKE
    latency_clean_windows: int = 0                # for LATENCY_SPIKE

    # Transient — SUSTAINED_ELEVATION
    above_baseline_since: Optional[datetime] = None
    sustained_severity_fired: Optional[str] = None  # "WARNING" | "CRITICAL" already open

    # Transient — LATENCY_SPIKE (not yet in DB schema; resets on restart)
    latency_ewma: float = 0.0
    latency_variance: float = 0.0
    latency_warmup: int = 0

    # Transient — SERVICE_SILENCE de-dup
    silence_alerted: bool = False

    # Transient — DB row id for upsert shortcut
    db_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class AnomalyEngine:

    def __init__(
        self,
        cache: CacheBackend,
        session_factory: Optional[Callable[[], Session]] = None,
    ) -> None:
        self._cache = cache
        self._session_factory = session_factory
        # In-memory guard: tenant_id → last CASCADE fire time.
        # Prevents repeated CASCADE firing within the same 5-min window.
        self._cascade_fired: dict[str, datetime] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def ingest(
        self,
        entries: list[NormalizedLogEntry],
        db: Session,
    ) -> list[AnomalyAlert]:
        """
        Process a batch of log entries from ONE source.
        Caller must commit the session after this returns.
        """
        if not entries:
            return []

        source_id = entries[0].source_id
        tenant_id = entries[0].tenant_id

        state = self._load_state(source_id, tenant_id, db)
        alerts: list[AnomalyAlert] = []

        # 1. SERVICE_SILENCE check — before updating last_log_at so we can
        #    measure the gap between the previous batch and this one.
        silence = self._check_service_silence(state, entries, db)
        if silence:
            alerts.append(silence)

        # 2. Compute error fraction for this batch
        error_count = sum(1 for e in entries if e.level in _ERROR_LEVELS)
        error_rate = error_count / len(entries)

        # 3. Capture pre-update baseline values BEFORE any in-place mutation.
        #    Spike detection compares the current observation against EWMA_{t-1}
        #    (the established baseline), never against EWMA_t which has already
        #    absorbed the spike and inflates the upper bound past the observation.
        prev_error_ewma = state.ewma_value
        prev_error_var  = state.ewma_variance

        # 4. Update error-rate EWMA (always, including during warmup)
        self._update_ewma(state, error_rate)

        # 5. Update latency EWMA (only when entries carry latency data)
        latency_values = [e.latency_ms for e in entries if e.latency_ms is not None]
        prev_lat_ewma = state.latency_ewma
        prev_lat_var  = state.latency_variance
        if latency_values:
            self._update_latency_ewma(state, latency_values)

        # 6. Update log-volume EWMA (for SERVICE_SILENCE baseline)
        self._update_volume_ewma(state, len(entries))

        # 7. Update last_log_at with the latest entry timestamp
        entry_times = [e.occurred_at for e in entries if e.occurred_at]
        if entry_times:
            state.last_log_at = max(entry_times)
            state.silence_alerted = False  # logs resumed — clear silence flag

        # 8. Post-warmup detectors — all use PRE-update baselines for comparison
        if state.warmup_count >= state.warmup_required:
            spike = self._check_error_rate_spike(
                state, error_rate, entries, db, prev_error_ewma, prev_error_var
            )
            if spike:
                alerts.append(spike)
                # CASCADE check runs immediately after a spike fires
                cascade = self._check_cascade(state, db)
                if cascade:
                    alerts.append(cascade)

            sustained = self._check_sustained_elevation(state, error_rate, db)
            if sustained:
                alerts.append(sustained)

            if latency_values:
                lat_spike = self._check_latency_spike(
                    state, latency_values, entries, db, prev_lat_ewma, prev_lat_var
                )
                if lat_spike:
                    alerts.append(lat_spike)

            novel = self._check_novel_error(state, entries, db)
            if novel:
                alerts.extend(novel)

        # 8. Write-through to cache and periodic DB persist
        state.events_since_persist += 1
        self._cache.set(_cache_key(tenant_id, source_id), state)
        if state.events_since_persist >= PERSIST_EVERY:
            self._persist_state(state, db)
            state.events_since_persist = 0

        return alerts

    def flush(self, db: Session) -> None:
        """Persist all cached EWMA states.  Call on graceful shutdown."""
        for entry in list(self._cache._store.values()):
            value = entry[0] if isinstance(entry, tuple) else entry
            if isinstance(value, _EwmaState):
                self._persist_state(value, db)

    # ------------------------------------------------------------------
    # EWMA maths
    # ------------------------------------------------------------------

    def _update_ewma(self, state: _EwmaState, observed: float) -> None:
        """
        EWMA_t     = α × x_t + (1 − α) × EWMA_{t-1}
        Variance_t = α × (x_t − EWMA_{t-1})² + (1 − α) × Variance_{t-1}

        Variance uses prev_ewma (not updated ewma) so it measures deviation
        from the previous smoothed baseline — not from the new value.
        """
        prev_ewma = state.ewma_value
        state.ewma_value = state.alpha * observed + (1.0 - state.alpha) * prev_ewma
        state.ewma_variance = (
            state.alpha * (observed - prev_ewma) ** 2
            + (1.0 - state.alpha) * state.ewma_variance
        )
        state.warmup_count += 1

    def _update_latency_ewma(
        self, state: _EwmaState, latency_values: list[float]
    ) -> None:
        """Update latency EWMA with the mean latency for this batch."""
        batch_mean = sum(latency_values) / len(latency_values)
        prev = state.latency_ewma
        state.latency_ewma = state.alpha * batch_mean + (1.0 - state.alpha) * prev
        state.latency_variance = (
            state.alpha * (batch_mean - prev) ** 2
            + (1.0 - state.alpha) * state.latency_variance
        )
        state.latency_warmup += 1

    def _update_volume_ewma(self, state: _EwmaState, batch_size: int) -> None:
        """Track rolling average log volume for SERVICE_SILENCE baseline."""
        state.log_volume_ewma = (
            state.alpha * batch_size + (1.0 - state.alpha) * state.log_volume_ewma
        )

    def _upper_bound(self, ewma: float, variance: float, sensitivity: float) -> float:
        return ewma + sensitivity * math.sqrt(variance)

    # ------------------------------------------------------------------
    # Detector 1 — ERROR_RATE_SPIKE
    # ------------------------------------------------------------------

    def _check_error_rate_spike(
        self,
        state: _EwmaState,
        error_rate: float,
        entries: list[NormalizedLogEntry],
        db: Session,
        prev_ewma: float = 0.0,
        prev_variance: float = 0.0,
    ) -> Optional[AnomalyAlert]:
        # Use EWMA_{t-1} (pre-update) so the bound reflects the established baseline,
        # not a baseline already contaminated by the current spike.
        warn_bound = self._upper_bound(prev_ewma, prev_variance, _WARNING_SENSITIVITY)
        crit_bound = self._upper_bound(prev_ewma, prev_variance, _CRITICAL_SENSITIVITY)

        if error_rate <= warn_bound:
            state.clean_windows += 1
            if state.clean_windows >= 2:
                self._try_auto_resolve("ERROR_RATE_SPIKE", state, db)
            return None

        state.clean_windows = 0
        severity = "CRITICAL" if error_rate > crit_bound else "WARNING"

        return self._build_alert(
            state=state,
            anomaly_type="ERROR_RATE_SPIKE",
            severity=severity,
            current_value=error_rate,
            baseline_value=state.ewma_value,
            upper_bound=warn_bound,
            unit="error_fraction",
            entries=entries,
            db=db,
        )

    # ------------------------------------------------------------------
    # Detector 2 — SUSTAINED_ELEVATION
    # ------------------------------------------------------------------

    def _check_sustained_elevation(
        self,
        state: _EwmaState,
        error_rate: float,
        db: Session,
    ) -> Optional[AnomalyAlert]:
        """
        Fires when error_rate stays above ewma_value for more than 10 min
        (WARNING) or 15 min (CRITICAL).  Distinct from spike: this detects
        chronic elevation that hasn't resolved after multiple EWMA windows.
        """
        now = datetime.now(timezone.utc)

        if error_rate <= state.ewma_value:
            # Returned to baseline — reset tracker and auto-resolve
            state.above_baseline_since = None
            state.sustained_severity_fired = None
            self._try_auto_resolve("SUSTAINED_ELEVATION", state, db)
            return None

        # Above baseline — track start time
        if state.above_baseline_since is None:
            state.above_baseline_since = now
            return None

        duration_s = (now - state.above_baseline_since).total_seconds()

        # CRITICAL escalation: >15 min and we already fired WARNING
        if (duration_s >= _SUSTAINED_CRITICAL_S
                and state.sustained_severity_fired != "CRITICAL"):
            state.sustained_severity_fired = "CRITICAL"
            return self._build_alert(
                state=state,
                anomaly_type="SUSTAINED_ELEVATION",
                severity="CRITICAL",
                current_value=error_rate,
                baseline_value=state.ewma_value,
                upper_bound=state.ewma_value,  # threshold IS the baseline for this type
                unit="error_fraction",
                entries=[],
                db=db,
            )

        # WARNING: >10 min and we haven't fired anything yet
        if (duration_s >= _SUSTAINED_WARNING_S
                and state.sustained_severity_fired is None):
            state.sustained_severity_fired = "WARNING"
            return self._build_alert(
                state=state,
                anomaly_type="SUSTAINED_ELEVATION",
                severity="WARNING",
                current_value=error_rate,
                baseline_value=state.ewma_value,
                upper_bound=state.ewma_value,
                unit="error_fraction",
                entries=[],
                db=db,
            )

        return None

    # ------------------------------------------------------------------
    # Detector 3 — SERVICE_SILENCE
    # ------------------------------------------------------------------

    def _check_service_silence(
        self,
        state: _EwmaState,
        entries: list[NormalizedLogEntry],
        db: Session,
    ) -> Optional[AnomalyAlert]:
        """
        Called at the START of ingest(), before last_log_at is updated.

        Measures the gap between the previous batch's latest timestamp and
        the current batch's earliest timestamp.  If gap > 2 min and the
        service had established a non-zero log volume baseline, fire CRITICAL.

        The alert auto-resolves immediately because new entries are arriving —
        silence has ended.  Duration is captured in the evidence window.
        """
        if state.last_log_at is None:
            # Never seen logs from this source — no baseline, no silence
            return None
        if state.log_volume_ewma <= 0:
            # Service was never meaningfully active — silence not meaningful
            return None
        if state.silence_alerted:
            # Already fired for this silence gap — don't double-fire
            return None

        now = datetime.now(timezone.utc)
        entry_times = [e.occurred_at for e in entries if e.occurred_at]
        earliest_now = min(entry_times) if entry_times else now

        # Make both sides timezone-aware for subtraction
        last = state.last_log_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)

        silence_s = (earliest_now - last).total_seconds()

        if silence_s < _SILENCE_WINDOW_S:
            return None

        # Silence confirmed — mark so we don't re-fire mid-silence
        state.silence_alerted = True

        alert = self._build_alert(
            state=state,
            anomaly_type="SERVICE_SILENCE",
            severity="CRITICAL",
            current_value=silence_s,
            baseline_value=state.log_volume_ewma,
            upper_bound=float(_SILENCE_WINDOW_S),
            unit="seconds_silent",
            entries=entries,
            db=db,
            window_override=(last, earliest_now),
        )

        # Immediately auto-resolve: logs have resumed
        self._try_auto_resolve("SERVICE_SILENCE", state, db)
        return alert

    # ------------------------------------------------------------------
    # Detector 4 — LATENCY_SPIKE
    # ------------------------------------------------------------------

    def _check_latency_spike(
        self,
        state: _EwmaState,
        latency_values: list[float],
        entries: list[NormalizedLogEntry],
        db: Session,
        prev_lat_ewma: float = 0.0,
        prev_lat_variance: float = 0.0,
    ) -> Optional[AnomalyAlert]:
        """
        Same 2.5×/5.0× EWMA threshold applied to latency_ms.
        Only active when entries carry latency_ms values.
        Latency EWMA resets on service restart (no DB column yet — Stage C limitation).
        Uses pre-update EWMA_{t-1} for the bound (same fix as ERROR_RATE_SPIKE).
        """
        if state.latency_warmup < state.warmup_required:
            return None

        batch_mean = sum(latency_values) / len(latency_values)
        warn_bound = self._upper_bound(prev_lat_ewma, prev_lat_variance, _WARNING_SENSITIVITY)
        crit_bound = self._upper_bound(prev_lat_ewma, prev_lat_variance, _CRITICAL_SENSITIVITY)

        if batch_mean <= warn_bound:
            state.latency_clean_windows += 1
            if state.latency_clean_windows >= 2:
                self._try_auto_resolve("LATENCY_SPIKE", state, db)
            return None

        state.latency_clean_windows = 0
        severity = "CRITICAL" if batch_mean > crit_bound else "WARNING"

        return self._build_alert(
            state=state,
            anomaly_type="LATENCY_SPIKE",
            severity=severity,
            current_value=batch_mean,
            baseline_value=state.latency_ewma,
            upper_bound=warn_bound,
            unit="ms",
            entries=entries,
            db=db,
        )

    # ------------------------------------------------------------------
    # Detector 5 — NOVEL_ERROR
    # ------------------------------------------------------------------

    def _check_novel_error(
        self,
        state: _EwmaState,
        entries: list[NormalizedLogEntry],
        db: Session,
    ) -> list[AnomalyAlert]:
        """
        One WARNING per novel error pattern not seen in 24 h.

        Fingerprint = first 16 hex chars of SHA-256(normalised_message).
        Normalisation strips numeric tokens so "timeout after 5s" and
        "timeout after 30s" produce the same fingerprint.

        Fingerprints are stored with timestamps.  Entries older than 24 h are
        pruned on each call so the set acts like a TTL'd bloom filter.
        Capped at _MAX_FINGERPRINTS to prevent unbounded growth.
        """
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=_FINGERPRINT_TTL_S)

        # Prune expired fingerprints
        state.error_fingerprints = [
            fp for fp in state.error_fingerprints
            if datetime.fromisoformat(fp["seen_at"]) > cutoff
        ]

        error_entries = [e for e in entries if e.level in _ERROR_LEVELS]
        alerts: list[AnomalyAlert] = []

        seen_fps: set[str] = {fp["fp"] for fp in state.error_fingerprints}

        for entry in error_entries:
            fp = _fingerprint(entry.message)
            if fp in seen_fps:
                continue  # known pattern — not novel

            # Novel fingerprint
            seen_fps.add(fp)
            if len(state.error_fingerprints) < _MAX_FINGERPRINTS:
                state.error_fingerprints.append(
                    {"fp": fp, "seen_at": now.isoformat()}
                )

            alert = self._build_alert(
                state=state,
                anomaly_type="NOVEL_ERROR",
                severity="WARNING",
                current_value=1.0,
                baseline_value=0.0,
                upper_bound=0.0,
                unit="novel_pattern",
                entries=[entry],
                db=db,
            )
            alerts.append(alert)

        return alerts

    # ------------------------------------------------------------------
    # Detector 6 — CASCADE
    # ------------------------------------------------------------------

    def _check_cascade(
        self,
        state: _EwmaState,
        db: Session,
    ) -> Optional[AnomalyAlert]:
        """
        Fires when ERROR_RATE_SPIKE has been detected on 3+ distinct services
        owned by the same tenant within a 5-minute window.

        How the 5-minute window works:
          We query anomaly_alerts for this tenant where:
            anomaly_type = 'ERROR_RATE_SPIKE'
            status = 'open'
            detected_at >= now - 5 min
          The DB flush() in _build_alert() already made the triggering spike
          visible in this session, so the query includes it.

        Cross-tenant isolation:
          The WHERE clause carries tenant_id == state.tenant_id.  It is
          structurally impossible for this query to return rows from another
          tenant regardless of what source_id or service_name values look like.

        CASCADE references:
          The cascade_context JSON contains a list of
          {"service_name": str, "alert_id": str} for each contributing service.
          alert_id values are the UUIDs of the actual ERROR_RATE_SPIKE alerts
          stored in anomaly_alerts, enabling full drill-down.

        De-duplication:
          _cascade_fired[tenant_id] tracks the last CASCADE fire time.
          A second CASCADE cannot fire within the same 5-min window.
        """
        now = datetime.now(timezone.utc)

        # In-memory de-dup: only one CASCADE per tenant per 5-min window
        last_fired = self._cascade_fired.get(state.tenant_id)
        if (last_fired is not None
                and (now - last_fired).total_seconds() < _CASCADE_WINDOW_S):
            return None

        five_min_ago = now - timedelta(seconds=_CASCADE_WINDOW_S)

        # Tenant-scoped query — tenant_id in WHERE is MANDATORY (not optional)
        recent_spikes = (
            db.query(AnomalyAlert.service_name, AnomalyAlert.id)
            .filter(
                AnomalyAlert.tenant_id == state.tenant_id,   # isolation: never omit
                AnomalyAlert.anomaly_type == "ERROR_RATE_SPIKE",
                AnomalyAlert.detected_at >= five_min_ago,
                AnomalyAlert.status == "open",
            )
            .all()
        )

        # Deduplicate: one entry per distinct service_name, keep first alert_id seen
        services: dict[str, str] = {}
        for service_name, alert_id in recent_spikes:
            if service_name not in services:
                services[service_name] = alert_id

        if len(services) < _CASCADE_MIN_SERVICES:
            return None

        # Record fire time before building alert (build_alert flushes to DB)
        self._cascade_fired[state.tenant_id] = now

        cascade_context = {
            "contributing_services": [
                {"service_name": svc, "alert_id": aid}
                for svc, aid in services.items()
            ],
            "window_seconds": _CASCADE_WINDOW_S,
            "service_count": len(services),
        }

        logger.info(
            "CASCADE detected",
            extra={
                "tenant_id": state.tenant_id,
                "service_count": len(services),
                "services": list(services.keys()),
            },
        )

        return self._build_alert(
            state=state,
            anomaly_type="CASCADE",
            severity="CRITICAL",
            current_value=float(len(services)),
            baseline_value=float(_CASCADE_MIN_SERVICES - 1),
            upper_bound=float(_CASCADE_MIN_SERVICES),
            unit="services_spiking",
            entries=[],
            db=db,
            cascade_context=cascade_context,
        )

    # ------------------------------------------------------------------
    # Alert construction
    # ------------------------------------------------------------------

    def _build_alert(
        self,
        state: _EwmaState,
        anomaly_type: str,
        severity: str,
        current_value: float,
        baseline_value: float,
        upper_bound: float,
        unit: str,
        entries: list[NormalizedLogEntry],
        db: Session,
        cascade_context: Optional[dict] = None,
        window_override: Optional[tuple[datetime, datetime]] = None,
    ) -> AnomalyAlert:
        now = datetime.now(timezone.utc)

        if window_override:
            window_start, window_end = window_override
        else:
            timestamps = [e.occurred_at for e in entries if e.occurred_at]
            window_start = min(timestamps) if timestamps else now
            window_end   = max(timestamps) if timestamps else now

        error_msgs = [e.message for e in entries if e.level in _ERROR_LEVELS]
        representative = list(dict.fromkeys(error_msgs))[:3]

        detection_context = {
            "algorithm": "EWMA",
            "ewma_value": round(state.ewma_value, 6),
            "ewma_variance": round(state.ewma_variance, 6),
            "alpha": state.alpha,
            "sensitivity_multiplier": state.sensitivity,
            "warmup_complete": state.warmup_count >= state.warmup_required,
            "observations_count": state.warmup_count,
        }

        service_name = entries[0].service_name if entries else "unknown"
        environment  = entries[0].environment  if entries else "production"

        alert_id = str(uuid.uuid4())
        full_payload = {
            "anomaly_id": alert_id,
            "schema_version": "1.0",
            "detected_at": now.isoformat(),
            "anomaly_type": anomaly_type,
            "severity": severity,
            "service": {
                "name": service_name,
                "environment": environment,
                "source_id": state.source_id,
            },
            "evidence": {
                "current_value": round(current_value, 6),
                "baseline_value": round(baseline_value, 6),
                "upper_bound": round(upper_bound, 6),
                "unit": unit,
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "sample_count": len(entries),
                "representative_messages": representative,
            },
            "detection_context": detection_context,
            "cascade_context": cascade_context,
            "resolution": {
                "resolved_at": None,
                "duration_seconds": None,
                "auto_resolved": None,
            },
            "links": {
                "self": f"/api/v1/alerts/{alert_id}",
                "acknowledge": f"/api/v1/alerts/{alert_id}/acknowledge",
            },
        }

        alert = AnomalyAlert(
            id=alert_id,
            tenant_id=state.tenant_id,
            source_id=state.source_id,
            detected_at=now,
            anomaly_type=anomaly_type,
            severity=severity,
            service_name=service_name,
            environment=environment,
            current_value=current_value,
            baseline_value=baseline_value,
            upper_bound=upper_bound,
            unit=unit,
            window_start=window_start,
            window_end=window_end,
            sample_count=len(entries),
            representative_msgs=json.dumps(representative),
            detection_context=json.dumps(detection_context),
            cascade_context=json.dumps(cascade_context) if cascade_context else None,
            full_payload=json.dumps(full_payload),
            status="open",
        )

        try:
            db.add(alert)
            db.flush()
            logger.info(
                "anomaly alert created",
                extra={
                    "alert_id": alert_id,
                    "tenant_id": state.tenant_id,
                    "anomaly_type": anomaly_type,
                    "severity": severity,
                },
            )
        except IntegrityError:
            db.rollback()
            logger.error(
                "failed to persist anomaly alert",
                extra={"tenant_id": state.tenant_id, "anomaly_type": anomaly_type},
            )
            raise

        return alert

    # ------------------------------------------------------------------
    # Auto-resolution
    # ------------------------------------------------------------------

    def _try_auto_resolve(
        self, anomaly_type: str, state: _EwmaState, db: Session
    ) -> None:
        try:
            open_alert = (
                db.query(AnomalyAlert)
                .filter(
                    AnomalyAlert.tenant_id == state.tenant_id,
                    AnomalyAlert.source_id == state.source_id,
                    AnomalyAlert.anomaly_type == anomaly_type,
                    AnomalyAlert.status == "open",
                )
                .order_by(AnomalyAlert.detected_at.desc())
                .first()
            )
            if open_alert is None:
                return

            now = datetime.now(timezone.utc)
            open_alert.status = "resolved"
            open_alert.resolved_at = now
            open_alert.auto_resolved = True

            try:
                payload = json.loads(open_alert.full_payload)
                detected_str = payload.get("detected_at", "")
                if detected_str:
                    detected = datetime.fromisoformat(detected_str)
                    if detected.tzinfo is None:
                        detected = detected.replace(tzinfo=timezone.utc)
                    duration = (now - detected).total_seconds()
                    payload["resolution"] = {
                        "resolved_at": now.isoformat(),
                        "duration_seconds": round(duration, 1),
                        "auto_resolved": True,
                    }
                    open_alert.full_payload = json.dumps(payload)
            except Exception:
                pass

            db.flush()
            logger.info(
                "anomaly auto-resolved",
                extra={
                    "alert_id": open_alert.id,
                    "tenant_id": state.tenant_id,
                    "anomaly_type": anomaly_type,
                },
            )
        except Exception as exc:
            logger.warning(
                "auto-resolve failed",
                extra={"tenant_id": state.tenant_id, "error": str(exc)},
            )

    # ------------------------------------------------------------------
    # State load / persist
    # ------------------------------------------------------------------

    def _load_state(
        self, source_id: str, tenant_id: str, db: Session
    ) -> _EwmaState:
        cache_key = _cache_key(tenant_id, source_id)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        row = (
            db.query(EwmaState)
            .filter(
                EwmaState.tenant_id == tenant_id,   # always tenant-scoped
                EwmaState.source_id == source_id,
            )
            .first()
        )

        if row is not None:
            state = _EwmaState(
                source_id=source_id,
                tenant_id=tenant_id,
                ewma_value=row.ewma_value,
                ewma_variance=row.ewma_variance,
                alpha=row.alpha,
                sensitivity=row.sensitivity,
                warmup_count=row.warmup_count,
                warmup_required=row.warmup_required,
                error_fingerprints=json.loads(row.error_fingerprints or "[]"),
                log_volume_ewma=row.log_volume_ewma,
                last_log_at=row.last_log_at,
                db_id=row.id,
            )
        else:
            state = _EwmaState(source_id=source_id, tenant_id=tenant_id)

        self._cache.set(cache_key, state)
        return state

    def _persist_state(self, state: _EwmaState, db: Session) -> None:
        try:
            existing = None
            if state.db_id:
                existing = db.query(EwmaState).filter(EwmaState.id == state.db_id).first()
            if existing is None:
                existing = (
                    db.query(EwmaState)
                    .filter(
                        EwmaState.tenant_id == state.tenant_id,
                        EwmaState.source_id == state.source_id,
                    )
                    .first()
                )

            if existing is not None:
                existing.ewma_value       = state.ewma_value
                existing.ewma_variance    = state.ewma_variance
                existing.warmup_count     = state.warmup_count
                existing.error_fingerprints = json.dumps(state.error_fingerprints)
                existing.log_volume_ewma  = state.log_volume_ewma
                existing.last_log_at      = state.last_log_at
                db.flush()
                state.db_id = existing.id
            else:
                new_row = EwmaState(
                    source_id=state.source_id,
                    tenant_id=state.tenant_id,
                    ewma_value=state.ewma_value,
                    ewma_variance=state.ewma_variance,
                    alpha=state.alpha,
                    sensitivity=state.sensitivity,
                    warmup_count=state.warmup_count,
                    warmup_required=state.warmup_required,
                    error_fingerprints=json.dumps(state.error_fingerprints),
                    log_volume_ewma=state.log_volume_ewma,
                    last_log_at=state.last_log_at,
                )
                db.add(new_row)
                db.flush()
                state.db_id = new_row.id
        except IntegrityError:
            db.rollback()
            logger.warning(
                "EWMA persist skipped — source_id not in log_sources (push path?)",
                extra={"tenant_id": state.tenant_id, "source_id": state.source_id},
            )
        except Exception as exc:
            logger.error(
                "EWMA persist failed",
                extra={"tenant_id": state.tenant_id, "error": str(exc)},
            )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _cache_key(tenant_id: str, source_id: str) -> str:
    """
    Format: ewma:{tenant_id}:{source_id}
    tenant_id is first so no source_id value (even one containing ":") can
    produce a key that collides with another tenant's entry.
    """
    return f"ewma:{tenant_id}:{source_id}"


def _normalize_message(message: str) -> str:
    """
    Strip numeric sequences so variant forms of the same error cluster together.
    "Connection refused port 5432" → "connection refused port N"
    "Timeout after 5s" → "timeout after Ns"  (handles unit suffixes too)
    Uses r"\\d+" (not \\b\\d+\\b) so digits embedded in tokens like "5s" are captured.
    """
    return re.sub(r"\d+", "N", message.lower().strip())


def _fingerprint(message: str) -> str:
    """SHA-256 of normalised message, first 16 hex chars (64-bit fingerprint)."""
    normalised = _normalize_message(message)
    return hashlib.sha256(normalised.encode()).hexdigest()[:16]
