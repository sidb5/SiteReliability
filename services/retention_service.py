"""
services/retention_service.py — Hourly cleanup jobs.

Two background tasks:
  retention_loop()  — delete old resolved/acknowledged alerts, webhook events,
                      and request logs per tenant's configured retention days.
                      Open alerts are NEVER auto-deleted regardless of age.
  key_expiry_loop() — mark expired API keys as revoked; mark grace-period-
                      expired keys as revoked.

Both loops run every 3600s (1 hour). Errors are logged and swallowed so a
single tenant's bad data never kills the cleanup for all tenants.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

UTC = timezone.utc


class RetentionService:
    def __init__(self, session_factory=None) -> None:
        self._session_factory = session_factory

    def set_session_factory(self, factory) -> None:
        self._session_factory = factory

    # ------------------------------------------------------------------
    # Background loops
    # ------------------------------------------------------------------

    async def retention_loop(self) -> None:
        """Runs hourly.  Deletes aged-out alerts, webhook events, request logs."""
        while True:
            await asyncio.sleep(3600)
            if self._session_factory is None:
                continue
            db = self._session_factory()
            try:
                self._run_retention(db)
                db.commit()
            except Exception as exc:
                db.rollback()
                logger.error("retention_loop error", extra={"error": str(exc)})
            finally:
                db.close()

    async def key_expiry_loop(self) -> None:
        """Runs hourly.  Marks expired and grace-period-expired API keys as revoked."""
        while True:
            await asyncio.sleep(3600)
            if self._session_factory is None:
                continue
            db = self._session_factory()
            try:
                self._run_key_expiry(db)
                db.commit()
            except Exception as exc:
                db.rollback()
                logger.error("key_expiry_loop error", extra={"error": str(exc)})
            finally:
                db.close()

    # ------------------------------------------------------------------
    # Synchronous workers (called from loops, also directly testable)
    # ------------------------------------------------------------------

    def _run_retention(self, db: Session) -> None:
        from models.db import AnomalyAlert, Tenant, WebhookEvent, RequestLog

        tenants = db.query(Tenant).filter(Tenant.active.is_(True)).all()
        for tenant in tenants:
            try:
                self._clean_tenant(db, tenant)
            except Exception as exc:
                logger.error(
                    "retention cleanup failed for tenant",
                    extra={"tenant_id": tenant.id, "error": str(exc)},
                )

    def _clean_tenant(self, db: Session, tenant) -> None:
        from models.db import AnomalyAlert, WebhookEvent, RequestLog

        now = datetime.now(UTC)

        # Alerts: only resolved or acknowledged; never open
        alert_cutoff = now - timedelta(days=tenant.retention_days)
        deleted_alerts = (
            db.query(AnomalyAlert)
            .filter(
                AnomalyAlert.tenant_id == tenant.id,
                AnomalyAlert.status.in_(["resolved", "acknowledged"]),
                AnomalyAlert.created_at < alert_cutoff,
            )
            .delete(synchronize_session=False)
        )

        # Webhook events
        wh_cutoff = now - timedelta(days=tenant.retention_days)
        deleted_wh = (
            db.query(WebhookEvent)
            .filter(
                WebhookEvent.tenant_id == tenant.id,
                WebhookEvent.created_at < wh_cutoff,
            )
            .delete(synchronize_session=False)
        )

        # Request logs
        log_cutoff = now - timedelta(days=tenant.log_retention_days)
        deleted_logs = (
            db.query(RequestLog)
            .filter(
                RequestLog.tenant_id == tenant.id,
                RequestLog.timestamp < log_cutoff,
            )
            .delete(synchronize_session=False)
        )

        if deleted_alerts or deleted_wh or deleted_logs:
            logger.info(
                "retention cleanup complete",
                extra={
                    "tenant_id": tenant.id,
                    "alerts_deleted": deleted_alerts,
                    "webhook_events_deleted": deleted_wh,
                    "request_logs_deleted": deleted_logs,
                },
            )

    def _run_key_expiry(self, db: Session) -> None:
        from models.db import ApiKey

        now = datetime.now(UTC)

        # Keys past their expiry date
        expired = (
            db.query(ApiKey)
            .filter(
                ApiKey.revoked_at.is_(None),
                ApiKey.expires_at.isnot(None),
                ApiKey.expires_at < now,
            )
            .all()
        )
        for key in expired:
            key.revoked_at = now
            logger.info("api key expired", extra={"api_key_id": key.id})

        # Keys whose 24-hour grace period has elapsed
        grace_expired = (
            db.query(ApiKey)
            .filter(
                ApiKey.revoked_at.is_(None),
                ApiKey.grace_period_ends_at.isnot(None),
                ApiKey.grace_period_ends_at < now,
            )
            .all()
        )
        for key in grace_expired:
            key.revoked_at = now
            logger.info("api key grace period expired", extra={"api_key_id": key.id})
