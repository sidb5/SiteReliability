"""
models/schemas/v1/webhook.py — Request/response schemas for webhook operations.

Module 7:
  WebhookSetRequest   — attach a webhook URL to an API key
  WebhookResponse     — API key webhook config (URL, filters; secret never returned)
  DeliveryRecord      — one row from webhook_events
  DeliveryListResponse — paginated delivery history
  WebhookReceiveResponse — response for the simulated consumer endpoint
"""
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, HttpUrl, field_validator


class WebhookSetRequest(BaseModel):
    """Attach or update a webhook on an API key.  Secret is generated server-side."""
    webhook_url: str
    severity_filter: Optional[str] = None    # None = all severities
    service_filter: Optional[str] = None     # None = all services

    @field_validator("webhook_url")
    @classmethod
    def url_must_be_https_or_http(cls, v: str) -> str:
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("webhook_url must start with http:// or https://")
        return v

    @field_validator("severity_filter")
    @classmethod
    def valid_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in {"WARNING", "CRITICAL"}:
            raise ValueError("severity_filter must be WARNING, CRITICAL, or null")
        return v


class WebhookResponse(BaseModel):
    """Webhook config for an API key.  Secret is never returned after creation."""
    model_config = ConfigDict(from_attributes=True)

    api_key_id: str
    webhook_url: Optional[str]
    severity_filter: Optional[str]
    service_filter: Optional[str]
    has_secret: bool


class DeliveryRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_id: str
    attempt_number: int
    sent_at: datetime
    target_url: str
    delivery_id: str
    response_status: Optional[int]
    latency_ms: Optional[int]
    success: bool
    next_retry_at: Optional[datetime]
    created_at: datetime


class DeliveryListResponse(BaseModel):
    items: List[DeliveryRecord]
    total: int


class WebhookReceiveResponse(BaseModel):
    received: bool
    delivery_id: str
    event_type: str
