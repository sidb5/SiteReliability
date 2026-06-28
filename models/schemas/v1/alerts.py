"""
models/schemas/v1/alerts.py — Alert list/get/acknowledge schemas.

Cursor pagination:
  Cursor encodes (detected_at ISO, id) of the LAST item returned.
  Next page: WHERE (detected_at, id) < (cursor_detected_at, cursor_id) ORDER BY detected_at DESC, id DESC.
  Stable under concurrent inserts because we paginate backward in time.
"""
import base64
import json
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class AnomalyAlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    source_id: str
    detected_at: datetime
    anomaly_type: str
    severity: str
    service_name: str
    environment: str
    current_value: float
    baseline_value: float
    upper_bound: float
    unit: str
    window_start: datetime
    window_end: datetime
    sample_count: int
    representative_msgs: str   # JSON string
    detection_context: str     # JSON string
    cascade_context: Optional[str]
    full_payload: str          # JSON string — complete v1.0 contract
    status: str
    acknowledged_by: Optional[str]
    acknowledged_at: Optional[datetime]
    resolved_at: Optional[datetime]
    auto_resolved: Optional[bool]
    created_at: datetime


class AnomalyListResponse(BaseModel):
    items: List[AnomalyAlertResponse]
    next_cursor: Optional[str]    # opaque base64 token for next page
    total_returned: int


class AcknowledgeResponse(BaseModel):
    id: str
    status: str
    acknowledged_at: datetime
    acknowledged_by: str


def encode_cursor(detected_at: datetime, alert_id: str) -> str:
    """Encode a cursor from the last item's (detected_at, id) pair."""
    data = {"detected_at": detected_at.isoformat(), "id": alert_id}
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()


def decode_cursor(cursor: str) -> Optional[tuple]:
    """
    Decode a pagination cursor.  Returns (detected_at_str, id) or None on error.
    """
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor).decode())
        return data["detected_at"], data["id"]
    except Exception:
        return None
