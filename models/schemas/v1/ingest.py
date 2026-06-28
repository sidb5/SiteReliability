"""
models/schemas/v1/ingest.py — Request/response schemas for the push ingest endpoint.

Design notes:
  - Raw log entries are NEVER persisted to the database.  They flow directly to
    the anomaly engine.  LogEntryResponse.id is a request-scoped correlation ID,
    not a database primary key.
  - level is validated at the API boundary against a fixed set so callers get
    useful 422s for garbage values.  UNKNOWN is a valid explicit value.
  - occurred_at defaults to the server's UTC clock if the caller omits it, but
    a future timestamp from the caller is accepted as-is (the client's clock
    authority over when the event occurred).
  - BatchIngestRequest validates all entries before any processing; one invalid
    entry rejects the entire batch (transactional).
"""
from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

_VALID_LEVELS = frozenset({"ERROR", "WARNING", "INFO", "DEBUG", "TRACE", "CRITICAL", "UNKNOWN"})

_BATCH_MAX = 500


class LogEntryRequest(BaseModel):
    message: str = Field(..., min_length=1)
    level: str = Field(default="INFO")
    # default_factory runs at request time so every entry gets the server's current
    # UTC clock when the caller omits occurred_at.  A future timestamp from the
    # caller is accepted as-is — the client is authoritative over event occurrence.
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    service_name: Optional[str] = Field(default=None)
    latency_ms: Optional[float] = Field(default=None, ge=0)
    metadata: Optional[dict] = Field(default=None)

    @field_validator("level")
    @classmethod
    def level_must_be_known(cls, v: str) -> str:
        upper = v.upper()
        if upper not in _VALID_LEVELS:
            raise ValueError(
                f"level must be one of {sorted(_VALID_LEVELS)!r}, got {v!r}"
            )
        return upper


class LogEntryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str                          # correlation UUID for this request; NOT a DB PK
    tenant_id: str
    received_at: datetime
    status: Literal["accepted"] = "accepted"


class BatchIngestRequest(BaseModel):
    entries: list[LogEntryRequest] = Field(..., min_length=1, max_length=_BATCH_MAX)


class BatchIngestResponse(BaseModel):
    accepted: int
    status: Literal["accepted"] = "accepted"
