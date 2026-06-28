"""models/schemas/v1/health.py — Health check response schema."""
from typing import Dict, Optional
from pydantic import BaseModel


class ComponentStatus(BaseModel):
    status: str                      # "ok" | "degraded" | "down"
    latency_ms: Optional[float] = None
    detail: Optional[str] = None


class HealthResponse(BaseModel):
    status: str                      # "ok" | "degraded" | "down"
    version: str
    components: Dict[str, ComponentStatus]
