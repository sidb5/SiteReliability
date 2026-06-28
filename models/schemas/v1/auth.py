from datetime import datetime
from typing import Optional

from pydantic import BaseModel, field_validator


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access token expiry


class UserResponse(BaseModel):
    id: str
    tenant_id: str
    email: str
    role: str
    active: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}
