"""
security.py — Authentication, authorisation, and cryptographic primitives.

Security invariants enforced in this file:
- API key plaintext is NEVER logged, stored, or returned after generation.
  Only SHA-256(plaintext) is persisted.  Only api_key_id (UUID) appears in logs.
- Authorization header value is NEVER logged.
- JWT uses RS256 asymmetric signing (private key signs, public key verifies).
- Secrets at rest (webhook signing secrets, DB connection strings) use Fernet
  symmetric encryption — not hashing, because we must retrieve them for use.
- TenantContext is always derived from verified credentials, never from raw
  request parameters. This eliminates IDOR by design.
"""
import hashlib
import json
import logging
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional

import bcrypt
import jwt
from cryptography.fernet import InvalidToken  # re-exported for callers  # noqa: F401
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from config import settings
from database import get_db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Role definitions
# ---------------------------------------------------------------------------

class Role(str, Enum):
    PLATFORM_ADMIN = "platform_admin"
    TENANT_ADMIN = "tenant_admin"
    TENANT_OPERATOR = "tenant_operator"


# Hierarchy for tenant roles only. PLATFORM_ADMIN is intentionally absent —
# it has its own endpoints and must NOT pass tenant-role guards.
_TENANT_ROLE_HIERARCHY: dict[Role, int] = {
    Role.TENANT_OPERATOR: 0,
    Role.TENANT_ADMIN: 1,
}


# ---------------------------------------------------------------------------
# TenantContext
# ---------------------------------------------------------------------------

@dataclass
class TenantContext:
    tenant_id: str
    user_id: Optional[str]       # None when authenticated via API key
    api_key_id: Optional[str]    # None when authenticated via JWT
    role: Role
    scopes: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Password hashing (bcrypt, cost 12)
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ---------------------------------------------------------------------------
# JWT — RS256 asymmetric signing
# ---------------------------------------------------------------------------

def create_access_token(user_id: str, tenant_id: str, role: str, email: str = "") -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "tenant_id": tenant_id,
        "role": role,
        "type": "access",
        "jti": str(uuid.uuid4()),   # unique per token — prevents hash collisions
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.get_jwt_private_key(), algorithm="RS256")


def create_refresh_token(user_id: str, tenant_id: str) -> str:
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "type": "refresh",
        "jti": str(uuid.uuid4()),   # unique per token — each refresh token has distinct hash
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, settings.get_jwt_private_key(), algorithm="RS256")


def decode_token(token: str) -> dict:
    """
    Decode and verify a JWT. Raises:
    - jwt.ExpiredSignatureError  if the token is past its exp claim
    - jwt.InvalidTokenError      for any other structural/signature failure
    """
    return jwt.decode(token, settings.get_jwt_public_key(), algorithms=["RS256"])


def hash_refresh_token(token: str) -> str:
    """SHA-256 of a refresh token string — used for DB lookup and revocation."""
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------------------
# API key — SHA-256 hashing (one-way, for O(1) lookup)
# ---------------------------------------------------------------------------

def generate_api_key(environment: str = "live") -> tuple[str, str]:
    """
    Mint a new API key.
    Returns (plaintext, sha256_hash).
    NEVER persist the plaintext — return it once to the caller, then discard.
    """
    plaintext = f"wdog_{environment}_{secrets.token_urlsafe(32)}"
    return plaintext, hash_api_key(plaintext)


def hash_api_key(key: str) -> str:
    """SHA-256 of an API key. This hash is what gets stored and looked up."""
    return hashlib.sha256(key.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Fernet encryption (two-way — must retrieve webhook secrets, connection strings)
# ---------------------------------------------------------------------------

def encrypt(value: str) -> str:
    """Fernet-encrypt a string. Returns base64-encoded ciphertext."""
    return settings.get_fernet().encrypt(value.encode()).decode()


def decrypt(encrypted: str) -> str:
    """
    Fernet-decrypt a ciphertext string.
    Raises cryptography.fernet.InvalidToken if the ciphertext was tampered with.
    """
    return settings.get_fernet().decrypt(encrypted.encode()).decode()


# ---------------------------------------------------------------------------
# TenantContext dependency
# ---------------------------------------------------------------------------

async def get_tenant_context(
    request: Request,
    db: Session = Depends(get_db),
) -> TenantContext:
    """
    FastAPI dependency.  Extracts and validates the caller's identity from:
      1. Authorization: Bearer <JWT>  — human operator (JWT auth)
      2. X-API-Key: <key>             — machine consumer (API key auth)

    Returns a TenantContext whose tenant_id is guaranteed to come from the
    verified credential — never from request parameters or body.
    """
    # Lazy import to avoid circular dependency at module load time
    from models.db import ApiKey, User

    auth_header = request.headers.get("Authorization", "")

    # ------------------------------------------------------------------
    # Path 1: JWT bearer token
    # ------------------------------------------------------------------
    if auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ")
        try:
            payload = decode_token(token)
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "TOKEN_EXPIRED", "message": "Access token has expired"},
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "TOKEN_INVALID", "message": "Access token is invalid"},
            )

        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "TOKEN_INVALID", "message": "Token is not an access token"},
            )

        user = (
            db.query(User)
            .filter(
                User.id == payload["sub"],
                User.active == True,
                User.deleted_at == None,
            )
            .first()
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "USER_NOT_FOUND", "message": "User not found or inactive"},
            )

        ctx = TenantContext(
            tenant_id=user.tenant_id,
            user_id=user.id,
            api_key_id=None,
            role=Role(user.role),
            scopes=[],
        )
        request.state.tenant_context = ctx
        return ctx

    # ------------------------------------------------------------------
    # Path 2: API key
    # SECURITY: The plaintext value is consumed exactly once to compute
    # the hash.  It is never stored in a variable that outlives this block,
    # never logged, and never included in any error response.
    # ------------------------------------------------------------------
    raw_key = request.headers.get("X-API-Key", "")
    if raw_key:
        key_hash = hash_api_key(raw_key)
        # raw_key is no longer referenced after this line

        key_row = db.query(ApiKey).filter(ApiKey.key_hash == key_hash).first()
        if not key_row:
            logger.warning("API key authentication failed: hash not found")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "KEY_INVALID", "message": "API key is not valid"},
            )

        now = datetime.utcnow()

        if key_row.revoked_at is not None:
            logger.warning("Revoked API key used", extra={"api_key_id": key_row.id})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "KEY_REVOKED", "message": "API key has been revoked"},
            )

        if key_row.expires_at is not None and key_row.expires_at < now:
            logger.warning("Expired API key used", extra={"api_key_id": key_row.id})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "KEY_EXPIRED", "message": "API key has expired"},
            )

        # A key in its 24-hour grace period (rotated but not yet auto-revoked)
        # is still valid. Once the grace period ends it is effectively revoked.
        if (
            key_row.grace_period_ends_at is not None
            and key_row.grace_period_ends_at < now
        ):
            logger.warning(
                "Grace-period-expired API key used", extra={"api_key_id": key_row.id}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "KEY_REVOKED", "message": "API key grace period has expired"},
            )

        # Only the UUID is logged — never the plaintext key
        logger.info("API key authenticated", extra={"api_key_id": key_row.id})

        scopes: List[str] = json.loads(key_row.scopes) if key_row.scopes else []

        ctx = TenantContext(
            tenant_id=key_row.tenant_id,
            user_id=None,
            api_key_id=key_row.id,
            role=Role.TENANT_OPERATOR,
            scopes=scopes,
        )
        request.state.tenant_context = ctx
        return ctx

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "NOT_AUTHENTICATED", "message": "No credentials provided"},
    )


# ---------------------------------------------------------------------------
# Authorisation guard factories
# ---------------------------------------------------------------------------

def require_role(minimum_role: Role):
    """
    FastAPI dependency factory — enforces a minimum tenant role.

    PLATFORM_ADMIN is deliberately excluded from the tenant role hierarchy.
    Platform Admins access data through /platform/* endpoints, not through
    tenant-scoped endpoints.  Passing require_role(TENANT_ADMIN) will reject
    a Platform Admin, which is the correct behaviour.
    """
    async def _guard(ctx: TenantContext = Depends(get_tenant_context)) -> TenantContext:
        level = _TENANT_ROLE_HIERARCHY.get(ctx.role, -1)
        required = _TENANT_ROLE_HIERARCHY.get(minimum_role, -1)
        if level < required:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "INSUFFICIENT_ROLE",
                    "message": f"Requires {minimum_role.value} or higher",
                },
            )
        return ctx
    return _guard


def require_platform_admin():
    """FastAPI dependency — ensures the caller is a Platform Admin."""
    async def _guard(ctx: TenantContext = Depends(get_tenant_context)) -> TenantContext:
        if ctx.role != Role.PLATFORM_ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "PLATFORM_ADMIN_REQUIRED"},
            )
        return ctx
    return _guard


def require_scope(scope: str):
    """
    FastAPI dependency factory — enforces an API key scope.

    JWT-authenticated users (human operators) bypass scope checks entirely;
    their access is governed by role.  Only API key callers are scope-restricted.
    """
    async def _guard(ctx: TenantContext = Depends(get_tenant_context)) -> TenantContext:
        if ctx.api_key_id is not None and scope not in ctx.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "INSUFFICIENT_SCOPE",
                    "message": f"API key missing required scope: {scope}",
                },
            )
        return ctx
    return _guard
