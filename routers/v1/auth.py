"""
routers/v1/auth.py — Authentication endpoints.

POST /api/v1/auth/login   — issue access token + httpOnly refresh cookie
POST /api/v1/auth/logout  — revoke refresh token, clear cookie
POST /api/v1/auth/refresh — exchange valid refresh cookie for new access token

Security invariants:
- Unknown email returns 401 with identical body to wrong password (no enumeration)
- Refresh token stored only as SHA-256 hash in DB (never plaintext)
- Refresh cookie: HttpOnly, SameSite=Strict — not accessible from JavaScript
- Rate limited: 10 requests/minute per client IP
"""
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from limiter import limiter
from models.db import RefreshToken, User
from models.schemas.v1.auth import LoginRequest, TokenResponse
from security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)

# Dummy bcrypt hash used when the email is unknown.  verify_password() is
# always called so the response time is indistinguishable from a wrong
# password on a real account — prevents email-enumeration via timing.
_DUMMY_HASH: str = hash_password("__dummy_never_matches__")

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

_INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail={"code": "INVALID_CREDENTIALS", "message": "Invalid email or password"},
)

_REFRESH_COOKIE = "refresh_token"
_REFRESH_COOKIE_PATH = "/api/v1/auth"


@router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def login(
    request: Request,
    body: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """
    Authenticate with email + password.
    Returns an RS256 access token (15 min) in the body and sets a 7-day
    httpOnly refresh token cookie.  Unknown email and wrong password return
    identical 401s — no information about which email addresses exist.
    """
    user = (
        db.query(User)
        .filter(
            User.email == body.email,
            User.active == True,
            User.deleted_at == None,
        )
        .first()
    )

    # Always run bcrypt regardless of whether the user was found.
    # This keeps the response time constant — an attacker cannot distinguish
    # "email not found" from "wrong password" via timing.
    candidate_hash = user.password_hash if user is not None else _DUMMY_HASH
    if not verify_password(body.password, candidate_hash) or user is None:
        raise _INVALID_CREDENTIALS

    # Issue tokens
    access_token = create_access_token(user.id, user.tenant_id, user.role, user.email)
    raw_refresh = create_refresh_token(user.id, user.tenant_id)
    token_hash = hash_refresh_token(raw_refresh)

    db.add(
        RefreshToken(
            user_id=user.id,
            tenant_id=user.tenant_id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
        )
    )

    user.last_login_at = datetime.utcnow()
    db.commit()

    response.set_cookie(
        key=_REFRESH_COOKIE,
        value=raw_refresh,
        httponly=True,
        samesite="strict",
        path=_REFRESH_COOKIE_PATH,
        max_age=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )

    return TokenResponse(
        access_token=access_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    db: Session = Depends(get_db),
    refresh_token: str | None = Cookie(default=None),
) -> None:
    """
    Revoke the refresh token from the httpOnly cookie and clear the cookie.
    Safe to call even if the cookie is absent or already revoked.
    """
    if refresh_token:
        token_hash = hash_refresh_token(refresh_token)
        row = (
            db.query(RefreshToken)
            .filter(RefreshToken.token_hash == token_hash, RefreshToken.revoked_at == None)
            .first()
        )
        if row:
            row.revoked_at = datetime.utcnow()
            db.commit()

    response.delete_cookie(key=_REFRESH_COOKIE, path=_REFRESH_COOKIE_PATH)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    db: Session = Depends(get_db),
    refresh_token: str | None = Cookie(default=None),
) -> TokenResponse:
    """
    Exchange a valid httpOnly refresh cookie for a new access token.
    Does NOT rotate the refresh token — the same cookie remains valid until
    it expires or is explicitly revoked via /logout.
    """
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "REFRESH_TOKEN_MISSING", "message": "No refresh token cookie"},
        )

    token_hash = hash_refresh_token(refresh_token)
    now = datetime.utcnow()

    row = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked_at == None,
            RefreshToken.expires_at > now,
        )
        .first()
    )

    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "REFRESH_TOKEN_INVALID", "message": "Refresh token is invalid or expired"},
        )

    user = db.query(User).filter(User.id == row.user_id, User.active == True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "USER_NOT_FOUND", "message": "User no longer active"},
        )

    access_token = create_access_token(user.id, user.tenant_id, user.role, user.email)

    return TokenResponse(
        access_token=access_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
