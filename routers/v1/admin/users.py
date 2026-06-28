"""
routers/v1/admin/users.py — Tenant user management (Tenant Admin only).

POST   /api/v1/admin/users          create / invite user within tenant
GET    /api/v1/admin/users          list users in tenant
PATCH  /api/v1/admin/users/{id}     update user (active, role)
DELETE /api/v1/admin/users/{id}     soft-delete (deactivate) user

Security:
  - All queries scoped to ctx.tenant_id.
  - Tenant Admin cannot promote users to platform_admin.
  - Tenant Admin cannot deactivate themselves.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db
from models.db import User
from models.schemas.v1.admin import UserCreateRequest, UserResponse, UserUpdateRequest
from security import Role, TenantContext, hash_password, require_role

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/users", tags=["admin-users"])


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreateRequest,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_ADMIN)),
) -> UserResponse:
    existing = db.query(User).filter(User.email == body.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "EMAIL_EXISTS", "message": "A user with this email already exists"},
        )

    user = User(
        tenant_id=ctx.tenant_id,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
        active=True,
        created_by=ctx.user_id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info("user created", extra={
        "new_user_id": user.id, "tenant_id": ctx.tenant_id, "created_by": ctx.user_id
    })
    return UserResponse.model_validate(user)


@router.get("", response_model=list[UserResponse])
async def list_users(
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_ADMIN)),
) -> list[UserResponse]:
    users = (
        db.query(User)
        .filter(
            User.tenant_id == ctx.tenant_id,
            User.deleted_at.is_(None),
        )
        .order_by(User.created_at.desc())
        .all()
    )
    return [UserResponse.model_validate(u) for u in users]


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    body: UserUpdateRequest,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_ADMIN)),
) -> UserResponse:
    user = _get_or_404(user_id, ctx.tenant_id, db)

    if body.active is not None:
        if user_id == ctx.user_id and body.active is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "CANNOT_DEACTIVATE_SELF", "message": "Cannot deactivate your own account"},
            )
        user.active = body.active

    if body.role is not None:
        user.role = body.role

    db.commit()
    db.refresh(user)
    return UserResponse.model_validate(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_role(Role.TENANT_ADMIN)),
) -> None:
    if user_id == ctx.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "CANNOT_DELETE_SELF", "message": "Cannot delete your own account"},
        )
    user = _get_or_404(user_id, ctx.tenant_id, db)
    from datetime import datetime, timezone
    user.deleted_at = datetime.now(timezone.utc)
    user.active = False
    db.commit()


def _get_or_404(user_id: str, tenant_id: str, db: Session) -> User:
    user = (
        db.query(User)
        .filter(
            User.id == user_id,
            User.tenant_id == tenant_id,
            User.deleted_at.is_(None),
        )
        .first()
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "USER_NOT_FOUND", "message": "User not found"},
        )
    return user
