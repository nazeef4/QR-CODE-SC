"""Auth endpoints: login, session introspection, user management."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crypto, security
from ..db import get_db
from ..models import User
from ..schemas import LoginIn, TokenOut, UserCreateIn, UserOut

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

ALLOWED_ROLES = {"org_admin", "operator", "distributor", "retailer", "auditor"}


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if user is None or not security.verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    if user.disabled:
        raise HTTPException(403, "Account disabled")
    return TokenOut(
        access_token=security.create_access_token(user),
        company_id=user.company_id,
        role=user.role,
        user_id=user.id,
    )


@router.get("/me")
def me(user: User = Depends(security.get_current_user)):
    return UserOut(id=user.id, email=user.email, name=user.name, role=user.role)


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreateIn,
    db: Session = Depends(get_db),
    actor: User = Depends(security.require_perms("user.manage")),
):
    if body.role not in ALLOWED_ROLES:
        raise HTTPException(400, f"role must be one of {sorted(ALLOWED_ROLES)}")
    exists = db.scalar(
        select(User).where(
            User.company_id == actor.company_id, User.email == body.email.lower()
        )
    )
    if exists:
        raise HTTPException(409, "Email already registered in this company")
    user = User(
        id=crypto.new_id("usr"),
        company_id=actor.company_id,
        email=body.email.lower(),
        name=body.name,
        password_hash=security.hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    db.flush()
    audit.record(
        db,
        company_id=actor.company_id,
        action="user.create",
        subject_type="user",
        subject_id=user.id,
        data={"email": user.email, "role": body.role},
        actor_id=actor.id,
        actor_role=actor.role,
    )
    db.commit()
    return UserOut(id=user.id, email=user.email, name=user.name, role=user.role)
