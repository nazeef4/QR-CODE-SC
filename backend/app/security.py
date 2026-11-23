"""Authentication, session tokens and RBAC dependencies.

Roles (docs/07-roles-and-permissions.md):
  org_admin   – full control of the company tenant: schema, keys, users, recalls
  operator    – manufacturing/packing: register entities, bind, print, transition
  distributor – logistics: dispatch/receive events, limited transitions
  retailer    – point of sale: receive, sell, verify
  auditor     – read-only across everything including the audit chain
  (consumer)  – no account; public POST /api/v1/scans only
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import JWT_SECRET, JWT_TTL_SECONDS
from .db import get_db
from .models import User

ROLE_MATRIX: dict[str, set[str]] = {
    "org_admin": {
        "company.read", "company.update", "schema.read", "schema.write",
        "key.rotate", "user.manage", "entity.read", "entity.register",
        "entity.print", "binding.create", "binding.remove", "lifecycle.transition",
        "event.create", "scan.read", "alert.read", "audit.read",
    },
    "operator": {
        "company.read", "schema.read", "entity.read", "entity.register",
        "entity.print", "binding.create", "lifecycle.transition", "event.create",
        "scan.read", "alert.read",
    },
    "distributor": {
        "company.read", "schema.read", "entity.read", "event.create",
        "lifecycle.transition", "scan.read",
    },
    "retailer": {
        "company.read", "schema.read", "entity.read", "event.create",
        "lifecycle.transition", "scan.read",
    },
    "auditor": {
        "company.read", "schema.read", "entity.read", "scan.read",
        "alert.read", "audit.read",
    },
}

bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    import hashlib
    import secrets

    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"pbkdf2_sha256$200000${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    import hashlib

    try:
        _, rounds, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds)
        )
        return dk.hex() == dk_hex
    except (ValueError, TypeError):
        return False


def create_access_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": user.id,
        "org": user.company_id,
        "role": user.role,
        "email": user.email,
        "iat": now,
        "exp": now + timedelta(seconds=JWT_TTL_SECONDS),
        "iss": "scqr",
    }
    return jwt.encode(claims, JWT_SECRET, algorithm="HS256")


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    try:
        claims = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"], issuer="scqr")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    user = db.get(User, claims.get("sub", ""))
    if user is None or user.disabled:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or disabled user")
    return user


def require_perms(*perms: str):
    """Dependency factory: caller must hold *every* listed permission."""

    def _dep(user: User = Depends(get_current_user)) -> User:
        granted = ROLE_MATRIX.get(user.role, set())
        missing = [p for p in perms if p not in granted]
        if missing:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Role '{user.role}' lacks permission: {', '.join(missing)}",
            )
        return user

    return _dep


def same_company(user: User, company_id: str) -> None:
    if user.company_id != company_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cross-tenant access denied")
