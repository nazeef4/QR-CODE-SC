"""Pydantic request/response schemas."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, EmailStr, Field


# ---- onboarding / auth -----------------------------------------------------
class AdminIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    name: str = ""


class OnboardingIn(BaseModel):
    company_name: str = Field(min_length=2, max_length=200)
    admin: AdminIn
    template: str | None = None          # e.g. "pharma-classic"
    hierarchy: dict[str, Any] | None = None  # full custom definition (overrides template)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    company_id: str
    role: str
    user_id: str


class UserCreateIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    name: str = ""
    role: str


class UserOut(BaseModel):
    id: str
    email: str
    name: str
    role: str


# ---- schema / keys ---------------------------------------------------------
class SchemaPutIn(BaseModel):
    name: str = "custom"
    definition: dict[str, Any]


class SchemaOut(BaseModel):
    id: str
    name: str
    version: int
    is_active: bool
    definition: dict[str, Any]


# ---- entities --------------------------------------------------------------
class EntityCreateIn(BaseModel):
    entity_type: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    serial: str | None = None
    schema_id: str | None = None
    parent_id: str | None = None
    territory: list[str] | None = None


class BindingIn(BaseModel):
    parent_id: str


class TransitionIn(BaseModel):
    to_state: str


class EventIn(BaseModel):
    event_type: str
    details: dict[str, Any] = Field(default_factory=dict)
    location_lat: float | None = None
    location_lon: float | None = None
    location_text: str | None = None


class LineageNode(BaseModel):
    id: str
    type: str
    lifecycle_state: str
    serial: str | None = None
    revoked: bool = False


class HopVerification(BaseModel):
    child_id: str
    parent_id: str
    statement_seq: int
    signature_valid: bool
    is_current_binding: bool
    statement_id: str


# ---- scans -----------------------------------------------------------------
class ScanContext(BaseModel):
    lat: float | None = None
    lon: float | None = None
    country: str | None = None
    device_fp: str | None = None
    user_agent: str | None = None


class ScanIn(BaseModel):
    payload: str
    context: ScanContext = Field(default_factory=ScanContext)
