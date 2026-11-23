"""SQLAlchemy models — the persistent data model described in docs/05-data-model.md."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Company(Base):
    __tablename__ = "companies"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    settings_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    users: Mapped[list["User"]] = relationship(back_populates="company")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("company_id", "email", name="uq_user_org_email"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"), index=True)
    email: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(40))  # org_admin | operator | distributor | retailer | auditor
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    company: Mapped[Company] = relationship(back_populates="users")


class SigningKey(Base):
    __tablename__ = "signing_keys"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # key id (kid)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"), index=True)
    purpose: Mapped[str] = mapped_column(String(40))  # entity_qr | relationship
    algo: Mapped[str] = mapped_column(String(20), default="Ed25519")
    public_key: Mapped[str] = mapped_column(Text)  # base64url raw 32 B
    private_key_wrapped: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class HierarchySchema(Base):
    __tablename__ = "hierarchy_schemas"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    version: Mapped[int] = mapped_column(Integer, default=1)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    definition_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(40), nullable=True)


class Entity(Base):
    __tablename__ = "entities"
    __table_args__ = (
        Index("ix_entities_org_type", "company_id", "entity_type"),
        Index("ix_entities_parent", "parent_id"),
        UniqueConstraint("company_id", "serial", name="uq_entity_serial"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"), index=True)
    schema_id: Mapped[str] = mapped_column(ForeignKey("hierarchy_schemas.id"))
    entity_type: Mapped[str] = mapped_column(String(60), index=True)
    attributes_json: Mapped[str] = mapped_column(Text, default="{}")
    serial: Mapped[str | None] = mapped_column(String(120), nullable=True)
    parent_id: Mapped[str | None] = mapped_column(String(40), nullable=True)  # current binding
    lifecycle_state: Mapped[str] = mapped_column(String(40), default="registered")
    payload_seq: Mapped[int] = mapped_column(Integer, default=1)
    current_kid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    territory_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(40), nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RelationshipStatement(Base):
    """Append-only, signed child→parent statements (the cryptographic spine)."""

    __tablename__ = "relationship_statements"
    __table_args__ = (
        Index("ix_stmt_child_seq", "child_id", "seq"),
        Index("ix_stmt_org", "company_id"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"))
    child_id: Mapped[str] = mapped_column(String(40))
    parent_id: Mapped[str | None] = mapped_column(String(40), nullable=True)  # null for unbind
    op: Mapped[str] = mapped_column(String(16))  # bind | unbind
    seq: Mapped[int] = mapped_column(Integer)
    ts: Mapped[str] = mapped_column(String(40))
    kid: Mapped[str] = mapped_column(String(64))
    statement_json: Mapped[str] = mapped_column(Text)
    signature: Mapped[str] = mapped_column(Text)
    actor_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SupplyEvent(Base):
    __tablename__ = "supply_events"
    __table_args__ = (Index("ix_events_entity_ts", "entity_id", "ts"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    company_id: Mapped[str] = mapped_column(ForeignKey("companies.id"))
    entity_id: Mapped[str] = mapped_column(String(40))
    event_type: Mapped[str] = mapped_column(String(60))  # packed|dispatched|received|sold|recalled|…
    ts: Mapped[str] = mapped_column(String(40))
    actor_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    location_lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    location_lon: Mapped[float | None] = mapped_column(Float, nullable=True)
    location_text: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_entity_ts", "entity_id", "ts"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    company_id: Mapped[str] = mapped_column(String(40), index=True)
    entity_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    lon: Mapped[float | None] = mapped_column(Float, nullable=True)
    country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    device_fp: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(400), nullable=True)
    verdict: Mapped[str] = mapped_column(String(20))  # authentic|suspicious|invalid|revoked
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    flags_json: Mapped[str] = mapped_column(Text, default="[]")
    is_first_scan: Mapped[bool] = mapped_column(Boolean, default=False)
    payload_prefix: Mapped[str | None] = mapped_column(String(80), nullable=True)


class AuditLog(Base):
    """Hash-chained, append-only audit trail (tamper-evident, per company)."""

    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_org_id", "company_id", "id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    company_id: Mapped[str] = mapped_column(String(40))
    ts: Mapped[str] = mapped_column(String(40))
    actor_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    actor_role: Mapped[str | None] = mapped_column(String(40), nullable=True)
    action: Mapped[str] = mapped_column(String(80))
    subject_type: Mapped[str] = mapped_column(String(40))
    subject_id: Mapped[str] = mapped_column(String(64))
    data_json: Mapped[str] = mapped_column(Text, default="{}")
    prev_hash: Mapped[str] = mapped_column(String(64))
    row_hash: Mapped[str] = mapped_column(String(64))
