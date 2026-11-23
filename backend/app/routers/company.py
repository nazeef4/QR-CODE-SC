"""Company-scoped admin endpoints: hierarchy schema, keys, alerts, audit chain."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crypto, security, service
from ..config import MASTER_KEY
from ..db import get_db
from ..hierarchy import TEMPLATES, validate_definition
from ..models import (
    AuditLog,
    Company,
    Entity,
    HierarchySchema,
    Scan,
    SigningKey,
    SupplyEvent,
    User,
)
from ..schemas import SchemaOut, SchemaPutIn

router = APIRouter(prefix="/api/v1/companies", tags=["company"])


def _company_or_403(db: Session, user: User, cid: str) -> Company:
    security.same_company(user, cid)
    company = db.get(Company, cid)
    if company is None:
        raise HTTPException(404, "Company not found")
    return company


# --------------------------------------------------------------------------- #
# Hierarchy schema
# --------------------------------------------------------------------------- #
@router.get("/{cid}/schema", response_model=SchemaOut)
def get_active_schema(
    cid: str,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("schema.read")),
):
    _company_or_403(db, user, cid)
    row = db.scalar(
        select(HierarchySchema)
        .where(HierarchySchema.company_id == cid, HierarchySchema.is_active.is_(True))
        .order_by(HierarchySchema.version.desc())
    )
    if row is None:
        raise HTTPException(409, "No active schema")
    return SchemaOut(
        id=row.id,
        name=row.name,
        version=row.version,
        is_active=row.is_active,
        definition=json.loads(row.definition_json),
    )


@router.get("/{cid}/schemas", response_model=list[SchemaOut])
def list_schemas(
    cid: str,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("schema.read")),
):
    _company_or_403(db, user, cid)
    rows = db.scalars(
        select(HierarchySchema)
        .where(HierarchySchema.company_id == cid)
        .order_by(HierarchySchema.version.desc())
    ).all()
    return [
        SchemaOut(
            id=r.id, name=r.name, version=r.version, is_active=r.is_active,
            definition=json.loads(r.definition_json),
        )
        for r in rows
    ]


@router.put("/{cid}/schema", response_model=SchemaOut)
def put_schema(
    cid: str,
    body: SchemaPutIn,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("schema.write")),
):
    """Publish a new schema version. Existing entities keep the schema they
    were created under; new registrations use the new active schema."""
    _company_or_403(db, user, cid)
    errors = validate_definition(body.definition)
    if errors:
        raise HTTPException(400, {"schema_errors": errors})
    current = db.scalar(
        select(HierarchySchema)
        .where(HierarchySchema.company_id == cid, HierarchySchema.is_active.is_(True))
        .order_by(HierarchySchema.version.desc())
    )
    next_version = (current.version + 1) if current else 1
    if current:
        current.is_active = False
    row = HierarchySchema(
        id=crypto.new_id("sch"),
        company_id=cid,
        name=body.name,
        version=next_version,
        is_active=True,
        definition_json=json.dumps(body.definition, sort_keys=True),
        created_by=user.id,
    )
    db.add(row)
    db.flush()
    audit.record(
        db,
        company_id=cid,
        action="schema.publish",
        subject_type="schema",
        subject_id=row.id,
        data={"name": body.name, "version": next_version},
        actor_id=user.id,
        actor_role=user.role,
    )
    db.commit()
    return SchemaOut(
        id=row.id, name=row.name, version=row.version, is_active=True,
        definition=body.definition,
    )


# --------------------------------------------------------------------------- #
# Signing keys
# --------------------------------------------------------------------------- #
@router.get("/{cid}/keys")
def list_keys(
    cid: str,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("key.rotate")),
):
    _company_or_403(db, user, cid)
    rows = db.scalars(
        select(SigningKey).where(SigningKey.company_id == cid).order_by(SigningKey.created_at)
    ).all()
    return [
        {
            "kid": r.id,
            "purpose": r.purpose,
            "algo": r.algo,
            "public_key": r.public_key,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
        }
        for r in rows
    ]


@router.post("/{cid}/keys/rotate")
def rotate_key(
    cid: str,
    purpose: str = Query(pattern="^(entity_qr|relationship)$"),
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("key.rotate")),
):
    """Create a new signing key. Previous keys remain available for
    verification of already-printed codes/statements (rotation ≠ revocation)."""
    _company_or_403(db, user, cid)
    pub, priv = crypto.generate_keypair()
    short = cid.split("_")[1][:8]
    kid = f"kid_{short}_{purpose}_{pub[:10]}"
    row = SigningKey(
        id=kid,
        company_id=cid,
        purpose=purpose,
        public_key=pub,
        private_key_wrapped=crypto.wrap_private_key(priv, MASTER_KEY),
    )
    db.add(row)
    db.flush()
    service.clear_key_cache()
    audit.record(
        db,
        company_id=cid,
        action="key.rotate",
        subject_type="signing_key",
        subject_id=kid,
        data={"purpose": purpose},
        actor_id=user.id,
        actor_role=user.role,
    )
    db.commit()
    return {"kid": kid, "purpose": purpose, "note": "old keys remain valid for verification"}


# --------------------------------------------------------------------------- #
# Alerts & statistics
# --------------------------------------------------------------------------- #
@router.get("/{cid}/alerts")
def alerts(
    cid: str,
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("alert.read")),
):
    _company_or_403(db, user, cid)
    rows = db.scalars(
        select(Scan)
        .where(Scan.company_id == cid, Scan.verdict != "authentic")
        .order_by(Scan.ts.desc())
        .limit(limit)
    ).all()
    return [
        {
            "scan_id": s.id,
            "entity_id": s.entity_id,
            "ts": s.ts.isoformat(),
            "verdict": s.verdict,
            "risk_score": s.risk_score,
            "flags": json.loads(s.flags_json),
            "lat": s.lat,
            "lon": s.lon,
            "country": s.country,
        }
        for s in rows
    ]


@router.get("/{cid}/stats")
def stats(
    cid: str,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("company.read")),
):
    _company_or_403(db, user, cid)
    entities = db.scalars(select(Entity).where(Entity.company_id == cid)).all()
    scans = db.scalars(select(Scan).where(Scan.company_id == cid)).all()
    events = db.scalars(select(SupplyEvent).where(SupplyEvent.company_id == cid)).all()
    by_type: dict[str, int] = {}
    by_state: dict[str, int] = {}
    for e in entities:
        by_type[e.entity_type] = by_type.get(e.entity_type, 0) + 1
        by_state[e.lifecycle_state] = by_state.get(e.lifecycle_state, 0) + 1
    by_verdict: dict[str, int] = {}
    for s in scans:
        by_verdict[s.verdict] = by_verdict.get(s.verdict, 0) + 1
    return {
        "entities_total": len(entities),
        "entities_by_type": by_type,
        "entities_by_state": by_state,
        "scans_total": len(scans),
        "scans_by_verdict": by_verdict,
        "events_total": len(events),
        "alerts": sum(1 for s in scans if s.verdict != "authentic"),
    }


# --------------------------------------------------------------------------- #
# Audit chain
# --------------------------------------------------------------------------- #
@router.get("/{cid}/audit")
def audit_trail(
    cid: str,
    limit: int = Query(default=200, le=1000),
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("audit.read")),
):
    _company_or_403(db, user, cid)
    rows = db.scalars(
        select(AuditLog).where(AuditLog.company_id == cid).order_by(AuditLog.id.desc()).limit(limit)
    ).all()
    chain = audit.verify_chain(db, cid)
    return {
        "chain": chain,
        "entries": [
            {
                "id": r.id,
                "ts": r.ts,
                "actor_id": r.actor_id,
                "actor_role": r.actor_role,
                "action": r.action,
                "subject_type": r.subject_type,
                "subject_id": r.subject_id,
                "data": json.loads(r.data_json),
                "prev_hash": r.prev_hash,
                "row_hash": r.row_hash,
            }
            for r in rows
        ],
    }
