"""Domain services: payload issuance, binding, lineage verification.

Kept separate from routers so tests can exercise the core without HTTP.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, crypto
from .config import MASTER_KEY
from .hierarchy import check_binding, schema_def
from .models import (
    Entity,
    HierarchySchema,
    RelationshipStatement,
    SigningKey,
    SupplyEvent,
    User,
)


def get_key(db: Session, company_id: str, purpose: str) -> SigningKey:
    key = db.scalar(
        select(SigningKey)
        .where(
            SigningKey.company_id == company_id,
            SigningKey.purpose == purpose,
            SigningKey.revoked_at.is_(None),
        )
        .order_by(SigningKey.created_at.desc())
    )
    if key is None:
        raise HTTPException(500, f"No active '{purpose}' signing key for company")
    return key


def issue_payload(db: Session, entity: Entity, *, purpose: str = "entity_qr") -> str:
    """(Re)generate the signed SCQR1 payload for an entity and persist the seq."""
    key = get_key(db, entity.company_id, purpose)
    priv = crypto.unwrap_private_key(key.private_key_wrapped, MASTER_KEY)
    body = crypto.entity_payload_body(
        company_id=entity.company_id,
        entity_id=entity.id,
        entity_type=entity.entity_type,
        kid=key.id,
        seq=entity.payload_seq,
        parent_id=entity.parent_id,
        issued_at=entity.created_at.isoformat().replace("+00:00", "Z")
        if entity.created_at
        else crypto.utcnow_iso(),
    )
    payload = crypto.build_qr_payload(body, priv)
    entity.current_kid = key.id
    db.flush()
    return payload


def register_entity(
    db: Session,
    *,
    company_id: str,
    schema_row: HierarchySchema,
    entity_type: str,
    attributes: dict[str, Any],
    serial: str | None,
    actor: User,
    parent_id: str | None,
    territory: list[str] | None,
) -> Entity:
    defn = schema_def(schema_row)
    if entity_type not in defn.get("entity_types", {}):
        raise HTTPException(400, f"Entity type '{entity_type}' not in schema '{schema_row.name}'")
    tdef = defn["entity_types"][entity_type]
    if tdef.get("serial_required") and not serial:
        raise HTTPException(400, f"Serial is required for entity type '{entity_type}'")

    entity = Entity(
        id=crypto.new_id("ent"),
        company_id=company_id,
        schema_id=schema_row.id,
        entity_type=entity_type,
        attributes_json=json.dumps(attributes, sort_keys=True),
        serial=serial,
        lifecycle_state="registered",
        territory_json=json.dumps(sorted({c.upper() for c in territory})) if territory else None,
        created_by=actor.id,
    )
    db.add(entity)
    db.flush()

    if parent_id:
        parent = db.get(Entity, parent_id)
        if parent is None:
            raise HTTPException(404, "Parent entity not found")
        bind(db, child=entity, parent=parent, actor=actor, already_flushed=True)

    audit.record(
        db,
        company_id=company_id,
        action="entity.register",
        subject_type="entity",
        subject_id=entity.id,
        data={"type": entity_type, "serial": serial, "parent_id": parent_id},
        actor_id=actor.id,
        actor_role=actor.role,
    )
    return entity


def _latest_statement(db: Session, child_id: str) -> RelationshipStatement | None:
    return db.scalar(
        select(RelationshipStatement)
        .where(RelationshipStatement.child_id == child_id)
        .order_by(RelationshipStatement.seq.desc())
        .limit(1)
    )


def bind(
    db: Session,
    *,
    child: Entity,
    parent: Entity,
    actor: User,
    already_flushed: bool = False,
) -> RelationshipStatement:
    defn = schema_def(db.get(HierarchySchema, child.schema_id))  # type: ignore[arg-type]
    check_binding(db, defn, child, parent)

    seq = 1
    latest = _latest_statement(db, child.id)
    if latest:
        seq = latest.seq + 1

    ts = crypto.utcnow_iso()
    stmt = crypto.relationship_statement(
        op="bind",
        child_id=child.id,
        parent_id=parent.id,
        company_id=child.company_id,
        seq=seq,
        ts=ts,
    )
    key = get_key(db, child.company_id, "relationship")
    priv = crypto.unwrap_private_key(key.private_key_wrapped, MASTER_KEY)
    signature = crypto.sign_statement(stmt, priv)

    row = RelationshipStatement(
        id=crypto.new_id("rel"),
        company_id=child.company_id,
        child_id=child.id,
        parent_id=parent.id,
        op="bind",
        seq=seq,
        ts=ts,
        kid=key.id,
        statement_json=json.dumps(stmt, sort_keys=True),
        signature=signature,
        actor_id=actor.id,
    )
    db.add(row)
    child.parent_id = parent.id
    db.flush()

    audit.record(
        db,
        company_id=child.company_id,
        action="relationship.bind",
        subject_type="relationship",
        subject_id=row.id,
        data={"child": child.id, "parent": parent.id, "seq": seq, "kid": key.id},
        actor_id=actor.id,
        actor_role=actor.role,
    )
    return row


def unbind(db: Session, *, child: Entity, actor: User) -> RelationshipStatement:
    if not child.parent_id:
        raise HTTPException(409, "Entity has no current parent binding")
    prev_parent = child.parent_id
    seq = 1
    latest = _latest_statement(db, child.id)
    if latest:
        seq = latest.seq + 1
    ts = crypto.utcnow_iso()
    stmt = crypto.relationship_statement(
        op="unbind",
        child_id=child.id,
        parent_id=None,
        company_id=child.company_id,
        seq=seq,
        ts=ts,
    )
    key = get_key(db, child.company_id, "relationship")
    priv = crypto.unwrap_private_key(key.private_key_wrapped, MASTER_KEY)
    signature = crypto.sign_statement(stmt, priv)
    row = RelationshipStatement(
        id=crypto.new_id("rel"),
        company_id=child.company_id,
        child_id=child.id,
        parent_id=None,
        op="unbind",
        seq=seq,
        ts=ts,
        kid=key.id,
        statement_json=json.dumps(stmt, sort_keys=True),
        signature=signature,
        actor_id=actor.id,
    )
    db.add(row)
    child.parent_id = None
    db.flush()
    audit.record(
        db,
        company_id=child.company_id,
        action="relationship.unbind",
        subject_type="relationship",
        subject_id=row.id,
        data={"child": child.id, "previous_parent": prev_parent, "seq": seq},
        actor_id=actor.id,
        actor_role=actor.role,
    )
    return row


_KEY_CACHE: dict[str, SigningKey | None] = {}


def prime_key_cache(db: Session, kid: str) -> SigningKey | None:
    """Lookup signing key by kid with a tiny process-local cache."""
    if kid not in _KEY_CACHE:
        _KEY_CACHE[kid] = db.get(SigningKey, kid)
    return _KEY_CACHE[kid]


def clear_key_cache() -> None:
    _KEY_CACHE.clear()


def verify_statement(row: RelationshipStatement) -> bool:
    """Cryptographic verification of a stored relationship statement.

    Rotation policy: a *retired* key keeps verifying historical statements.
    A *revoked* (compromised) key invalidates anything it signed — the hop
    then fails verification and the chain is reported as unverified.
    """
    key = prime_key_cache_stub(row.kid)
    if key is None or key.revoked_at is not None:
        return False
    stmt = json.loads(row.statement_json)
    return crypto.verify(
        key.public_key,
        crypto.PAYLOAD_PREFIX.encode("ascii") + b"." + crypto.canonical_json(stmt),
        row.signature,
    )


def prime_key_cache_stub(kid: str) -> SigningKey | None:
    return _KEY_CACHE.get(kid)


def verify_chain_up(db: Session, entity: Entity) -> tuple[list[dict[str, Any]], bool]:
    """Walk ancestors from *entity* upward, verifying each hop's statement.

    Returns (hops, all_valid). Every hop must have: a signed bind statement
    whose (child, parent) matches the *current* parent pointers, a valid
    Ed25519 signature under the company's relationship key, and no revocation.
    """
    hops: list[dict[str, Any]] = []
    all_valid = True
    cursor = entity
    guard = 0
    while cursor.parent_id and guard < 64:
        guard += 1
        parent = db.get(Entity, cursor.parent_id)
        stmt = db.scalar(
            select(RelationshipStatement)
            .where(
                RelationshipStatement.child_id == cursor.id,
                RelationshipStatement.op == "bind",
                RelationshipStatement.parent_id == cursor.parent_id,
            )
            .order_by(RelationshipStatement.seq.desc())
            .limit(1)
        )
        sig_ok = False
        if stmt is not None:
            prime_key_cache(db, stmt.kid)
            sig_ok = verify_statement(stmt)
        hop_ok = sig_ok and parent is not None and not (parent.revoked_at is not None)
        all_valid = all_valid and hop_ok
        hops.append(
            {
                "child_id": cursor.id,
                "parent_id": cursor.parent_id,
                "parent_type": parent.entity_type if parent else None,
                "statement_seq": stmt.seq if stmt else None,
                "statement_id": stmt.id if stmt else None,
                "signature_valid": sig_ok,
                "is_current_binding": stmt is not None,
                "verified": hop_ok,
            }
        )
        if parent is None:
            break
        cursor = parent
    return hops, all_valid


def descendants_tree(db: Session, entity_id: str, depth: int = 0, max_depth: int = 4) -> dict[str, Any]:
    node_ent = db.get(Entity, entity_id)
    if node_ent is None:
        raise HTTPException(404, "Entity not found")
    node = {
        "id": node_ent.id,
        "type": node_ent.entity_type,
        "lifecycle_state": node_ent.lifecycle_state,
        "serial": node_ent.serial,
        "revoked": node_ent.revoked_at is not None,
        "children": [],
    }
    if depth >= max_depth:
        return node
    children = db.scalars(
        select(Entity).where(Entity.parent_id == entity_id).order_by(Entity.created_at)
    ).all()
    for ch in children:
        node["children"].append(descendants_tree(db, ch.id, depth + 1, max_depth))
    return node


def record_event(
    db: Session,
    *,
    entity: Entity,
    event_type: str,
    actor: User,
    details: dict[str, Any],
    lat: float | None,
    lon: float | None,
    location_text: str | None,
) -> SupplyEvent:
    ev = SupplyEvent(
        id=crypto.new_id("evt"),
        company_id=entity.company_id,
        entity_id=entity.id,
        event_type=event_type,
        ts=crypto.utcnow_iso(),
        actor_id=actor.id,
        location_lat=lat,
        location_lon=lon,
        location_text=location_text,
        details_json=json.dumps(details, sort_keys=True),
    )
    db.add(ev)
    db.flush()
    audit.record(
        db,
        company_id=entity.company_id,
        action=f"event.{event_type}",
        subject_type="entity",
        subject_id=entity.id,
        data={"event_id": ev.id, "details": details, "location": location_text},
        actor_id=actor.id,
        actor_role=actor.role,
    )
    return ev
