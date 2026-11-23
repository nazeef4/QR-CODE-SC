"""Entity lifecycle: registration, bindings, lineage, QR issuance, events."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, crypto, qr, security, service
from ..db import get_db
from ..hierarchy import active_schema, entity_lifecycle, schema_def
from ..models import Entity, HierarchySchema, RelationshipStatement, SupplyEvent, User
from ..schemas import BindingIn, EntityCreateIn, EventIn, TransitionIn

router = APIRouter(prefix="/api/v1/entities", tags=["entities"])

LIFECYCLE_ORDER_OVERRIDE = ["recalled", "destroyed"]  # terminal states


def _entity_or_403(db: Session, user: User, eid: str) -> Entity:
    ent = db.get(Entity, eid)
    if ent is None:
        raise HTTPException(404, "Entity not found")
    security.same_company(user, ent.company_id)
    return ent


def _entity_json(e: Entity, *, include_attrs: bool = True) -> dict:
    out = {
        "id": e.id,
        "entity_type": e.entity_type,
        "serial": e.serial,
        "parent_id": e.parent_id,
        "lifecycle_state": e.lifecycle_state,
        "payload_seq": e.payload_seq,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "activated_at": e.activated_at.isoformat() if e.activated_at else None,
        "revoked": e.revoked_at is not None,
        "schema_id": e.schema_id,
    }
    if include_attrs:
        out["attributes"] = json.loads(e.attributes_json or "{}")
        out["territory"] = json.loads(e.territory_json) if e.territory_json else None
    return out


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #
@router.post("", status_code=201)
def create_entity(
    body: EntityCreateIn,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("entity.register")),
):
    schema_row = None
    if body.schema_id:
        schema_row = db.get(HierarchySchema, body.schema_id)
        if schema_row is None or schema_row.company_id != user.company_id:
            raise HTTPException(404, "Schema not found")
    else:
        schema_row = active_schema(db, user.company_id)

    try:
        entity = service.register_entity(
            db,
            company_id=user.company_id,
            schema_row=schema_row,
            entity_type=body.entity_type,
            attributes=body.attributes,
            serial=body.serial,
            actor=user,
            parent_id=body.parent_id,
            territory=body.territory,
        )
        payload = service.issue_payload(db, entity)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Duplicate serial for this company")
    return {**_entity_json(entity), "payload": payload}


@router.get("")
def list_entities(
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("entity.read")),
    entity_type: str | None = None,
    parent_id: str | None = None,
    state: str | None = None,
    serial: str | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
):
    q = select(Entity).where(Entity.company_id == user.company_id)
    if entity_type:
        q = q.where(Entity.entity_type == entity_type)
    if parent_id:
        q = q.where(Entity.parent_id == parent_id)
    if state:
        q = q.where(Entity.lifecycle_state == state)
    if serial:
        q = q.where(Entity.serial.contains(serial))
    rows = db.scalars(q.order_by(Entity.created_at.desc()).offset(offset).limit(limit)).all()
    return {"items": [_entity_json(e, include_attrs=False) for e in rows], "offset": offset}


# --------------------------------------------------------------------------- #
# Detail / lineage / QR
# --------------------------------------------------------------------------- #
@router.get("/{eid}")
def get_entity(
    eid: str,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("entity.read")),
):
    ent = _entity_or_403(db, user, eid)
    defn = schema_def(db.get(HierarchySchema, ent.schema_id))  # type: ignore[arg-type]
    events = db.scalars(
        select(SupplyEvent)
        .where(SupplyEvent.entity_id == ent.id)
        .order_by(SupplyEvent.ts.desc())
        .limit(20)
    ).all()
    stmts = db.scalars(
        select(RelationshipStatement)
        .where(RelationshipStatement.child_id == ent.id)
        .order_by(RelationshipStatement.seq.desc())
        .limit(20)
    ).all()
    children = db.scalars(select(Entity).where(Entity.parent_id == ent.id)).all()
    return {
        **_entity_json(ent),
        "lifecycle_states": entity_lifecycle(defn, ent.entity_type),
        "children_count": len(children),
        "children": [_entity_json(c, include_attrs=False) for c in children[:50]],
        "relationship_statements": [
            {
                "id": s.id,
                "op": s.op,
                "seq": s.seq,
                "parent_id": s.parent_id,
                "ts": s.ts,
                "kid": s.kid,
                "actor_id": s.actor_id,
                "signature": s.signature,
            }
            for s in stmts
        ],
        "events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "ts": e.ts,
                "location_text": e.location_text,
                "details": json.loads(e.details_json),
            }
            for e in events
        ],
    }


@router.get("/{eid}/lineage")
def lineage(
    eid: str,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("entity.read")),
    max_descendant_depth: int = Query(default=3, le=6),
):
    """Verified hierarchy from this node in both directions."""
    ent = _entity_or_403(db, user, eid)
    hops, all_valid = service.verify_chain_up(db, ent)

    # ancestor node summaries
    ancestors = []
    cursor = ent
    seen: set[str] = set()
    while cursor.parent_id and cursor.id not in seen and len(ancestors) < 64:
        seen.add(cursor.id)
        parent = db.get(Entity, cursor.parent_id)
        if parent is None:
            break
        ancestors.append(_entity_json(parent, include_attrs=False))
        cursor = parent

    tree = service.descendants_tree(db, eid, max_depth=max_descendant_depth)
    root = _entity_json(cursor, include_attrs=False)
    return {
        "scanned_node": _entity_json(ent),
        "direction_up": {
            "ancestors": ancestors,
            "hops": hops,
            "chain_verified": all_valid and bool(hops or ent.parent_id is None),
        },
        "direction_down": {"tree": tree},
        "root": root,
        "depth": len(ancestors),
    }


@router.get("/{eid}/payload")
def get_payload(
    eid: str,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("entity.print")),
):
    ent = _entity_or_403(db, user, eid)
    return {"payload": service.issue_payload(db, ent)}


@router.get("/{eid}/qr.png")
def get_qr(
    eid: str,
    size: int = Query(default=480, le=1600),
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("entity.print")),
):
    ent = _entity_or_403(db, user, eid)
    payload = service.issue_payload(db, ent)
    db.commit()
    png = qr.render_qr(payload, size=size)
    return Response(
        content=png,
        media_type="image/png",
        headers={"X-Entity-Id": ent.id, "X-Payload-Seq": str(ent.payload_seq)},
    )


@router.post("/{eid}/reissue")
def reissue(
    eid: str,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("entity.print")),
):
    """Re-sign the payload with the current parent binding (reprint flow).
    Bumps seq so previously printed copies are detectable as superseded."""
    ent = _entity_or_403(db, user, eid)
    ent.payload_seq += 1
    payload = service.issue_payload(db, ent)
    audit.record(
        db,
        company_id=ent.company_id,
        action="entity.reissue",
        subject_type="entity",
        subject_id=ent.id,
        data={"seq": ent.payload_seq, "parent_id": ent.parent_id},
        actor_id=user.id,
        actor_role=user.role,
    )
    db.commit()
    return {"id": ent.id, "payload_seq": ent.payload_seq, "payload": payload}


# --------------------------------------------------------------------------- #
# Bindings (signed parent-child relationships)
# --------------------------------------------------------------------------- #
@router.post("/{eid}/bindings", status_code=201)
def bind_to_parent(
    eid: str,
    body: BindingIn,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("binding.create")),
):
    ent = _entity_or_403(db, user, eid)
    parent = db.get(Entity, body.parent_id)
    if parent is None:
        raise HTTPException(404, "Parent entity not found")
    stmt = service.bind(db, child=ent, parent=parent, actor=user)
    db.commit()
    return {
        "statement_id": stmt.id,
        "seq": stmt.seq,
        "child_id": ent.id,
        "parent_id": parent.id,
        "signature": stmt.signature,
        "kid": stmt.kid,
        "note": "QR payload keeps its identity signature; reissue to embed the parent",
    }


@router.delete("/{eid}/bindings/current")
def unbind_current(
    eid: str,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("binding.remove")),
):
    """Controlled authorization step: only org_admin may re-parent."""
    ent = _entity_or_403(db, user, eid)
    previous = ent.parent_id
    stmt = service.unbind(db, child=ent, actor=user)
    db.commit()
    return {
        "statement_id": stmt.id,
        "seq": stmt.seq,
        "child_id": ent.id,
        "previous_parent": previous,
        "parent_id": None,
        "signature": stmt.signature,
    }


# --------------------------------------------------------------------------- #
# Lifecycle transitions & supply-chain events
# --------------------------------------------------------------------------- #
@router.post("/{eid}/transitions")
def transition(
    eid: str,
    body: TransitionIn,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("lifecycle.transition")),
):
    ent = _entity_or_403(db, user, eid)
    schema_row = db.get(HierarchySchema, ent.schema_id)
    states = entity_lifecycle(schema_def(schema_row), ent.entity_type)  # type: ignore[arg-type]
    if body.to_state not in states:
        raise HTTPException(400, f"'{body.to_state}' is not a lifecycle state for {ent.entity_type}")
    if ent.lifecycle_state in ("recalled", "destroyed"):
        raise HTTPException(409, f"Entity is terminal ('{ent.lifecycle_state}')")
    if body.to_state in ("recalled", "destroyed") and user.role != "org_admin":
        raise HTTPException(403, "Only org_admin can recall or destroy entities")
    if states.index(body.to_state) < states.index(ent.lifecycle_state) and body.to_state not in LIFECYCLE_ORDER_OVERRIDE:
        raise HTTPException(409, f"Backward transition refused ({ent.lifecycle_state} → {body.to_state})")
    prev = ent.lifecycle_state
    ent.lifecycle_state = body.to_state
    db.flush()
    audit.record(
        db,
        company_id=ent.company_id,
        action="lifecycle.transition",
        subject_type="entity",
        subject_id=ent.id,
        data={"from": prev, "to": body.to_state},
        actor_id=user.id,
        actor_role=user.role,
    )
    db.commit()
    return {"id": ent.id, "from": prev, "to": ent.lifecycle_state}


_EVENT_STATE_MAP = {
    "dispatched": "dispatched",
    "shipped": "dispatched",
    "received": "received",
    "sold": "sold",
    "recalled": "recalled",
    "packed": "packed",
}


@router.post("/{eid}/events", status_code=201)
def add_event(
    eid: str,
    body: EventIn,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("event.create")),
):
    ent = _entity_or_403(db, user, eid)
    ev = service.record_event(
        db,
        entity=ent,
        event_type=body.event_type,
        actor=user,
        details=body.details,
        lat=body.location_lat,
        lon=body.location_lon,
        location_text=body.location_text,
    )
    # convenience: standard events advance lifecycle (forward-only)
    target = _EVENT_STATE_MAP.get(body.event_type)
    schema_row = db.get(HierarchySchema, ent.schema_id)
    states = entity_lifecycle(schema_def(schema_row), ent.entity_type)  # type: ignore[arg-type]
    if (
        target
        and target in states
        and ent.lifecycle_state not in ("recalled", "destroyed")
        and states.index(target) >= states.index(ent.lifecycle_state)
        and target != ent.lifecycle_state
    ):
        ent.lifecycle_state = target
    db.commit()
    return {"event_id": ev.id, "event_type": ev.event_type, "entity_state": ent.lifecycle_state}


@router.get("/{eid}/events")
def list_events(
    eid: str,
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("entity.read")),
):
    ent = _entity_or_403(db, user, eid)
    events = db.scalars(
        select(SupplyEvent)
        .where(SupplyEvent.entity_id == ent.id)
        .order_by(SupplyEvent.ts.desc())
    ).all()
    return {
        "items": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "ts": e.ts,
                "actor_id": e.actor_id,
                "location_text": e.location_text,
                "lat": e.location_lat,
                "lon": e.location_lon,
                "details": json.loads(e.details_json),
            }
            for e in events
        ]
    }
