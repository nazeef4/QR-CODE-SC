"""Public verification endpoint + authenticated scan history.

POST /api/v1/scans is the only unauthenticated data endpoint. It performs:
  1. parse + Ed25519 verification of the SCQR1 payload (kid → registered key)
  2. entity resolution + revocation check
  3. payload↔state consistency (parent mismatch / superseded seq)
  4. telemetry clone heuristics (velocity, impossible travel, territory)
  5. signed-hierarchy verification upward from the scanned node
  6. persisted scan record (first scan = activation)
"""
from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import crypto, security, service
from ..config import SCAN_RATE_LIMIT, SCAN_RATE_WINDOW_SECONDS
from ..db import get_db
from ..models import Entity, HierarchySchema, Scan, SigningKey, SupplyEvent, User
from ..risk import evaluate_scan
from ..schemas import ScanIn

router = APIRouter(prefix="/api/v1", tags=["scans"])

# naive in-memory per-IP budget (replace with Redis-backed limiter in prod)
_BUCKETS: dict[str, deque[float]] = defaultdict(deque)


def _rate_limit(ip: str) -> None:
    now = time.monotonic()
    window = _BUCKETS[ip]
    while window and now - window[0] > SCAN_RATE_WINDOW_SECONDS:
        window.popleft()
    if len(window) >= SCAN_RATE_LIMIT:
        raise HTTPException(429, "Scan rate limit exceeded")
    window.append(now)


@router.post("/scans")
def submit_scan(
    body: ScanIn,
    db: Session = Depends(get_db),
    x_forwarded_for: str | None = Header(default=None),
    user_agent: str | None = Header(default=None),
):
    ip = (x_forwarded_for or "").split(",")[0].strip() or "local"
    _rate_limit(ip)

    ctx = body.context
    ua = ctx.user_agent or (user_agent or "")[:400]

    # --- 1. parse ---------------------------------------------------------- #
    parsed, sig, parse_err = crypto.parse_qr_payload(body.payload)
    entity: Entity | None = None
    signature_ok = False
    unknown_key = False
    payload_body = parsed

    if parse_err is None and parsed is not None:
        kid = str(parsed.get("kid", ""))
        key = service.prime_key_cache(db, kid)
        if key is None or key.revoked_at is not None:
            unknown_key = True
        else:
            payload_body, signature_ok, parse_err = crypto.verify_qr_payload(
                body.payload, key.public_key
            )
            if signature_ok:
                entity = db.get(Entity, str(payload_body.get("ent", "")))
                # org binding: entity must belong to the org that signed it
                if entity is not None and entity.company_id != payload_body.get("org"):
                    entity = None  # cross-org claim → unknown entity

    # --- 2..4. risk evaluation --------------------------------------------- #
    ev = evaluate_scan(
        db,
        entity=entity,
        signature_ok=signature_ok,
        parse_error=parse_err,
        unknown_key=unknown_key,
        payload_body=payload_body,
        lat=ctx.lat,
        lon=ctx.lon,
        country=ctx.country.upper() if ctx.country else None,
        device_fp=ctx.device_fp,
    )

    company_id = (
        entity.company_id
        if entity is not None
        else str((payload_body or {}).get("org", "unknown"))
    )
    now = datetime.now(timezone.utc)
    scan = Scan(
        id=crypto.new_id("scn"),
        company_id=company_id,
        entity_id=entity.id if entity else None,
        ts=now,
        lat=ctx.lat,
        lon=ctx.lon,
        country=ctx.country.upper() if ctx.country else None,
        device_fp=ctx.device_fp,
        ip=ip,
        user_agent=ua,
        verdict=ev.verdict,
        risk_score=ev.risk_score,
        flags_json=json.dumps(ev.flags),
        is_first_scan=ev.first_scan and entity is not None,
        payload_prefix=body.payload[:80],
    )
    db.add(scan)
    if entity is not None and ev.first_scan and entity.activated_at is None:
        entity.activated_at = now
    db.commit()

    # --- response ----------------------------------------------------------- #
    out: dict = {
        "scan_id": scan.id,
        "scanned_at": scan.ts.isoformat(),
        "verdict": ev.verdict,
        "risk_score": ev.risk_score,
        "flags": ev.flags,
        "activation": ev.activation,
        "authenticity": {
            "signature_valid": signature_ok,
            "parse_error": parse_err,
            "kid": (payload_body or {}).get("kid"),
            "payload_seq": (payload_body or {}).get("seq"),
        },
    }
    if entity is not None:
        hops, chain_ok = service.verify_chain_up(db, entity)
        events = db.scalars(
            select(SupplyEvent)
            .where(SupplyEvent.entity_id == entity.id)
            .order_by(SupplyEvent.ts.asc())
            .limit(50)
        ).all()
        attrs = json.loads(entity.attributes_json or "{}")
        out["entity"] = {
            "id": entity.id,
            "type": entity.entity_type,
            "serial": entity.serial,
            "lifecycle_state": entity.lifecycle_state,
            "attributes": attrs,
            "activated_at": entity.activated_at.isoformat() if entity.activated_at else None,
        }
        # origin resolution: attributes.batch_id → batch → its parent (maker)
        out["origin"] = None
        batch_ref = attrs.get("batch_id")
        if batch_ref:
            batch_ent = db.get(Entity, str(batch_ref))
            if batch_ent is None:
                batch_ent = db.scalar(
                    select(Entity).where(
                        Entity.company_id == entity.company_id, Entity.serial == str(batch_ref)
                    )
                )
            if batch_ent is not None:
                maker = db.get(Entity, batch_ent.parent_id) if batch_ent.parent_id else None
                out["origin"] = {
                    "batch": {
                        "id": batch_ent.id,
                        "serial": batch_ent.serial,
                        "attributes": json.loads(batch_ent.attributes_json or "{}"),
                    },
                    "manufacturer": {
                        "id": maker.id,
                        "name": json.loads(maker.attributes_json or "{}").get("name")
                        if maker
                        else None,
                    },
                }
        out["relationships"] = {
            "current_parent_id": entity.parent_id,
            "claimed_parent_in_qr": (payload_body or {}).get("par"),
            "chain_verified": chain_ok,
            "hops": hops,
        }
        out["journey"] = [
            {
                "event_type": e.event_type,
                "ts": e.ts,
                "location": e.location_text,
                "details": json.loads(e.details_json),
            }
            for e in events
        ]
    return out


@router.get("/scans")
def scan_history(
    entity_id: str | None = None,
    verdict: str | None = None,
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(security.require_perms("scan.read")),
):
    q = select(Scan).where(Scan.company_id == user.company_id)
    if entity_id:
        q = q.where(Scan.entity_id == entity_id)
    if verdict:
        q = q.where(Scan.verdict == verdict)
    rows = db.scalars(q.order_by(Scan.ts.desc()).limit(limit)).all()
    return {
        "items": [
            {
                "id": s.id,
                "entity_id": s.entity_id,
                "ts": s.ts.isoformat(),
                "verdict": s.verdict,
                "risk_score": s.risk_score,
                "flags": json.loads(s.flags_json),
                "lat": s.lat,
                "lon": s.lon,
                "country": s.country,
                "is_first_scan": s.is_first_scan,
            }
            for s in rows
        ]
    }
