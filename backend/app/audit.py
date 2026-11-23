"""Hash-chained append-only audit log.

Every mutating action appends a row whose hash covers the previous row hash,
making silent deletion or edits detectable without a blockchain: verify the
chain offline with ``verify_chain()``. (See docs/01-architecture.md §7 for
why this replaces a distributed ledger in the single-operator deployment.)
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .crypto import canonical_json, sha256_hex, utcnow_iso
from .models import AuditLog

GENESIS = "0" * 64


def record(
    db: Session,
    *,
    company_id: str,
    action: str,
    subject_type: str,
    subject_id: str,
    data: dict[str, Any] | None = None,
    actor_id: str | None = None,
    actor_role: str | None = None,
) -> AuditLog:
    prev = db.scalar(
        select(AuditLog)
        .where(AuditLog.company_id == company_id)
        .order_by(AuditLog.id.desc())
        .limit(1)
    )
    prev_hash = prev.row_hash if prev else GENESIS
    ts = utcnow_iso()
    payload = {
        "ts": ts,
        "org": company_id,
        "action": action,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "actor": actor_id,
        "data": data or {},
    }
    row_hash = sha256_hex(prev_hash.encode("ascii") + b"|" + canonical_json(payload))
    row = AuditLog(
        company_id=company_id,
        ts=ts,
        actor_id=actor_id,
        actor_role=actor_role,
        action=action,
        subject_type=subject_type,
        subject_id=subject_id,
        data_json=json.dumps(payload["data"], sort_keys=True),
        prev_hash=prev_hash,
        row_hash=row_hash,
    )
    db.add(row)
    db.flush()
    return row


def verify_chain(db: Session, company_id: str) -> dict[str, Any]:
    rows = list(
        db.scalars(
            select(AuditLog).where(AuditLog.company_id == company_id).order_by(AuditLog.id)
        )
    )
    prev = GENESIS
    for i, row in enumerate(rows):
        if row.prev_hash != prev:
            return {"ok": False, "broken_at": i, "rows": len(rows)}
        payload = {
            "ts": row.ts,
            "org": row.company_id,
            "action": row.action,
            "subject_type": row.subject_type,
            "subject_id": row.subject_id,
            "actor": row.actor_id,
            "data": json.loads(row.data_json),
        }
        expect = sha256_hex(prev.encode("ascii") + b"|" + canonical_json(payload))
        if expect != row.row_hash:
            return {"ok": False, "broken_at": i, "rows": len(rows)}
        prev = row.row_hash
    return {"ok": True, "rows": len(rows), "head": prev}
