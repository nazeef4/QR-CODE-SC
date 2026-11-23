"""Clone/counterfeit detection engine.

Evaluates every scan against cryptographic validity, the signed hierarchy and
telemetry heuristics. Returns a verdict in {authentic, suspicious, invalid,
revoked} plus weighted flags. See docs/04-anti-counterfeiting.md for the full
threat-driven rationale of each rule.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import (
    MAX_PLAUSIBLE_GROUND_SPEED_KMH,
    VELOCITY_MAX_SCANS,
    VELOCITY_WINDOW_SECONDS,
)
from .models import Entity, Scan, SupplyEvent

# flag code → (severity, risk weight, template)
FLAGS: dict[str, tuple[str, int, str]] = {
    "MALFORMED_PAYLOAD":        ("critical", 100, "Payload is not a well-formed SCQR1 token"),
    "UNKNOWN_KEY":              ("critical", 100, "Signing key (kid) is not known or is revoked"),
    "BAD_SIGNATURE":            ("critical", 100, "Ed25519 signature does not verify"),
    "UNKNOWN_ENTITY":           ("critical", 100, "Payload is well-formed but entity is not registered"),
    "ENTITY_REVOKED":           ("critical", 100, "Entity has been revoked by the issuer"),
    "PARENT_MISMATCH":          ("high", 45, "Parent encoded in the printed QR differs from the "
                                             "current signed binding (possible repacking)"),
    "STALE_PAYLOAD_SEQ":        ("medium", 25, "Payload sequence is behind the current re-issued "
                                               "sequence (superseded print)"),
    "IMPOSSIBLE_TRAVEL":        ("high", 40, "Consecutive scans imply impossible physical travel"),
    "SCAN_VELOCITY":            ("high", 30, "Scan frequency exceeds the plausible organic rate"),
    "PRE_DISPATCH_SCAN":        ("medium", 20, "Scanned before any dispatch event was recorded"),
    "TERRITORY_BREACH":         ("medium", 20, "Scanned outside the entity's allowed territory"),
    "MULTI_COUNTRY":            ("medium", 15, "Same entity observed in multiple countries in a day"),
    "NO_LIFECYCLE_TRACE":       ("low", 10, "No lifecycle events recorded yet"),
}


@dataclass
class ScanEvaluation:
    verdict: str
    risk_score: int
    flags: list[dict] = field(default_factory=list)
    first_scan: bool = False
    activation: dict | None = None

    def add(self, code: str, detail: str | None = None) -> None:
        sev, weight, template = FLAGS.get(code, ("medium", 15, code))
        self.flags.append({"code": code, "severity": sev, "detail": detail or template})
        self.risk_score = min(100, self.risk_score + weight)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def evaluate_scan(
    db: Session,
    *,
    entity: Entity | None,
    signature_ok: bool,
    parse_error: str | None,
    unknown_key: bool,
    payload_body: dict | None,
    lat: float | None,
    lon: float | None,
    country: str | None,
    device_fp: str | None,
) -> ScanEvaluation:
    """Core decision function. Caller has already established org binding."""
    ev = ScanEvaluation(verdict="authentic", risk_score=0)

    # ---- Layer 1: cryptographic validity -------------------------------- #
    if parse_error:
        ev.add("MALFORMED_PAYLOAD", parse_error)
        ev.verdict = "invalid"
        return ev
    if unknown_key:
        ev.add("UNKNOWN_KEY")
        ev.verdict = "invalid"
        return ev
    if not signature_ok:
        ev.add("BAD_SIGNATURE")
        ev.verdict = "invalid"
        return ev
    if entity is None:
        ev.add("UNKNOWN_ENTITY")
        ev.verdict = "invalid"
        return ev
    if entity.revoked_at is not None:
        ev.add("ENTITY_REVOKED")
        ev.verdict = "revoked"
        return ev

    # ---- Layer 2: payload ↔ current state consistency ------------------- #
    if payload_body is not None:
        claimed_parent = payload_body.get("par")
        if claimed_parent and claimed_parent != entity.parent_id:
            ev.add(
                "PARENT_MISMATCH",
                f"QR claims parent {claimed_parent} but signed binding says "
                f"{entity.parent_id or 'none'}",
            )
        seq = payload_body.get("seq")
        if isinstance(seq, int) and seq < entity.payload_seq:
            ev.add("STALE_PAYLOAD_SEQ", f"payload seq {seq} < current {entity.payload_seq}")

    # ---- Layer 3: telemetry / clone heuristics -------------------------- #
    now = datetime.now(timezone.utc)
    history = list(
        db.scalars(
            select(Scan)
            .where(Scan.entity_id == entity.id)
            .order_by(Scan.ts.desc())
            .limit(50)
        )
    )

    is_first = entity.activated_at is None
    ev.first_scan = is_first

    # pre-dispatch awareness: a consumer-style scan of an item that has not
    # yet left the origin (states before "dispatched") is anomalous.
    has_dispatch = db.scalar(
        select(SupplyEvent).where(
            SupplyEvent.entity_id == entity.id,
            SupplyEvent.event_type.in_(["dispatched", "shipped", "transferred"]),
        )
    )
    if entity.lifecycle_state in ("registered", "manufactured", "packed"):
        ev.add(
            "PRE_DISPATCH_SCAN",
            f"scanned while lifecycle_state='{entity.lifecycle_state}' "
            "(no dispatch recorded)",
        )

    # impossible travel: compare with most recent located scan
    prev_located = next((s for s in history if s.lat is not None and s.lon is not None), None)
    if prev_located is not None and lat is not None and lon is not None:
        dist = haversine_km(prev_located.lat, prev_located.lon, lat, lon)
        dt_s = max(
            1.0,
            (now - _as_utc(prev_located.ts)).total_seconds(),
        )
        speed = dist / (dt_s / 3600.0)
        if dist > 50 and speed > MAX_PLAUSIBLE_GROUND_SPEED_KMH:
            if dt_s < 60:
                when = f"{dt_s:.0f} s"
            elif dt_s < 3600:
                when = f"{dt_s/60:.0f} min"
            else:
                when = f"{dt_s/3600:.1f} h"
            ev.add(
                "IMPOSSIBLE_TRAVEL",
                f"{dist:.0f} km between scans within {when} "
                f"(≈{speed:.0f} km/h)",
            )

    # velocity window
    window_start = now - timedelta(seconds=VELOCITY_WINDOW_SECONDS)
    recent = [s for s in history if _as_utc(s.ts) >= window_start]
    if len(recent) + 1 > VELOCITY_MAX_SCANS:
        ev.add(
            "SCAN_VELOCITY",
            f"{len(recent) + 1} scans within the last {VELOCITY_WINDOW_SECONDS}s",
        )

    # territory / multi-country
    entity_countries: set[str] = set()
    for s in history:
        if s.country:
            entity_countries.add(s.country.upper())
    if country:
        entity_countries.add(country.upper())
    allowed = None
    if entity.territory_json:
        import json as _json

        try:
            allowed = {c.upper() for c in _json.loads(entity.territory_json)}
        except ValueError:
            allowed = None
    if allowed and country and country.upper() not in allowed:
        ev.add("TERRITORY_BREACH", f"scanned in {country.upper()}, allowed: {sorted(allowed)}")
    if len(entity_countries) >= 3:
        ev.add("MULTI_COUNTRY", f"observed in {sorted(entity_countries)}")

    # lifecycle signals
    if entity.lifecycle_state in ("registered",) and not has_dispatch:
        ev.add("NO_LIFECYCLE_TRACE")

    # ---- Verdict -------------------------------------------------------- #
    sev_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    top = max((sev_rank.get(f["severity"], 1) for f in ev.flags), default=-1)
    if top >= 1 or ev.risk_score >= 20:  # any medium+ flag, or accumulated risk
        ev.verdict = "suspicious"
    else:
        ev.verdict = "authentic"

    if is_first:
        ev.activation = {
            "first_scan_at": now.isoformat().replace("+00:00", "Z"),
            "lat": lat,
            "lon": lon,
            "country": country,
            "device_fp": device_fp,
        }
    else:
        first = history[-1] if history else None
        ev.activation = {
            "first_scan_at": _as_utc(first.ts).isoformat().replace("+00:00", "Z") if first else None,
            "previously_activated": True,
            "scan_count": len(history) + 1,
        }
    return ev
