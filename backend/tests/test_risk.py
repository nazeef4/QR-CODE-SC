"""Clone-detection heuristics tests (impossible travel, velocity, territory)."""
from __future__ import annotations

import backend.app.risk as risk
from backend.tests.conftest import auth, onboard


def _setup(client, email):
    data = onboard(client, name="RiskCo", email=email)
    cid, tok = data["company_id"], data["access_token"]
    box = client.post(
        "/api/v1/entities",
        json={"entity_type": "product_box", "serial": f"B-{email}"},
        headers=auth(tok),
    ).json()
    pack = client.post(
        "/api/v1/entities",
        json={
            "entity_type": "medicine_pack",
            "serial": f"P-{email}",
            "parent_id": box["id"],
            "territory": ["PK"],
        },
        headers=auth(tok),
    ).json()
    client.post(
        f"/api/v1/entities/{pack['id']}/transitions",
        json={"to_state": "dispatched"},
        headers=auth(tok),
    )
    return cid, tok, pack


def test_impossible_travel_flags_clone(client):
    _, _, pack = _setup(client, "geo@risk.co")
    payload = pack["payload"]

    # legitimate activation: Karachi
    r1 = client.post(
        "/api/v1/scans",
        json={"payload": payload, "context": {"lat": 24.86, "lon": 67.00, "country": "PK"}},
    ).json()
    assert r1["verdict"] == "authentic"

    # clone scanned 1,000+ km away minutes later: Lahore
    r2 = client.post(
        "/api/v1/scans",
        json={"payload": payload, "context": {"lat": 31.52, "lon": 74.36, "country": "PK"}},
    ).json()
    codes = [f["code"] for f in r2["flags"]]
    assert "IMPOSSIBLE_TRAVEL" in codes
    assert r2["verdict"] == "suspicious"


def test_territory_breach(client):
    _, _, pack = _setup(client, "terr@risk.co")
    res = client.post(
        "/api/v1/scans",
        json={"payload": pack["payload"], "context": {"lat": 1.3, "lon": 103.8, "country": "SG"}},
    ).json()
    codes = [f["code"] for f in res["flags"]]
    assert "TERRITORY_BREACH" in codes
    assert res["verdict"] == "suspicious"


def test_pre_dispatch_scan_flagged(client):
    data = onboard(client, name="PreDisCo", email="pre@risk.co")
    cid, tok = data["company_id"], data["access_token"]
    pack = client.post(
        "/api/v1/entities",
        json={"entity_type": "medicine_pack", "serial": "PD-1"},
        headers=auth(tok),
    ).json()
    # state remains 'registered' — scanning it now is anomalous
    res = client.post("/api/v1/scans", json={"payload": pack["payload"], "context": {}}).json()
    codes = [f["code"] for f in res["flags"]]
    assert "PRE_DISPATCH_SCAN" in codes
    assert res["verdict"] == "suspicious"


def test_revoked_entity_verdict(client):
    data = onboard(client, name="RevokeCo", email="rev@risk.co")
    cid, tok = data["company_id"], data["access_token"]
    pack = client.post(
        "/api/v1/entities",
        json={"entity_type": "medicine_pack", "serial": "RV-1"},
        headers=auth(tok),
    ).json()
    # revoke directly in DB (revocation API is an admin operation in the roadmap)
    from backend.app.db import SessionLocal
    from backend.app.models import Entity

    db = SessionLocal()
    ent = db.get(Entity, pack["id"])
    from datetime import datetime, timezone

    ent.revoked_at = datetime.now(timezone.utc)
    db.commit()
    db.close()

    res = client.post("/api/v1/scans", json={"payload": pack["payload"], "context": {}}).json()
    assert res["verdict"] == "revoked"


def test_haversine():
    # Karachi → Lahore ≈ 1030 km
    d = risk.haversine_km(24.86, 67.00, 31.52, 74.36)
    assert 1000 < d < 1100
