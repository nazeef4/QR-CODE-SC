"""Demo data generator — builds a realistic medicine supply-chain hierarchy,
renders QR PNGs for every entity, and runs a scripted clone-detection demo.

Usage (from repo root):
    .venv/bin/python scripts/seed_demo.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from backend.app.db import init_db  # noqa: E402
from backend.app.main import app  # noqa: E402

OUT_QR = REPO_ROOT / "output" / "qr"


def auth(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


def main() -> None:
    init_db()
    OUT_QR.mkdir(parents=True, exist_ok=True)
    client = TestClient(app)

    # ---- 1. Onboarding ---------------------------------------------------- #
    email = "admin@aurora-pharma.example"
    r = client.post(
        "/api/v1/onboarding/company",
        json={
            "company_name": "Aurora Pharmaceuticals",
            "admin": {"email": email, "password": "aurora-demo-pass-1", "name": "QA Director"},
            "template": "pharma-classic",
        },
    )
    if r.status_code == 409:
        print("Demo data already seeded (account exists) — logging in instead.")
        r = client.post(
            "/api/v1/auth/login", json={"email": email, "password": "aurora-demo-pass-1"}
        )
        tok = r.json()["access_token"]
        cid = r.json()["company_id"]
    else:
        assert r.status_code == 201, r.text
        tok = r.json()["access_token"]
        cid = r.json()["company_id"]
        print(f"✓ Onboarded {cid}")

    # supporting roles
    for role, remail in [
        ("operator", "line@aurora-pharma.example"),
        ("distributor", "logistics@aurora-pharma.example"),
        ("retailer", "pharmacy@aurora-pharma.example"),
        ("auditor", "audit@aurora-pharma.example"),
    ]:
        client.post(
            "/api/v1/auth/users",
            json={"email": remail, "password": "aurora-demo-pass-1", "name": role.title(), "role": role},
            headers=auth(tok),
        )

    # ---- 2. Entities + signed parent-child bindings ----------------------- #
    def mk(etype, serial=None, parent=None, attrs=None, territory=None):
        body = {"entity_type": etype, "attributes": attrs or {}}
        if serial:
            body["serial"] = serial
        if parent:
            body["parent_id"] = parent
        if territory:
            body["territory"] = territory
        r = client.post("/api/v1/entities", json=body, headers=auth(tok))
        assert r.status_code == 201, r.text
        return r.json()

    if any(
        e["serial"] == "LOT-A2026-11"
        for e in client.get(
            f"/api/v1/entities?entity_type=batch", headers=auth(tok)
        ).json()["items"]
    ):
        print("Entities already exist — skipping creation.")
        return

    manufacturer = mk("manufacturer", attrs={"name": "Aurora Pharma Karacihti Plant", "license": "MFG-PK-7781"})
    batch = mk("batch", serial="LOT-A2026-11", parent=manufacturer["id"],
               attrs={"formula": "Amoxicillin 500mg", "mfg_date": "2026-11-01", "expiry": "2028-11"})

    # Packs are line-printed WITHOUT a parent (QR carries identity only);
    # the origin batch is referenced in attributes and resolved at scan time.
    # The signed containment spine (box→carton→container…) is bound later.
    packs = [
        mk("medicine_pack", serial=f"SN-AMX-{i:04d}",
           attrs={"dose": "500mg", "units": 21, "batch_id": batch["id"]},
           territory=["PK"])
        for i in range(1, 5)
    ]
    # two boxes × two packs each (bind after registration — packing-line flow)
    boxes = [mk("product_box", serial=f"BOX-{i}") for i in (1, 2)]
    for i, pack in enumerate(packs):
        r = client.post(
            f"/api/v1/entities/{pack['id']}/bindings",
            json={"parent_id": boxes[i // 2]["id"]},
            headers=auth(tok),
        )
        assert r.status_code == 201, r.text

    carton = mk("shipping_carton", serial="CTN-2026-1130-A")
    for b in boxes:
        assert client.post(
            f"/api/v1/entities/{b['id']}/bindings",
            json={"parent_id": carton["id"]},
            headers=auth(tok),
        ).status_code == 201
    container = mk("container", serial="CONT-MSKU-441219")
    assert client.post(
        f"/api/v1/entities/{carton['id']}/bindings",
        json={"parent_id": container["id"]},
        headers=auth(tok),
    ).status_code == 201
    distributor = mk("distributor", attrs={"name": "Sinai Logistics (Karachi DC)", "gln": "8901234567890"})
    retailer = mk("retailer", attrs={"name": "City Medicos (Blue Area)", "gln": "8901234567899"},
                  territory=["PK"])
    assert client.post(
        f"/api/v1/entities/{container['id']}/bindings",
        json={"parent_id": distributor["id"]},
        headers=auth(tok),
    ).status_code == 201
    assert client.post(
        f"/api/v1/entities/{distributor['id']}/bindings",
        json={"parent_id": retailer["id"]},
        headers=auth(tok),
    ).status_code == 201

    # ---- 3. Lifecycle + supply-chain events ------------------------------- #
    for p in packs:
        client.post(f"/api/v1/entities/{p['id']}/transitions", json={"to_state": "manufactured"}, headers=auth(tok))
        client.post(f"/api/v1/entities/{p['id']}/transitions", json={"to_state": "packed"}, headers=auth(tok))
        client.post(
            f"/api/v1/entities/{p['id']}/events",
            json={"event_type": "packed", "details": {"line": "FillingLine-3"},
                  "location_text": "Karachi Plant"},
            headers=auth(tok),
        )
        client.post(f"/api/v1/entities/{p['id']}/transitions", json={"to_state": "dispatched"}, headers=auth(tok))
        client.post(f"/api/v1/entities/{p['id']}/transitions", json={"to_state": "received"}, headers=auth(tok))
    client.post(
        f"/api/v1/entities/{container['id']}/events",
        json={"event_type": "dispatched", "details": "Truck KHI-8841 → Islamabad DC",
              "location_text": "Karachi Port Qasim", "location_lat": 24.82, "location_lon": 67.11},
        headers=auth(tok),
    )
    client.post(
        f"/api/v1/entities/{container['id']}/events",
        json={"event_type": "received", "details": "Inbound gate check OK",
              "location_text": "Islamabad DC", "location_lat": 33.68, "location_lon": 73.05},
        headers=auth(tok),
    )
    # mark parties as received so consumer scans don't trip pre-dispatch rules
    for party in (manufacturer, distributor, retailer, container, carton, *boxes):
        cur = client.get(f"/api/v1/entities/{party['id']}", headers=auth(tok)).json()
        if cur["lifecycle_state"] == "registered":
            client.post(
                f"/api/v1/entities/{party['id']}/transitions",
                json={"to_state": "received"},
                headers=auth(tok),
            )

    # ---- 4. Render QR PNGs for every entity ------------------------------- #
    manifest = []
    r = client.get(f"/api/v1/entities?limit=200", headers=auth(tok))
    for e in r.json()["items"]:
        png = client.get(f"/api/v1/entities/{e['id']}/qr.png?size=360", headers=auth(tok))
        fpath = OUT_QR / f"{e['entity_type']}_{(e['serial'] or e['id'])}.png"
        fpath.write_bytes(png.content)
        payload = client.get(f"/api/v1/entities/{e['id']}/payload", headers=auth(tok)).json()["payload"]
        manifest.append({"type": e["entity_type"], "serial": e["serial"], "id": e["id"],
                         "payload": payload, "qr": str(fpath.relative_to(REPO_ROOT))})
    (REPO_ROOT / "output" / "qr_manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"✓ Rendered {len(manifest)} QR codes → output/qr/ (+ qr_manifest.json)")

    # ---- 5. Scripted scans: genuine vs clone ----------------------------- #
    pack = next(m for m in manifest if m["serial"] == "SN-AMX-0001")

    def scan(payload, lat, lon, country, device):
        r = client.post("/api/v1/scans", json={
            "payload": payload,
            "context": {"lat": lat, "lon": lon, "country": country, "device_fp": device},
        })
        assert r.status_code == 200, r.text
        return r.json()

    print("\n--- Scan 1: genuine first activation (Islamabad pharmacy) ---")
    s1 = scan(pack["payload"], 33.68, 73.05, "PK", "iphone-phys-1")
    print(f"    verdict={s1['verdict']}  risk={s1['risk_score']}  flags={[f['code'] for f in s1['flags']]}")

    print("--- Scan 2: same QR photographed and reprinted, scanned in Karachi 12 min later ---")
    s2 = scan(pack["payload"], 24.86, 67.00, "PK", "android-cheap-77")
    print(f"    verdict={s2['verdict']}  risk={s2['risk_score']}  flags={[f['code'] for f in s2['flags']]}")
    for f in s2["flags"]:
        print(f"      · [{f['severity']}] {f['code']}: {f['detail']}")

    print("--- Scan 3: forged payload (mutated body segment) ---")
    parts = pack["payload"].split(".")
    mid = len(parts[1]) // 2
    mutated = parts[1][:mid] + ("A" if parts[1][mid] != "A" else "B") + parts[1][mid + 1:]
    forged = f"{parts[0]}.{mutated}.{parts[2]}"
    s3 = scan(forged, 30.0, 70.0, "PK", "android-cheap-77")
    print(f"    verdict={s3['verdict']}  flags={[f['code'] for f in s3['flags']]}")

    print("\n--- Admin: alerts feed ---")
    alerts = client.get(f"/api/v1/companies/{cid}/alerts", headers=auth(tok)).json()
    for a in alerts:
        print(f"    {a['ts']}  {a['verdict']:11s}  risk={a['risk_score']:3d}  entity={a['entity_id']}")

    print("\n--- Auditor: audit chain verification ---")
    audit = client.get(f"/api/v1/companies/{cid}/audit", headers=auth(tok)).json()
    print(f"    chain={audit['chain']}  (sample head: {audit['entries'][-1]['row_hash'][:16]}…)")

    lineage = client.get(
        f"/api/v1/entities/{pack['id']}/lineage", headers=auth(tok)
    ).json()
    print("\n--- Verified lineage of SN-AMX-0001 (upward) ---")
    print("    " + " → ".join(
        [lineage["scanned_node"]["entity_type"]]
        + [a["entity_type"] for a in lineage["direction_up"]["ancestors"]]
    ))
    print(f"    chain_verified = {lineage['direction_up']['chain_verified']}")
    print("\nSeed complete.")


if __name__ == "__main__":
    main()
