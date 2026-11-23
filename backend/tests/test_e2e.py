"""End-to-end API tests: onboarding → hierarchy → bindings → lineage → scans."""
from __future__ import annotations

from backend.tests.conftest import auth, make_user, onboard


def _mk(client, token, cid, etype, serial=None, parent=None, attrs=None):
    body = {"entity_type": etype, "attributes": attrs or {}}
    if serial:
        body["serial"] = serial
    if parent:
        body["parent_id"] = parent
    r = client.post("/api/v1/entities", json=body, headers=auth(token))
    assert r.status_code == 201, r.text
    return r.json()


def test_onboarding_and_schema(client):
    data = onboard(client, name="Aurora Pharma")
    cid = data["company_id"]
    tok = data["access_token"]
    r = client.get(f"/api/v1/companies/{cid}/schema", headers=auth(tok))
    assert r.status_code == 200
    defn = r.json()["definition"]
    assert "medicine_pack" in defn["entity_types"]
    rels = {(x["parent"], x["child"]) for x in defn["relations"]}
    assert ("product_box", "medicine_pack") in rels

    # schema versions: publishing a new one keeps history
    defn["entity_types"]["cold_chain_unit"] = {
        "kind": "packaging", "serial_required": True, "lifecycle": ["registered", "packed"],
    }
    r = client.put(
        f"/api/v1/companies/{cid}/schema",
        json={"name": "pharma-plus", "definition": defn},
        headers=auth(tok),
    )
    assert r.status_code == 200 and r.json()["version"] == 2
    r = client.get(f"/api/v1/companies/{cid}/schemas", headers=auth(tok))
    assert len(r.json()) == 2


def test_invalid_schema_rejected(client):
    data = onboard(client, name="BadSchemaCo", email="bad@schema.co")
    cid, tok = data["company_id"], data["access_token"]
    r = client.put(
        f"/api/v1/companies/{cid}/schema",
        json={"name": "broken", "definition": {"entity_types": {}, "relations": []}},
        headers=auth(tok),
    )
    assert r.status_code == 400
    # unknown parent type in relation
    r = client.put(
        f"/api/v1/companies/{cid}/schema",
        json={
            "name": "broken2",
            "definition": {
                "entity_types": {"a": {"kind": "object"}, "b": {"kind": "object"}},
                "relations": [{"parent": "a", "child": "ghost"}],
            },
        },
        headers=auth(tok),
    )
    assert r.status_code == 400
    assert "schema_errors" in r.json()["detail"]


def test_full_hierarchy_trace_from_pack(client):
    """pack → box → carton → container → distributor → retailer"""
    data = onboard(client, name="TraceCo", email="trace@co.io")
    cid, tok = data["company_id"], data["access_token"]

    maker = _mk(client, tok, cid, "manufacturer", attrs={"name": "Aurora Mfg"})
    batch = _mk(client, tok, cid, "batch", serial="LOT-001", parent=maker["id"])
    pack = _mk(client, tok, cid, "medicine_pack", serial="SN-P1", parent=batch["id"])
    box = _mk(client, tok, cid, "product_box", serial="BOX-1")
    # pack must sit in a box: bind after creation (box existed already? bind pack→box)
    # re-bind flow: pack already has parent batch per schema (batch→pack). Choose
    # schema-legal chain only: pack's parent is box or batch per relations.
    r = client.post(
        f"/api/v1/entities/{pack['id']}/bindings",
        json={"parent_id": batch["id"]},
        headers=auth(tok),
    )
    assert r.status_code == 409  # already bound → unbind first (audited op)

    # build a second pack with box as parent from creation
    pack2 = _mk(client, tok, cid, "medicine_pack", serial="SN-P2", parent=box["id"])
    carton = _mk(client, tok, cid, "shipping_carton", serial="CTN-1", parent=None)
    r = client.post(
        f"/api/v1/entities/{carton['id']}/bindings",
        json={"parent_id": carton["id"]},
        headers=auth(tok),
    )
    assert r.status_code == 400  # self-binding refused

    # bind box→carton, carton→container etc.
    container = _mk(client, tok, cid, "container", serial="CONT-1")
    r = client.post(
        f"/api/v1/entities/{box['id']}/bindings",
        json={"parent_id": carton["id"]},
        headers=auth(tok),
    )
    assert r.status_code == 201, r.text
    r = client.post(
        f"/api/v1/entities/{carton['id']}/bindings",
        json={"parent_id": container["id"]},
        headers=auth(tok),
    )
    assert r.status_code == 201
    dist = _mk(client, tok, cid, "distributor", attrs={"name": "Karachi Logistics"})
    r = client.post(
        f"/api/v1/entities/{container['id']}/bindings",
        json={"parent_id": dist["id"]},
        headers=auth(tok),
    )
    assert r.status_code == 201
    retail = _mk(client, tok, cid, "retailer", attrs={"name": "City Pharmacy"})
    client.post(
        f"/api/v1/entities/{dist['id']}/bindings",
        json={"parent_id": retail["id"]},
        headers=auth(tok),
    )

    # ---- traceability from the leaf pack -------------------------------- #
    lin = client.get(
        f"/api/v1/entities/{pack2['id']}/lineage", headers=auth(tok)
    ).json()
    up = lin["direction_up"]
    assert up["chain_verified"] is True
    types_up = [a["entity_type"] for a in up["ancestors"]]
    assert types_up == ["product_box", "shipping_carton", "container", "distributor", "retailer"]

    # ---- traceability from the container (downward) ---------------------- #
    lin_c = client.get(f"/api/v1/entities/{container['id']}/lineage", headers=auth(tok)).json()
    tree = lin_c["direction_down"]["tree"]
    child_types = {c["type"] for c in tree["children"]}
    assert "shipping_carton" in child_types

    # ---- traceability from the root (downward to packs) ------------------ #
    lin_r = client.get(
        f"/api/v1/entities/{retail['id']}/lineage?max_descendant_depth=6",
        headers=auth(tok),
    ).json()
    def flatten(n):
        out = [n["type"]]
        for c in n["children"]:
            out += flatten(c)
        return out

    assert "medicine_pack" in flatten(lin_r["direction_down"]["tree"])


def test_scan_authentic_and_tampered(client):
    data = onboard(client, name="ScanCo", email="scan@co.io")
    cid, tok = data["company_id"], data["access_token"]
    box = _mk(client, tok, cid, "product_box", serial="BOX-S")
    pack = _mk(client, tok, cid, "medicine_pack", serial="SN-SCAN", parent=box["id"])
    # move lifecycle forward so the scan isn't flagged as pre-dispatch
    client.post(
        f"/api/v1/entities/{pack['id']}/transitions",
        json={"to_state": "dispatched"},
        headers=auth(tok),
    )

    payload = pack["payload"]
    r = client.post(
        "/api/v1/scans",
        json={"payload": payload, "context": {"lat": 24.86, "lon": 67.00, "country": "PK"}},
    )
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["verdict"] in ("authentic", "suspicious")
    assert res["authenticity"]["signature_valid"] is True
    assert res["relationships"]["chain_verified"] is True
    assert res["entity"]["serial"] == "SN-SCAN"
    assert res["activation"]["first_scan_at"] is not None

    # second scan reports activation info
    r2 = client.post("/api/v1/scans", json={"payload": payload, "context": {"country": "PK"}})
    res2 = r2.json()
    assert res2["activation"].get("previously_activated") is True

    # tampered payload → invalid
    parts = payload.split(".")
    body = parts[1]
    mutated = body[:-2] + ("AA" if body[-2:] != "AA" else "BB")
    bad = f"{parts[0]}.{mutated}.{parts[2]}"
    r3 = client.post("/api/v1/scans", json={"payload": bad, "context": {}})
    assert r3.json()["verdict"] == "invalid"
    codes = [f["code"] for f in r3.json()["flags"]]
    assert "BAD_SIGNATURE" in codes or "MALFORMED_PAYLOAD" in codes or "UNKNOWN_ENTITY" in codes

    # garbage payload → invalid
    r4 = client.post("/api/v1/scans", json={"payload": "not-a-token", "context": {}})
    assert r4.json()["verdict"] == "invalid"


def test_parent_mismatch_detected(client):
    """QR printed with parent A, then entity re-parented to B → flag."""
    data = onboard(client, name="ReparentCo", email="rep@co.io")
    cid, tok = data["company_id"], data["access_token"]
    box_a = _mk(client, tok, cid, "product_box", serial="BOX-A")
    box_b = _mk(client, tok, cid, "product_box", serial="BOX-B")
    pack = _mk(client, tok, cid, "medicine_pack", serial="SN-R", parent=box_a["id"])
    # printed payload contains par=box_a; admin re-parents to box_b
    r = client.request(
        "DELETE",
        f"/api/v1/entities/{pack['id']}/bindings/current",
        headers=auth(tok),
    )
    assert r.status_code == 200, r.text
    r = client.post(
        f"/api/v1/entities/{pack['id']}/bindings",
        json={"parent_id": box_b["id"]},
        headers=auth(tok),
    )
    assert r.status_code == 201
    client.post(
        f"/api/v1/entities/{pack['id']}/transitions",
        json={"to_state": "dispatched"},
        headers=auth(tok),
    )
    res = client.post("/api/v1/scans", json={"payload": pack["payload"], "context": {}}).json()
    codes = [f["code"] for f in res["flags"]]
    assert "PARENT_MISMATCH" in codes
    assert res["verdict"] == "suspicious"


def test_audit_chain_and_rbac(client):
    data = onboard(client, name="RbacCo", email="rbac@co.io")
    cid, tok = data["company_id"], data["access_token"]
    op_tok = make_user(client, tok, cid, "operator", "op@rbac.co")
    ret_tok = make_user(client, tok, cid, "retailer", "ret@rbac.co")
    aud_tok = make_user(client, tok, cid, "auditor", "aud@rbac.co")

    # operator can register, retailer cannot
    r = client.post(
        "/api/v1/entities",
        json={"entity_type": "product_box", "serial": "B1"},
        headers=auth(op_tok),
    )
    assert r.status_code == 201
    r = client.post(
        "/api/v1/entities",
        json={"entity_type": "product_box", "serial": "B2"},
        headers=auth(ret_tok),
    )
    assert r.status_code == 403

    # operator cannot rotate keys; admin can
    r = client.post(f"/api/v1/companies/{cid}/keys/rotate?purpose=entity_qr", headers=auth(op_tok))
    assert r.status_code == 403
    r = client.post(f"/api/v1/companies/{cid}/keys/rotate?purpose=entity_qr", headers=auth(tok))
    assert r.status_code == 200

    # auditor can read audit chain and it verifies
    r = client.get(f"/api/v1/companies/{cid}/audit", headers=auth(aud_tok))
    assert r.status_code == 200
    assert r.json()["chain"]["ok"] is True
    assert r.json()["chain"]["rows"] >= 3

    # auditor cannot mutate
    r = client.post(
        "/api/v1/entities",
        json={"entity_type": "product_box", "serial": "B3"},
        headers=auth(aud_tok),
    )
    assert r.status_code == 403

    # cross-tenant isolation
    other = onboard(client, name="OtherCo", email="other@co.io")
    r = client.get(f"/api/v1/companies/{cid}/schema", headers=auth(other["access_token"]))
    assert r.status_code == 403


def test_lifecycle_rules(client):
    data = onboard(client, name="LifeCo", email="life@co.io")
    cid, tok = data["company_id"], data["access_token"]
    pack = _mk(client, tok, cid, "medicine_pack", serial="SN-L")
    # forward transitions allowed
    for state in ["manufactured", "packed", "dispatched"]:
        r = client.post(
            f"/api/v1/entities/{pack['id']}/transitions",
            json={"to_state": state},
            headers=auth(tok),
        )
        assert r.status_code == 200, r.text
    # backward refused
    r = client.post(
        f"/api/v1/entities/{pack['id']}/transitions",
        json={"to_state": "packed"},
        headers=auth(tok),
    )
    assert r.status_code == 409
    # recall allowed for admin, terminal afterwards
    r = client.post(
        f"/api/v1/entities/{pack['id']}/transitions",
        json={"to_state": "recalled"},
        headers=auth(tok),
    )
    assert r.status_code == 200
    r = client.post(
        f"/api/v1/entities/{pack['id']}/transitions",
        json={"to_state": "sold"},
        headers=auth(tok),
    )
    assert r.status_code == 409


def test_duplicate_serial_rejected(client):
    data = onboard(client, name="SerialCo", email="serial@co.io")
    cid, tok = data["company_id"], data["access_token"]
    r = client.post(
        "/api/v1/entities",
        json={"entity_type": "product_box", "serial": "DUP-1"},
        headers=auth(tok),
    )
    assert r.status_code == 201
    r = client.post(
        "/api/v1/entities",
        json={"entity_type": "product_box", "serial": "DUP-1"},
        headers=auth(tok),
    )
    assert r.status_code == 409  # uniqueness enforced
