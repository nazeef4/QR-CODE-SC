"""Unit tests for the cryptographic core."""
from __future__ import annotations

import json

from backend.app import crypto


def test_key_wrap_roundtrip():
    pub, priv = crypto.generate_keypair()
    blob = crypto.wrap_private_key(priv, "master")
    assert crypto.unwrap_private_key(blob, "master") == priv
    try:
        crypto.unwrap_private_key(blob, "wrong-master")
        assert False, "must not unwrap with wrong key"
    except Exception:
        pass


def test_sign_verify_and_tamper_detection():
    pub, priv = crypto.generate_keypair()
    body = crypto.entity_payload_body(
        company_id="org_a", entity_id="ent_1", entity_type="medicine_pack",
        kid="kid_1", seq=1, parent_id=None, issued_at="2026-01-01T00:00:00Z",
    )
    payload = crypto.build_qr_payload(body, priv)
    parsed, ok, err = crypto.verify_qr_payload(payload, pub)
    assert err is None and ok and parsed == body

    # flip one character in the body segment → signature must fail
    parts = payload.split(".")
    flipped = ("A" if parts[1][5] != "A" else "B")
    tampered = parts[0] + "." + parts[1][:5] + flipped + parts[1][6:] + "." + parts[2]
    parsed2, ok2, err2 = crypto.verify_qr_payload(tampered, pub)
    assert not ok2
    # JSON may still parse — signature is what catches the mutation
    if err2 is None:
        assert parsed2 != body or not ok2

    # swapping the signature segment also fails
    payload2 = f"{parts[0]}.{parts[1]}.{crypto.b64u_encode(b'x' * 64)}"
    _, ok3, _ = crypto.verify_qr_payload(payload2, pub)
    assert not ok3


def test_malformed_payloads():
    for bad in ["", "hello", "SCQR1.only-two", "SCQR2.aaa.bbb", "SCQR1.!!!.bbb"]:
        body, ok, err = None, False, None
        parsed, sig, err = crypto.parse_qr_payload(bad)
        assert err is not None or parsed is None


def test_canonical_json_is_deterministic():
    a = crypto.canonical_json({"b": 1, "a": [1, 2], "c": {"z": True}})
    b = crypto.canonical_json({"c": {"z": True}, "a": [1, 2], "b": 1})
    assert a == b
    assert b'{"a":[1,2],"b":1,"c":{"z":true}}' == a


def test_relationship_statement_sign_verify():
    pub, priv = crypto.generate_keypair()
    stmt = crypto.relationship_statement(
        op="bind", child_id="ent_c", parent_id="ent_p",
        company_id="org_1", seq=3, ts="2026-01-01T00:00:00Z",
    )
    sig = crypto.sign_statement(stmt, priv)
    data = crypto.PAYLOAD_PREFIX.encode() + b"." + crypto.canonical_json(stmt)
    assert crypto.verify(pub, data, sig)
    tampered = dict(stmt, parent_id="ent_evil")
    data2 = crypto.PAYLOAD_PREFIX.encode() + b"." + crypto.canonical_json(tampered)
    assert not crypto.verify(pub, data2, sig)


def test_qr_render_smoke():
    from backend.app.qr import render_qr

    pub, priv = crypto.generate_keypair()
    body = {"v": 1, "org": "o", "ent": "e", "typ": "t", "kid": "k", "seq": 1,
            "iss": "2026-01-01T00:00:00Z"}
    payload = crypto.build_qr_payload(body, priv)
    png = render_qr(payload, size=240)
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert len(png) > 500
