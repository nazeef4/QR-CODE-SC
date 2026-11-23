"""Cryptographic primitives for SCQR.

Design summary (see docs/03-cryptography.md for the full rationale):

* Ed25519 (RFC 8032) is used for all signing. Small signatures (64 B),
  fast verification, deterministic nonces, no parameter pitfalls.
* Every organisation owns an Ed25519 key-pair per *purpose*
  (``entity_qr`` and ``relationship``), identified by a ``kid``.
  Private keys are wrapped at rest with AES-256-GCM under a master key
  (KMS/HSM in production — this module isolates that concern).
* QR payloads are compact, self-describing signed statements:

      SCQR1.<base64url(canonical_json(body))>.<base64url(signature)>

* Canonical JSON = UTF-8, sorted keys, separators ("," ":"), no NaN —
  the exact bytes that were signed are what a verifier re-serialises.
* Relationship statements (child→parent binds/unbinds) are separate
  signed statements persisted in an append-only table so the hierarchy
  can be re-verified independently of mutable columns.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PAYLOAD_PREFIX = "SCQR1"
SIG_SCHEME = "Ed25519"


# --------------------------------------------------------------------------- #
# Encoding helpers
# --------------------------------------------------------------------------- #
def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def canonical_json(obj: Any) -> bytes:
    """Deterministic byte encoding used for everything that gets signed."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Key management
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[str, bytes]:
    """Return (public_key_b64u, raw_private_bytes)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    return b64u_encode(pub), priv.private_bytes_raw()


def _wrapping_key(master_key: str) -> bytes:
    return hashlib.sha256(("scqr-wrap-v1:" + master_key).encode("utf-8")).digest()


def wrap_private_key(raw_priv: bytes, master_key: str) -> str:
    """AES-256-GCM wrap of the raw Ed25519 private key (demo key storage)."""
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_wrapping_key(master_key)).encrypt(nonce, raw_priv, b"scqr-privkey-v1")
    return b64u_encode(nonce + ct)


def unwrap_private_key(blob: str, master_key: str) -> bytes:
    raw = b64u_decode(blob)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(_wrapping_key(master_key)).decrypt(nonce, ct, b"scqr-privkey-v1")


def sign(private_key_raw: bytes, data: bytes) -> str:
    return b64u_encode(Ed25519PrivateKey.from_private_bytes(private_key_raw).sign(data))


def verify(public_key_b64u: str, data: bytes, signature_b64u: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(b64u_decode(public_key_b64u))
        pub.verify(b64u_decode(signature_b64u), data)
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


# --------------------------------------------------------------------------- #
# QR payload: identity statement
# --------------------------------------------------------------------------- #
def build_qr_payload(body: dict[str, Any], private_key_raw: bytes) -> str:
    """Serialise + sign an entity identity statement into an SCQR1 token."""
    body_b64 = b64u_encode(canonical_json(body))
    signed_bytes = PAYLOAD_PREFIX.encode("ascii") + b"." + body_b64.encode("ascii")
    sig_b64 = b64u_encode(
        Ed25519PrivateKey.from_private_bytes(private_key_raw).sign(signed_bytes)
    )
    return ".".join([PAYLOAD_PREFIX, body_b64, sig_b64])


def entity_payload_body(
    *,
    company_id: str,
    entity_id: str,
    entity_type: str,
    kid: str,
    seq: int,
    parent_id: str | None,
    issued_at: str,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "v": 1,
        "org": company_id,
        "ent": entity_id,
        "typ": entity_type,
        "kid": kid,
        "seq": seq,
        "iss": issued_at,
    }
    if parent_id:
        body["par"] = parent_id
    return body


def parse_qr_payload(raw: str) -> tuple[dict[str, Any] | None, str | None, str | None]:
    """Return (body, signature_b64u, error_code)."""
    parts = raw.strip().split(".")
    if len(parts) != 3 or parts[0] != PAYLOAD_PREFIX:
        return None, None, "MALFORMED_PAYLOAD"
    try:
        body = json.loads(b64u_decode(parts[1]))
        sig = parts[2]
    except (ValueError, json.JSONDecodeError):
        return None, None, "MALFORMED_PAYLOAD"
    if not isinstance(body, dict):
        return None, None, "MALFORMED_PAYLOAD"
    return body, sig, None


def signed_payload_bytes(raw: str) -> bytes:
    """Bytes a verifier must re-derive: 'SCQR1.' + body segment."""
    parts = raw.strip().split(".")
    if len(parts) != 3:
        raise ValueError("malformed payload")
    return PAYLOAD_PREFIX.encode("ascii") + b"." + parts[1].encode("ascii")


def verify_qr_payload(raw: str, public_key_b64u: str) -> tuple[dict[str, Any] | None, bool, str | None]:
    """Full cryptographic verification of a payload against a known key.

    Returns (body, signature_ok, parse_error).
    """
    body, sig, err = parse_qr_payload(raw)
    if err:
        return None, False, err
    try:
        ok = verify(public_key_b64u, signed_payload_bytes(raw), sig)
    except ValueError:
        return None, False, "MALFORMED_PAYLOAD"
    return body, ok, None


# --------------------------------------------------------------------------- #
# Relationship statements (signed parent-child bindings)
# --------------------------------------------------------------------------- #
def relationship_statement(
    *, op: str, child_id: str, parent_id: str | None, company_id: str, seq: int, ts: str
) -> dict[str, Any]:
    return {
        "v": 1,
        "op": op,  # "bind" | "unbind"
        "org": company_id,
        "child": child_id,
        "parent": parent_id,
        "seq": seq,
        "ts": ts,
    }


def sign_statement(stmt: dict[str, Any], private_key_raw: bytes) -> str:
    return sign(private_key_raw, PAYLOAD_PREFIX.encode("ascii") + b"." + canonical_json(stmt))
