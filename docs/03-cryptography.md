# Deliverables 3 & 5 — Cryptographic QR Methodology and Parent-Child Relationships

## 1. Goals → primitive selection

| Goal | Candidate | Decision | Why |
|---|---|---|---|
| Publicly verifiable authenticity, non-repudiation | Ed25519 / ECDSA-P256 / RSA | **Ed25519** (RFC 8032) | deterministic nonces (no `k`-reuse disasters), 64-byte sigs (QR budget), fast verify, no curve-parameter footguns. ECDSA-P256 kept as an option **only** where FIPS/HSM mandates it. |
| Shared-secret token | HMAC-SHA256 | **rejected for on-product tokens** | every verifier would hold the forging secret; fine inside a single vendor's server, incompatible with "third parties/auditors can verify". |
| Integrity of payload bytes | signature over canonical bytes | **Ed25519 over canonical JSON** | canonical form (sorted keys, `","`/`":"`, UTF-8, no NaN) removes encoding ambiguity attacks. |
| Identity uniqueness | UUIDv4 ids + tenant-unique serials | **kept** | collisions negligible; serial uniqueness enforced per tenant (409 on duplicate). |
| Key storage | plaintext / KMS / HSM | **wrapped at rest + KMS/HSM seam** | AES-256-GCM under master secret in MVP (`config.MASTER_KEY`); same call surface swaps to KMS/HSM without touching domain code. |
| Parent-child link | hashed link / signed statement / DB FK alone | **signed statement + FK pointer** | FK alone is mutable; hash-only links don't prove authorization. A signature proves *the org's key holder authorized this exact edge at this exact time*. |

## 2. The QR payload: `SCQR1` token

```
SCQR1 . <base64url(canonical_json(body))> . <base64url(Ed25519 signature)>

signed bytes = "SCQR1" || "." || <body segment>      (prefix binding prevents cross-protocol reuse)

body = {
  "v":    1,                       // format version
  "org":  "org_26743f44…",         // issuer tenant
  "ent":  "ent_67c964a0…",         // entity id — the unique identity
  "typ":  "medicine_pack",         // entity type (self-describing offline)
  "kid":  "kid_26743f44_entity_qr_VMEwD-EG0Q",  // which public key verifies this
  "seq":  1,                       // issuance generation (re-issue bumps it)
  "iss":  "2026-11-23T19:22:01Z",  // stable issue time (entity creation / re-issue)
  "par":  "ent_box…",              // OPTIONAL: parent at issuance (aggregation labels)
  ...                              // deliberately minimal: ≤ ~300 chars total
}
```

Size budget: body ≈ 180–260 chars + 64-byte sig (86 b64u) → typical token 300–420
bytes → QR version 10–15 at ECC M, comfortably printable at 20×20 mm. `qr.py` uses ECC
M because *correctness of the print* (wear, dirt) is what error correction addresses;
*forgery* is addressed by the signature — layers kept separate on purpose.

**Design rules encoded in the format:**
- **No secrets in the QR.** The token is public; it proves issuer authorization, not
  possession. Anything that must stay secret (PINs, NFC keys) is a *separate* layer
  (docs/04).
- **Prefix domain separation** (`SCQR1.` signed bytes) — a signature can never be
  replayed as a relationship statement (which signs `"SCQR1." + canonical(statement)`).
- **`kid` inline** — verifiers resolve exactly which key without ambiguity.
- **`seq`** — re-issued payloads (reprint after re-parenting) bump it; the server flags
  scans of superseded prints (`STALE_PAYLOAD_SEQ`).
- **`par` present only when known at issuance** (pre-planned aggregation labels, or
  re-issue after packing). Item codes printed on the filling line legitimately have no
  parent yet — the server resolves the current signed binding instead. If `par` *is*
  printed and later disagrees with the signed state → `PARENT_MISMATCH` flag, which is
  exactly the repacking-fraud signal (docs/04 §5).

## 3. QR-vs-server: where must crypto live?

**Decision: hybrid — signed statement *in* the QR, authoritative *state* on the server.**

| | Everything in QR (offline-proof) | Everything through server (plain URL) | **Hybrid (chosen)** |
|---|---|---|---|
| Detects bit-flips/forgery of payload | ✅ | ❌ (URL is forgeable; only lookup saves you) | ✅ signature verified first |
| Detects cloned-but-genuine print | ❌ stateless | ✅ telemetry | ✅ telemetry |
| Detects revocation / re-parenting | ❌ snapshot goes stale | ✅ | ✅ |
| Works without backend reachability | ✅ signature check offline | ❌ | partial: signature offline, state pending |
| QR size | large (sig inside) | tiny | medium (still ≤ 420 B) |
| Non-repudiable to third parties | ✅ | ❌ depends on vendor DB | ✅ pubkeys exportable |

A pure-offline design is *provably* unable to notice that the same authentic token now
appears on two continents — clone detection is inherently a stateful, online function.
A pure-server design reduces the QR to "a link the server may or may not validate
honestly", forfeiting offline evidence and third-party verifiability. The hybrid keeps
the two guarantees where they can actually exist: **authenticity/integrity in the code,
currency/consistency/telemetry in the service.**

## 4. Key management

- **Per tenant, per purpose:** `entity_qr` (product tokens) and `relationship`
  (bindings) keys are separate so a print-pipeline compromise doesn't automatically
  authorize re-parenting. `kid = kid_<org8>_<purpose>_<pubprefix>`.
- **Rotation:** `POST /companies/{cid}/keys/rotate` mints a new key; **old keys remain
  valid for verification** (already-printed codes must keep verifying) but stop being
  used for issuance (newest non-revoked key wins). Rotation is audited.
- **Revocation:** `revoked_at` on a key invalidates everything it signed (payloads
  with that kid → `UNKNOWN_KEY` invalid verdict; statements → hop verification fails).
  This is the break-glass response to key theft.
- **At rest:** private halves AES-256-GCM-wrapped (`crypto.wrap_private_key`) under a
  master secret from the environment. Production note: the wrap/unwrap functions are
  the single seam that becomes a KMS/HSM (CloudKMS `encrypt/Decrypt`, PKCS#11) —
  domain code never sees raw private keys in that configuration.
- **Ceremony:** MVP generates keys in-process at onboarding. Production step: generate
  in HSM, export public only; dual-control for revocation (roadmap).

## 5. Parent-child relationships: signed statements

Every edge mutation produces an **append-only signed statement**:

```json
{"v":1,"op":"bind","org":"org_…","child":"ent_pack…","parent":"ent_box…",
 "seq":3,"ts":"2026-11-23T19:22:05Z"}
// signed: Ed25519(org relationship key) over  "SCQR1." + canonical_json(stmt)
```

Stored in `relationship_statements` together with `kid`, signature, actor, timestamp.
An `unbind` statement (parent `null`) supersedes prior binds; `seq` orders the history.

**Write path (`service.bind`)** — one DB transaction:
1. RBAC (`binding.create`; **unbind requires `binding.remove` = org_admin only**);
2. schema relation check, tenant check, revocation check;
3. **cycle check** by walking the current parent chain (max 64 hops);
4. append statement (signed) → update `entities.parent_id` → audit row.

**Why sign if the DB also has the pointer?** The pointer is for *fast reads*; the
statement is for *proof*. Tampering with `parent_id` alone makes current state
disagree with the newest statement → `is_current_binding=false` on that hop →
`chain_verified=false`. Deleting/altering statements breaks the audit hash chain.
An attacker who controls *both* DB and API still cannot forge a *new* statement
without the relationship key, and cannot erase history silently after external
anchoring of chain heads (docs/01 §7).

## 6. Verifying the hierarchy from any scanned node

`GET /entities/{id}/lineage` and every scan run the same algorithm:

```
upward (child → root):                        downward (node → leaves):
  cursor = scanned node                         BFS over entities.parent_id == cursor
  while cursor.parent_id:                       depth-limited (≤6 in API)
    load newest bind statement for              each child edge re-checked by the
      (cursor, current parent)                  same hop-verification on request
    hop_valid = statement exists
                ∧ Ed25519(statement) verifies
                ∧ statement.parent == entities.parent_id
                ∧ parent not revoked
    edge case: missing/invalid statement ⇒ chain_verified = false, hop flagged
    cursor = parent
  cycle-guard: visited-set, cap 64 hops
```

Properties:
- **Works from any node**: an upward walk from a pack and a downward walk from a
  container meet in the same verified spine; roots and isolated nodes verify trivially
  (`chain_verified=true`, zero hops).
- **No trust in unverified relationships**: a hop counts only if its *own* signature
  checks out under the tenant's relationship key; the response reports per-hop
  `signature_valid` and `is_current_binding`, not a single opaque boolean.
- **Depth safety**: cycle guard + cap; descendant trees are depth-limited per request.
- **Batch-level corroboration** (origin): packs reference `batch_id` in attributes;
  scans resolve batch → manufacturer through the same verified chain (single-parent
  spine keeps containment semantics clean; see roadmap for multi-edge qualifiers à la
  EPCIS AssociationEvent).

## 7. What this construction guarantees — and what it does not

**Guarantees.** (g1) Only holders of the tenant keys can mint valid codes or edges.
(g2) Any mutation of payload or statement bytes invalidates signatures. (g3) Current
state and historical statements must agree or verification reports it. (g4) History is
append-only and tamper-evident (hash chain). (g5) Every code is unique per entity and
supersedible via `seq`.

**Explicit non-guarantees.** (n1) A *photographed* genuine token still verifies —
handled by docs/04 telemetry, not cryptography. (n2) A malicious tenant admin can
authorize false edges *with their own key* — detectable by counterparties/auditors who
pin expected chain heads (anchoring), not preventable inside one tenant. (n3) Scan
context (geo/device) is client-claimed. Each non-guarantee maps to a control in
docs/04/docs/10 rather than being hand-waved away.
