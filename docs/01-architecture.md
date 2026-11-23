# Deliverable 1 — System Architecture

## 1. Architecture at a glance

```
                         ┌────────────────────────────────────────────────┐
   PHYSICAL LAYER        │  printed QR (SCQR1 signed token) · tamper      │
   pack · box · carton   │  label · optional NFC/scratch · CDP pattern    │
   container · pallet    └───────────────┬────────────────────────────────┘
                                        │ camera / handheld scanner
   CLIENTS              ┌───────────────▼──────────────────┐
                        │  Scan PWA (index.html)           │  consumer / warehouse
                        │  camera+jsQR · geolocation       │  — no account
                        │  verdict + journey + lineage     │
                        ├──────────────────────────────────┤
                        │  Company Console (admin.html)    │  org_admin/operator/
                        │  onboarding · schema · entities  │  distributor/retailer/
                        │  QR print · alerts · audit       │  auditor — JWT + RBAC
                        └───────────────┬──────────────────┘
                                        │ HTTPS (same-origin / REST)
   API GATEWAY          ┌───────────────▼──────────────────┐
                        │  FastAPI application             │
                        │  /onboarding /auth /companies    │
                        │  /entities /scans /audit         │
                        ├──────┬──────────┬────────┬───────┤
                        │ RBAC │ rate     │ schema │ audit │
                        │ deps │ limiter  │ valid. │ chain │
                        └──┬───┴────┬─────┴───┬────┴───┬───┘
   DOMAIN SERVICES       ┌─▼────────▼─────────▼────────▼──────────────────┐
                        │  QR issuance     signed relationship service    │
                        │  verification    clone-detection (risk engine)  │
                        │  lineage walker  lifecycle/event service        │
                        ├─────────────────────────────────────────────────┤
                        │  Crypto core: Ed25519 sign/verify · key wrap    │
                        │  canonical JSON · SCQR1 payload codec           │
                        └──────────────────┬──────────────────────────────┘
   PERSISTENCE          ┌──────────────────▼──────────────────────────────┐
                        │  PostgreSQL (prod) / SQLite (reference)         │
                        │  entities · hierarchy_schemas · relationship_   │
                        │  statements · supply_events · scans · signing_  │
                        │  keys · users · audit_log(hash-chained)         │
                        └──────────────────┬──────────────────────────────┘
   TRUST ANCHORS        ┌──────────────────▼──────────────────────────────┐
                        │  KMS/HSM wraps org private keys (prod)         │
                        │  External anchor: chain-head commitments →      │
                        │  RFC3161 TSA / transparency log (pluggable)     │
                        │  Notifications: webhook/email on alerts         │
                        └─────────────────────────────────────────────────┘
```

**Style.** Modular monolith with strict internal layering (routers → services → crypto/
risk/audit → persistence). Justification: the write-path invariants (a binding must be
checked, signed, audited *atomically*) are far easier to guarantee inside one transaction
boundary than across microservices. Clear module seams (`crypto.py`, `risk.py`,
`service.py`) allow later extraction of the scan path (hottest endpoint) into a dedicated
service without redesign.

## 2. Component responsibilities

| Component | Responsibility | Reference implementation |
|---|---|---|
| Scan PWA | decode QR, collect context (geo/device), render verdict/journey | `frontend/index.html` + vendored jsQR |
| Company Console | onboarding wizard, hierarchy editor, entity/QR management, alerts, audit | `frontend/admin.html` |
| API gateway | authn (JWT), RBAC, tenant scoping, rate limiting, validation | FastAPI dependencies |
| QR issuance | build canonical body → Ed25519 sign → `SCQR1` token → PNG | `crypto.py`, `qr.py`, `service.issue_payload` |
| Verification | signature → entity → state consistency → risk → lineage | `routers/scans.py`, `risk.py` |
| Relationship service | signed bind/unbind statements, cycle & schema checks | `service.py`, `hierarchy.py` |
| Lineage walker | upward verified chain, downward tree, from **any** node | `service.verify_chain_up`, `descendants_tree` |
| Risk engine | activation, geo-velocity, territory, lifecycle heuristics | `risk.py` |
| Audit chain | append-only hash-chained log + offline `verify_chain()` | `audit.py` |
| Key management | per-org keys per purpose; wrap at rest; rotate/revoke | `models.SigningKey`, `config.MASTER_KEY` |

## 3. Trust model (what is trusted, what is verified)

1. **Clients are hostile.** Every payload, binding, transition and scan context is
   server-validated against schema, RBAC and signatures. Scan context (lat/lon/country)
   is *signal*, never proof.
2. **The database is not trusted for integrity.** Entity state (parent pointers,
   lifecycle) is *corroborated* by signed statements and signatures; any silent row edit
   breaks statement consistency or the audit hash chain, and `verify_chain()` exposes it.
3. **Signing keys are the root of trust per tenant.** Private keys are wrapped
   (AES-256-GCM under a master secret; KMS/HSM in production), per-purpose separated,
   rotatable and revocable. Compromise of the DB without key access yields *denial of
   truth* (availability) but not *undetectable forgery* (edits break the chain; forging
   statements requires the key).
4. **The operator itself is in the threat model.** Hence hash-chained audit + the
   external anchoring hook (docs/10): the operator cannot silently rewrite history once
   a chain head has been anchored elsewhere.
5. **What cryptography cannot cover:** the physical-to-digital link (a genuine QR on a
   fake pack) — handled by docs/04's layered strategy, not by this layer.

## 4. Request paths

**Consumer scan (hot path, unauthenticated):**
`POST /api/v1/scans` → rate limit → parse SCQR1 → kid lookup → Ed25519 verify →
entity resolve (org binding!) → revocation → payload↔state consistency
(parent/seq) → risk heuristics vs scan history → persist scan (first scan ⇒ activation)
→ upward signed-lineage verification → verdict + journey response. Target p95 < 200 ms
at MVP scale (single-digit ms of that is crypto; the rest is one indexed read-path).

**Packing-line bind (write path, authenticated):**
`POST /entities/{child}/bindings` → RBAC (`binding.create`) → schema relation check →
cycle/tenant/revocation checks → build statement → sign with org *relationship* key →
append `relationship_statements` + update pointer + audit row — **one transaction**.

**QR issuance:** canonical body `{v,org,ent,typ,kid,seq,iss[,par]}` → sign → token;
PNG rendering is stateless and can be re-run any time (payload is deterministic for a
given seq/key, so the QR on the box equals the token in the DB).

## 5. Deployment topologies

- **MVP / evaluation (this repo):** one process, SQLite (WAL), file-backed QR cache.
  `uvicorn backend.app.main:app` — horizontally *not* scalable by design of file state.
- **Production single-tenant or SaaS:** stateless API replicas behind LB; PostgreSQL;
  Redis for rate limits + kid cache; object storage for QR print batches; KMS for key
  wrapping; workers for alert fan-out (email/webhook); Prometheus/Grafana.
- **Edge (warehouse lines):** local issuance agent batches registrations from the line
  and flushes to the API — the QR can even be pre-signed offline with a line-local key
  (documented extension: offline issuance under a delegated, rate-limited sub-key).

## 6. Availability & degradation

- Verification *requires* online state (revocation, bindings, telemetry) — accepted
  trade-off, stated openly: signature-only offline verification would accept revoked or
  re-parented entities. Mitigation for constrained contexts: an `export` of the public
  keys + recent revocation list allows **offline signature authenticity checks** with
  online state deferred (roadmap).
- SQLite → PostgreSQL is a config change (`SCQR_DB_PATH` vs `DATABASE_URL`), all SQL is
  dialect-portable.

## 7. Centralized DB vs distributed ledger — decision record

| Option | Integrity across parties | Against operator malfeasance | Ops cost | Fit here |
|---|---|---|---|---|
| Plain centralized DB | single trust point | none | low | ✗ alone |
| + signed statements + hash-chained audit + **external anchoring** | verifiable by any party with public keys | edits detectable after anchor | low | ✅ **chosen** |
| Consortium blockchain | consensus trust | strong (if partners run nodes) | high (governance!) | only under trigger below |
| Full on-chain storage | — | — | data explosion, privacy leak | ✗ always |

**Trigger to revisit:** ≥3 mutually distrusting write-parties with verified willingness
to run nodes *and* contractual agreement on visibility — then hybrid (events off-chain,
Merkle roots of `audit_log.row_hash` on-chain) behind the same anchor interface.
Rationale and citations: docs/00 §5.

## 8. Security controls inventory (architecture level)

TLS everywhere · JWT (HS256, 12 h expiry; asymmetric in prod) · PBKDF2-SHA256 200k
iterations · tenant scoping on every query · RBAC matrix (docs/07) · per-IP scan rate
limit · canonical JSON (no signature-bypass via re-encoding) · key separation by
purpose · payload `seq` supersession · append-only tables for statements/events/audit ·
full audit of every mutation · security headers and payload size caps (hardening list,
docs/10 §backlog).
