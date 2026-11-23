# Deliverable 7 — API Endpoint Design

Base path `/api/v1`. Auth = `Authorization: Bearer <JWT>` except where marked **public**.
Errors: RFC-7807-style JSON `{"detail": … | {"schema_errors":[…]}}`. Full OpenAPI at
`/api/v1/docs` (Swagger UI) when the service runs.

## 1. Onboarding & auth

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/templates` | public | starter hierarchy templates for the wizard |
| POST | `/onboarding/company` | public* | provision company + admin + 2 keys + schema v1; returns token |
| POST | `/auth/login` | public* | email/password → JWT (12 h) |
| GET | `/auth/me` | any user | session introspection |
| POST | `/auth/users` | `user.manage` | create scoped user (role constrained) |

\* public = rate-limited in production; onboarding additionally guarded by CAPTCHA/invite
in the hosted offering (docs/10).

## 2. Company / hierarchy / keys

| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/companies/{cid}/schema` | `schema.read` | active hierarchy definition |
| GET | `/companies/{cid}/schemas` | `schema.read` | immutable version history |
| PUT | `/companies/{cid}/schema` | `schema.write` | validate + publish new version |
| GET | `/companies/{cid}/keys` | `key.rotate` | list public keys (kid, purpose, state) |
| POST | `/companies/{cid}/keys/rotate?purpose=` | `key.rotate` | mint new key (old stays valid for verify) |
| GET | `/companies/{cid}/stats` | `company.read` | dashboard aggregates |
| GET | `/companies/{cid}/alerts?limit=` | `alert.read` | non-authentic scans feed |
| GET | `/companies/{cid}/audit?limit=` | `audit.read` | audit rows **+ chain verification status** |

## 3. Entities, bindings, lineage, QR

| Method | Path | Permission | Purpose / notes |
|---|---|---|---|
| POST | `/entities` | `entity.register` | create entity; optional `parent_id` binds at creation (signed); serial per schema rules |
| GET | `/entities?type=&parent=&state=&serial=&limit=&offset=` | `entity.read` | filtered listing |
| GET | `/entities/{id}` | `entity.read` | detail: attrs, children, latest statements, events |
| GET | `/entities/{id}/lineage?max_descendant_depth=` | `entity.read` | **verified chain upward** (per-hop signature status) + descendants tree downward |
| GET | `/entities/{id}/payload` | `entity.print` | deterministic SCQR1 token |
| GET | `/entities/{id}/qr.png?size=` | `entity.print` | rendered PNG (same token) |
| POST | `/entities/{id}/reissue` | `entity.print` | bump `seq`, re-sign with current parent (reprint flow) |
| POST | `/entities/{id}/bindings` | `binding.create` | signed bind; 400 (pair not in schema) / 409 (bound, cycle, revoked, cross-tenant) |
| DELETE | `/entities/{id}/bindings/current` | `binding.remove` | **org_admin only** — audited unbind (re-parent step 1) |
| POST | `/entities/{id}/transitions` | `lifecycle.transition` | forward-only state change; recall/destroy = `org_admin` |
| POST | `/entities/{id}/events` | `event.create` | supply event (+ optional geo); standard types auto-advance lifecycle |
| GET | `/entities/{id}/events` | `entity.read` | event history |

## 4. Scans (the verification surface)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/scans` | **public** | full verification pipeline (docs/03 §2, docs/04 §3). Body: `{payload, context:{lat,lon,country,device_fp}}`; per-IP budget (429 over limit) |
| GET | `/scans?entity_id=&verdict=&limit=` | `scan.read` | scan history for triage |

**Response shape (abridged):**
```jsonc
{
  "verdict": "authentic|suspicious|invalid|revoked",
  "risk_score": 0,
  "flags": [{"code":"IMPOSSIBLE_TRAVEL","severity":"high","detail":"1142 km … 12 min"}],
  "authenticity": {"signature_valid": true, "kid": "kid_…", "payload_seq": 1},
  "activation": {"first_scan_at":"…","previously_activated": true, "scan_count": 2},
  "entity": {"id":"ent_…","type":"medicine_pack","serial":"SN-…","lifecycle_state":"received", …},
  "origin": {"batch": {…}, "manufacturer": {"name": "…"}},
  "relationships": {"chain_verified": true, "hops": [
      {"child_id":"…","parent_id":"…","signature_valid":true,"is_current_binding":true}
  ]},
  "journey": [{"event_type":"packed","ts":"…","location":"Karachi Plant","details":{…}}]
}
```

## 5. Conventions

- **Verdict vocabulary is closed:** consumers and integrators switch on four values;
  flags carry the evidence detail.
- **Idempotency:** scans are naturally append-mostly (never idempotent — each is
  evidence); binds are guarded (409 on rebind); registration rejects duplicate serials.
- **Versioning:** breaking changes → `/api/v2`, additive fields allowed silently.
- **Pagination:** `limit`/`offset` with hard caps (≤500 / ≤1000).
- **Non-ideal choices acknowledged:** JWT-HS256 instead of mTLS (roadmap), no OpenAPI
  webhook subscriptions yet (alerts are polled) — both tracked in docs/11.
