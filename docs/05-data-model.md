# Deliverable 6 — Database Schema & Entity-Relationship Diagram

## 1. ER diagram (Mermaid — renders on GitHub / mermaid.live)

```mermaid
erDiagram
    COMPANY ||--o{ USER : "owns"
    COMPANY ||--o{ SIGNING_KEY : "holds"
    COMPANY ||--o{ HIERARCHY_SCHEMA : "defines"
    COMPANY ||--o{ ENTITY : "registers"
    COMPANY ||--o{ RELATIONSHIP_STATEMENT : "appends"
    COMPANY ||--o{ SUPPLY_EVENT : "records"
    COMPANY ||--o{ SCAN : "observes"
    COMPANY ||--o{ AUDIT_LOG : "chains"

    HIERARCHY_SCHEMA ||--o{ ENTITY : "pinned at creation"
    ENTITY ||--o{ ENTITY : "parent_id (current binding)"
    ENTITY ||--o{ RELATIONSHIP_STATEMENT : "child side"
    ENTITY ||--o{ SUPPLY_EVENT : "target"
    ENTITY ||--o{ SCAN : "scanned"
    USER ||--o{ ENTITY : "created_by / actor"
    SIGNING_KEY ||--o{ RELATIONSHIP_STATEMENT : "kid"

    COMPANY {
        string id PK
        string name
        string settings_json "alert config, territory defaults"
        datetime created_at
    }
    USER {
        string id PK
        string company_id FK
        string email "unique per company"
        string password_hash "PBKDF2-SHA256 200k"
        string role "org_admin|operator|distributor|retailer|auditor"
        bool disabled
    }
    SIGNING_KEY {
        string id PK "kid"
        string company_id FK
        string purpose "entity_qr|relationship"
        string algo "Ed25519"
        string public_key "b64url"
        string private_key_wrapped "AES-256-GCM under master/KMS"
        datetime revoked_at NULL
    }
    HIERARCHY_SCHEMA {
        string id PK
        string company_id FK
        int version
        bool is_active
        string name
        string definition_json "entity_types + relations + lifecycle"
    }
    ENTITY {
        string id PK "ent_<uuid>"
        string company_id FK
        string schema_id FK "hierarchy version pinned"
        string entity_type
        string serial "unique per company"
        string parent_id "current parent (FK logical)"
        string lifecycle_state
        int payload_seq "issuance generation"
        string attributes_json
        string territory_json NULL
        datetime activated_at NULL "first scan"
        datetime revoked_at NULL
    }
    RELATIONSHIP_STATEMENT {
        string id PK
        string company_id FK
        string child_id FK
        string parent_id "NULL for unbind"
        string op "bind|unbind"
        int seq "per-child order"
        string kid FK "signing key"
        string statement_json "canonical stmt"
        string signature "Ed25519 b64url"
        string actor_id
    }
    SUPPLY_EVENT {
        string id PK
        string company_id FK
        string entity_id FK
        string event_type "packed|dispatched|received|sold|recalled|…"
        string ts
        float location_lat/lon NULL
        string location_text
        string details_json
        string actor_id
    }
    SCAN {
        string id PK
        string company_id FK "attribution (also for unknown-entity hits)"
        string entity_id NULL
        datetime ts
        float lat/lon NULL
        string country NULL
        string device_fp NULL
        string verdict "authentic|suspicious|invalid|revoked"
        int risk_score
        string flags_json
        bool is_first_scan
    }
    AUDIT_LOG {
        int id PK "autoincrement"
        string company_id "chain per company"
        string ts
        string actor_id/actor_role
        string action
        string subject_type / subject_id
        string data_json
        string prev_hash "sha256 hex"
        string row_hash "sha256(prev|canonical(payload))"
    }
```

## 2. Design notes & invariants

- **Append-only by convention + evidence:** `relationship_statements`, `supply_events`,
  `audit_log` are never UPDATEd/DELETEd by application code (only inserts); mutations
  always *append* superseding rows (`unbind` after `bind`). `audit_log` additionally
  self-verifies via the hash chain (`audit.verify_chain`).
- **Single current pointer:** `entities.parent_id` is the read-optimized projection of
  the newest `bind` statement — projection may lag/corrupt, proof lives in statements
  (docs/03 §5–6).
- **Tenant scoping:** every table carries `company_id` (directly or via entity);
  *every query* filters by it after RBAC — cross-tenant reads are structurally
  impossible through the API (`security.same_company`).
- **Pinned schema versions:** entities reference the hierarchy schema version active at
  registration; schema evolution never rewrites existing entities (docs/02 §2).
- **Serial uniqueness:** `UNIQUE(company_id, serial)` — a duplicate identity in the same
  tenant is rejected at the database level (409).
- **Indexes:** `(company_id, entity_type)`, `parent_id`, `(child_id, seq)` for the hop
  walk, `(entity_id, ts)` for scan/event history, `(company_id, id)` for audit reads.
- **Signature storage:** statement bytes stored verbatim (`statement_json` re-serialized
  canonically at verify time); signatures in `signature` — full verification possible
  from an offline DB dump + public keys (auditor scenario).
- **Scan attribution edge case:** well-formed payloads of unknown entities (leaked or
  destroyed prints) attribute the scan to the payload's `org` so the tenant *sees* the
  probe in alerts; fully invalid blobs land under `company_id='unknown'` (documented
  spam caveat; production adds authenticated scan-token minting).

## 3. SQLite (reference) → PostgreSQL (production)

Schema uses portable types; `JSON` columns are text-wrapped for SQLite and map to
`JSONB` in Postgres (better indexing of `flags_json`/`attributes_json`). The audit chain
needs **strict insert serialization per company** — Postgres: `SELECT … FOR UPDATE` on a
per-company chain-head row or serializable transactions under high concurrency; SQLite
is serialized by its single-writer lock. WAL mode enabled for read-during-write.
