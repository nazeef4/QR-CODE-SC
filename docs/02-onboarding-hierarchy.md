# Deliverable 2 — Company Onboarding & Configurable Hierarchy Workflow

> Core requirement: *the system asks each company how its supply chain actually works*
> and builds the hierarchy from the answers — no hardcoded levels, multiple structures
> per company, multiple plants/partners.

## 1. The onboarding questionnaire (wizard)

The console (`/admin` → *Onboard your company*) guides an administrator through six steps.
Each step's answer maps to a field of the configuration posted to
`POST /api/v1/onboarding/company`.

| # | Question asked | Answer maps to | Example A (pharma) | Example B (raw materials) |
|---|---|---|---|---|
| 1 | Company name, admin account | `company_name`, `admin` | Aurora Pharma | TextileCo |
| 2 | "Which best describes your flow?" — pick a template or start blank | `template` | `pharma-classic` | `general-manufacturing` or custom |
| 3 | "List the entities you track, in operational order" (repeatable rows: name + kind + does it carry a serial?) | `entity_types` | manufacturer, batch, medicine_pack, product_box, shipping_carton, container, distributor, retailer | raw_material_supplier, manufacturing_batch, product_unit, packaging, warehouse, distributor, retailer |
| 4 | "Which entity can be packed/contained in which?" (drag-connect or add-pair rows; system prevents type-level cycles) | `relations` | box ⊃ pack, carton ⊃ box, container ⊃ carton, container ∈ distributor… | batch from supplier, unit from batch, packaging ⊃ unit, packaging in warehouse… |
| 5 | "What lifecycle states apply?" (template default shown, editable per type) | `entity_types[*].lifecycle` | registered→manufactured→packed→dispatched→received→on_sale→sold→recalled/destroyed | same default or trimmed |
| 6 | "Who may do what?" (role matrix with sensible defaults; optional per-SKU territory lists) | created users + `settings_json` | operator prints, distributor ships, retailer sells, auditor reads | same defaults |

**Design principles the wizard enforces:**
- **Type-level cycle detection at configuration time** (not just at bind time): the graph
  of `relations` is checked for cycles before publication (`hierarchy.validate_definition`).
- **Kind vocabulary** limited to `object | packaging | lot | party | location | shipment`
  so downstream UIs (lineage rendering, QR sizing, lifecycle defaults) can specialize —
  but membership is data, not code.
- **Templates are conveniences, not constraints**: `pharma-classic` and
  `general-manufacturing` ship with the product; any company can publish a fully custom
  schema. Answers are still editable JSON in the console (*Hierarchy* tab) for power users.
- **Multiple structures per company**: `hierarchy_schemas` holds many rows; entities pin
  `schema_id` at creation. Publishing a new schema version only affects *future*
  registrations, so an old product family is never retroactively invalidated.

## 2. What provisioning creates (atomic)

`POST /api/v1/onboarding/company` performs, in one transaction (`routers/onboarding.py`):

1. `companies` row + default `settings_json`.
2. Admin `users` row (role `org_admin`, PBKDF2 hash).
3. **Two Ed25519 signing keys** (`entity_qr`, `relationship`), private halves wrapped
   under the master secret; `kid = kid_<org>_<purpose>_<pubprefix>`.
4. Version 1 `hierarchy_schemas` row from the chosen template or custom definition —
   validated first (unknown types, illegal kinds, type-level cycles → HTTP 400 with a
   structured error list).
5. An `company.onboard` audit row (genesis link of the hash chain).
6. Returns `company_id`, `schema_id`, and a session token so the wizard continues
   logged-in.

Subsequent steps: create partner/operator accounts (`POST /auth/users`), register first
entities, print a pilot QR batch, then go live. The console's *Hierarchy* tab is the
living editor afterwards:

```
PUT /api/v1/companies/{cid}/schema   → validate → deactivate old active → insert v+1
GET /api/v1/companies/{cid}/schemas  → full version history (immutable rows)
```

## 3. Relationship & permission configuration

Relations are defined once at type level:

```json
{"parent": "shipping_carton", "child": "product_box", "label": "contains"}
```

At runtime `check_binding()` refuses any pair not listed — so a company can *express*
e.g. "medicine packs may sit in product boxes but never directly in containers" without
code changes. Permission model per action is the role matrix (docs/07); per-entity
territory overrides (used by the risk engine) are set at registration
(`"territory": ["PK","AE"]`).

## 4. Multi-party reality (scoped honestly)

MVP: one tenant owns its hierarchy; counterparties (distributors, retailers) are
*parties within* the tenant's schema, with their own console logins scoped to the same
company. Cross-company binding is explicitly rejected (`check_binding`: "Cross-company
bindings are forbidden"). The roadmap (docs/11 §Inter-organization) adds
invited-partner tenants with shared-visibility grants and statement co-signing —
the schema model already accommodates it because relations are org-local while entities
carry their own org id.

## 5. Failure modes handled

| Situation | Behaviour |
|---|---|
| Invalid custom schema | 400 + `schema_errors[]`, nothing written |
| Unknown entity type at registration | 400 (type not in pinned schema) |
| Serial required by type but missing | 400 |
| Duplicate serial in tenant | 409 (unique constraint) |
| Bind pair not in schema | 400 with the illegal pair named |
| Rebind without unbind | 409 (single current parent; unbind is org_admin-only and audited) |
| Old entities after schema publish | unaffected — pinned `schema_id` |
