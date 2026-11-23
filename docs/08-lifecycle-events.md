# Deliverable 9 — Product Lifecycle & Supply-Chain Event Model

## 1. Two related but distinct concepts

| | Lifecycle state (`entities.lifecycle_state`) | Supply event (`supply_events`) |
|---|---|---|
| Nature | current *status* of an entity (state machine) | immutable *fact* that happened (append-only) |
| Cardinality | one current value per entity | many per entity |
| Mutability | updated via audited transition | never updated — corrected by appending |
| Audience | quick filtering, risk heuristics, UI badges | journey timeline, EPCIS export, forensics |

Events *drive* states in practice: recording `dispatched` advances the lifecycle
forward-only (map in `routers/entities.py`), while a raw transition remains available
for edge flows (QC holds, corrections). Both paths are audited.

## 2. Default state machine (per-type overridable in schema)

```
registered ─▶ manufactured ─▶ packed ─▶ dispatched ─▶ received ─▶ on_sale ─▶ sold
     │              │             │           │            │
     └──────────────┴─────────────┴───────────┴────────────┴──▶ recalled ◀── (org_admin only)
                                                                        │
                                                                 destroyed (org_admin only)
```

Rules enforced (`POST /entities/{id}/transitions`):
1. target must exist in the entity type's `lifecycle` list (schema-configurable);
2. **forward-only** (index comparison) — backward moves 409 unless explicitly overridden;
3. `recalled`/`destroyed` are **terminal** — nothing exits them;
4. `recalled`/`destroyed` require `org_admin`;
5. every transition writes an audit row `{from, to, actor}`.

**Semantics of key states**
- `registered` — identity exists (QR may be printed); not yet in trade.
- `packed` — inside its parent packaging; scanning now trips `PRE_DISPATCH_SCAN`
  (behavioural control, docs/04).
- `dispatched` — custody left origin (event carries geo/time).
- `received` — counterparty accepted (closes the custody hop).
- `on_sale` / `sold` — retail presence / final transfer.
- `recalled` — tainted: any further scan reports the entity as non-authentic
  territory (`revoked` verdict comes from `revoked_at`, the harder kill-switch).
- `destroyed` — identity retired (returns, destruction audits).

Parties/locations (`kind: party|location`) typically live in `received`/`active`
states — the lifecycle list per type is configurable precisely so a retailer row isn't
forced through `manufactured`.

## 3. Event taxonomy

| `event_type` | Producer role | Auto-advances to | Payload details (examples) |
|---|---|---|---|
| `packed` | operator | `packed` | line id, operator, units in container |
| `dispatched` / `shipped` | operator, distributor | `dispatched` | vehicle, destination, ASN ref |
| `received` | distributor, retailer | `received` | gate check, condition notes |
| `sold` | retailer | `sold` | channel, till ref |
| `recalled` | org_admin | `recalled` | recall case id, reason |
| `qc_hold`, `rework`, `destroyed`, custom… | per permission | optional | free-form JSON |

Every event: `id, entity_id, org, ts, actor, location{lat,lon,text}, details_json` —
mirrors EPCIS' *what/when/where/who/why* columns for later export (docs/00 §1). Sensor
extensions (temperature during `dispatched`) ride in `details_json` now, become typed
`SensorElement` mappings in the integration phase.

## 4. Example timeline (medicine pack, from the demo seed)

```
t0  entity.register   SN-AMX-0001 created (serial, batch_id ref)          [operator]
t1  relationship.bind pack → BOX-1 (signed stmt seq=1)                    [operator]
t2  event packed       details{line: FillingLine-3}  state: packed        [operator]
t3  transition         packed → dispatched → received                     [operator/distrib.]
t4  SCAN #1            Islamabad, device-iPhone  → authentic, activation  [consumer]
t5  SCAN #2            Karachi 12 min later       → suspicious:
                         IMPOSSIBLE_TRAVEL (1142 km / 12 min)            [alert!]
t6  (analyst)          entity revoked / batch recalled (org_admin)        [audited]
t7  SCAN #3            → revoked verdict, consumer sees warning
```

## 5. Event integrity posture (honest scope)

MVP events are authenticated by *who could write them* (RBAC + JWT) and covered by the
hash-chained audit log — not individually signed with per-device keys. Production
hardening (roadmap): detachable event signatures (per-line/device keys), enabling EPCIS
`certificationInfo`-style portable proofs and co-signing by counterparties at
receipt hops.
