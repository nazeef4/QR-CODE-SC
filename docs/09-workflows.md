# Deliverable 10 — End-to-End Workflows with Practical Examples

> Everything below runs against the reference implementation. The scripted demo
> (`scripts/seed_demo.py`) executes flows A–D and prints its transcript; console UI at
> `/admin`, consumer scanner at `/`.

## 0. Actors & setup (once per tenant)

```
POST /api/v1/onboarding/company
  {company_name:"Aurora Pharmaceuticals",
   admin:{email:"admin@aurora-pharma.example", password:"aurora-demo-pass-1"},
   template:"pharma-classic"}
→ {company_id:"org_26743f44…", schema_id:"sch_…", access_token:"…"}

POST /auth/users   (admin) → operator@, distributor@, retailer@, auditor@ logins
```

Schema installed: `manufacturer → batch → medicine_pack`, `product_box → medicine_pack`,
`shipping_carton → product_box`, `container → shipping_carton`,
`distributor → container`, `retailer → distributor` (parent → child direction
for each "contains/custody" edge).

## A. Manufacturing & packing (operator)

```http
POST /entities {"entity_type":"manufacturer","attributes":{"name":"Aurora Karacihti Plant"}}   → ent_mfr
POST /entities {"entity_type":"batch","serial":"LOT-A2026-11","parent_id":ent_mfr,
                "attributes":{"formula":"Amoxicillin 500mg"}}                                  → ent_batch
POST /entities {"entity_type":"medicine_pack","serial":"SN-AMX-0001",
                "attributes":{"batch_id":ent_batch,"dose":"500mg"},"territory":["PK"]}
        # line-printed: payload has identity only (no parent yet)
GET  /entities/ent_pack/qr.png?size=360          # → PNG to the label printer
…
POST /entities/ent_box      {"entity_type":"product_box","serial":"BOX-1"}
POST /entities/ent_pack/bindings  {"parent_id":ent_box}     # signed statement seq=1
POST /entities/ent_pack/transitions {"to_state":"manufactured"}
POST /entities/ent_pack/events {"event_type":"packed","details":{"line":"FillingLine-3"},
                                "location_text":"Karachi Plant"}
POST /entities/ent_pack/transitions {"to_state":"dispatched"}
```

**What was created:** a signed `bind` statement (`org relationship key`) linking pack →
box, an audit row, and a lifecycle history — all one transaction each.

## B. Aggregation up the chain (operator → distributor)

```
box → shipping_carton (bind)      carton → container (bind)
container → distributor (bind)    distributor → retailer (bind)
container events: dispatched (Karachi Port Qasim, geo) … received (Islamabad DC, geo)
```

Carton/container labels can be printed *after* binding — their payloads then embed
`par` (re-issue at print time), giving the repacking-detection property for the labels
that matter most at logistics scale.

## C. Traceability from any node (auditor / support)

```http
GET /entities/ent_pack/lineage?max_descendant_depth=6
{
 "direction_up": {"chain_verified": true,
   "ancestors": [product_box, shipping_carton, container, distributor, retailer],
   "hops": [{… "signature_valid": true, "is_current_binding": true}, …]},
 "direction_down": {"tree": {…}},   # packs are leaves
 "root": retailer}

GET /entities/ent_container/lineage     # downward: cartons → boxes → packs
GET /entities/ent_retailer/lineage      # the whole subtree under the store
```

Demo transcript output:
```
medicine_pack → product_box → shipping_carton → container → distributor → retailer
chain_verified = True
```

## D. Consumer scan & clone attack (public)

```http
POST /scans {"payload":"SCQR1.eyJ2…​.u1Xk…",
             "context":{"lat":33.68,"lon":73.05,"country":"PK","device_fp":"iphone-phys-1"}}
→ 200 {verdict:"authentic", risk_score:0, flags:[], activation:{first_scan_at:…},
       entity:{…state:"received"}, origin:{batch:{serial:"LOT-A2026-11"},
       manufacturer:{name:"Aurora Karacihti Plant"}},
       relationships:{chain_verified:true, hops:[…]},
       journey:[packed …, dispatched …, received …]}

# 12 minutes later, same QR photographed and reprinted, scanned 1,142 km away:
POST /scans (Karachi coords, device "android-cheap-77")
→ {verdict:"suspicious", risk_score:40,
   flags:[{code:"IMPOSSIBLE_TRAVEL", severity:"high",
           detail:"1142 km between scans within 12 min (≈5710 km/h)"}]}

# Bit-flipped payload:
POST /scans "SCQR1.<mutated>.<sig>"   → {verdict:"invalid", flags:[BAD_SIGNATURE…]}
```

Admin console → *Alerts & scans* shows the suspicious row with geo; the analyst can
watchlist the serial or `revoked` the entity (audited), after which any further scan
returns `verdict:"revoked"`.

## E. Controlled re-parenting (authorized change, fully audited)

```
operator believes pack was mis-boxed      → cannot unbind (403 — org_admin only)
org_admin DELETE /entities/ent_pack/bindings/current        → unbind stmt (audited)
org_admin POST  /entities/ent_pack/bindings {parent_id:box_B} → bind stmt seq+1
org_admin POST  /entities/ent_pack/reissue  → seq++, payload now embeds par=box_B
```
Old printed QR (seq=1, no parent): still authentic identity, server resolves new
parent. If it *had* been printed with `par=box_A` → scan now flags `PARENT_MISMATCH`
(evidence of repacking). Superseded re-prints trip `STALE_PAYLOAD_SEQ`.

## F. Recall (org_admin)

```
POST /entities/ent_pack/transitions {"to_state":"recalled"}     # or batch → all children
[roadmap: fan-out notification, mass revoke by batch]
subsequent scans → entity state recalled surfaces to consumer; alerts feed tracks echoes
```

## G. Auditor's independent check

```
GET /companies/{cid}/audit  (auditor JWT)
→ chain:{ok:true, rows:54, head:"4d3a422e…"}     # recomputed every request
```
Plus, from an offline DB export + published public keys: re-verify every statement and
payload signature without trusting the running service (docs/03 §6).

## H. Schema evolution mid-flight

```
PUT /companies/{cid}/schema  {name:"pharma-plus",
  definition:{… + cold_chain_unit type …}}        → v2 active, v1 frozen
old packs: unaffected (schema_id pinned) ; new registrations validated against v2
```
