# Deliverable 4 — Anti-Copying & Anti-Counterfeiting Strategy

## 0. The premise, stated honestly

**A printed QR cannot be made copy-proof.** It is machine-readable by design; any camera
that can read it can reproduce it ([Unotag](https://unotags.com/blog/anti-copy-qr-codes.html)).
Therefore the strategy separates two different problems:

- **Detection** — notice that an authentic code is being used as a clone (digital,
  works at scale, inherently reactive *or* proactive depending on layer).
- **Physical prevention/resistance** — make copying the *label* costly, fragile or
  evident (tamper evident, scratch, CDP, NFC). Purely physical, SKU-tiered.

Cryptography alone solves neither: it stops *forging new valid codes* (nobody can mint
`SCQR1` without the org key) but says nothing about *reusing* a genuine one.

## 1. Layer model

```
L0  Cryptographic identity      Ed25519-signed unique token per unit          ✅ built
L1  Activation & custody        first-scan ground truth, gated scans          ✅ built
L2  Telemetry clone detection   velocity · impossible travel · territory ·    ✅ built
                                lifecycle anomalies · multi-country
L3  Physical features           tamper-evident seal, scratch PIN,             ▸ per-SKU
                                copy-detection pattern, covert print
L4  Hardware auth (NFC/UHF)     NTAG424 DNA rolling crypto, POE tags          ▸ high-value
L5  Response playbooks          alerts → quarantine → investigate → revoke    ▸ partially*
```

*A recall/revoke state exists (`lifecycle_state='recalled'`, `revoked_at`); the
notification fan-out and case-management UI are roadmap items.

## 2. L1 — one-time activation & custody gating

- **First scan = activation.** `entity.activated_at` + first-scan fingerprint
  (time, coarse geo, device) recorded; every later scan of that unit carries
  `previously_activated` with the first-scan timestamp to the consumer.
- **Ground-truth problem & mitigation.** If a counterfeiter scans a copy *before* the
  genuine unit ever scans, they own "first" and the *genuine* product later looks
  suspicious ([Nabcore](https://nabcore.com/dynamic-vs-serialized-qr-codes-why-product-authentication-needs-more-than-a-redirect/)).
  Mitigation built into the operational workflow: **activation scans happen at the
  factory gate / packing QA on known-good devices** — the org seeds first-scan truth
  before goods leave. Consumer-side first scans then mean "reached user before internal
  activation", itself an anomaly (`PRE_DISPATCH_SCAN` family).
- **Custody gates:** dispatch/receive events at each hop (parties in the demo chain)
  give the risk engine expected geography over time.

## 3. L2 — clone-detection heuristics (implemented in `risk.py`)

Every scan computes weighted flags → `risk_score` → verdict
{`authentic`, `suspicious`, `invalid`, `revoked`}:

| Flag | Trigger | Weight | Catches |
|---|---|---|---|
| `BAD_SIGNATURE` / `MALFORMED_PAYLOAD` / `UNKNOWN_KEY` / `UNKNOWN_ENTITY` | crypto or registry failure | 100 → **invalid** | forged/erased/mutated codes |
| `ENTITY_REVOKED` | issuer revoked entity | 100 → **revoked** | recalls, blacklisted serials |
| `PARENT_MISMATCH` | printed `par` ≠ signed current parent | 45 | **repacking fraud** |
| `IMPOSSIBLE_TRAVEL` | >900 km/h implied between located scans | 40 | same token scanned in two cities |
| `SCAN_VELOCITY` | >5 scans/hour/token | 30 | mass-digitised code, bot probing |
| `TERRITORY_BREACH` / `MULTI_COUNTRY` | scan outside allowed set / ≥3 countries/day | 20/15 | grey-market + cloned batches |
| `PRE_DISPATCH_SCAN` | scan while state ∈ {registered, manufactured, packed} | 20 | code harvested pre-shipment |
| `STALE_PAYLOAD_SEQ` | scanned print older than current issuance | 25 | superseded/reprinted labels |
| `NO_LIFECYCLE_TRACE` | zero events | 10 | ghost registrations |

**Honest caveats:** geolocation is client-claimed (a determined attacker spoofs GPS —
device attestation and carrier-grade location are roadmap hardenings); thresholds are
tuned per program (env-configurable); medium+ flags degrade the verdict, low flags only
accumulate. Alerts surface in the console (`GET /companies/{cid}/alerts`) for human
adjudication — the system *detects and evidences*, humans *convict*.

## 4. Distinguishing detection from prevention

| Attack | Prevented? | Detected? | By |
|---|---|---|---|
| Mint a valid-looking code for an unregistered product | ✅ impossible without org key | n/a | Ed25519 (L0) |
| Bit-flip/alter payload | ✅ signature fails | ✅ first scan | L0 |
| Photograph genuine QR → print on fakes | ❌ possible | ✅ once telemetry shows dual use (2nd scan onward) + earlier if L1 owned ground truth | L1/L2 |
| Copy harvested *before* any genuine scan | ❌ | ⚠ only via factory-gate activation discipline | L1 workflow |
| Peel label / transfer to fake pack | ❌ QR alone | ⚠ `PARENT_MISMATCH` if hierarchy implies repack; else L3 tamper seal | L3 |
| Steal print-run file, mass print | ❌ | ⚠ velocity/geo patterns; reconciliation of printed-vs-issued serials (roadmap) | L2 + print reconciliation |
| Brute-force / guess serials | ✅ signature | ✅ invalid-verdict telemetry | L0/L2 |

## 5. Physical layers (L3/L4) — tiered by SKU risk

- **All SKUs:** unique serialised token; tamper-evident label stock (transfer leaves
  void pattern); quiet-zone respected; payload never duplicated across a batch
  (reconciliation gap = leak).
- **High-risk SKUs:** scratch-off covering a second factor (payload + PIN ⇒ two things
  to steal); copy-detection pattern adjacent to QR — the *only* proactive digital layer
  (degrades measurably on scan-and-reprint; first consumer scan scores it
  ([Nabcore](https://nabcore.com/what-makes-a-qr-code-secure-anti-copy-encryption-serialization-explained/));
  micro-text/covert UV features.
- **High-value:** NFC NTAG424 DNA (rolling crypto, unclonable UID, ~$0.10–0.50/unit
  chip cost) with QR as fallback display of the same serial — challenge-response where
  the phone supports it. Justified only when unit margin covers the cent-cost or
  regulatory exposure demands it.
- **Dynamic challenge-response via plain QR** is inherently limited (the challenge must
  be printed ⇒ static). True challenge-response needs NFC or a per-purchase
  scratch-reveal — stated openly rather than claimed.

## 6. Lifecycle states as a security control

States (docs/08) constrain interpretation: scans of non-dispatched goods are anomalous;
`recalled` units flip any later scan to non-`authentic` territory; `destroyed`/`revoked`
close the identity. Transitions are RBAC-gated (recall = org_admin only) and audited.

## 7. Operational loop

`scan → verdict+flags → alert feed → analyst triage → (revoke serial | lock batch |
watchlist | report)` — every step recorded in the hash-chained audit log so the
resulting evidence package is itself tamper-evident (useful for enforcement actions).
