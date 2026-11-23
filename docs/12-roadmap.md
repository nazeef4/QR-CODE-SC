# Deliverable 13 — Development Roadmap

Phases are acceptance-criteria-driven; estimates assume 2–3 engineers.

## Phase 0 — Architecture MVP ✅ (this repository, ~3 weeks)

- [x] Configurable hierarchy (schema-as-data, versioned, multi-structure per tenant)
- [x] Ed25519-signed `SCQR1` payloads + deterministic re-issuance + PNG pipeline
- [x] Signed parent-child statements; bind/unbind with cycle/schema/tenant checks
- [x] Verified lineage **from any node** (up-hops signed, down-trees enumerated)
- [x] Public scan API: activation, clone heuristics, verdict vocabulary
- [x] Lifecycle state machine + event model (EPCIS-shaped)
- [x] RBAC matrix (5 roles), tenant isolation, hash-chained audit + verify endpoint
- [x] Onboarding API + templates; consumer scanner PWA; company console
- [x] Demo seed with scripted clone attack; 19 automated tests

**Exit criteria met:** every §9 critical requirement demonstrably exercised.

## Phase 1 — Production hardening (~6–8 weeks)

1. PostgreSQL migration + serialized audit appends (`FOR UPDATE`); migration tooling.
2. KMS-backed key wrapping; secrets rotation runbook (rotate → revoke → re-issue).
3. MFA for `org_admin`; JWT asymmetric keys; lockout/IP-allowlist on console.
4. Alert delivery: webhook + email with signature; triage states (ack/confirm/false-positive).
5. Print pipeline: batch issuance API, ZIP/PDF sheets, **issued-vs-printed reconciliation**.
6. External anchoring: hourly chain-head commitment (TSA), verification page for auditors.
7. EPCIS 2.0 JSON-LD **export** of `supply_events` + AssociationEvent mapping (docs/00 §1).
8. GS1 Digital Link URI rendering for POS/DPP contexts alongside `SCQR1`.
9. Hardening backlog from docs/10 §4; load tests on `/scans`; WAF rules.
10. Privacy: retention windows, consent copy, DPAs for scan telemetry.

**Exit:** security review passed; SLOs p95 scan verify <200 ms / 99.9% availability.

## Phase 2 — Multi-party & scale (~1 quarter)

- Partner tenants: invited orgs with shared-visibility grants; receipt co-signing
  (distributor signs the `received` hop) — the step toward cross-org trust.
- Delegated API keys for machines (print farms, handhelds); scoped offline issuance.
- Device attestation for scan-fleet hardware; IP/ASN anomaly enrichment.
- Case-management for alerts (watchlist, quarantine, revoke-by-batch workflows).
- Scan-facing PWA i18n; low-bandwidth mode; app-store wrappers if needed.
- Advanced risk: cohort analysis (batch-level clone signatures), ML scoring *on top of*
  explainable rules — never replacing them.

## Phase 3 — Advanced / optional

- **Hybrid anchoring** (Merkle roots on a consortium ledger) **iff** the docs/01 §7
  trigger materialises; SCITT/W3C VC receipts for portable provenance proofs.
- NFC NTAG424 challenge-response tier for high-value SKUs; CDP image scoring in the
  consumer flow.
- Offline verification bundles (pubkeys + revocation list) for field inspectors.
- Sensor telemetry (cold chain) as typed EPCIS SensorElement events.
- Multi-parent edge qualifiers (EPCIS AssociationEvent semantics) if customers demand
  batch+containment simultaneity.

## Cross-cutting (continuous)

- Threat-model review each phase (docs/10 is a living document).
- Contract tests for partner integrations; fuzzing on payload parser.
- Pricing/cost watch: per-unit cost table maintained against vendor quotes
  (docs/00 §4 baseline).
