# Research: Existing Approaches to Secure Supply-Chain Traceability

> Deliverable support for §10 (Research and Design Approach). This document critically
> evaluates the standards and technologies the design must coexist with or improve upon,
> and states what we deliberately do **not** reinvent.

## 1. GS1 EPCIS 2.0 — the event standard

**What it is.** EPCIS (ratified as 2.0 in June 2022, ISO/IEC 19987) defines *event* data —
what happened, when, where, why, and how — as a continuous chain-of-custody stream rather
than static inventory snapshots. Version 2.0 added JSON/JSON-LD and REST APIs alongside the
original XML/SOAP stack, plus sensor data capture ([QRStuff EPCIS guide](https://www.qrstuff.com/feeds/blog/gs1-epcis-20-traceability-food-supply-chain)).
Its companion CBV (ISO/IEC 19988) standardises ~41 business-step codes so "shipping" means
the same thing across partners. EPCIS 2.0 also added a fifth event type, *AssociationEvent*,
for parent-child aggregation — the same class of fact our `relationship_statements` table
records ([LDUX traceability mapping](https://www.ldux.io/trace/)).

**Strengths.**
- Semantic interoperability: identifiers (GTIN, GLN, SSCC) + CBV vocabulary are the lingua
  franca that makes multi-party data sharing possible at all; surveys of industry put
  supply-chain visibility beyond tier-1 at ~2% of companies ([Anglera EPCIS overview](https://www.anglera.com/glossary/epcis-electronic-product-code-information-services)).
- It is what regulators and large retailers actually ask for: DSCSA (US pharma), FSMA 204,
  EU Digital Product Passport work all lean on EPCIS as the underlying data format.

**Limitations relevant to this project.**
- **EPCIS has no native signature bytes.** Integrity/authenticity must be bolted on —
  `certificationInfo` is a *URL pointer* to a credential, not an embedded proof; EPCIS 1.2
  had no signing concept at all ([LDUX](https://www.ldux.io/trace/)). An EPCIS repository
  answers "what does the record say", not "prove this record wasn't forged".
- **It standardises events, not physical anti-counterfeiting.** A copied identifier yields
  perfectly valid EPCIS events describing a fake product. Garbage-in remains garbage:
  "the ledger [or standard] guarantees a record was not altered, not that it was true when
  entered" ([SpaceDev blockchain-traceability analysis](https://spacedev.io/blog/blockchain-supply-chain-traceability)).
- Adoption requires *every* trading partner to capture and share events; the chain of
  custody "breaks down if stakeholders do not scan and log events consistently"
  ([GS1 QR security analysis](https://digital-link-qr-code.com/gs1-qr-code-security)).

**How this system improves on it.** We treat EPCIS as an *export format*, not the core:
our event model (`supply_events`) maps 1:1 onto EPCIS Object/Association events so the
platform can emit EPCIS 2.0 JSON-LD at the integration layer (roadmap §Integration),
while adding what EPCIS lacks natively: per-statement Ed25519 signatures, first-scan
activation, and clone-detection telemetry. For SMEs that will never run an EPCIS
repository, we provide the same guarantees out of the box.

## 2. GS1 Digital Link — the QR carrier standard

**What it is.** A URI syntax encoding GS1 identifiers (`/01/<GTIN>/10/<lot>/21/<serial>`)
so one QR satisfies retail POS scanners, supply-chain systems and consumer phones.
GS1's "Sunrise 2027" initiative makes 2D barcode reading at POS a industry deadline,
and GS1 Digital Link is the recommended URI carrier for EU Digital Product Passports
([QR-Verse Digital Link guide](https://qr-verse.com/en/blog/gs1-digital-link-complete-guide-2026)).

**Limitations (stated by its own ecosystem).**
- "GS1 QR codes are not inherently more secure than standard QR codes… without a secure
  backend, the QR code is just a static identifier — easily copied and useless for
  security purposes" ([GS1 QR security](https://digital-link-qr-code.com/gs1-qr-code-security)).
- The payload is plaintext by design (interoperability wins over confidentiality).
- Authentication, serialisation checks, scan-count and geo anomaly detection are all
  functions of the *verification platform*, not the standard
  ([Nabcore Digital Link analysis](https://nabcore.com/gs1-digital-link-one-qr-code-for-authentication-traceability-and-the-consumer/)).

**Design decision.** Our QR payload (`SCQR1.<body>.<sig>`) is *not* a Digital Link URI —
carrying a 64-byte signature inside a URL path is possible but hostile to POS parsers.
Instead: (a) each entity may additionally carry its GS1 identifiers in `attributes`
(gtin/lot/serial), (b) the REST API can render Digital Link URIs for POS/DPP contexts,
and (c) the signed SCQR token rides on the pack for authenticity. Where a partner
mandates Digital Link, the resolver URL can point at `POST /api/v1/scans` with the
serial — the security lives in the same backend either way. This is the pragmatic
"one token, two audiences" position, documented so no integration surprises emerge later.

## 3. Digitally signed QR codes (state of practice)

Commercial practice converges on exactly the architecture this project adopts:
- Per-unit serialised tokens signed at production time, verified server-side
  (HMAC-SHA256 or public-key), with first-scan registration and GPS/velocity anomaly
  detection as the clone layer ([QRSansar](https://qrsansar.com/solutions/product-authentication),
  [Sprouter SVT](https://getsprouter.com/gs1/anti-counterfeiting/)).
- Public-key signatures are preferred over HMAC when any third party must verify —
  HMAC forces every verifier to hold the shared secret, so one verifier compromise
  enables universal forgery. Sprouter's own docs use HMAC because *only their server
  ever verifies*; our requirement ("prevent unauthorized QR generation", auditor-grade
  verification) mandates non-repudiation → Ed25519.
- W3C Verifiable Credentials / SCITT receipts are emerging as the portable-proof layer
  over EPCIS events; noted as roadmap interoperability, not MVP ([LDUX](https://www.ldux.io/trace/)).

## 4. Anti-counterfeiting technologies (physical + digital)

| Layer | Mechanism | Cost/unit (observed) | What it stops | What it does not stop |
|---|---|---|---|---|
| Serialized signed QR | unique token per unit, server verification | $0.003–0.05 | digital forgery of the payload | photographing a genuine print |
| First-scan activation | binds code to place/device at first plausible scan | platform cost | silent mass reuse (after 2nd scan) | a copy scanned *first*, or single plausible-place copies |
| Tamper-evident label | void pattern / destructive adhesive | $0.02–0.08 | label transfer to another pack | re-printing the whole fake pack |
| Scratch-off PIN | hidden second factor revealed at purchase | $0.01–0.05 | shelf-harvesting of codes | after the customer scratches |
| Copy-detection pattern (CDP) | print-resolution micro-pattern degraded by scan-and-reprint | $0.20–1.00 + print spec | **first scan of a copy** (proactive) | low-light photos give uncertain scores |
| NFC (NTAG424 DNA) | rolling cryptographic challenge | $0.10–0.50 (chip $8–25 inlaid) | cloning the chip itself | cost (only justifies on high-value goods) |

Sources: [Cubit packaging cost guide](https://www.cubitpackaging.com/blog/anti-counterfeit-packaging-guide),
[TryQRMint technical guide](https://www.tryqrmint.com/blog/qr-codes-for-product-authentication-and-anti-counterfeiting),
[Unotag anti-copy analysis](https://unotags.com/blog/anti-copy-qr-codes.html),
[Nabcore security layers](https://nabcore.com/what-makes-a-qr-code-secure-anti-copy-encryption-serialization-explained/).

**The uncomfortable truth** (stated plainly in our own docs): *no printed QR is
copy-proof* — "a QR is designed to be read by any camera and therefore any camera can
reproduce it" ([Unotag](https://unotags.com/blog/anti-copy-qr-codes.html)). Serialization
alone is reactive: copies pass until anomalies accumulate, and in the worst case a
counterfeit scanned before the genuine unit poisons first-scan ground truth
([Nabcore dynamic vs serialized](https://nabcore.com/dynamic-vs-serialized-qr-codes-why-product-authentication-needs-more-than-a-redirect/)).
Our anti-counterfeiting design (docs/04) therefore combines: activation scans at the
factory gate (to own ground truth *before* goods ship), telemetry detection, and an
explicit escalation path to CDP/NFC for high-risk SKUs.

## 5. Blockchain / DLT — evaluated and mostly rejected

**Claims.** Tamper-evident shared record across mutually distrusting partners; no single
point of failure ([ScienceDirect overview](https://www.sciencedirect.com/science/article/abs/pii/S0360835720305829)).

**Counter-evidence.**
- It does not fix data quality: "the biggest limitation is the garbage-in problem… if a
  warehouse worker scans the wrong barcode… the blockchain preserves that error
  permanently" ([SpaceDev](https://spacedev.io/blog/blockchain-supply-chain-traceability)).
- Consortium governance, not technology, kills projects: real deployments die when
  competitors refuse shared visibility ([EPKO case analysis](https://epko.gov.gr/arts/the-rise-of-blockchain-in-supply-chain-management-revolutionizing-transparency-and-efficiency))
  and full on-chain storage causes data explosion; production systems are hybrid with
  events off-chain and only hashes on-chain ([MDPI Sensors study](https://doi.org/10.3390/s22228680)).
- A single-operator SaaS has exactly one party that needs write access — consensus
  among non-existent mutually-distrusting writers buys nothing.

**Verdict (docs/01 §7).** Centralized transactional store + cryptographic soundness:
Ed25519 statements (integrity), hash-chained audit log (tamper-evidence against the
operator's own DBAs), and a pluggable **external anchoring** interface (periodic
commitment of the chain head to an RFC 3161 timestamp authority or public transparency
log). This yields "detect any post-hoc edit or deletion" — the property blockchain is
actually cited for — without consensus latency, gas costs, or privacy leakage.
Blockchain re-enters the picture *only* under the documented trigger: a multi-party
consortium with no mutually trusted operator that has verified partner buy-in; even
then the recommended shape is hybrid (events off-chain, Merkle roots on-chain).

## 6. Summary of positioning

| Capability | EPCIS 2.0 | Digital Link | Typical brand-protection SaaS | **This system** |
|---|---|---|---|---|
| Event vocabulary | ✅ standard | — | partial | mapped, exportable to EPCIS |
| QR carrier standard | — | ✅ | proprietary | coexists (attributes + resolver) |
| Signed entity identity | ❌ | ❌ | usually HMAC | Ed25519 in-payload |
| Signed parent-child chain | AssociationEvent, unsigned | ❌ | rarely | signed statements per hop |
| Configurable hierarchy | fixed semantics | — | hardcoded | schema-as-data per company |
| Clone detection | ❌ | ❌ | ✅ | ✅ (activation, geo, velocity) |
| Tamper-evident audit | repo trust | — | vendor trust | hash chain + anchor hook |
| Works for SME without integration | ❌ heavy | partial | ✅ | ✅ |

The rest of the documentation set specifies exactly how each of these is built.
