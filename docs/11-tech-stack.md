# Deliverable 12 — Recommended Technology Stack

## 1. Reference implementation (this repository) — chosen for auditability

| Layer | Choice | Why this, now |
|---|---|---|
| Language | Python 3.11 | fastest path to *correct* crypto + API code reviewers can read; the domain logic (signatures, chains, heuristics) is what's being evaluated, not framework agility |
| API | FastAPI + Pydantic | typed contracts, OpenAPI for free, dependency-injection maps cleanly onto the RBAC matrix |
| ORM/DB | SQLAlchemy 2 + SQLite (WAL) | zero-ops demo; every construct is Postgres-portable |
| Crypto | `cryptography` (Ed25519, AESGCM) | the mainstream, audited binding — no hand-rolled primitives |
| QR | `qrcode` + Pillow | ECC-M PNG rendering; deterministic payload ⇒ reproducible prints |
| Frontend | static HTML/JS + vendored jsQR | no build chain to audit; camera decode on-device (`jsQR` npm dist, Apache-2.0) |
| Tests | pytest + TestClient | 19 tests cover crypto tamper, hierarchy, RBAC, clone heuristics, audit chain |

Run: `uvicorn backend.app.main:app --host 0.0.0.0 --port 8080` · seed: `scripts/seed_demo.py` · tests: `python -m pytest backend/tests`.

## 2. Production stack (recommended, with reasoning)

**Keep the architecture, upgrade the runtime:**

| Concern | Recommendation | Rationale / trade-off |
|---|---|---|
| API runtime | same Python service, or Go rewrite of the *scan path* only | Python is comfortably <100 ms p95 at this workload; rewrite only if scan QPS forces it — isolate first (`risk.py` boundary exists) |
| Database | **PostgreSQL 16** | JSONB, `FOR UPDATE` for serialized audit-chain appends, mature HA; the SQLite→PG delta is config + chain-lock code |
| Cache / limits | Redis | distributed rate limits, kid cache (invalidate on rotate) |
| Object storage | S3-compatible | QR print batches (per-SKU ZIPs), report exports |
| Key management | **Cloud KMS / HashiCorp Vault / on-prem HSM** | wrap/unwrap seam already isolated; HSM-backed Ed25519 for regulated pharma |
| Async work | worker queue (RQ/Celery/Temporal) | alert fan-out, EPCIS exports, reconciliation jobs |
| Frontend | keep static PWA; optional React only if console UX outgrows it | scanner must stay light for low-end phones |
| Observability | OpenTelemetry + Prometheus/Grafana + structured logs | risk-engine decisions must be explainable (flag traces) |
| Hosting | container (Docker/K8s), LB, WAF/CDN in front of public `/scans` | horizontal scale of stateless API; DB pinned |
| Anchoring | RFC 3161 TSA client or public transparency-log submitter | executes the docs/01 §7 decision; pluggable interface |
| Mail/webhooks | SES + signed webhooks | alert delivery SLAs |

## 3. Alternatives considered and why not (short form)

- **Node/TypeScript full stack:** fine choice; rejected only because Python's
  `cryptography` + test ergonomics shortened this evaluation build — no architectural
  dependency on language.
- **Java/Kotlin + Spring:** strongest enterprise posture, 3× the code for the same MVP;
  revisit if the client's ops standardizes on JVM.
- **Blockchain (Hyperledger Fabric/Ethereum):** see decision record docs/00 §5,
  docs/01 §7 — default **no**; hybrid anchoring instead; re-evaluate only under the
  documented consortium trigger.
- **GraphQL:** scan endpoint benefits from a fixed verdict contract; REST + OpenAPI is
  the right shape for integrators and partner EPCIS gateways.
- **MongoDB/document store:** relationship statements + audit chain *are* relational
  invariants; a document store weakens exactly what this system sells.
- **GS1 off-the-shelf (resolver + EPCIS repo):** complementary, not competitive —
  integrate as export (docs/00 §1); owning the verification/anti-clone layer is the
  product.
