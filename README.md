# QR-CODE-SC — Cryptographically Secured QR-Based Supply Chain Traceability & Verification

A company-configurable traceability platform in which **every product and packaging
entity has a cryptographically signed digital identity**, its complete parent-child
hierarchy can be **verified from any node**, and **QR duplication or manipulation is
detectable** through layered controls.

This repository contains both deliverables of the engagement:

1. **Architecture & design documentation** — all 13 required technical deliverables
   (`docs/`), research-grounded and decision-justified.
2. **Working reference implementation** — a tested MVP you can run, scan against, and
   attack (deliberately), plus a console and a scripted clone-detection demo.

---

## Quick start

**Linux / macOS:**

```bash
python3 -m venv .venv
.venv/bin/pip install fastapi "uvicorn[standard]" sqlalchemy cryptography \
    qrcode pillow pytest httpx pyjwt email-validator

.venv/bin/python -m pytest backend/tests -q     # 19 tests: crypto, hierarchy, RBAC, clone detection
.venv/bin/python scripts/seed_demo.py           # demo tenant + 12 QR PNGs + scripted attack transcript
.venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8080
```

**Windows (cmd)** — requires Python 3.11+ from [python.org](https://python.org/downloads/)
(tick *“Add python.exe to PATH”*) or `winget install Python.Python.3.12`.
Note: Windows keeps venv tools in `.venv\Scripts\`, not `.venv\bin\`:

```bat
cd /d <path-to-repo>

py -3 -m venv .venv
.venv\Scripts\python -m pip install --upgrade pip
.venv\Scripts\python -m pip install fastapi "uvicorn[standard]" sqlalchemy cryptography qrcode pillow pytest httpx pyjwt email-validator

.venv\Scripts\python -m pytest backend\tests -q
.venv\Scripts\python scripts\seed_demo.py
.venv\Scripts\uvicorn backend.app.main:app --host 0.0.0.0 --port 8080
```

**Windows (PowerShell)** — same commands with `.\` prefixes:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install fastapi "uvicorn[standard]" sqlalchemy cryptography qrcode pillow pytest httpx pyjwt email-validator
.\.venv\Scripts\python -m pytest backend\tests -q
.\.venv\Scripts\python scripts\seed_demo.py
.\.venv\Scripts\uvicorn backend.app.main:app --host 0.0.0.0 --port 8080
```

- **Consumer scanner:** `http://localhost:8080/` — camera QR verification (or paste a
  payload from `output/qr_manifest.json`).
- **Company console:** `http://localhost:8080/admin`
- **API docs (Swagger):** `http://localhost:8080/api/v1/docs`
- **Demo logins** (password `aurora-demo-pass-1` for all):
  `admin@aurora-pharma.example` (org_admin) · `line@` (operator) ·
  `logistics@` (distributor) · `pharmacy@` (retailer) · `audit@` (auditor),
  all `@aurora-pharma.example`

The seed script's transcript shows the security model working end-to-end:

```
Scan 1: genuine first activation (Islamabad)          → verdict=authentic  risk=0
Scan 2: same QR reprinted, scanned in Karachi 12 min  → verdict=suspicious risk=40  [IMPOSSIBLE_TRAVEL]
Scan 3: bit-flipped payload                           → verdict=invalid    [BAD_SIGNATURE]
Audit chain: {ok: True, rows: 54, head: 4d3a422e…}
Lineage:    medicine_pack → product_box → shipping_carton → container → distributor → retailer
            chain_verified = True
```

---

## Documentation map — the 13 required deliverables

| # | Deliverable | Document |
|---|---|---|
| 1 | Complete system architecture | [`docs/01-architecture.md`](docs/01-architecture.md) |
| 2 | Company onboarding & hierarchy configuration workflow | [`docs/02-onboarding-hierarchy.md`](docs/02-onboarding-hierarchy.md) |
| 3 | Cryptographic QR generation & verification methodology | [`docs/03-cryptography.md`](docs/03-cryptography.md) |
| 4 | Anti-copying & anti-counterfeiting strategy | [`docs/04-anti-counterfeiting.md`](docs/04-anti-counterfeiting.md) |
| 5 | Parent-child relationship verification mechanism | [`docs/03-cryptography.md`](docs/03-cryptography.md) §5–6 |
| 6 | Database schema & ER diagram | [`docs/05-data-model.md`](docs/05-data-model.md) |
| 7 | API endpoint design | [`docs/06-api-design.md`](docs/06-api-design.md) |
| 8 | User roles & permission model | [`docs/07-roles-permissions.md`](docs/07-roles-permissions.md) |
| 9 | Product lifecycle & supply-chain event model | [`docs/08-lifecycle-events.md`](docs/08-lifecycle-events.md) |
| 10 | End-to-end workflows with practical examples | [`docs/09-workflows.md`](docs/09-workflows.md) |
| 11 | Threat model (cloning, replay, transfers, data manipulation, compromised accounts) | [`docs/10-threat-model.md`](docs/10-threat-model.md) |
| 12 | Recommended technology stack | [`docs/11-tech-stack.md`](docs/11-tech-stack.md) |
| 13 | Development roadmap (MVP → advanced) | [`docs/12-roadmap.md`](docs/12-roadmap.md) |
| §10 | Research: GS1 EPCIS/Digital Link, signed QR, anti-counterfeit tech, blockchain critique | [`docs/00-research-and-standards.md`](docs/00-research-and-standards.md) |

## Design decisions in one screen

| Question | Decision | Where argued |
|---|---|---|
| Crypto in the QR or via a central service? | **Hybrid** — Ed25519-signed identity token *in* the code (offline-verifiable authenticity), authoritative state (bindings, revocation, clone telemetry) checked server-side | docs/03 §3 |
| Ed25519 vs ECDSA vs HMAC | Ed25519 (small, deterministic, third-party verifiable); ECDSA only under FIPS/HSM mandates; HMAC rejected for public verification | docs/03 §1 |
| How is a parent-child link protected? | Append-only **signed relationship statements** + fast pointer + hash-chained audit; each hop verified independently during lineage walks | docs/03 §5–6 |
| Can cryptography alone stop QR copying? | **No** — a printed QR is reproducible by definition. Layered: factory-gate activation → telemetry detection → physical features (tamper/scratch/CDP) → NFC for high-value | docs/04 |
| Centralized DB or blockchain? | Centralized + signed statements + hash-chained audit + **external anchoring hook**; blockchain only under a documented consortium trigger (hybrid, events off-chain) | docs/01 §7, docs/00 §5 |
| Different companies, different hierarchies? | Schema-as-data: per-tenant, versioned, multi-structure, cycle-checked at publish time; entities pin their schema version | docs/02 |
| Traceability from any level? | Lineage endpoint walks *up* verifying every signed hop and *down* enumerating children — works from pack, box, container or root | docs/03 §6, tests |

## Repository layout

```
backend/app/         FastAPI service
  crypto.py          Ed25519 · canonical JSON · SCQR1 codec · key wrapping
  service.py         payload issuance · signed bind/unbind · lineage verification
  risk.py            clone-detection engine (verdicts & flags)
  hierarchy.py       schema validation · binding rules · templates
  audit.py           hash-chained append-only audit + verify_chain()
  routers/           onboarding · auth · companies · entities · scans
backend/tests/       pytest suite (19 tests)
frontend/            scan PWA (index.html) · company console (admin.html) · vendored jsQR
scripts/seed_demo.py demo tenant, QR rendering, scripted clone attack
docs/                the 13 deliverables + research (see map above)
output/qr/           rendered demo QR codes + payload manifest
```
