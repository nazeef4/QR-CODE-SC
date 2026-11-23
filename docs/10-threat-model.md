# Deliverable 11 — Threat Model

Scope: the platform (tokens, API, data, accounts, keys) and its interaction with the
physical world. Assets: (A1) authenticity of identities, (A2) integrity of the hierarchy,
(A3) audit credibility, (A4) key material, (A5) clone-detection visibility, (A6)
availability of verification, (A7) commercially sensitive trace data, (A8) PII-adjacent
scan telemetry. Attacker classes: **external counterfeiter**, **malicious insider with
console access**, **compromised account**, **platform operator itself**, **network
adversary**.

## 1. Attack → control matrix

| # | Attack | Attacker | Impact | Controls (implemented) | Residual risk / follow-up |
|---|---|---|---|---|---|
| T1 | **QR cloning** — photograph genuine code, print on fakes | counterfeiter | fake passes first look | L1 activation at factory gate; telemetry: velocity, impossible-travel, territory, multi-country, pre-dispatch; per-unit serial; alert feed (docs/04) | copy scanned once, plausibly, before genuine → passes; escalate to CDP/scratch/NFC per SKU; print-run reconciliation |
| T2 | Payload forgery (mutate body, re-encode) | counterfeiter | fake accepted | Ed25519 over canonical bytes; prefix domain binding; invalid verdict = closed vocabulary | none (cryptographic) |
| T3 | Mint codes for phantom products | insider w/ operator+print | fraud inside tenant | `entity.print` restricted + audited; kid scoped per org; org_admin oversight via audit | malicious *admin* can mint — see T8/T12 |
| T4 | **Replay** of a captured token (shoulder-surf, phishing link) | network/physical | same as clone | replay == clone: token is public by nature; detection identical to T1 (stateful telemetry); TLS for API | pure replay in same place/time indistinguishable from a legit re-scan — accepted; NFC challenge-response for high-value (roadmap) |
| T5 | **Unauthorized transfer / re-parenting** | insider (operator) | hierarchy falsified | `binding.remove` = org_admin only; all binds signed + cycle/schema/tenant checks; unbind+bind audited; `PARENT_MISMATCH` surfaces printed-vs-state divergence | colluding admin — T8 |
| T6 | **DB data manipulation** (direct SQL: flip `parent_id`, edit events) | DBA/malware | silent history rewrite | statements corroborate pointers (`is_current_binding`); hash-chained audit exposes row edits/deletes; verify endpoint recomputes chain each read; external anchor hook (docs/01 §7) | attacker who edits *both* DB and chain rows before any anchor can rewrite history → anchoring cadence = exposure window |
| T7 | Statement/event row deletion | DBA | gaps in proof | chain verify flags broken link (`broken_at`); missing hop ⇒ `chain_verified:false` at scan time | same anchor window as T6 |
| T8 | **Compromised admin account** | external→stolen creds | worst case: mint, revoke, rewrite | PBKDF2-200k; 12 h JWT; role re-checked per request; full audit attribution; key rotation + `revoked_at` kill-switch invalidates everything the key signed | MFA missing in MVP (**roadmap: launch blocker for prod**); dual-control for key ops |
| T9 | Stolen operator/retailer creds | external | unwanted binds/events | scoped roles (no print/unbind for retailer); disable flag takes effect per-request; audit | credential stuffing → rate limits + lockout (roadmap) |
| T10 | Private key exfiltration (server/host) | insider/APT | token forgery at scale | keys wrapped AES-256-GCM at rest, KMS/HSM seam, per-purpose separation, rotation, revocation blast-radius = one purpose | host compromise w/ master secret available ⇒ rotate + revoke + re-issue (runbook in roadmap); keep master in KMS only in prod |
| T11 | Cross-tenant access (IDOR) | compromised user of tenant A | B's data | every query tenant-scoped; entity routes resolve-then-compare; tested (`test_audit_chain_and_rbac`) | none known |
| T12 | **Operator malfeasance** (vendor rewrites customer history) | platform operator | trust collapse | signatures make rewrites detectable by third parties with public keys; hash chain + **external anchoring** post-dates history | pre-anchor window; contract + anchoring cadence mitigations |
| T13 | Geo/device spoofing (fake GPS in clone tooling) | counterfeiter | weakens T1 signals | heuristics are *weighted signals* not proofs; combine with device attestation, IP/ASN anomalies (roadmap); verdicts shown as evidence, humans adjudicate | determined attacker lowers detection rate — layered physical (L3/L4) exists for exactly this |
| T14 | First-scan poisoning (scan copy before genuine) | counterfeiter | genuine flagged later | factory-gate activation discipline seeds ground truth pre-shipment (docs/04 §2) | codes leaked *pre-print* still poison → file handling + reconciliation |
| T15 | **DoS on public `/scans`** | vandal | verification outage | per-IP token bucket (429); stateless horizontal scale; WAL read path | distributed flood → CDN/WAF (ops), docs/01 §5 |
| T16 | Payload harvesting from print files | insider at printer | mass clone readying | serial reconciliation (issued vs printed vs bound) roadmap; batches bind to parents only at packing — harvested pre-packing codes lack custody events | physical security of print supply chain — contractual + audit |
| T17 | JWT secret compromise | attacker | account forgery | env-secrets rotate → all sessions invalid; per-request user reload limits window | secret in env ≠ HSM — prod uses managed signing (roadmap) |
| T18 | Schema sabotage (admin publishes broken hierarchy) | malicious/erroneous admin | ops disruption | full validation incl. type-cycle detection; version history; existing entities pinned (no retroactive break) | bad-but-valid schemas allowed by design — that's configuration authority, review via audit |

## 2. Abuse cases walked through

1. **Cloned best-seller across two cities:** covered by T1 — demo transcript in
   docs/09 §D (detected on second scan, 40/100 risk, alert filed).
2. **Insider re-boxes product to fake provenance:** T5 — operator blocked, admin
   action produces two signed statements + two audit rows; consumer scans of the
   pack-printed-with-parent variant show `PARENT_MISMATCH`.
3. **DBA quietly edits a distributor name in the audit table:** T6 — recomputed chain
   mismatches `row_hash` → `chain:{ok:false}` to any auditor account.

## 3. Explicitly out of scope (stated, not ignored)

- Physical coercion / supply-side infiltration of the plant (process security, not
  software); side-channel attacks on the scanning phone; browser-level compromise of
  the consumer device (result display integrity post-render); spam/fraud via the public
  scan endpoint beyond rate limits (WAF territory).
- Privacy posture: scans store coarse geo + device fingerprint — retention limits,
  consent copy, and DPAs are launch requirements (roadmap) even though telemetry is
  the detection layer (documented tension, not hidden).

## 4. Security backlog (ordered)

MFA for admin/rotation ops → KMS-managed wrapping in prod → JWT asymmetric keys →
IP allowlist + lockout on console → webhook alerting → print-run reconciliation →
device attestation on scan fleet → external anchoring cadence → mTLS/partner API keys.
