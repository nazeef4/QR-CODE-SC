# Deliverable 8 — User Roles & Permission Model

## 1. Roles

| Role | Who holds it | Intent |
|---|---|---|
| `org_admin` | company security/QA lead | full control incl. the dangerous operations (schema, key rotation, unbind/re-parent, recall, users) |
| `operator` | manufacturing / packing line | register entities, bind during packing, print/re-issue QRs, normal lifecycle progression, record events |
| `distributor` | logistics partner staff | record dispatch/receive events, progress logistics states, read |
| `retailer` | store / pharmacy staff | receive, sell, verify, read |
| `auditor` | internal audit / regulator read-only account | read everything **including the audit chain**, mutate nothing |
| *(consumer)* | anyone with a camera | public `POST /scans` only — no account, no PII stored beyond scan telemetry |

Roles are **fixed vocabulary** (single `ROLE_MATRIX` table), not per-tenant custom RBAC:
custom permission sets multiply configuration errors and review burden; the matrix covers
every API surface, and tenant differentiation happens through *who gets which role*.
Roadmap item: delegate-scoped API keys for machines (print farms, scanners).

## 2. Permission matrix (authoritative — `security.ROLE_MATRIX`)

| Permission | org_admin | operator | distributor | retailer | auditor |
|---|:-:|:-:|:-:|:-:|:-:|
| `company.read` / `schema.read` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `company.update`, `schema.write` | ✅ | — | — | — | — |
| `key.rotate` (incl. key list) | ✅ | — | — | — | — |
| `user.manage` | ✅ | — | — | — | — |
| `entity.read` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `entity.register` | ✅ | ✅ | — | — | — |
| `entity.print` (payload/QR/reissue) | ✅ | ✅ | — | — | — |
| `binding.create` | ✅ | ✅ | — | — | — |
| `binding.remove` (unbind/re-parent) | ✅ | — | — | — | — |
| `lifecycle.transition` | ✅ | ✅ | ✅ | ✅ | — |
| — of which `recall`/`destroy` | ✅ | — | — | — | — |
| `event.create` | ✅ | ✅ | ✅ | ✅ | — |
| `scan.read` (history) | ✅ | ✅ | ✅ | ✅ | ✅ |
| `alert.read` | ✅ | ✅ | — | — | ✅ |
| `audit.read` | ✅ | — | — | — | ✅ |
| public `POST /scans` | ✅* | ✅* | ✅* | ✅* | ✅* |

\* everyone on the internet; no token needed.

**Separation-of-duties choices worth defending:**
- **Unbind ≠ bind.** Re-parenting breaks the printed evidence story, so only
  `org_admin` may unbind; operators can still *form* the hierarchy in the first place.
- **Printing is its own permission.** Anyone who can mint QR tokens can counterfeit
  *within* the tenant — hence `entity.print` is excluded from read roles and every
  issuance/re-issue is audited with actor + seq.
- **Key rotation gated but not separable from admin** in MVP; production adds dual
  control (two admins, or admin + hardware-backed approval) for rotation/revocation.
- **Auditor is truly read-only** — enforced by dependencies, tested
  (`test_audit_chain_and_rbac`).

## 3. Enforcement mechanics

1. **Authentication:** login → JWT `{sub, org, role, exp 12 h, iss=scqr}`; server-side
   re-loads the user on every request (role/disable changes take effect immediately —
   no stale claims).
2. **Authorization:** route handlers depend on `require_perms(...)`; dependency raises
   403 naming the missing permission. Roles map to permission *sets*, handlers declare
   *permissions* — adding a role later touches one table.
3. **Tenant isolation:** `same_company(user, cid)` runs on every company-scoped path;
   entity access resolves the entity first then compares its `company_id` — IDOR across
   tenants returns 403, tested.
4. **Resource-level rules** layered on top: recall/destroy requires `org_admin` *even
   for* holders of `lifecycle.transition`; backward transitions refused; terminal states
   locked.
5. **Audit:** every mutation writes actor id + role into the hash-chained log —
   "who did what" is tamper-evident, which is what makes the matrix *accountable* rather
   than merely enforced.

## 4. Account lifecycle (MVP scope)

Created by `org_admin`; disablement via `users.disabled` (takes effect on next request).
Password: PBKDF2-SHA256, 200k iterations, per-user salt. Production hardening (roadmap):
MFA for `org_admin`, SSO/SAML, IP allowlists for console, session revocation list,
passwordless scan-fleet credentials.
