# What the EMR backend needs (proposal, not built)

The auth service is separate, so two small pieces are needed in `modern-emr-backend` before the
copilot can call EMR APIs and MCP with an Entra sign-in. None of this exists yet.

## 1. Trust the auth service's tokens (second JWT strategy)

Today `JwtStrategy` (`src/modules/auth/strategies/jwt.strategy.ts`) verifies only the backend's own
HS256 tokens with `JWT_ACCESS_SECRET`. Add a second Passport strategy, e.g. `entra-copilot-jwt`, that:

- picks tokens whose header is `alg: RS256`, `typ: at+jwt`, and whose `iss` equals
  `COPILOT_AUTH_ISSUER`;
- verifies them against `COPILOT_AUTH_JWKS_URI` (`<auth service>/.well-known/jwks.json`) with
  `aud = icu-copilot`;
- maps claims to the existing `AuthenticatedUser`:

| `AuthenticatedUser` | from token |
| --- | --- |
| `clientId` | `"icu-copilot-entra"` (fixed) |
| `userId` | `userId` |
| `orgId` | `orgId` |
| `roles` | `roles` (drop `SYSTEM` defensively) |
| `scopes` | `scopes` |
| `regionId` / `locationId` | same names |
| `actorType` | `"human"` |

The global `JwtAuthGuard` then accepts either strategy. Everything after it (RBAC, the MCP role
filter, audit) keeps working unchanged because it reads `AuthenticatedUser`.

**Why not share `JWT_ACCESS_SECRET` with the auth service instead?** With a shared HS256 secret,
anything that can verify tokens can also mint them. With RS256 + JWKS, only the auth service holds
the private key, and the backend only needs the public key.

## 2. Look users up and store the Entra link

The auth service's `UserDirectory` interface (`auth-service/src/users/user-directory.ts`) needs a
production implementation backed by the EMR, which owns `core.users`. Proposed backend changes:

- Migration: `core.users.entra_tenant_id` and `core.users.entra_oid` (nullable), unique together.
- Internal endpoints, callable only with a machine token for the auth service:
  - `GET  /api/v1/internal/identity/users?email=<email>` → users with that email, across orgs
    (id, orgId, email, displayName, active, roles, regionId, locationId, entra link)
  - `GET  /api/v1/internal/identity/users/by-entra?tenantId=&oid=`
  - `GET  /api/v1/internal/identity/users/:id`
  - `PUT  /api/v1/internal/identity/users/:id/entra-link` `{ tenantId, oid }` (refuse if already
    linked to a different oid)

## 3. Fill in emails first

`core.users.email` exists (unique per org), but MedMantra's `GetUserDetails` returns no email, so
MedMantra-synced users have none. Before go-live, load emails once (HR export or Entra), or ask
MedMantra to include email. Until then those users get `USER_NOT_PROVISIONED`.
