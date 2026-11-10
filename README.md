# ICU Copilot – Entra ID sign-in

A separate auth service that lets clinicians sign in to the ICU Clinician Copilot with their hospital
**Microsoft Entra ID** account. It works without any MedMantra iframe: the user signs in directly with
Microsoft in a normal browser tab.

```
┌──────────────┐ 1. Sign in with Microsoft (Auth Code + PKCE)   ┌──────────────────────┐
│  Copilot web │ ─────────────────────────────────────────────▶ │ Microsoft Entra ID   │
│  (Next.js)   │ ◀──── Entra access token (aud = auth service) ─ │ (or entra-local)     │
└──────┬───────┘                                                └──────────┬───────────┘
       │ 2. POST /auth/entra/exchange  (Bearer <Entra token>)              │ JWKS
       ▼                                                                   ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ Auth service (NestJS, this repo)                                                      │
│  a. verify the Entra token: signature, issuer, audience, tenant (tid), scope          │
│  b. find the EMR user: by Entra oid if linked before, else by email (then link oid)   │
│  c. issue an ICU Copilot access token (RS256, 15 min) + httpOnly refresh cookie       │
│  d. publish its public keys at /.well-known/jwks.json                                 │
└──────┬───────────────────────────────────────────────────────────────────────────────┘
       │ 3. Copilot calls APIs with the ICU Copilot token
       ▼
┌──────────────────────────────┐   verifies the token with the auth service's JWKS
│ EMR backend / copilot / MCP  │   (second trust path next to its own HS256 tokens;
└──────────────────────────────┘    see docs/emr-backend-integration.md)
```

## What is in the repo

| Folder | What it is |
| --- | --- |
| `auth-service/` | NestJS service. Verifies Entra access tokens, links them to EMR users by email, issues its own tokens. |
| `web/` | Minimal Next.js page: "Sign in with Microsoft", then shows the session and token claims. A reference for the copilot UI, not the copilot itself. |
| `docker-compose.yml` | Runs [entra-local](https://github.com/cmaneu/entra-local), a local Entra ID emulator, so you can develop with no Azure tenant. |
| `docs/` | Azure setup and what the EMR backend needs. |

## Run it locally (no Azure needed)

Needs Docker and Node 22+.

```bash
# 1. Start the Entra emulator
docker compose up -d
#    Open https://localhost:8443 once in your browser and accept the self-signed certificate.

# 2. Auth service (terminal 1)
cd auth-service
cp .env.example .env
npm install
npm run start:dev            # http://localhost:4100

# 3. Web demo (terminal 2)
cd web
cp .env.example .env.local
npm install
npm run dev                  # http://localhost:3000
```

Open http://localhost:3000, click **Sign in with Microsoft**, and sign in as `alice@entralocal.dev` /
`Password1!` (seeded by the emulator). You should see Dr Alice Example, role `INTENSIVIST`, and the
ICU Copilot token claims. `bob@entralocal.dev` signs in as an `INCHARGE_NURSE`.

The demo users live in `auth-service/config/users.dev.json`. Change an email there to see the
"not set up in the EMR" refusal.

### Troubleshooting

| What you see | Fix |
| --- | --- |
| `endpoints_resolution_error` / "Could not reach the Microsoft sign-in server" | The browser can't load the emulator's settings. Check `docker compose ps`, then open `https://localhost:8443/11111111-1111-1111-1111-111111111111/v2.0/.well-known/openid-configuration` and accept the self-signed certificate. |
| "Could not reach the auth service" | Start `auth-service` (`npm run start:dev`) on port 4100. |
| Auth service logs a TLS / certificate error when verifying tokens | `ENTRA_CA_CERT_PATH` must point at `.entra-local-data/tls/cert.pem`, which the emulator writes on first start. |
| `EADDRINUSE :3000` | Something else is on port 3000. Stop it: the seeded emulator app only allows `http://localhost:3000` as the redirect URI. |

## How the user link works

1. **Already linked:** match on the Entra object id (`oid` + tenant). Stable even if the email changes.
2. **First sign-in:** match on email (`email` claim, else `upn` / `preferred_username`), lower-cased.
   - no EMR user with that email → `USER_NOT_PROVISIONED` (no account is ever created here)
   - more than one (email is unique per org in the EMR, not globally) → `USER_EMAIL_AMBIGUOUS`
   - that EMR user is already linked to a different Microsoft account → `USER_LINK_CONFLICT`
   - inactive → `USER_INACTIVE`
   - otherwise the `oid` is saved on the user and sign-in continues.

Only the hospital's own tenant is trusted (`tid` must equal `ENTRA_TENANT_ID`; `common` /
`organizations` are refused at startup), so an outside Microsoft account using the same email cannot
take over a user.

## API

| Method | Path | Auth | Returns |
| --- | --- | --- | --- |
| POST | `/auth/entra/exchange` | `Authorization: Bearer <Entra access token>` | `{ access_token, token_type, expires_in, user }` + refresh cookie |
| POST | `/auth/refresh` | refresh cookie | new token pair; re-reads the user, so role changes and deactivation apply |
| POST | `/auth/logout` | – | clears the refresh cookie |
| GET | `/auth/me` | `Authorization: Bearer <ICU Copilot token>` | the token's claims |
| GET | `/.well-known/jwks.json` | – | public signing keys |
| GET | `/.well-known/openid-configuration` | – | issuer + `jwks_uri` |
| GET | `/health` | – | `{ status: "ok" }` |

Errors are `{ "error": "<CODE>", "message": "<safe to show>" }`. Codes are listed in
`auth-service/src/common/auth-error.ts`.

ICU Copilot access token claims mirror the EMR backend's `JwtPayload`:
`sub`/`userId` (EMR `core.users.id`), `orgId`, `roles`, `scopes`, `regionId`, `locationId`,
`actorType: "human"`, plus `grantType: "entra"`, `email`, `name`, `entraOid`, `entraTid`.
The machine-only `SYSTEM` role is never issued.

## Tests

```bash
cd auth-service && npm test     # 35 tests: token checks, linking rules, refresh, cookies, CORS, JWKS
```

The tests sign tokens with a fake Entra key, so they need no emulator or network.

## Going to real Entra ID

See [docs/azure-setup.md](docs/azure-setup.md) for the two app registrations and the settings to
change. In short: point `ENTRA_AUTHORITY_ORIGIN` at `https://login.microsoftonline.com` (the
default), set the real tenant and app ids, remove `ENTRA_CA_CERT_PATH`, and give the service a
persistent signing key.

## Not done yet

- **Real user directory.** Users come from a JSON file. Production needs the EMR backend to look users
  up by email and store the Entra `oid` ([docs/emr-backend-integration.md](docs/emr-backend-integration.md)).
- **EMR backend trusting these tokens.** Needs a second JWT strategy in the backend (same doc).
- **Agent tokens.** The admission-scoped tokens for Nylorun agents will be issued here later, tied to
  the signed-in user.
- **Key rotation.** One signing key today; JWKS can publish two during a rotation.
