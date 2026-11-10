# Setting up real Microsoft Entra ID

Two app registrations in the hospital's tenant (Entra admin center → App registrations).
Someone with Application Administrator (or higher) rights does this once per environment.

## 1. Auth service API ("ICU Copilot Auth API")

- **Supported account types:** this organizational directory only (single tenant).
- **Expose an API:**
  - Application ID URI: `api://<this app's client id>`
  - Add scope `access_as_user` (who can consent: admins only; admin consent display name
    "Sign in to ICU Copilot").
- **Manifest:** set `"requestedAccessTokenVersion": 2` (shown as `accessTokenAcceptedVersion` in
  older manifests). Without it Entra issues v1 tokens whose issuer is `https://sts.windows.net/<tenant>/`
  and the service rejects them.
- **Token configuration → Add optional claim → Access token:** `email` (and `upn`). This is how the
  email reaches the auth service.
- No client secret is needed: the service only verifies tokens.

Auth service settings:

```
ENTRA_TENANT_ID=<tenant id>
ENTRA_AUTHORITY_ORIGIN=https://login.microsoftonline.com
ENTRA_API_AUDIENCE=<auth API client id>,api://<auth API client id>
ENTRA_REQUIRED_SCOPE=access_as_user
ENTRA_CA_CERT_PATH=            # empty
```

## 2. Copilot web app ("ICU Copilot Web")

- **Supported account types:** single tenant.
- **Authentication → Add a platform → Single-page application:** redirect URI = the copilot URL
  (e.g. `https://copilot.<hospital>.in`). SPA platform means Authorization Code + PKCE, no secret.
- **API permissions → Add → My APIs → ICU Copilot Auth API → `access_as_user`**, then
  **Grant admin consent** so clinicians are never shown a consent prompt.

Web settings:

```
NEXT_PUBLIC_ENTRA_AUTHORITY=https://login.microsoftonline.com/<tenant id>
NEXT_PUBLIC_ENTRA_KNOWN_AUTHORITY=
NEXT_PUBLIC_ENTRA_CLIENT_ID=<web app client id>
NEXT_PUBLIC_ENTRA_API_SCOPE=api://<auth API client id>/access_as_user
```

## 3. Optional but recommended

- **Enterprise applications → ICU Copilot Web → Properties → Assignment required = Yes**, then assign
  the clinician groups. People outside those groups are stopped by Microsoft before they reach us.
- **Conditional Access** (MFA, compliant device, hospital network) applies automatically to this sign-in.
  The local emulator does not emulate it, so test it against the real tenant.

## 4. Production settings for the auth service

- `NODE_ENV=production` (makes the refresh cookie `Secure`; requires a signing key).
- `TOKEN_SIGNING_PRIVATE_KEY`: a 3072-bit RSA key in PKCS#8 PEM, kept in the secret store (e.g. Azure Key Vault).
- `TOKEN_ISSUER`: the service's public HTTPS URL.
- `WEB_ORIGINS`: the copilot's exact origin(s).
- Serve the web app and the auth service under the same site (e.g. `copilot.<hospital>.in` and
  `auth.copilot.<hospital>.in`) so the SameSite=Strict refresh cookie is sent.
