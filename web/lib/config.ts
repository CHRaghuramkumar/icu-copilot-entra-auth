/**
 * Browser-side settings. All values are public (they end up in the JS bundle);
 * no secrets belong here. The web app is a public client: it uses
 * Authorization Code + PKCE and holds no client secret.
 */
function env(name: string, value: string | undefined): string {
  if (!value) throw new Error(`${name} is not set. Copy web/.env.example to web/.env.local.`);
  return value;
}

export const webConfig = {
  /** `<authority origin>/<tenant id>`, e.g. https://login.microsoftonline.com/<tenant> or https://localhost:8443/<tenant>. */
  authority: env('NEXT_PUBLIC_ENTRA_AUTHORITY', process.env.NEXT_PUBLIC_ENTRA_AUTHORITY),
  /** The web app's own Entra app registration (SPA platform). */
  clientId: env('NEXT_PUBLIC_ENTRA_CLIENT_ID', process.env.NEXT_PUBLIC_ENTRA_CLIENT_ID),
  /** The auth service's exposed scope, e.g. api://<auth-service-app-id>/access_as_user. */
  apiScope: env('NEXT_PUBLIC_ENTRA_API_SCOPE', process.env.NEXT_PUBLIC_ENTRA_API_SCOPE),
  /** Set only for a non-Microsoft authority (the local emulator), e.g. localhost:8443. */
  knownAuthority: process.env.NEXT_PUBLIC_ENTRA_KNOWN_AUTHORITY || undefined,
  authServiceUrl: (process.env.NEXT_PUBLIC_AUTH_SERVICE_URL || 'http://localhost:4100').replace(/\/+$/, ''),
  redirectUri: process.env.NEXT_PUBLIC_REDIRECT_URI || 'http://localhost:3000',
};
