#!/usr/bin/env node
/**
 * End-to-end sign-in check against the entra-local emulator (no browser).
 *
 * Plays the part of the web app: Authorization Code + PKCE sign-in at the emulator with a seeded
 * user and password, then swaps the Microsoft access token for an ICU Copilot session at the auth
 * service, and checks every step a real sign-in depends on.
 *
 * Needs, already running:
 *   - the emulator:     docker compose up -d          (repo root, https://localhost:8443)
 *   - the auth service: npm run start:dev             (auth-service/, http://localhost:4100)
 *
 * Run:  npm run e2e:emulator      (from auth-service/)
 *
 * Settings (env, all optional; defaults match docker-compose.yml, auth-service/.env.example and
 * web/.env.example):
 *   ENTRA_AUTHORITY_ORIGIN  https://localhost:8443
 *   ENTRA_TENANT_ID         11111111-1111-1111-1111-111111111111
 *   ENTRA_CA_CERT_PATH      ../.entra-local-data/tls/cert.pem
 *   E2E_CLIENT_ID           cccccccc-0000-0000-0000-000000000006   (seeded local-web-client)
 *   E2E_API_SCOPE           api://cccccccc-0000-0000-0000-000000000007/access_as_user
 *   E2E_REDIRECT_URI        http://localhost:3000
 *   AUTH_SERVICE_URL        http://localhost:4100
 *   E2E_PASSWORD            Password1!   (the emulator's seeded dev password)
 *
 * Exit code 0 when every check passes, 1 otherwise.
 */
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import https from 'node:https';
import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';

const env = (name, fallback) => process.env[name] || fallback;
const AUTHORITY_ORIGIN = env('ENTRA_AUTHORITY_ORIGIN', 'https://localhost:8443').replace(/\/+$/, '');
const TENANT = env('ENTRA_TENANT_ID', '11111111-1111-1111-1111-111111111111');
const CA_PATH = env('ENTRA_CA_CERT_PATH', '../.entra-local-data/tls/cert.pem');
const CLIENT_ID = env('E2E_CLIENT_ID', 'cccccccc-0000-0000-0000-000000000006');
const API_SCOPE = env('E2E_API_SCOPE', 'api://cccccccc-0000-0000-0000-000000000007/access_as_user');
const REDIRECT_URI = env('E2E_REDIRECT_URI', 'http://localhost:3000');
const AUTH_URL = env('AUTH_SERVICE_URL', 'http://localhost:4100').replace(/\/+$/, '');
const PASSWORD = env('E2E_PASSWORD', 'Password1!');
const WEB_ORIGIN = new URL(REDIRECT_URI).origin;

// Same scopes the web app asks for at sign-in (web/lib/auth.ts loginScopes).
const LOGIN_SCOPES = ['openid', 'profile', 'email', 'offline_access', API_SCOPE].join(' ');

const ca = existsSync(CA_PATH) ? readFileSync(CA_PATH) : undefined;

// ---------- tiny helpers -----------------------------------------------------------------------

let failures = 0;
function check(label, ok, detail = '') {
  console.log(`${ok ? '  PASS' : '  FAIL'}  ${label}${detail ? `  (${detail})` : ''}`);
  if (!ok) failures += 1;
  return ok;
}
function section(title) {
  console.log(`\n${title}`);
}
class Fatal extends Error {}
function must(label, ok, detail) {
  if (!check(label, ok, detail)) throw new Fatal(label);
}

/** HTTPS request to the emulator, trusting its self-signed cert. No redirects are followed. */
function emulator(method, url, { headers = {}, form, cookie } = {}) {
  const body = form ? new URLSearchParams(form).toString() : undefined;
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        method,
        hostname: u.hostname,
        port: u.port || 443,
        path: u.pathname + u.search,
        ca,
        headers: {
          ...headers,
          ...(cookie ? { cookie } : {}),
          ...(body
            ? { 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(body) }
            : {}),
        },
      },
      (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: data }));
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function authService(method, path, { token, cookie, origin } = {}) {
  const res = await fetch(`${AUTH_URL}${path}`, {
    method,
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(cookie ? { cookie } : {}),
      ...(origin ? { origin } : {}),
    },
  });
  const body = await res.json().catch(() => ({}));
  return { status: res.status, headers: res.headers, body };
}

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const hiddenField = (html, name) =>
  html.match(new RegExp(`name="${name}"\\s+value="([^"]*)"`))?.[1]?.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>');

// ---------- the sign-in itself ---------------------------------------------------------------

let discovery;

/** Authorization Code + PKCE at the emulator, exactly like MSAL does. Returns the token response or the failure. */
async function signInAtEmulator(username, password) {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  const state = b64url(randomBytes(12));
  const authorize = new URL(discovery.authorization_endpoint);
  authorize.search = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: 'code',
    redirect_uri: REDIRECT_URI,
    response_mode: 'query',
    scope: LOGIN_SCOPES,
    state,
    nonce: b64url(randomBytes(12)),
    code_challenge: challenge,
    code_challenge_method: 'S256',
    prompt: 'login',
  }).toString();

  const page = await emulator('GET', authorize.toString());
  const signedState = page.status === 200 ? hiddenField(page.text, '__el_state') : undefined;
  if (!signedState) return { stage: 'authorize', detail: `HTTP ${page.status}, no sign-in form` };

  const submit = await emulator('POST', `${authorize.origin}${authorize.pathname}`, {
    form: { __el_state: signedState, __el_username: username, __el_password: password },
  });
  const location = submit.headers.location;
  if (submit.status !== 302 || !location) {
    return { stage: 'password', detail: `HTTP ${submit.status}, no redirect`, html: submit.text };
  }
  const back = new URL(location, REDIRECT_URI);
  if (back.origin + back.pathname.replace(/\/$/, '') !== REDIRECT_URI.replace(/\/$/, '')) {
    return { stage: 'redirect', detail: `redirected to ${back.origin}${back.pathname}` };
  }
  if (back.searchParams.get('error')) {
    return { stage: 'redirect', detail: `${back.searchParams.get('error')}: ${back.searchParams.get('error_description')}` };
  }
  if (back.searchParams.get('state') !== state) return { stage: 'redirect', detail: 'state mismatch' };
  const code = back.searchParams.get('code');
  if (!code) return { stage: 'redirect', detail: 'no code' };

  // SPA token redemption: public client, PKCE verifier, browser Origin header (real Entra requires it).
  const tokenRes = await emulator('POST', discovery.token_endpoint, {
    headers: { origin: WEB_ORIGIN },
    form: {
      client_id: CLIENT_ID,
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      scope: LOGIN_SCOPES,
    },
  });
  let tokens = {};
  try {
    tokens = JSON.parse(tokenRes.text);
  } catch {
    /* handled below */
  }
  if (tokenRes.status !== 200 || !tokens.access_token) {
    return { stage: 'token', detail: `HTTP ${tokenRes.status} ${tokens.error ?? ''} ${tokens.error_description ?? ''}`.trim() };
  }
  return { tokens };
}

async function main() {
  console.log('ICU Copilot Entra sign-in, end to end against entra-local');
  console.log(`  emulator      ${AUTHORITY_ORIGIN}/${TENANT}`);
  console.log(`  auth service  ${AUTH_URL}`);
  console.log(`  web client    ${CLIENT_ID}  redirect ${REDIRECT_URI}`);

  section('1. Services are up');
  must(`emulator TLS certificate found at ${CA_PATH}`, Boolean(ca), ca ? '' : 'start the emulator once so it writes the cert, or set ENTRA_CA_CERT_PATH');
  let disco;
  try {
    disco = await emulator('GET', `${AUTHORITY_ORIGIN}/${TENANT}/v2.0/.well-known/openid-configuration`);
  } catch (err) {
    must('emulator reachable over HTTPS with that certificate', false, err.message);
  }
  must('emulator OpenID configuration', disco.status === 200, `HTTP ${disco.status}`);
  discovery = JSON.parse(disco.text);
  check('issuer is <origin>/<tenant>/v2.0', discovery.issuer === `${AUTHORITY_ORIGIN}/${TENANT}/v2.0`, discovery.issuer);
  let health;
  try {
    health = await authService('GET', '/health');
  } catch (err) {
    must('auth service reachable', false, err.message);
  }
  must('auth service /health', health.status === 200 && health.body.status === 'ok', `HTTP ${health.status}`);

  section('2. Alice signs in at the emulator (Auth Code + PKCE)');
  const alice = await signInAtEmulator('alice@entralocal.dev', PASSWORD);
  must('Microsoft access token issued for the auth service API', Boolean(alice.tokens), alice.stage ? `${alice.stage}: ${alice.detail}` : '');
  const entraClaims = decodeJwt(alice.tokens.access_token);
  check('aud is the auth service app (local-api)', [API_SCOPE.split('/')[2], `api://${API_SCOPE.split('/')[2]}`].includes(entraClaims.aud), String(entraClaims.aud));
  check('tid is the hospital tenant', entraClaims.tid === TENANT, String(entraClaims.tid));
  check('scp includes access_as_user', String(entraClaims.scp ?? '').split(' ').includes('access_as_user'), String(entraClaims.scp));
  check('email (or upn) claim present', Boolean(entraClaims.email || entraClaims.upn || entraClaims.preferred_username), String(entraClaims.email ?? entraClaims.upn));
  check('oid claim present', Boolean(entraClaims.oid), String(entraClaims.oid));
  check('ID token and refresh token returned too', Boolean(alice.tokens.id_token && alice.tokens.refresh_token));

  section('3. Auth service swaps it for an ICU Copilot session');
  const ex = await authService('POST', '/auth/entra/exchange', { token: alice.tokens.access_token, origin: WEB_ORIGIN });
  must('POST /auth/entra/exchange 200', ex.status === 200, `HTTP ${ex.status} ${ex.body.error ?? ''} ${ex.body.message ?? ''}`.trim());
  check('mapped to Dr Alice Example (by email)', ex.body.user?.displayName === 'Dr Alice Example', ex.body.user?.displayName);
  check('role INTENSIVIST', JSON.stringify(ex.body.user?.roles) === '["INTENSIVIST"]', JSON.stringify(ex.body.user?.roles));
  const setCookie = ex.headers.get('set-cookie') ?? '';
  check('httpOnly refresh cookie set on /auth', /HttpOnly/i.test(setCookie) && /Path=\/auth/i.test(setCookie));
  const refreshCookie = setCookie.split(';')[0];

  section('4. ICU Copilot token is valid for the EMR backend');
  const copilotToken = ex.body.access_token;
  const oidc = await authService('GET', '/.well-known/openid-configuration');
  const jwks = createRemoteJWKSet(new URL(oidc.body.jwks_uri ?? `${AUTH_URL}/.well-known/jwks.json`));
  try {
    const { payload, protectedHeader } = await jwtVerify(copilotToken, jwks, { issuer: oidc.body.issuer });
    check('signature verifies with the published JWKS (RS256)', protectedHeader.alg === 'RS256', protectedHeader.alg);
    check('sub/userId is the EMR user id', payload.sub === ex.body.user.userId && payload.userId === ex.body.user.userId);
    check('entraOid matches the Microsoft oid', payload.entraOid === entraClaims.oid);
    check('grantType entra, actorType human', payload.grantType === 'entra' && payload.actorType === 'human');
    check('no SYSTEM role', !(payload.roles ?? []).includes('SYSTEM'));
  } catch (err) {
    check('signature verifies with the published JWKS', false, err.message);
  }
  const me = await authService('GET', '/auth/me', { token: copilotToken });
  check('GET /auth/me with the copilot token', me.status === 200 && me.body.email === 'alice@entralocal.dev', `HTTP ${me.status}`);

  section('5. Refresh and sign out');
  const refreshed = await authService('POST', '/auth/refresh', { cookie: refreshCookie, origin: WEB_ORIGIN });
  check('POST /auth/refresh with the cookie', refreshed.status === 200 && Boolean(refreshed.body.access_token), `HTTP ${refreshed.status} ${refreshed.body.error ?? ''}`.trim());
  const foreign = await authService('POST', '/auth/refresh', { cookie: refreshCookie, origin: 'https://evil.example' });
  check('refresh from another origin refused', foreign.status === 403 && foreign.body.error === 'ORIGIN_NOT_ALLOWED', `HTTP ${foreign.status}`);
  const out = await authService('POST', '/auth/logout', { origin: WEB_ORIGIN });
  check('POST /auth/logout clears the cookie', out.status === 200 && /Max-Age=0|Expires=Thu, 01 Jan 1970/i.test(out.headers.get('set-cookie') ?? ''));

  section('6. Second user and refusals');
  const bob = await signInAtEmulator('bob@entralocal.dev', PASSWORD);
  if (check('Bob signs in at the emulator', Boolean(bob.tokens), bob.detail)) {
    const bobEx = await authService('POST', '/auth/entra/exchange', { token: bob.tokens.access_token, origin: WEB_ORIGIN });
    check('Bob maps to role INCHARGE_NURSE', bobEx.status === 200 && JSON.stringify(bobEx.body.user?.roles) === '["INCHARGE_NURSE"]', `HTTP ${bobEx.status} ${JSON.stringify(bobEx.body.user?.roles ?? bobEx.body.error)}`);
  }
  const wrong = await signInAtEmulator('alice@entralocal.dev', 'not-the-password');
  check('wrong password gets no code', !wrong.tokens && wrong.stage === 'password', wrong.stage);
  const [h, , s] = alice.tokens.access_token.split('.');
  const tamperedPayload = b64url(JSON.stringify({ ...decodeJwt(alice.tokens.access_token), email: 'bob@entralocal.dev' }));
  const tampered = await authService('POST', '/auth/entra/exchange', { token: `${h}.${tamperedPayload}.${s}` });
  check('tampered Microsoft token refused', tampered.status === 401 && tampered.body.error === 'ENTRA_TOKEN_INVALID', `HTTP ${tampered.status} ${tampered.body.error ?? ''}`);
  const idTokenAsAccess = await authService('POST', '/auth/entra/exchange', { token: alice.tokens.id_token });
  check('ID token (wrong audience) refused', idTokenAsAccess.status === 401, `HTTP ${idTokenAsAccess.status} ${idTokenAsAccess.body.error ?? ''}`);
  const garbage = await authService('GET', '/auth/me', { token: alice.tokens.access_token });
  check('Microsoft token not accepted as a copilot token', garbage.status === 401, `HTTP ${garbage.status}`);
}

main()
  .catch((err) => {
    if (!(err instanceof Fatal)) {
      failures += 1;
      console.error(`\n  ERROR  ${err.stack ?? err}`);
    }
  })
  .finally(() => {
    console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) failed.`);
    process.exitCode = failures === 0 ? 0 : 1;
  });
