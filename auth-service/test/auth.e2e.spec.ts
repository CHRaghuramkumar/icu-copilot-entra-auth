import type { NestExpressApplication } from '@nestjs/platform-express';
import { createRemoteJWKSet, decodeJwt, generateKeyPair, jwtVerify } from 'jose';
import request from 'supertest';
import type { FileUserDirectory } from '../src/users/file-user-directory';
import { API_APP_ID, createTestApp, FakeEntra, OTHER_TENANT, WEB_ORIGIN } from './helpers';

function refreshCookie(res: request.Response): string {
  const raw = res.headers['set-cookie'] as unknown as string[] | undefined;
  const cookie = raw?.find((c) => c.startsWith('icu_copilot_rt='));
  if (!cookie) throw new Error('no refresh cookie set');
  return cookie;
}

describe('Entra exchange', () => {
  let entra: FakeEntra;
  let app: NestExpressApplication;
  let directory: FileUserDirectory;

  beforeEach(async () => {
    entra = await FakeEntra.create();
    ({ app, directory } = await createTestApp(entra));
  });

  afterEach(async () => {
    await app.close();
  });

  const exchange = (token?: string) => {
    const req = request(app.getHttpServer()).post('/auth/entra/exchange');
    return token ? req.set('Authorization', `Bearer ${token}`) : req;
  };

  it('links a first-time user by email and issues a session', async () => {
    const res = await exchange(await entra.token()).expect(200);

    expect(res.body.token_type).toBe('Bearer');
    expect(res.body.expires_in).toBe(900);
    expect(res.body.user).toMatchObject({ userId: 'u-alice', orgId: 'org-1', roles: ['INTENSIVIST'] });

    const claims = decodeJwt(res.body.access_token);
    expect(claims).toMatchObject({
      iss: 'http://auth.test',
      aud: 'icu-copilot',
      sub: 'u-alice',
      userId: 'u-alice',
      orgId: 'org-1',
      roles: ['INTENSIVIST'],
      locationId: '101',
      actorType: 'human',
      grantType: 'entra',
      entraOid: 'oid-alice',
    });

    const cookie = refreshCookie(res);
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/SameSite=Strict/);
    expect(cookie).toMatch(/Path=\/auth/);
    expect(res.headers['cache-control']).toBe('no-store');

    expect((await directory.findById('u-alice'))?.entra).toEqual({
      tenantId: '11111111-1111-1111-1111-111111111111',
      oid: 'oid-alice',
    });
  });

  it('matches by oid after linking, even when the email has changed', async () => {
    await exchange(await entra.token()).expect(200);
    const res = await exchange(await entra.token({ email: 'alice.new@hospital.org' })).expect(200);
    expect(res.body.user.userId).toBe('u-alice');
  });

  it('falls back to upn when the email claim is absent', async () => {
    const res = await exchange(await entra.token({ email: undefined, upn: 'BOB@hospital.org', oid: 'oid-bob' })).expect(200);
    expect(res.body.user.userId).toBe('u-bob');
  });

  it('never issues the machine-only SYSTEM role', async () => {
    const res = await exchange(await entra.token({ email: 'bob@hospital.org', oid: 'oid-bob' })).expect(200);
    expect(res.body.user.roles).toEqual(['INCHARGE_NURSE']);
    expect(decodeJwt(res.body.access_token).roles).toEqual(['INCHARGE_NURSE']);
  });

  it.each([
    ['no token', undefined, 401, 'ENTRA_TOKEN_MISSING'],
  ])('rejects %s', async (_label, token, status, code) => {
    const res = await exchange(token).expect(status);
    expect(res.body.error).toBe(code);
  });

  it('rejects a token signed by someone other than Entra', async () => {
    const { privateKey } = await generateKeyPair('RS256');
    const res = await exchange(await entra.token({}, '10m', privateKey)).expect(401);
    expect(res.body.error).toBe('ENTRA_TOKEN_INVALID');
  });

  it('rejects a token for another app (wrong audience), e.g. an ID token', async () => {
    const res = await exchange(await entra.token({ aud: 'cccccccc-0000-0000-0000-000000000006' })).expect(401);
    expect(res.body.error).toBe('ENTRA_TOKEN_INVALID');
  });

  it('accepts the App ID URI form of the audience', async () => {
    await exchange(await entra.token({ aud: `api://${API_APP_ID}` })).expect(200);
  });

  it('rejects an expired token', async () => {
    const res = await exchange(await entra.token({}, Math.floor(Date.now() / 1000) - 3600)).expect(401);
    expect(res.body.error).toBe('ENTRA_TOKEN_INVALID');
  });

  it('rejects a token from another issuer', async () => {
    const res = await exchange(await entra.token({ iss: `https://login.test/${OTHER_TENANT}/v2.0` })).expect(401);
    expect(res.body.error).toBe('ENTRA_TOKEN_INVALID');
  });

  it('rejects a token whose tid is another tenant', async () => {
    const res = await exchange(await entra.token({ tid: OTHER_TENANT })).expect(401);
    expect(res.body.error).toBe('ENTRA_TENANT_MISMATCH');
  });

  it('rejects an app-only token with no delegated scope', async () => {
    const res = await exchange(await entra.token({ scp: undefined, roles: ['Tasks.Read'] })).expect(403);
    expect(res.body.error).toBe('ENTRA_SCOPE_MISSING');
  });

  it('rejects a token with no usable email', async () => {
    const res = await exchange(await entra.token({ email: undefined, oid: 'oid-x' })).expect(403);
    expect(res.body.error).toBe('ENTRA_EMAIL_MISSING');
  });

  it('refuses someone the EMR does not know', async () => {
    const res = await exchange(await entra.token({ email: 'stranger@hospital.org', oid: 'oid-s' })).expect(403);
    expect(res.body.error).toBe('USER_NOT_PROVISIONED');
  });

  it('refuses an email shared by several EMR users', async () => {
    const res = await exchange(await entra.token({ email: 'dup@hospital.org', oid: 'oid-d' })).expect(403);
    expect(res.body.error).toBe('USER_EMAIL_AMBIGUOUS');
  });

  it('refuses an inactive EMR user', async () => {
    const res = await exchange(await entra.token({ email: 'off@hospital.org', oid: 'oid-off' })).expect(403);
    expect(res.body.error).toBe('USER_INACTIVE');
  });

  it('refuses a second Microsoft account claiming an already-linked EMR user', async () => {
    await exchange(await entra.token()).expect(200);
    const res = await exchange(await entra.token({ oid: 'oid-impostor' })).expect(403);
    expect(res.body.error).toBe('USER_LINK_CONFLICT');
  });
});

describe('Session', () => {
  let entra: FakeEntra;
  let app: NestExpressApplication;
  let directory: FileUserDirectory;

  beforeEach(async () => {
    entra = await FakeEntra.create();
    ({ app, directory } = await createTestApp(entra));
  });

  afterEach(async () => {
    await app.close();
  });

  async function signIn() {
    const res = await request(app.getHttpServer())
      .post('/auth/entra/exchange')
      .set('Authorization', `Bearer ${await entra.token()}`)
      .expect(200);
    return { accessToken: res.body.access_token as string, cookie: refreshCookie(res) };
  }

  it('refreshes from the cookie and rotates it', async () => {
    const { cookie } = await signIn();
    const res = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Origin', WEB_ORIGIN)
      .set('Cookie', cookie.split(';')[0])
      .expect(200);
    expect(decodeJwt(res.body.access_token).sub).toBe('u-alice');
    expect(refreshCookie(res)).toBeDefined();
  });

  it('picks up role changes on refresh', async () => {
    const { cookie } = await signIn();
    const user = await directory.findById('u-alice');
    user!.roles = ['CONSULTANT'];
    const res = await request(app.getHttpServer()).post('/auth/refresh').set('Cookie', cookie.split(';')[0]).expect(200);
    expect(decodeJwt(res.body.access_token).roles).toEqual(['CONSULTANT']);
  });

  it('ends the session when the user is deactivated', async () => {
    const { cookie } = await signIn();
    (await directory.findById('u-alice'))!.active = false;
    const res = await request(app.getHttpServer()).post('/auth/refresh').set('Cookie', cookie.split(';')[0]).expect(403);
    expect(res.body.error).toBe('USER_INACTIVE');
  });

  it('rejects refresh without a cookie', async () => {
    const res = await request(app.getHttpServer()).post('/auth/refresh').expect(401);
    expect(res.body.error).toBe('SESSION_MISSING');
  });

  it('rejects refresh from a foreign origin', async () => {
    const { cookie } = await signIn();
    const res = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Origin', 'https://evil.example')
      .set('Cookie', cookie.split(';')[0])
      .expect(403);
    expect(res.body.error).toBe('ORIGIN_NOT_ALLOWED');
  });

  it('does not accept an access token as a refresh token, or the reverse', async () => {
    const { accessToken, cookie } = await signIn();
    await request(app.getHttpServer()).post('/auth/refresh').set('Cookie', `icu_copilot_rt=${accessToken}`).expect(401);
    const refreshToken = cookie.split(';')[0].split('=')[1];
    await request(app.getHttpServer()).get('/auth/me').set('Authorization', `Bearer ${refreshToken}`).expect(401);
  });

  it('does not accept a raw Entra token at /auth/me', async () => {
    await request(app.getHttpServer())
      .get('/auth/me')
      .set('Authorization', `Bearer ${await entra.token()}`)
      .expect(401);
  });

  it('returns claims at /auth/me', async () => {
    const { accessToken } = await signIn();
    const res = await request(app.getHttpServer()).get('/auth/me').set('Authorization', `Bearer ${accessToken}`).expect(200);
    expect(res.body).toMatchObject({ userId: 'u-alice', grantType: 'entra' });
  });

  it('logout clears the cookie', async () => {
    const res = await request(app.getHttpServer()).post('/auth/logout').expect(200);
    expect(refreshCookie(res)).toMatch(/Expires=Thu, 01 Jan 1970/);
  });

  it('publishes keys another service can verify its tokens with', async () => {
    const server = app.getHttpServer();
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const { port } = server.address() as import("node:net").AddressInfo;
    const { accessToken } = await signIn();
    const jwks = createRemoteJWKSet(new URL(`http://127.0.0.1:${port}/.well-known/jwks.json`));
    const { payload } = await jwtVerify(accessToken, jwks, { issuer: 'http://auth.test', audience: 'icu-copilot' });
    expect(payload.userId).toBe('u-alice');

    const discovery = await request(server).get('/.well-known/openid-configuration').expect(200);
    expect(discovery.body.jwks_uri).toBe('http://auth.test/.well-known/jwks.json');
  });

  it('allows CORS with credentials only for the web origin', async () => {
    const ok = await request(app.getHttpServer())
      .options('/auth/refresh')
      .set('Origin', WEB_ORIGIN)
      .set('Access-Control-Request-Method', 'POST');
    expect(ok.headers['access-control-allow-origin']).toBe(WEB_ORIGIN);
    expect(ok.headers['access-control-allow-credentials']).toBe('true');

    const bad = await request(app.getHttpServer())
      .options('/auth/refresh')
      .set('Origin', 'https://evil.example')
      .set('Access-Control-Request-Method', 'POST');
    expect(bad.headers['access-control-allow-origin']).toBeUndefined();
  });
});
