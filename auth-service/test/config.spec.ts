import { ConfigError, loadConfig } from '../src/config/app-config';

const base = {
  ENTRA_TENANT_ID: '11111111-1111-1111-1111-111111111111',
  ENTRA_API_AUDIENCE: 'cccccccc-0000-0000-0000-000000000007',
};

describe('loadConfig', () => {
  it('derives the Entra issuer and JWKS from the tenant', () => {
    const config = loadConfig(base);
    expect(config.entra.issuer).toBe('https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0');
    expect(config.entra.jwksUri).toBe(
      'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/discovery/v2.0/keys',
    );
    expect(config.token.accessTtlSeconds).toBe(900);
    expect(config.cookie.secure).toBe(false);
  });

  it('points at the local emulator when asked', () => {
    const config = loadConfig({ ...base, ENTRA_AUTHORITY_ORIGIN: 'https://localhost:8443/' });
    expect(config.entra.issuer).toBe('https://localhost:8443/11111111-1111-1111-1111-111111111111/v2.0');
  });

  it.each(['common', 'organizations', 'consumers'])('refuses the multi-tenant alias %s', (tenant) => {
    expect(() => loadConfig({ ...base, ENTRA_TENANT_ID: tenant })).toThrow(ConfigError);
  });

  it('requires a signing key in production and makes the cookie Secure', () => {
    expect(() => loadConfig({ ...base, NODE_ENV: 'production' })).toThrow(/TOKEN_SIGNING_PRIVATE_KEY/);
  });

  it('requires the refresh lifetime to exceed the access lifetime', () => {
    expect(() =>
      loadConfig({ ...base, ACCESS_TOKEN_TTL_SECONDS: '900', REFRESH_TOKEN_TTL_SECONDS: '600' }),
    ).toThrow(ConfigError);
  });
});
