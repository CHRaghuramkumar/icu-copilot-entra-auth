import 'reflect-metadata';
import { Test } from '@nestjs/testing';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWTPayload } from 'jose';
import { AppModule } from '../src/app.module';
import { loadConfig, type AppConfig } from '../src/config/app-config';
import { ENTRA_JWKS } from '../src/entra/entra-jwks.provider';
import { configureApp } from '../src/main';
import { FileUserDirectory } from '../src/users/file-user-directory';
import { USER_DIRECTORY, type EmrUser } from '../src/users/user-directory';

export const TENANT = '11111111-1111-1111-1111-111111111111';
export const OTHER_TENANT = '22222222-2222-2222-2222-222222222222';
export const API_APP_ID = 'cccccccc-0000-0000-0000-000000000007';
export const ENTRA_ORIGIN = 'https://login.test';
export const ENTRA_ISSUER = `${ENTRA_ORIGIN}/${TENANT}/v2.0`;
export const WEB_ORIGIN = 'http://localhost:3000';

export const baseUsers = (): EmrUser[] => [
  {
    userId: 'u-alice',
    orgId: 'org-1',
    email: 'Alice@Hospital.org',
    displayName: 'Dr Alice',
    roles: ['INTENSIVIST'],
    regionId: '1',
    locationId: '101',
    active: true,
  },
  {
    userId: 'u-bob',
    orgId: 'org-1',
    email: 'bob@hospital.org',
    displayName: 'Bob',
    roles: ['INCHARGE_NURSE', 'SYSTEM'],
    active: true,
  },
  { userId: 'u-dup-1', orgId: 'org-1', email: 'dup@hospital.org', displayName: 'Dup 1', roles: ['WARD_NURSE'], active: true },
  { userId: 'u-dup-2', orgId: 'org-2', email: 'dup@hospital.org', displayName: 'Dup 2', roles: ['WARD_NURSE'], active: true },
  { userId: 'u-off', orgId: 'org-1', email: 'off@hospital.org', displayName: 'Off', roles: ['WARD_NURSE'], active: false },
];

/** Plays the part of Microsoft Entra: a key pair that signs access tokens. */
export class FakeEntra {
  private constructor(
    private readonly privateKey: CryptoKey,
    readonly jwks: ReturnType<typeof createLocalJWKSet>,
  ) {}

  static async create(): Promise<FakeEntra> {
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const jwk = { ...(await exportJWK(publicKey)), kid: 'entra-test-key', alg: 'RS256' };
    return new FakeEntra(privateKey, createLocalJWKSet({ keys: [jwk] }));
  }

  /** A valid delegated access token for our API, unless `overrides` breaks it. */
  token(overrides: JWTPayload & { iss?: string; aud?: string } = {}, expiresIn: string | number = '10m', key?: CryptoKey): Promise<string> {
    const { iss, aud, ...claims } = overrides;
    return new SignJWT({
      tid: TENANT,
      oid: 'oid-alice',
      scp: 'access_as_user',
      email: 'alice@hospital.org',
      name: 'Alice',
      ...claims,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'entra-test-key' })
      .setIssuer(iss ?? ENTRA_ISSUER)
      .setAudience(aud ?? API_APP_ID)
      .setIssuedAt()
      .setExpirationTime(expiresIn)
      .sign(key ?? this.privateKey);
  }
}

export function testConfig(overrides: NodeJS.ProcessEnv = {}): AppConfig {
  return loadConfig({
    NODE_ENV: 'test',
    ENTRA_TENANT_ID: TENANT,
    ENTRA_AUTHORITY_ORIGIN: ENTRA_ORIGIN,
    ENTRA_API_AUDIENCE: `${API_APP_ID},api://${API_APP_ID}`,
    WEB_ORIGINS: WEB_ORIGIN,
    TOKEN_ISSUER: 'http://auth.test',
    ...overrides,
  });
}

export async function createTestApp(
  entra: FakeEntra,
  users: EmrUser[] = baseUsers(),
): Promise<{ app: NestExpressApplication; directory: FileUserDirectory; config: AppConfig }> {
  const config = testConfig();
  const directory = new FileUserDirectory(users);
  const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
    .overrideProvider(ENTRA_JWKS)
    .useValue(entra.jwks)
    .overrideProvider(USER_DIRECTORY)
    .useValue(directory)
    .compile();
  const app = moduleRef.createNestApplication<NestExpressApplication>({ logger: false });
  configureApp(app, config);
  await app.init();
  return { app, directory, config };
}
