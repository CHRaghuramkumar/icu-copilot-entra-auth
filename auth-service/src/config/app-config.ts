/**
 * Typed configuration, read once from the environment at startup.
 * Every value the service needs is validated here so a bad deploy fails at boot,
 * not on the first sign-in.
 */

export const APP_CONFIG = Symbol('APP_CONFIG');

export interface EntraConfig {
  /** The hospital's single Entra tenant (GUID). Multi-tenant values are refused. */
  tenantId: string;
  /** Expected `iss` of Entra v2 access tokens: `<authority>/<tenantId>/v2.0`. */
  issuer: string;
  /** Where Entra publishes its signing keys. */
  jwksUri: string;
  /** Accepted `aud` values: this service's Entra app registration (client id and/or App ID URI). */
  audiences: string[];
  /** Delegated scope the web app must request for this service, e.g. `access_as_user`. */
  requiredScope: string;
  /** Optional PEM file to trust for the JWKS fetch (only for the local entra-local emulator). */
  caCertPath?: string;
}

export interface TokenConfig {
  /** `iss` of the tokens this service issues (its own public URL). */
  issuer: string;
  /** `aud` of issued access tokens; the EMR backend and copilot check this. */
  audience: string;
  accessTtlSeconds: number;
  refreshTtlSeconds: number;
  /** PKCS#8 PEM private key (RS256). Required in production. */
  privateKeyPem?: string;
  keyId: string;
}

export interface CookieConfig {
  name: string;
  secure: boolean;
}

export interface AppConfig {
  nodeEnv: string;
  port: number;
  /** Browser origins allowed to call this service with credentials (CORS + cookie endpoints). */
  webOrigins: string[];
  entra: EntraConfig;
  token: TokenConfig;
  cookie: CookieConfig;
  usersFile: string;
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MULTI_TENANT_ALIASES = new Set(['common', 'organizations', 'consumers']);

export class ConfigError extends Error {}

function required(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key]?.trim();
  if (!value) throw new ConfigError(`${key} is required.`);
  return value;
}

function int(env: NodeJS.ProcessEnv, key: string, fallback: number, min: number, max: number): number {
  const raw = env[key]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new ConfigError(`${key} must be an integer between ${min} and ${max}.`);
  }
  return value;
}

function list(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
}

function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, '');
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const nodeEnv = env.NODE_ENV?.trim() || 'development';
  const isProduction = nodeEnv === 'production';

  const tenantId = required(env, 'ENTRA_TENANT_ID');
  if (MULTI_TENANT_ALIASES.has(tenantId.toLowerCase())) {
    throw new ConfigError(
      `ENTRA_TENANT_ID must be the hospital's tenant GUID, not "${tenantId}". Multi-tenant sign-in is not allowed.`,
    );
  }
  if (!GUID.test(tenantId)) throw new ConfigError('ENTRA_TENANT_ID must be a GUID.');

  const authority = stripTrailingSlash(env.ENTRA_AUTHORITY_ORIGIN?.trim() || 'https://login.microsoftonline.com');
  const audiences = list(required(env, 'ENTRA_API_AUDIENCE'));

  const privateKeyPem = env.TOKEN_SIGNING_PRIVATE_KEY?.trim()
    ? env.TOKEN_SIGNING_PRIVATE_KEY.replace(/\\n/g, '\n')
    : undefined;
  if (isProduction && !privateKeyPem) {
    throw new ConfigError('TOKEN_SIGNING_PRIVATE_KEY is required when NODE_ENV=production.');
  }

  const webOrigins = list(env.WEB_ORIGINS || 'http://localhost:3000').map(stripTrailingSlash);
  const tokenIssuer = stripTrailingSlash(env.TOKEN_ISSUER?.trim() || 'http://localhost:4100');

  const accessTtlSeconds = int(env, 'ACCESS_TOKEN_TTL_SECONDS', 900, 60, 3600);
  const refreshTtlSeconds = int(env, 'REFRESH_TOKEN_TTL_SECONDS', 8 * 3600, 300, 7 * 24 * 3600);
  if (refreshTtlSeconds <= accessTtlSeconds) {
    throw new ConfigError('REFRESH_TOKEN_TTL_SECONDS must be longer than ACCESS_TOKEN_TTL_SECONDS.');
  }

  return {
    nodeEnv,
    port: int(env, 'PORT', 4100, 1, 65535),
    webOrigins,
    entra: {
      tenantId,
      issuer: env.ENTRA_ISSUER?.trim() || `${authority}/${tenantId}/v2.0`,
      jwksUri: env.ENTRA_JWKS_URI?.trim() || `${authority}/${tenantId}/discovery/v2.0/keys`,
      audiences,
      requiredScope: env.ENTRA_REQUIRED_SCOPE?.trim() || 'access_as_user',
      caCertPath: env.ENTRA_CA_CERT_PATH?.trim() || undefined,
    },
    token: {
      issuer: tokenIssuer,
      audience: env.TOKEN_AUDIENCE?.trim() || 'icu-copilot',
      accessTtlSeconds,
      refreshTtlSeconds,
      privateKeyPem,
      keyId: env.TOKEN_SIGNING_KEY_ID?.trim() || 'icu-copilot-auth-1',
    },
    cookie: {
      name: env.REFRESH_COOKIE_NAME?.trim() || 'icu_copilot_rt',
      secure: env.REFRESH_COOKIE_SECURE ? env.REFRESH_COOKIE_SECURE === 'true' : isProduction,
    },
    usersFile: env.USERS_FILE?.trim() || 'config/users.dev.json',
  };
}
