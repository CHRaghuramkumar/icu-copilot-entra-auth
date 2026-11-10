import { Inject, Injectable, Logger } from '@nestjs/common';
import { errors as joseErrors, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import { AuthError } from '../common/auth-error';
import { APP_CONFIG, type AppConfig } from '../config/app-config';
import { ENTRA_JWKS } from './entra-jwks.provider';

/** Who Microsoft says signed in, after every check has passed. */
export interface EntraIdentity {
  /** Entra object id: stable for the user's lifetime in the tenant. The primary link key. */
  oid: string;
  tenantId: string;
  /** Lower-cased email used for the first-time link to an EMR user. */
  email: string;
  name?: string;
}

/**
 * Verifies an Entra ID **access token** issued for this service's app registration.
 *
 * The web app must request a token for our API scope (for example
 * `api://<auth-service-app-id>/access_as_user`). We do not accept ID tokens: an ID
 * token's audience is the web app, so accepting it would let any token minted for
 * any app in the tenant be replayed here.
 */
@Injectable()
export class EntraTokenVerifier {
  private readonly logger = new Logger(EntraTokenVerifier.name);

  constructor(
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    @Inject(ENTRA_JWKS) private readonly jwks: JWTVerifyGetKey,
  ) {}

  async verify(token: string): Promise<EntraIdentity> {
    const { entra } = this.config;
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, this.jwks, {
        issuer: entra.issuer,
        audience: entra.audiences,
        algorithms: ['RS256'],
        clockTolerance: 60,
      }));
    } catch (err) {
      if (err instanceof joseErrors.JOSEError) {
        this.logger.warn({ msg: 'Entra token rejected', code: err.code });
        throw new AuthError('ENTRA_TOKEN_INVALID', 'The Microsoft sign-in token is not valid.');
      }
      // Not a token problem: JWKS unreachable, TLS not trusted, etc. Let it surface as a 500.
      throw err;
    }

    // `iss` already embeds the tenant, but check `tid` explicitly as well so a token
    // from another tenant can never pass, even with a misconfigured ENTRA_ISSUER.
    if (typeof payload.tid !== 'string' || payload.tid.toLowerCase() !== entra.tenantId.toLowerCase()) {
      throw new AuthError('ENTRA_TENANT_MISMATCH', 'This Microsoft account is not from the hospital tenant.');
    }

    // App-only tokens (client credentials) carry `roles` and no `scp`/`oid`. This
    // service is for people only, so a delegated scope is mandatory.
    const scopes = typeof payload.scp === 'string' ? payload.scp.split(' ') : [];
    if (!scopes.includes(entra.requiredScope)) {
      throw new AuthError('ENTRA_SCOPE_MISSING', `The sign-in token is missing the "${entra.requiredScope}" scope.`);
    }

    if (typeof payload.oid !== 'string' || payload.oid.length === 0) {
      throw new AuthError('ENTRA_TOKEN_INVALID', 'The Microsoft sign-in token has no user id.');
    }

    const email = pickEmail(payload);
    if (!email) {
      throw new AuthError(
        'ENTRA_EMAIL_MISSING',
        'Your Microsoft account has no email address, so it cannot be linked to an EMR user.',
      );
    }

    return {
      oid: payload.oid,
      tenantId: payload.tid,
      email,
      name: typeof payload.name === 'string' ? payload.name : undefined,
    };
  }
}

/**
 * `email` is an optional claim on the API app registration; `upn` /
 * `preferred_username` hold the sign-in name, which is the work email in a
 * typical hospital tenant. Safe here because the tenant was already pinned above.
 */
function pickEmail(payload: JWTPayload): string | undefined {
  for (const claim of ['email', 'upn', 'preferred_username'] as const) {
    const value = payload[claim];
    if (typeof value === 'string') {
      const normalized = value.trim().toLowerCase();
      if (/^[^@\s]+@[^@\s]+$/.test(normalized)) return normalized;
    }
  }
  return undefined;
}
