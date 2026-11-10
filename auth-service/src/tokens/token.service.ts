import { randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { createLocalJWKSet, jwtVerify, SignJWT, type JWTPayload } from 'jose';
import { AuthError } from '../common/auth-error';
import { APP_CONFIG, type AppConfig } from '../config/app-config';
import type { EmrRole, EmrUser } from '../users/user-directory';
import { SIGNING_KEY, type SigningKey } from './signing-key.provider';

/**
 * Claims of the access token this service issues. Named to match the EMR
 * backend's `JwtPayload` (src/modules/auth/interfaces/authenticated-user.interface.ts)
 * so the backend can map it with little code. Differences:
 * - `sub` is the EMR user id (the EMR's own tokens put the API client id there);
 * - `grantType` is `entra`;
 * - signed with RS256 and verified via JWKS, not the backend's shared HS secret.
 */
export interface CopilotAccessClaims extends JWTPayload {
  sub: string;
  userId: string;
  orgId: string;
  roles: EmrRole[];
  scopes: string[];
  regionId?: string;
  locationId?: string;
  email: string;
  name: string;
  actorType: 'human';
  grantType: 'entra';
  entraOid: string;
  entraTid: string;
}

export interface RefreshClaims extends JWTPayload {
  sub: string;
  entraOid: string;
  entraTid: string;
  tokenUse: 'refresh';
}

export interface IssuedTokens {
  accessToken: string;
  expiresIn: number;
  refreshToken: string;
  refreshExpiresIn: number;
}

/** Roles a human Entra sign-in may never carry. SYSTEM means "machine" in the EMR. */
const MACHINE_ONLY_ROLES: ReadonlySet<EmrRole> = new Set(['SYSTEM']);

@Injectable()
export class TokenService {
  private readonly localJwks;

  constructor(
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    @Inject(SIGNING_KEY) private readonly key: SigningKey,
  ) {
    this.localJwks = createLocalJWKSet({ keys: [key.publicJwk] });
  }

  /** Refresh tokens get their own audience so they can never be used as access tokens. */
  private get refreshAudience(): string {
    return `${this.config.token.issuer}/refresh`;
  }

  async issue(user: EmrUser): Promise<IssuedTokens> {
    if (!user.entra) throw new Error('Cannot issue tokens for a user with no Entra link.');
    const { token } = this.config;

    const claims: Omit<CopilotAccessClaims, 'sub'> = {
      userId: user.userId,
      orgId: user.orgId,
      roles: user.roles.filter((r) => !MACHINE_ONLY_ROLES.has(r)),
      scopes: [],
      email: user.email,
      name: user.displayName,
      actorType: 'human',
      grantType: 'entra',
      entraOid: user.entra.oid,
      entraTid: user.entra.tenantId,
      ...(user.regionId ? { regionId: user.regionId } : {}),
      ...(user.locationId ? { locationId: user.locationId } : {}),
    };

    const accessToken = await new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: this.key.kid, typ: 'at+jwt' })
      .setIssuer(token.issuer)
      .setAudience(token.audience)
      .setSubject(user.userId)
      .setIssuedAt()
      .setExpirationTime(`${token.accessTtlSeconds}s`)
      .setJti(randomUUID())
      .sign(this.key.privateKey);

    const refreshClaims: Omit<RefreshClaims, 'sub'> = {
      entraOid: user.entra.oid,
      entraTid: user.entra.tenantId,
      tokenUse: 'refresh',
    };
    const refreshToken = await new SignJWT(refreshClaims)
      .setProtectedHeader({ alg: 'RS256', kid: this.key.kid, typ: 'JWT' })
      .setIssuer(token.issuer)
      .setAudience(this.refreshAudience)
      .setSubject(user.userId)
      .setIssuedAt()
      .setExpirationTime(`${token.refreshTtlSeconds}s`)
      .setJti(randomUUID())
      .sign(this.key.privateKey);

    return {
      accessToken,
      expiresIn: token.accessTtlSeconds,
      refreshToken,
      refreshExpiresIn: token.refreshTtlSeconds,
    };
  }

  async verifyAccess(jwt: string): Promise<CopilotAccessClaims> {
    try {
      const { payload } = await jwtVerify(jwt, this.localJwks, {
        issuer: this.config.token.issuer,
        audience: this.config.token.audience,
        algorithms: ['RS256'],
        typ: 'at+jwt',
      });
      return payload as CopilotAccessClaims;
    } catch {
      throw new AuthError('ACCESS_TOKEN_INVALID', 'The access token is not valid or has expired.');
    }
  }

  async verifyRefresh(jwt: string): Promise<RefreshClaims> {
    try {
      const { payload } = await jwtVerify(jwt, this.localJwks, {
        issuer: this.config.token.issuer,
        audience: this.refreshAudience,
        algorithms: ['RS256'],
      });
      if (payload.tokenUse !== 'refresh' || typeof payload.sub !== 'string') throw new Error('not a refresh token');
      return payload as RefreshClaims;
    } catch {
      throw new AuthError('SESSION_INVALID', 'Your session has expired. Please sign in again.');
    }
  }

  publicJwks(): { keys: SigningKey['publicJwk'][] } {
    return { keys: [this.key.publicJwk] };
  }
}
