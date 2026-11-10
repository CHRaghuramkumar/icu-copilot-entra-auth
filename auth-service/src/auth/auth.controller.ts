import { Controller, Get, HttpCode, HttpStatus, Inject, Post, Req, Res } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import type { CookieOptions, Request, Response } from 'express';
import { AuthError } from '../common/auth-error';
import { APP_CONFIG, type AppConfig } from '../config/app-config';
import { EntraTokenVerifier } from '../entra/entra-token.verifier';
import { TokenService, type IssuedTokens } from '../tokens/token.service';
import { sameLink } from '../users/file-user-directory';
import { IdentityLinkerService } from '../users/identity-linker.service';
import { USER_DIRECTORY, type EmrUser, type UserDirectory } from '../users/user-directory';

interface SessionResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  user: {
    userId: string;
    orgId: string;
    email: string;
    displayName: string;
    roles: string[];
  };
}

/** Refresh cookie lives only on /auth so it is never sent to other routes. */
const COOKIE_PATH = '/auth';

@Controller('auth')
export class AuthController {
  constructor(
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    private readonly entra: EntraTokenVerifier,
    private readonly linker: IdentityLinkerService,
    private readonly tokens: TokenService,
    @Inject(USER_DIRECTORY) private readonly directory: UserDirectory,
  ) {}

  /**
   * Swap a Microsoft (Entra ID) access token for an ICU Copilot session.
   * Send the Entra token as `Authorization: Bearer <token>`. It must be issued
   * for this service's API scope, not an ID token.
   */
  @Post('entra/exchange')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 20, ttl: 60_000 } })
  async exchange(@Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<SessionResponse> {
    const entraToken = bearer(req);
    if (!entraToken) {
      throw new AuthError('ENTRA_TOKEN_MISSING', 'Send the Microsoft access token as "Authorization: Bearer <token>".');
    }
    const identity = await this.entra.verify(entraToken);
    const user = await this.linker.resolve(identity);
    return this.startSession(user, res);
  }

  /** New access token from the refresh cookie. Re-reads the user so role changes and deactivation apply. */
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 60, ttl: 60_000 } })
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<SessionResponse> {
    this.assertAllowedOrigin(req);
    const cookie = (req.cookies as Record<string, string> | undefined)?.[this.config.cookie.name];
    if (!cookie) throw new AuthError('SESSION_MISSING', 'No session. Please sign in.');

    const claims = await this.tokens.verifyRefresh(cookie);
    const user = await this.directory.findById(claims.sub);
    const link = { tenantId: claims.entraTid, oid: claims.entraOid };
    // The user must still exist, still be active and still be linked to the same Microsoft account.
    if (!user || !user.entra || !sameLink(user.entra, link)) {
      this.clearCookie(res);
      throw new AuthError('SESSION_INVALID', 'Your session is no longer valid. Please sign in again.');
    }
    if (!user.active) {
      this.clearCookie(res);
      throw new AuthError('USER_INACTIVE', 'Your EMR account is inactive. Ask your EMR administrator.');
    }
    return this.startSession(user, res);
  }

  /**
   * Clears the refresh cookie. Like the EMR's own logout, this cannot revoke a
   * refresh token copied elsewhere; it expires on its own (REFRESH_TOKEN_TTL_SECONDS).
   * The web app should also sign the user out of Microsoft.
   */
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@Req() req: Request, @Res({ passthrough: true }) res: Response): { success: true } {
    this.assertAllowedOrigin(req);
    this.clearCookie(res);
    return { success: true };
  }

  /** Who am I, according to an access token this service issued. Handy for the demo and for debugging. */
  @Get('me')
  async me(@Req() req: Request): Promise<Record<string, unknown>> {
    const token = bearer(req);
    if (!token) throw new AuthError('ACCESS_TOKEN_INVALID', 'Send the access token as "Authorization: Bearer <token>".');
    return { ...(await this.tokens.verifyAccess(token)) };
  }

  private async startSession(user: EmrUser, res: Response): Promise<SessionResponse> {
    const issued: IssuedTokens = await this.tokens.issue(user);
    res.cookie(this.config.cookie.name, issued.refreshToken, this.cookieOptions(issued.refreshExpiresIn * 1000));
    res.setHeader('Cache-Control', 'no-store');
    return {
      access_token: issued.accessToken,
      token_type: 'Bearer',
      expires_in: issued.expiresIn,
      user: {
        userId: user.userId,
        orgId: user.orgId,
        email: user.email,
        displayName: user.displayName,
        roles: user.roles.filter((r) => r !== 'SYSTEM'),
      },
    };
  }

  private cookieOptions(maxAgeMs?: number): CookieOptions {
    return {
      httpOnly: true,
      secure: this.config.cookie.secure,
      sameSite: 'strict',
      path: COOKIE_PATH,
      ...(maxAgeMs ? { maxAge: maxAgeMs } : {}),
    };
  }

  private clearCookie(res: Response): void {
    res.clearCookie(this.config.cookie.name, this.cookieOptions());
  }

  /**
   * Cookie-authenticated routes only accept calls from the copilot web origins.
   * SameSite=Strict already blocks cross-site requests; this is a second check.
   * Requests with no Origin header (curl, server-to-server) are allowed.
   */
  private assertAllowedOrigin(req: Request): void {
    const origin = req.headers.origin;
    if (origin && !this.config.webOrigins.includes(origin.replace(/\/+$/, ''))) {
      throw new AuthError('ORIGIN_NOT_ALLOWED', 'This origin may not use the session cookie.');
    }
  }
}

function bearer(req: Request): string | undefined {
  const header = req.headers.authorization;
  if (!header) return undefined;
  const [scheme, token] = header.split(' ');
  return scheme?.toLowerCase() === 'bearer' && token ? token.trim() : undefined;
}
