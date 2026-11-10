import { Controller, Get, Header, Inject } from '@nestjs/common';
import { APP_CONFIG, type AppConfig } from '../config/app-config';
import { TokenService } from '../tokens/token.service';

/**
 * Public discovery endpoints. The EMR backend (and any other API the copilot
 * calls) verifies this service's tokens with the keys published here, the same
 * way this service verifies Microsoft's.
 */
@Controller()
export class WellKnownController {
  constructor(
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    private readonly tokens: TokenService,
  ) {}

  @Get('.well-known/jwks.json')
  @Header('Cache-Control', 'public, max-age=300')
  jwks() {
    return this.tokens.publicJwks();
  }

  @Get('.well-known/openid-configuration')
  @Header('Cache-Control', 'public, max-age=300')
  discovery() {
    const issuer = this.config.token.issuer;
    return {
      issuer,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      id_token_signing_alg_values_supported: ['RS256'],
      token_endpoint: `${issuer}/auth/entra/exchange`,
    };
  }

  @Get('health')
  health() {
    return { status: 'ok' };
  }
}
