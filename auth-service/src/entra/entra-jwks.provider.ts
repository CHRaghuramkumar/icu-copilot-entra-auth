import { readFileSync } from 'node:fs';
import { Agent as HttpsAgent, request as httpsRequest } from 'node:https';
import { Logger, Provider } from '@nestjs/common';
import { createRemoteJWKSet, customFetch, type FetchImplementation, type JWTVerifyGetKey } from 'jose';
import { APP_CONFIG, type AppConfig } from '../config/app-config';

export const ENTRA_JWKS = Symbol('ENTRA_JWKS');

/**
 * A minimal `fetch` for jose's JWKS download that trusts one extra CA. Only used
 * with the local entra-local emulator, which serves a self-signed certificate.
 * Against real Entra (login.microsoftonline.com) the default fetch is used.
 */
function caTrustingFetch(ca: Buffer): FetchImplementation {
  const agent = new HttpsAgent({ ca });
  return (url, options) =>
    new Promise((resolve, reject) => {
      const req = httpsRequest(
        url,
        {
          method: options.method,
          headers: Object.fromEntries(new Headers(options.headers as ConstructorParameters<typeof Headers>[0]).entries()),
          agent,
          signal: options.signal,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('end', () => {
            const headers = new Headers();
            for (const [key, value] of Object.entries(res.headers)) {
              if (typeof value === 'string') headers.set(key, value);
              else if (Array.isArray(value)) headers.set(key, value.join(', '));
            }
            resolve(new Response(Buffer.concat(chunks), { status: res.statusCode ?? 500, headers }));
          });
          res.on('error', reject);
        },
      );
      req.on('error', reject);
      req.end();
    });
}

export const entraJwksProvider: Provider = {
  provide: ENTRA_JWKS,
  inject: [APP_CONFIG],
  useFactory: (config: AppConfig): JWTVerifyGetKey => {
    const logger = new Logger('EntraJwks');
    const url = new URL(config.entra.jwksUri);
    // createRemoteJWKSet caches keys and refetches when it sees an unknown `kid`
    // (Entra rotates keys), so one instance is shared for the process lifetime.
    if (config.entra.caCertPath) {
      if (config.nodeEnv === 'production') {
        logger.warn('ENTRA_CA_CERT_PATH is set in production. It is only meant for the local emulator.');
      }
      const ca = readFileSync(config.entra.caCertPath);
      logger.log(`Trusting extra CA for the Entra JWKS fetch: ${config.entra.caCertPath}`);
      return createRemoteJWKSet(url, { [customFetch]: caTrustingFetch(ca) });
    }
    return createRemoteJWKSet(url);
  },
};
