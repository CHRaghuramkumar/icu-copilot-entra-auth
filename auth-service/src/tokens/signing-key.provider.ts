import { Logger, Provider } from '@nestjs/common';
import { exportJWK, generateKeyPair, importPKCS8, type JWK, type CryptoKey } from 'jose';
import { createPublicKey } from 'node:crypto';
import { APP_CONFIG, type AppConfig } from '../config/app-config';

export const SIGNING_KEY = Symbol('SIGNING_KEY');

export interface SigningKey {
  kid: string;
  privateKey: CryptoKey;
  /** Public half, published at /.well-known/jwks.json. */
  publicJwk: JWK;
}

const ALG = 'RS256';

/**
 * Loads the RS256 key this service signs with. In development, when no key is
 * configured, a throwaway key is generated at boot (tokens stop verifying after a
 * restart, which is fine locally). Production refuses to start without a key;
 * see loadConfig().
 */
export const signingKeyProvider: Provider = {
  provide: SIGNING_KEY,
  inject: [APP_CONFIG],
  useFactory: async (config: AppConfig): Promise<SigningKey> => {
    const { keyId, privateKeyPem } = config.token;

    if (privateKeyPem) {
      const privateKey = await importPKCS8(privateKeyPem, ALG, { extractable: false });
      const publicJwk = await exportJWK(createPublicKey(privateKeyPem));
      return { kid: keyId, privateKey, publicJwk: { ...publicJwk, kid: keyId, alg: ALG, use: 'sig' } };
    }

    new Logger('SigningKey').warn(
      'TOKEN_SIGNING_PRIVATE_KEY is not set: using a temporary key. Issued tokens stop working after a restart.',
    );
    const { privateKey, publicKey } = await generateKeyPair(ALG, { extractable: true });
    const publicJwk = await exportJWK(publicKey);
    return { kid: keyId, privateKey, publicJwk: { ...publicJwk, kid: keyId, alg: ALG, use: 'sig' } };
  },
};
