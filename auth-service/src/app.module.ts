import { DynamicModule, Module, Provider } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { AuthController } from './auth/auth.controller';
import { WellKnownController } from './auth/well-known.controller';
import { APP_CONFIG, type AppConfig } from './config/app-config';
import { entraJwksProvider } from './entra/entra-jwks.provider';
import { EntraTokenVerifier } from './entra/entra-token.verifier';
import { signingKeyProvider } from './tokens/signing-key.provider';
import { TokenService } from './tokens/token.service';
import { FileUserDirectory } from './users/file-user-directory';
import { IdentityLinkerService } from './users/identity-linker.service';
import { USER_DIRECTORY } from './users/user-directory';

@Module({})
export class AppModule {
  static forRoot(config: AppConfig): DynamicModule {
    const providers: Provider[] = [
      { provide: APP_CONFIG, useValue: config },
      entraJwksProvider,
      signingKeyProvider,
      { provide: USER_DIRECTORY, useFactory: () => FileUserDirectory.fromFile(config.usersFile) },
      EntraTokenVerifier,
      IdentityLinkerService,
      TokenService,
      { provide: APP_GUARD, useClass: ThrottlerGuard },
    ];
    return {
      module: AppModule,
      imports: [ThrottlerModule.forRoot([{ ttl: 60_000, limit: 120 }])],
      controllers: [AuthController, WellKnownController],
      providers,
    };
  }
}
