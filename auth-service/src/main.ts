import 'reflect-metadata';
import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';
import { loadConfig, type AppConfig } from './config/app-config';

export function configureApp(app: NestExpressApplication, config: AppConfig): void {
  app.disable('x-powered-by');
  app.use(cookieParser());
  app.enableCors({
    origin: config.webOrigins,
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Authorization', 'Content-Type'],
  });
}

async function bootstrap(): Promise<void> {
  const config = loadConfig();
  const app = await NestFactory.create<NestExpressApplication>(AppModule.forRoot(config));
  configureApp(app, config);
  await app.listen(config.port);
  const logger = new Logger('Bootstrap');
  logger.log(`ICU Copilot auth service on http://localhost:${config.port}`);
  logger.log(`Accepting Entra tokens from issuer ${config.entra.issuer} for audience ${config.entra.audiences.join(', ')}`);
}

if (require.main === module) {
  void bootstrap();
}
