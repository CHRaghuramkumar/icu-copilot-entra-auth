import { HttpException, HttpStatus } from '@nestjs/common';

/**
 * Stable error codes the web app can switch on. Messages are safe to show to a
 * clinician; they never echo token contents.
 */
export type AuthErrorCode =
  | 'ENTRA_TOKEN_MISSING'
  | 'ENTRA_TOKEN_INVALID'
  | 'ENTRA_TENANT_MISMATCH'
  | 'ENTRA_SCOPE_MISSING'
  | 'ENTRA_EMAIL_MISSING'
  | 'USER_NOT_PROVISIONED'
  | 'USER_EMAIL_AMBIGUOUS'
  | 'USER_LINK_CONFLICT'
  | 'USER_INACTIVE'
  | 'SESSION_MISSING'
  | 'SESSION_INVALID'
  | 'ORIGIN_NOT_ALLOWED'
  | 'ACCESS_TOKEN_INVALID';

const STATUS: Record<AuthErrorCode, HttpStatus> = {
  ENTRA_TOKEN_MISSING: HttpStatus.UNAUTHORIZED,
  ENTRA_TOKEN_INVALID: HttpStatus.UNAUTHORIZED,
  ENTRA_TENANT_MISMATCH: HttpStatus.UNAUTHORIZED,
  ENTRA_SCOPE_MISSING: HttpStatus.FORBIDDEN,
  ENTRA_EMAIL_MISSING: HttpStatus.FORBIDDEN,
  USER_NOT_PROVISIONED: HttpStatus.FORBIDDEN,
  USER_EMAIL_AMBIGUOUS: HttpStatus.FORBIDDEN,
  USER_LINK_CONFLICT: HttpStatus.FORBIDDEN,
  USER_INACTIVE: HttpStatus.FORBIDDEN,
  SESSION_MISSING: HttpStatus.UNAUTHORIZED,
  SESSION_INVALID: HttpStatus.UNAUTHORIZED,
  ORIGIN_NOT_ALLOWED: HttpStatus.FORBIDDEN,
  ACCESS_TOKEN_INVALID: HttpStatus.UNAUTHORIZED,
};

export class AuthError extends HttpException {
  constructor(
    readonly code: AuthErrorCode,
    message: string,
  ) {
    super({ error: code, message }, STATUS[code]);
  }
}
