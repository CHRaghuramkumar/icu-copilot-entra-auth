import {
  InteractionRequiredAuthError,
  PublicClientApplication,
  type AccountInfo,
  type Configuration,
} from '@azure/msal-browser';
import { webConfig } from './config';

export interface CopilotSession {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  user: { userId: string; orgId: string; email: string; displayName: string; roles: string[] };
}

export class AuthServiceError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

let msalInstance: PublicClientApplication | undefined;

/** One MSAL instance per page. Tokens are cached in sessionStorage, so closing the tab signs out of the app. */
export async function getMsal(): Promise<PublicClientApplication> {
  if (msalInstance) return msalInstance;
  const config: Configuration = {
    auth: {
      clientId: webConfig.clientId,
      authority: webConfig.authority,
      redirectUri: webConfig.redirectUri,
      postLogoutRedirectUri: webConfig.redirectUri,
      ...(webConfig.knownAuthority ? { knownAuthorities: [webConfig.knownAuthority] } : {}),
    },
    cache: { cacheLocation: 'sessionStorage' },
  };
  msalInstance = new PublicClientApplication(config);
  await msalInstance.initialize();
  return msalInstance;
}

/** Scopes asked for at sign-in. The API scope is included up front so the silent call below needs no prompt. */
const loginScopes = () => ['openid', 'profile', 'email', 'offline_access', webConfig.apiScope];

export async function signIn(): Promise<void> {
  const msal = await getMsal();
  await msal.loginRedirect({ scopes: loginScopes() });
}

/** After the redirect back from Microsoft, returns the signed-in account if there is one. */
export async function completeRedirect(): Promise<AccountInfo | null> {
  const msal = await getMsal();
  const result = await msal.handleRedirectPromise();
  const account = result?.account ?? msal.getAllAccounts()[0] ?? null;
  if (account) msal.setActiveAccount(account);
  return account;
}

/** Gets a Microsoft access token for the auth service and swaps it for an ICU Copilot session. */
export async function exchangeForCopilotSession(account: AccountInfo): Promise<CopilotSession> {
  const msal = await getMsal();
  let entraToken: string;
  try {
    entraToken = (await msal.acquireTokenSilent({ account, scopes: [webConfig.apiScope] })).accessToken;
  } catch (err) {
    if (err instanceof InteractionRequiredAuthError) {
      await msal.acquireTokenRedirect({ account, scopes: loginScopes() });
    }
    throw err;
  }
  return callAuthService('/auth/entra/exchange', { Authorization: `Bearer ${entraToken}` });
}

/** Restores a session from the refresh cookie (no Microsoft round trip). */
export function refreshCopilotSession(): Promise<CopilotSession> {
  return callAuthService('/auth/refresh');
}

export async function signOut(): Promise<void> {
  await fetch(`${webConfig.authServiceUrl}/auth/logout`, { method: 'POST', credentials: 'include' }).catch(() => undefined);
  const msal = await getMsal();
  const account = msal.getActiveAccount() ?? undefined;
  await msal.logoutRedirect({ account });
}

async function callAuthService(path: string, headers: Record<string, string> = {}): Promise<CopilotSession> {
  const res = await fetch(`${webConfig.authServiceUrl}${path}`, {
    method: 'POST',
    // Needed so the browser stores and sends the httpOnly refresh cookie.
    credentials: 'include',
    headers,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new AuthServiceError(body.error ?? `HTTP_${res.status}`, body.message ?? 'Sign-in failed.');
  return body as CopilotSession;
}
