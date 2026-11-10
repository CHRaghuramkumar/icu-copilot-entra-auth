'use client';

import { useEffect, useState } from 'react';
import {
  AuthServiceError,
  completeRedirect,
  exchangeForCopilotSession,
  refreshCopilotSession,
  signIn,
  signOut,
  type CopilotSession,
} from '../lib/auth';

type State =
  | { kind: 'loading' }
  | { kind: 'signed-out'; error?: string }
  | { kind: 'signed-in'; session: CopilotSession };

/** Decode a JWT payload for display only. The browser never makes access decisions from it. */
function claimsOf(jwt: string): Record<string, unknown> {
  const part = jwt.split('.')[1] ?? '';
  return JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/')));
}

function describe(err: unknown): string {
  if (err instanceof AuthServiceError) return `${err.message} (${err.code})`;
  return err instanceof Error ? err.message : 'Sign-in failed.';
}

export default function Home() {
  const [state, setState] = useState<State>({ kind: 'loading' });

  useEffect(() => {
    (async () => {
      try {
        const account = await completeRedirect();
        if (account) {
          setState({ kind: 'signed-in', session: await exchangeForCopilotSession(account) });
          return;
        }
        // No Microsoft account in this tab: try the refresh cookie from an earlier sign-in.
        setState({ kind: 'signed-in', session: await refreshCopilotSession() });
      } catch (err) {
        const quiet = err instanceof AuthServiceError && err.code === 'SESSION_MISSING';
        setState({ kind: 'signed-out', error: quiet ? undefined : describe(err) });
      }
    })();
  }, []);

  const refresh = async () => {
    try {
      setState({ kind: 'signed-in', session: await refreshCopilotSession() });
    } catch (err) {
      setState({ kind: 'signed-out', error: describe(err) });
    }
  };

  return (
    <main>
      <div className="card">
        <h1>ICU Clinician Copilot</h1>
        <p className="muted">Sign in with your hospital Microsoft account.</p>

        {state.kind === 'loading' && <p>Checking your sign-in…</p>}

        {state.kind === 'signed-out' && (
          <>
            {state.error && <p className="error" role="alert">{state.error}</p>}
            <button onClick={() => void signIn()}>Sign in with Microsoft</button>
          </>
        )}

        {state.kind === 'signed-in' && (
          <>
            <dl>
              <dt>Name</dt>
              <dd>{state.session.user.displayName}</dd>
              <dt>Email</dt>
              <dd>{state.session.user.email}</dd>
              <dt>EMR user id</dt>
              <dd>{state.session.user.userId}</dd>
              <dt>Roles</dt>
              <dd>{state.session.user.roles.join(', ') || 'none'}</dd>
              <dt>Token expires in</dt>
              <dd>{state.session.expires_in} s</dd>
            </dl>
            <button onClick={() => void refresh()}>Refresh session</button>
            <button className="secondary" onClick={() => void signOut()}>
              Sign out
            </button>
          </>
        )}
      </div>

      {state.kind === 'signed-in' && (
        <div className="card">
          <h1>ICU Copilot access token</h1>
          <p className="muted">
            Issued by the auth service, not by Microsoft. The EMR backend and copilot verify it with the auth
            service&apos;s public keys.
          </p>
          <pre data-testid="claims">{JSON.stringify(claimsOf(state.session.access_token), null, 2)}</pre>
        </div>
      )}
    </main>
  );
}
