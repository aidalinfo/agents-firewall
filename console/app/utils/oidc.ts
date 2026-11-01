import type { KeyValueStorage } from './security'

/**
 * OIDC authorization code flow with PKCE (public client), as advertised by
 * `GET /auth/oidc/config`. The console keeps the verifier in sessionStorage with the `state`
 * (single use) and exchanges the code at the provider's token endpoint.
 */
const VERIFIER_KEY = 'afw-oidc-verifier'

function base64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function createPkce(storage: KeyValueStorage): Promise<{ verifier: string, challenge: string }> {
  const raw = new Uint8Array(32)
  crypto.getRandomValues(raw)
  const verifier = base64url(raw)
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
  storage.setItem(VERIFIER_KEY, verifier)
  return { verifier, challenge: base64url(digest) }
}

export function takeVerifier(storage: KeyValueStorage): string | null {
  const v = storage.getItem(VERIFIER_KEY)
  storage.removeItem(VERIFIER_KEY)
  return v
}

export function authorizeUrl(endpoint: string, p: { clientId: string, redirectUri: string, scope: string, state: string, challenge: string }): string {
  const u = new URL(endpoint)
  u.searchParams.set('response_type', 'code')
  u.searchParams.set('client_id', p.clientId)
  u.searchParams.set('redirect_uri', p.redirectUri)
  u.searchParams.set('scope', p.scope)
  u.searchParams.set('state', p.state)
  u.searchParams.set('code_challenge', p.challenge)
  u.searchParams.set('code_challenge_method', 'S256')
  return u.toString()
}

/** Exchanges the authorization code for an access token at the provider's token endpoint. */
export async function exchangeCode(endpoint: string, p: { clientId: string, redirectUri: string, code: string, verifier: string }, fetcher: typeof fetch = fetch): Promise<string> {
  const res = await fetcher(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'accept': 'application/json' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: p.code, redirect_uri: p.redirectUri, client_id: p.clientId, code_verifier: p.verifier }),
  })
  if (!res.ok) throw new Error(`token endpoint: HTTP ${res.status}`)
  const body = await res.json() as { access_token?: unknown }
  if (typeof body.access_token !== 'string' || !body.access_token) throw new Error('token endpoint: no access_token')
  return body.access_token
}
