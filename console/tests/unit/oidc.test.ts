import { describe, expect, it, vi } from 'vitest'
import { authorizeUrl, createPkce, exchangeCode, takeVerifier } from '../../app/utils/oidc'

function memory() {
  const m = new Map<string, string>()
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k) }
}

describe('OIDC authorization code + PKCE', () => {
  it('derives the S256 challenge from a random verifier kept once', async () => {
    const s = memory()
    const { verifier, challenge } = await createPkce(s)
    expect(verifier).toMatch(/^[\w-]{43}$/)
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
    expect(challenge).toBe(btoa(String.fromCharCode(...digest)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''))
    expect(takeVerifier(s)).toBe(verifier)
    expect(takeVerifier(s)).toBeNull()
  })

  it('builds the authorization URL with state and challenge', () => {
    const u = new URL(authorizeUrl('https://id.example/auth?prompt=login', { clientId: 'afw', redirectUri: 'https://afw.example/login', scope: 'openid profile', state: 's1', challenge: 'c1' }))
    expect(Object.fromEntries(u.searchParams)).toEqual({ prompt: 'login', response_type: 'code', client_id: 'afw', redirect_uri: 'https://afw.example/login', scope: 'openid profile', state: 's1', code_challenge: 'c1', code_challenge_method: 'S256' })
  })

  it('exchanges the code with the verifier and refuses answers without a token', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ access_token: 'at-1' }), { status: 200 })).mockResolvedValueOnce(new Response('{}', { status: 200 }))
    expect(await exchangeCode('https://id.example/token', { clientId: 'afw', redirectUri: 'https://afw.example/login', code: 'k', verifier: 'v' }, fetcher)).toBe('at-1')
    const body = new URLSearchParams(String(fetcher.mock.calls[0]![1].body))
    expect(Object.fromEntries(body)).toEqual({ grant_type: 'authorization_code', code: 'k', redirect_uri: 'https://afw.example/login', client_id: 'afw', code_verifier: 'v' })
    await expect(exchangeCode('https://id.example/token', { clientId: 'afw', redirectUri: 'x', code: 'k', verifier: 'v' }, fetcher)).rejects.toThrow('no access_token')
  })
})
