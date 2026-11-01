import type { Body } from '~/api/types'

/**
 * Returns a same-origin, in-app path for a post-login redirect, or "/".
 * Accepts "/path" and absolute URLs on `origin`; rejects other origins, "//host", "/\host" and schemes.
 */
export function safeRedirect(target: unknown, origin: string): string {
  if (typeof target !== 'string' || !target) return '/'
  try {
    if (target.startsWith('/') && !target.startsWith('//') && !target.startsWith('/\\')) {
      const u = new URL(target, origin)
      return u.origin === origin ? `${u.pathname}${u.search}${u.hash}` : '/'
    }
    const u = new URL(target)
    return u.origin === origin ? `${u.pathname}${u.search}${u.hash}` : '/'
  }
  catch {
    return '/'
  }
}

/** Links received from the API are only followed when they are in-app absolute paths. */
export function safeHref(href: string | null | undefined): string | null {
  if (!href || !href.startsWith('/') || href.startsWith('//') || href.startsWith('/\\')) return null
  return href
}

export interface KeyValueStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

const STATE_KEY = 'afw-oidc-state'

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes)
  crypto.getRandomValues(buf)
  return [...buf].map(b => b.toString(16).padStart(2, '0')).join('')
}

/** Creates the OIDC `state` (128 bits, random) and remembers it with the redirect target. */
export function createOidcState(redirect: string, storage: KeyValueStorage): string {
  const state = randomHex(16)
  storage.setItem(STATE_KEY, JSON.stringify({ state, redirect }))
  return state
}

/** Checks the `state` returned by the identity provider; single use. */
export function takeOidcState(state: string | null, storage: KeyValueStorage): { ok: boolean, redirect: string } {
  const raw = storage.getItem(STATE_KEY)
  storage.removeItem(STATE_KEY)
  if (!raw || !state) return { ok: false, redirect: '/' }
  try {
    const saved = JSON.parse(raw) as { state?: string, redirect?: string }
    if (!saved.state || saved.state !== state) return { ok: false, redirect: '/' }
    return { ok: true, redirect: typeof saved.redirect === 'string' && saved.redirect.startsWith('/') && !saved.redirect.startsWith('//') ? saved.redirect : '/' }
  }
  catch {
    return { ok: false, redirect: '/' }
  }
}

export interface BodyView {
  kind: 'text' | 'binary'
  text: string
  truncated: boolean
  size: number
}

/** How to show a stored (already masked) body: decoded text when it is UTF-8 text, else a binary notice. */
export function bodyView(body: Body): BodyView {
  const base = { truncated: body.truncated, size: body.size }
  if (body.encoding === 'utf8') return { kind: 'text', text: body.data, ...base }
  try {
    const bin = atob(body.data)
    const bytes = Uint8Array.from(bin, c => c.charCodeAt(0))
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u0008\u000E-\u001F\u007F]/.test(text)) return { kind: 'binary', text: '', ...base }
    return { kind: 'text', text, ...base }
  }
  catch {
    return { kind: 'binary', text: '', ...base }
  }
}
