import { createHash } from 'node:crypto'

/** Origin of the control-plane API, or null when the console calls its own origin. */
export function apiOrigin(apiBase: string | undefined): string | null {
  if (!apiBase) return null
  try {
    const u = new URL(apiBase)
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.origin : null
  }
  catch {
    return null
  }
}

/** sha256 sources for every inline <script> of an HTML document (Nuxt payload/config, color mode). */
export function inlineScriptHashes(html: string): string[] {
  const out = new Set<string>()
  for (const m of html.matchAll(/<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi)) {
    if (m[1]) out.add(`'sha256-${createHash('sha256').update(m[1], 'utf8').digest('base64')}'`)
  }
  return [...out]
}

/**
 * Strict CSP of the console; inline scripts are only allowed by hash. `oidcOrigin` is the
 * identity provider whose token endpoint the console calls (authorization code + PKCE).
 */
export function contentSecurityPolicy(opts: { apiBase?: string, scriptHashes?: string[], oidcOrigin?: string }): string {
  const connect = [apiOrigin(opts.apiBase), apiOrigin(opts.oidcOrigin)].filter((o): o is string => !!o)
  return [
    `default-src 'self'`,
    `script-src 'self'${opts.scriptHashes?.length ? ` ${opts.scriptHashes.join(' ')}` : ''}`,
    `connect-src 'self'${[...new Set(connect)].map(o => ` ${o}`).join('')}`,
    `img-src 'self' data:`,
    `style-src 'self' 'unsafe-inline'`,
    `font-src 'self'`,
    `frame-ancestors 'none'`,
    `base-uri 'none'`,
    `object-src 'none'`,
    `form-action 'self'`,
  ].join('; ')
}

export const STATIC_SECURITY_HEADERS: Record<string, string> = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
}
