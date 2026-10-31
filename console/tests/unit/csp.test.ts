import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { apiOrigin, contentSecurityPolicy, inlineScriptHashes } from '../../server/utils/csp'

describe('content security policy', () => {
  it('is strict and only adds the API origin to connect-src', () => {
    const csp = contentSecurityPolicy({ apiBase: 'https://afw.example/some/path' })
    expect(csp).toContain(`default-src 'self'`)
    expect(csp).toContain(`connect-src 'self' https://afw.example;`)
    expect(csp).toContain(`img-src 'self' data:`)
    expect(csp).toContain(`style-src 'self' 'unsafe-inline'`)
    expect(csp).toContain(`font-src 'self'`)
    expect(csp).toContain(`frame-ancestors 'none'`)
    expect(csp).toContain(`base-uri 'none'`)
    expect(csp).toContain(`object-src 'none'`)
    expect(csp).not.toContain('unsafe-eval')
    expect(csp).toMatch(/script-src 'self';/)
  })

  it('adds the OIDC token endpoint origin when configured', () => {
    expect(contentSecurityPolicy({ oidcOrigin: 'https://id.example/realms/x' })).toContain(`connect-src 'self' https://id.example;`)
    expect(contentSecurityPolicy({ apiBase: 'https://a.example', oidcOrigin: 'javascript:x' })).toContain(`connect-src 'self' https://a.example;`)
  })

  it('ignores API bases that are not http(s) URLs', () => {
    expect(apiOrigin('javascript:alert(1)')).toBeNull()
    expect(apiOrigin('')).toBeNull()
    expect(apiOrigin('https://a.example:8443/x')).toBe('https://a.example:8443')
  })

  it('allows inline scripts by hash only', () => {
    const body = 'window.__NUXT__={}'
    const html = `<script>${body}</script><script type="module" src="/_nuxt/a.js"></script>`
    const expected = `'sha256-${createHash('sha256').update(body).digest('base64')}'`
    expect(inlineScriptHashes(html)).toEqual([expected])
    expect(contentSecurityPolicy({ scriptHashes: [expected] })).toContain(`script-src 'self' ${expected};`)
  })
})
