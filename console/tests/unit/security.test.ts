import { beforeEach, describe, expect, it } from 'vitest'
import { bodyView, createOidcState, safeHref, safeRedirect, takeOidcState } from '../../app/utils/security'

describe('safeRedirect', () => {
  const origin = 'https://console.example'
  it('keeps relative paths and same-origin URLs', () => {
    expect(safeRedirect('/rules?zone=1', origin)).toBe('/rules?zone=1')
    expect(safeRedirect('https://console.example/agents#x', origin)).toBe('/agents#x')
  })
  it('rejects other origins, protocol-relative and odd schemes', () => {
    for (const bad of ['https://evil.example/', '//evil.example/x', '/\\evil.example', 'javascript:alert(1)', 'rules', '', undefined, null, ['/']]) {
      expect(safeRedirect(bad as never, origin)).toBe('/')
    }
  })
})

describe('safeHref', () => {
  it('only allows in-app absolute paths from API data', () => {
    expect(safeHref('/agents/1')).toBe('/agents/1')
    expect(safeHref('//evil')).toBeNull()
    expect(safeHref('https://evil')).toBeNull()
    expect(safeHref('javascript:alert(1)')).toBeNull()
    expect(safeHref(null)).toBeNull()
  })
})

describe('OIDC state', () => {
  const store = new Map<string, string>()
  const storage = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v), removeItem: (k: string) => void store.delete(k) }
  beforeEach(() => store.clear())

  it('creates a random state bound to a safe redirect and accepts it once', () => {
    const a = createOidcState('/rules', storage)
    const b = createOidcState('/rules', storage)
    expect(a).toMatch(/^[0-9a-f]{32,}$/)
    expect(a).not.toBe(b)
    expect(takeOidcState(b, storage)).toEqual({ ok: true, redirect: '/rules' })
    expect(takeOidcState(b, storage)).toEqual({ ok: false, redirect: '/' })
  })

  it('rejects a missing or forged state', () => {
    createOidcState('/x', storage)
    expect(takeOidcState(null, storage).ok).toBe(false)
    expect(takeOidcState('forged', storage).ok).toBe(false)
  })
})

describe('bodyView', () => {
  const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64')
  it('shows utf8 bodies as is', () => {
    expect(bodyView({ encoding: 'utf8', data: '{"a":1}', size: 7, truncated: false, sha256: '' })).toEqual({ kind: 'text', text: '{"a":1}', truncated: false, size: 7 })
  })
  it('decodes base64 text and flags truncation', () => {
    expect(bodyView({ encoding: 'base64', data: b64('héllo'), size: 9000, truncated: true, sha256: '' })).toEqual({ kind: 'text', text: 'héllo', truncated: true, size: 9000 })
  })
  it('reports binary content without rendering it', () => {
    expect(bodyView({ encoding: 'base64', data: Buffer.from([0, 1, 2, 255, 254]).toString('base64'), size: 5, truncated: false, sha256: 'ab' })).toEqual({ kind: 'binary', text: '', truncated: false, size: 5 })
  })
})
