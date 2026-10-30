import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '../../app/api/client'
import { createHttpApi, parseSse } from '../../app/api/http'

function jsonResponse(body: unknown, status = 200, type = 'application/json') {
  return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'content-type': type } })
}

describe('http API', () => {
  it('prefixes /api/v1, sends the bearer token and encodes filters', async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ items: [], next_cursor: null, total: 0 }))
    const api = createHttpApi({ baseUrl: 'https://afw.example/', getToken: () => 'tok-1', fetch })
    await api.listFlows({ agent: 'daniel-bot', verdict: 'deny', destination: '*.exemple.com', q: undefined })
    const [url, init] = fetch.mock.calls[0]!
    expect(url).toBe('https://afw.example/api/v1/logs/flows?agent=daniel-bot&verdict=deny&destination=*.exemple.com')
    expect(new Headers(init.headers).get('authorization')).toBe('Bearer tok-1')
    expect(new Headers(init.headers).get('x-afw-interface')).toBe('ui')
  })

  it('tags every request, including the SSE stream, with X-Afw-Interface: ui', async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse({}))
    const api = createHttpApi({ baseUrl: '', getToken: () => null, fetch })
    await api.openSession('s')
    const stop = api.streamLogs(() => {})
    await new Promise(r => setTimeout(r, 0))
    stop()
    for (const [, init] of fetch.mock.calls) expect(new Headers(init.headers).get('x-afw-interface')).toBe('ui')
  })

  it('downloads the audit export with the bearer token as a Blob', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('{"seq":1}\n', { status: 200, headers: { 'content-type': 'application/x-ndjson' } }))
    const api = createHttpApi({ baseUrl: 'https://afw.example', getToken: () => 'tok-9', fetch })
    const blob = await api.exportAudit()
    const [url, init] = fetch.mock.calls[0]!
    expect(url).toBe('https://afw.example/api/v1/audit/export')
    expect(new Headers(init.headers).get('authorization')).toBe('Bearer tok-9')
    expect(blob).toBeInstanceOf(Blob)
    expect(await blob.text()).toBe('{"seq":1}\n')
  })

  it('passes the OIDC state to the login entry point', () => {
    const api = createHttpApi({ baseUrl: 'https://afw.example', getToken: () => null, fetch: vi.fn() })
    expect(api.oidcLoginUrl('https://console.example/', 'abc123')).toBe('https://afw.example/api/v1/auth/oidc/login?redirect=https%3A%2F%2Fconsole.example%2F&state=abc123')
  })

  it('posts JSON bodies', async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ rule: {}, changes: [] }))
    const api = createHttpApi({ baseUrl: '', getToken: () => null, fetch })
    await api.allowFromLog('s1', { flow_id: 'f1', destination: 'exact', expires_in_days: 30, track: 'detailed' })
    const [url, init] = fetch.mock.calls[0]!
    expect(url).toBe('/api/v1/sessions/s1/allow-from-log')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body)).toEqual({ flow_id: 'f1', destination: 'exact', expires_in_days: 30, track: 'detailed' })
    expect(new Headers(init.headers).has('authorization')).toBe(false)
  })

  it('maps problem+json errors to ApiError and calls onUnauthorized on 401', async () => {
    const onUnauthorized = vi.fn()
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ title: 'Unauthorized', status: 401, detail: 'token expired' }, 401, 'application/problem+json'))
    const api = createHttpApi({ baseUrl: '', getToken: () => 't', fetch, onUnauthorized })
    const err = await api.me().catch(e => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ status: 401, title: 'Unauthorized', detail: 'token expired' })
    expect(onUnauthorized).toHaveBeenCalledOnce()
  })

  it('returns null when there is no current session', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(null, { status: 204 }))
    const api = createHttpApi({ baseUrl: '', getToken: () => 't', fetch })
    expect(await api.currentSession()).toBeNull()
  })

  it('unwraps paginated collections for list endpoints', async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ items: [{ id: 'z' }], next_cursor: null, total: 1 }))
    const api = createHttpApi({ baseUrl: '', getToken: () => 't', fetch })
    expect(await api.listZones()).toEqual([{ id: 'z' }])
  })

  it('reports network failures as status 0', async () => {
    const fetch = vi.fn().mockRejectedValue(new TypeError('fetch failed'))
    const api = createHttpApi({ baseUrl: '', getToken: () => 't', fetch })
    await expect(api.listGateways()).rejects.toMatchObject({ status: 0 })
  })
})

describe('parseSse', () => {
  it('splits events, joins multi-line data and keeps the remainder', () => {
    const { events, rest } = parseSse('event: flow\ndata: {"a":1}\n\ndata: {"b":\ndata: 2}\n\ndata: {"c"')
    expect(events).toEqual([{ event: 'flow', data: '{"a":1}' }, { event: 'message', data: '{"b":\n2}' }])
    expect(rest).toBe('data: {"c"')
  })

  it('ignores comments and handles CRLF', () => {
    const { events } = parseSse(': keep-alive\r\n\r\ndata: x\r\n\r\n')
    expect(events).toEqual([{ event: 'message', data: 'x' }])
  })
})
