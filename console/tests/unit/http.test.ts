import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '../../app/api/client'
import { createHttpApi, parseSse, toStreamEvent } from '../../app/api/http'
import type { StreamEvent } from '../../app/api/types'

function jsonResponse(body: unknown, status = 200, type = 'application/json') {
  return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'content-type': type } })
}

/** fetch double: openapi-fetch calls it with a Request. */
function fake(...responses: (Response | (() => Response))[]) {
  const calls: Request[] = []
  const fn = vi.fn(async (req: Request) => {
    calls.push(req)
    const r = responses.length > 1 ? responses.shift()! : responses[0]!
    return typeof r === 'function' ? r() : r.clone()
  })
  return { fetch: fn as unknown as typeof globalThis.fetch, calls }
}

const problem = (status: number, title: string, detail?: string) =>
  jsonResponse({ type: 'about:blank', title, status, detail }, status, 'application/problem+json')

describe('http API (openapi-fetch)', () => {
  it('prefixes /api/v1, sends the bearer token, the interface tag and encodes filters', async () => {
    const { fetch, calls } = fake(jsonResponse({ items: [], next_cursor: null }))
    const api = createHttpApi({ baseUrl: 'https://afw.example/', getToken: () => 'tok-1', fetch })
    await api.listFlows({ agent: '7b0c7a52-0000-4000-8000-000000000001', verdict: 'deny', destination: '*.exemple.com', q: undefined })
    const req = calls[0]!
    const url = new URL(req.url)
    expect(url.origin + url.pathname).toBe('https://afw.example/api/v1/logs/flows')
    expect(Object.fromEntries(url.searchParams)).toEqual({ agent: '7b0c7a52-0000-4000-8000-000000000001', verdict: 'deny', destination: '*.exemple.com' })
    expect(req.headers.get('authorization')).toBe('Bearer tok-1')
    expect(req.headers.get('x-afw-interface')).toBe('ui')
  })

  it('sends X-Afw-Session on policy reads once a session is set, and on every write', async () => {
    const { fetch, calls } = fake(jsonResponse([]))
    const api = createHttpApi({ baseUrl: 'https://afw.example', getToken: () => 't', fetch })
    await api.objects.list()
    expect(calls[0]!.headers.has('x-afw-session')).toBe(false)
    api.setSession('s-1')
    await api.objects.list()
    await api.getRulebase()
    await api.listRules({ zone_id: 'z' })
    await api.whereUsed('o-1')
    expect(calls.slice(1).map(c => c.headers.get('x-afw-session'))).toEqual(['s-1', 's-1', 's-1', 's-1'])
    api.setSession(null)
    await api.zones.create('s-2', { id: 'z-1', name: 'prod', comment: '', mode: 'enforce', delegated_to_mcp: false })
    const create = calls.at(-1)!
    expect(create.method).toBe('POST')
    expect(new URL(create.url).pathname).toBe('/api/v1/zones')
    expect(create.headers.get('x-afw-session')).toBe('s-2')
    expect(await create.json()).toMatchObject({ name: 'prod' })
    await api.rules.update('s-3', { id: 'r-1' } as never)
    expect(new URL(calls.at(-1)!.url).pathname).toBe('/api/v1/rules/r-1')
    expect(calls.at(-1)!.method).toBe('PUT')
    expect(calls.at(-1)!.headers.get('x-afw-session')).toBe('s-3')
  })

  it('posts allow-from-log with the contract body', async () => {
    const { fetch, calls } = fake(jsonResponse({ rule: {}, changes: [] }, 201))
    const api = createHttpApi({ baseUrl: 'https://afw.example', getToken: () => null, fetch })
    await api.allowFromLog('s1', { flow_id: 'f1', destination: 'exact', expires_in_days: 30, track: 'detailed' })
    const req = calls[0]!
    expect(new URL(req.url).pathname).toBe('/api/v1/sessions/s1/allow-from-log')
    expect(req.method).toBe('POST')
    expect(await req.json()).toEqual({ flow_id: 'f1', destination: 'exact', expires_in_days: 30, track: 'detailed' })
    expect(req.headers.has('authorization')).toBe(false)
  })

  it('tells a published revision (201) from a pending approval (202)', async () => {
    const rev = { number: 43, comment: 'c', interface: 'ui', published_at: '2026-10-31T10:00:00Z', published_by: { kind: 'human', id: 'a', name: 'A' }, sha256: 'x' }
    const appr = { id: 'ap', status: 'pending', reason: 'widening', summary: 's', session_id: 's1', requested_at: '2026-10-31T10:00:00Z', requested_by: { kind: 'agent', id: 'm', name: 'mcp' } }
    const { fetch } = fake(jsonResponse(rev, 201), jsonResponse(appr, 202))
    const api = createHttpApi({ baseUrl: 'https://afw.example', getToken: () => 't', fetch })
    expect(await api.publishSession('s1', 'c')).toEqual({ status: 'published', revision: rev })
    expect(await api.publishSession('s1', 'c')).toEqual({ status: 'approval', approval: appr })
  })

  it('maps problem+json to ApiError: 401 calls onUnauthorized, 423 exposes the lock owner, 409 keeps the detail', async () => {
    const onUnauthorized = vi.fn()
    const { fetch } = fake(problem(401, 'Unauthorized'), problem(423, 'Locked', 'locked by Marie Durand'), problem(409, 'Conflict', 'approval pending'))
    const api = createHttpApi({ baseUrl: 'https://afw.example', getToken: () => 't', fetch, onUnauthorized })
    const e401 = await api.me().catch(e => e)
    expect(e401).toBeInstanceOf(ApiError)
    expect(e401).toMatchObject({ status: 401, title: 'Unauthorized' })
    expect(onUnauthorized).toHaveBeenCalledOnce()
    const e423 = await api.objects.update('s', { id: 'o' } as never).catch(e => e) as ApiError
    expect(e423.status).toBe(423)
    expect(e423.lockedBy).toBe('Marie Durand')
    const e409 = await api.publishSession('s', 'c').catch(e => e) as ApiError
    expect(e409).toMatchObject({ status: 409, detail: 'approval pending' })
    expect(e409.lockedBy).toBeNull()
  })

  it('returns null when there is no current session (404)', async () => {
    const { fetch } = fake(problem(404, 'Not Found'))
    const api = createHttpApi({ baseUrl: 'https://afw.example', getToken: () => 't', fetch })
    expect(await api.currentSession()).toBeNull()
  })

  it('returns the install envelope and bare arrays as the contract says', async () => {
    const { fetch, calls } = fake(jsonResponse({ installs: [{ id: 'i' }] }, 202), jsonResponse([{ id: 'g' }]))
    const api = createHttpApi({ baseUrl: 'https://afw.example', getToken: () => 't', fetch })
    expect(await api.install(43, [])).toEqual({ installs: [{ id: 'i' }] })
    expect(await calls[0]!.json()).toEqual({ revision: 43, gateways: [] })
    expect(await api.listGateways()).toEqual([{ id: 'g' }])
  })

  it('downloads the audit export with the bearer token as a Blob', async () => {
    const { fetch, calls } = fake(new Response('{"seq":1}\n', { status: 200, headers: { 'content-type': 'application/x-ndjson' } }))
    const api = createHttpApi({ baseUrl: 'https://afw.example', getToken: () => 'tok-9', fetch })
    const blob = await api.exportAudit()
    expect(new URL(calls[0]!.url).pathname).toBe('/api/v1/audit/export')
    expect(calls[0]!.headers.get('authorization')).toBe('Bearer tok-9')
    expect(await blob.text()).toBe('{"seq":1}\n')
  })

  it('reports network failures as status 0', async () => {
    const fetch = vi.fn().mockRejectedValue(new TypeError('fetch failed')) as unknown as typeof globalThis.fetch
    const api = createHttpApi({ baseUrl: 'https://afw.example', getToken: () => 't', fetch })
    await expect(api.listGateways()).rejects.toMatchObject({ status: 0 })
  })
})

describe('log stream (SSE)', () => {
  const flow = { type: 'flow', id: 'f1', gateway_id: 'g', src: '10.0.0.2:4000', dst: '1.2.3.4:443', protocol: 'tcp', bytes_in: 0, bytes_out: 0, started_at: '2026-10-31T10:00:00Z', verdict: 'deny', decision: { layer: 'zone', reason: 'r', rule_name: 'n' }, internal: false, llm_provider: false, observed: false, tls_inspected: false, data_classes: [] }

  function sse(body: string) {
    return () => new Response(new ReadableStream({
      start(c) {
        c.enqueue(new TextEncoder().encode(body))
        c.close()
      },
    }), { status: 200, headers: { 'content-type': 'text/event-stream' } })
  }

  it('reads named events and the lagged notice, then reconnects when the server closes the stream', async () => {
    const { fetch, calls } = fake(sse(`event: flow\ndata: ${JSON.stringify(flow)}\n\n: keep-alive\n\nevent: lagged\ndata: {"skipped":12}\n\n`))
    const api = createHttpApi({ baseUrl: 'https://afw.example', getToken: () => 't', fetch, streamRetryMs: 5 })
    const got: StreamEvent[] = []
    const stop = api.streamLogs(e => got.push(e), { verdict: 'deny' })
    await vi.waitFor(() => expect(calls.length).toBeGreaterThanOrEqual(2))
    stop()
    expect(got[0]).toEqual({ kind: 'event', event: flow })
    expect(got[1]).toEqual({ kind: 'lagged', skipped: 12 })
    const req = calls[0]!
    expect(new URL(req.url).pathname).toBe('/api/v1/logs/stream')
    expect(new URL(req.url).searchParams.get('verdict')).toBe('deny')
    expect(req.headers.get('accept')).toBe('text/event-stream')
    expect(req.headers.get('x-afw-interface')).toBe('ui')
    expect(req.headers.get('authorization')).toBe('Bearer t')
  })

  it('stops reconnecting on 401', async () => {
    const onUnauthorized = vi.fn()
    const { fetch, calls } = fake(problem(401, 'Unauthorized'))
    const api = createHttpApi({ baseUrl: 'https://afw.example', getToken: () => 't', fetch, onUnauthorized, streamRetryMs: 1 })
    const stop = api.streamLogs(() => {})
    await vi.waitFor(() => expect(onUnauthorized).toHaveBeenCalled())
    await new Promise(r => setTimeout(r, 20))
    stop()
    expect(calls.length).toBe(1)
  })

  it('ignores unknown or malformed events', () => {
    expect(toStreamEvent({ event: 'flow', data: '{' })).toBeNull()
    expect(toStreamEvent({ event: 'message', data: '{"type":"flow"}' })).toBeNull()
    expect(toStreamEvent({ event: 'flow', data: '{"type":"dns"}' })).toBeNull()
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
