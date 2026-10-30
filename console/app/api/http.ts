import createClient, { type Middleware } from 'openapi-fetch'
import { ApiError, type AfwApi, type PolicyCollection } from './client'
import type { paths } from './schema'
import type { GatewayEvent, Page, Problem, PublishOutcome, Revision, Approval, StreamEvent, Uuid } from './types'

export interface HttpOptions {
  /** Control-plane origin ("" = same origin as the console). */
  baseUrl: string
  getToken: () => string | null
  fetch?: typeof globalThis.fetch
  /** Called on 401 so the console can send the user back to the login screen. */
  onUnauthorized?: () => void
  /** First reconnection delay of the log stream (ms), doubled up to 30 s. */
  streamRetryMs?: number
}

export interface SseMessage {
  event: string
  data: string
}

/** Incremental Server-Sent Events parser (fetch-based, so the bearer header can be sent). */
export function parseSse(buffer: string): { events: SseMessage[], rest: string } {
  const normalized = buffer.replace(/\r\n/g, '\n')
  const blocks = normalized.split('\n\n')
  const rest = blocks.pop() ?? ''
  const events: SseMessage[] = []
  for (const block of blocks) {
    let event = 'message'
    const data: string[] = []
    for (const line of block.split('\n')) {
      if (!line || line.startsWith(':')) continue
      const idx = line.indexOf(':')
      const field = idx === -1 ? line : line.slice(0, idx)
      const value = idx === -1 ? '' : line.slice(idx + 1).replace(/^ /, '')
      if (field === 'event') event = value
      else if (field === 'data') data.push(value)
    }
    if (data.length) events.push({ event, data: data.join('\n') })
  }
  return { events, rest }
}

/** Turns one SSE message of `/logs/stream` into a typed event (null when unknown or malformed). */
export function toStreamEvent(m: SseMessage): StreamEvent | null {
  try {
    const data = JSON.parse(m.data) as Record<string, unknown>
    if (m.event === 'lagged') return { kind: 'lagged', skipped: Number(data.skipped ?? 0) }
    if (['flow', 'dns', 'http', 'alert', 'rule_hits'].includes(m.event) && data.type === m.event) {
      return { kind: 'event', event: data as unknown as GatewayEvent }
    }
  }
  catch {
    // malformed event: ignored
  }
  return null
}

interface Outcome<T> {
  data?: T
  error?: unknown
  response: Response
}

function problemOf(error: unknown, res: Response): ApiError {
  const p = (error && typeof error === 'object' ? error : {}) as Partial<Problem>
  const title = typeof p.title === 'string' ? p.title : (res.statusText || `HTTP ${res.status}`)
  const detail = typeof p.detail === 'string' ? p.detail : (typeof error === 'string' && error ? error : undefined)
  return new ApiError(res.status, title, detail)
}

export function createHttpApi(opts: HttpOptions): AfwApi {
  const doFetch = opts.fetch ?? globalThis.fetch.bind(globalThis)
  const baseUrl = `${opts.baseUrl.replace(/\/$/, '')}/api/v1`
  let session: Uuid | null = null

  const auth: Middleware = {
    onRequest({ request }) {
      // Every console call is tagged so that the audit log records the interface.
      request.headers.set('x-afw-interface', 'ui')
      if (!request.headers.has('accept')) request.headers.set('accept', 'application/json')
      const token = opts.getToken()
      if (token) request.headers.set('authorization', `Bearer ${token}`)
      return request
    },
    onResponse({ response }) {
      if (response.status === 401) opts.onUnauthorized?.()
      return response
    },
  }

  const client = createClient<paths>({ baseUrl, fetch: (req: Request) => doFetch(req) })
  client.use(auth)

  async function call<T>(p: Promise<Outcome<T>>): Promise<T> {
    let out: Outcome<T>
    try {
      out = await p
    }
    catch (e) {
      throw new ApiError(0, 'Network error', e instanceof Error ? e.message : String(e))
    }
    if (!out.response.ok) throw problemOf(out.error, out.response)
    return out.data as T
  }

  /** Optional session header of policy reads. */
  const read = () => (session ? { 'X-Afw-Session': session } : {})
  const write = (sid: Uuid) => ({ 'X-Afw-Session': sid })

  // The policy collections share one shape (list/get/create/update/delete in a session); the
  // generated client is typed per literal path, so this factory goes through an untyped view of it.
  type Loose = (path: string, init: Record<string, unknown>) => Promise<Outcome<unknown>>
  const loose = client as unknown as { GET: Loose, POST: Loose, PUT: Loose, DELETE: Loose }
  function collection<T extends { id: Uuid }>(base: string): PolicyCollection<T> {
    const one = `${base}/{id}`
    return {
      list: () => call(loose.GET(base, { params: { header: read() } })) as Promise<T[]>,
      get: id => call(loose.GET(one, { params: { path: { id }, header: read() } })) as Promise<T>,
      create: (sid, body) => call(loose.POST(base, { params: { header: write(sid) }, body })) as Promise<T>,
      update: (sid, body) => call(loose.PUT(one, { params: { path: { id: body.id }, header: write(sid) }, body })) as Promise<T>,
      remove: async (sid, id) => {
        await call(loose.DELETE(one, { params: { path: { id }, header: write(sid) } }))
      },
    }
  }

  return {
    setSession: (id) => {
      session = id
    },

    me: () => call(client.GET('/me')),
    oidcConfig: () => call(client.GET('/auth/oidc/config')),
    listTokens: () => call(client.GET('/tokens')),
    createToken: body => call(client.POST('/tokens', { body })),
    revokeToken: async (id) => {
      await call(client.DELETE('/tokens/{id}', { params: { path: { id } } }))
    },

    listFlows: query => call(client.GET('/logs/flows', { params: { query } })),
    flowStats: query => call(client.GET('/logs/flows/stats', { params: { query } })),
    getFlow: id => call(client.GET('/logs/flows/{id}', { params: { path: { id } } })),
    streamLogs: (onEvent, query = {}) => {
      const controller = new AbortController()
      void (async () => {
        let retry = opts.streamRetryMs ?? 1000
        while (!controller.signal.aborted) {
          try {
            const { response } = await client.GET('/logs/stream', {
              params: { query },
              parseAs: 'stream',
              signal: controller.signal,
              headers: { accept: 'text/event-stream' },
            })
            if (response.status === 401) return
            if (!response.ok || !response.body) throw new Error(`stream ${response.status}`)
            retry = opts.streamRetryMs ?? 1000
            const reader = response.body.pipeThrough(new TextDecoderStream()).getReader()
            let buffer = ''
            for (;;) {
              const { value, done } = await reader.read()
              if (done) break
              const parsed = parseSse(buffer + value)
              buffer = parsed.rest
              for (const m of parsed.events) {
                const ev = toStreamEvent(m)
                if (ev) onEvent(ev)
              }
            }
          }
          catch {
            if (controller.signal.aborted) return
          }
          // The server closes the stream periodically (token re-check): reconnect with backoff.
          await new Promise(r => setTimeout(r, retry))
          retry = Math.min(retry * 2, 30_000)
        }
      })()
      return () => controller.abort()
    },
    listCaptures: () => call(client.GET('/captures')),
    startCapture: body => call(client.POST('/captures', { body })),

    objects: collection('/objects'),
    services: collection('/services'),
    dataClasses: collection('/data-classes'),
    zones: collection('/zones'),
    agents: collection('/agents'),
    rules: collection('/rules'),
    inspectionRules: collection('/inspection-rules'),
    whereUsed: id => call(client.GET('/objects/{id}/where-used', { params: { path: { id }, header: read() } })),
    listRules: (query = {}) => call(client.GET('/rules', { params: { query, header: read() } })),
    moveRule: (sid, id, body) => call(client.POST('/rules/{id}/move', { params: { path: { id }, header: write(sid) }, body })),
    getRulebase: () => call(client.GET('/rulebase', { params: { header: read() } })),
    getSettings: () => call(client.GET('/settings', { params: { header: read() } })),
    updateSettings: (sid, body) => call(client.PUT('/settings', { params: { header: write(sid) }, body })),

    currentSession: async () => {
      try {
        return await call(client.GET('/sessions/current'))
      }
      catch (e) {
        if (e instanceof ApiError && e.status === 404) return null
        throw e
      }
    },
    openSession: name => call(client.POST('/sessions', { body: { name } })),
    getSession: id => call(client.GET('/sessions/{id}', { params: { path: { id } } })),
    discardSession: id => call(client.POST('/sessions/{id}/discard', { params: { path: { id } } })),
    allowFromLog: (id, body) => call(client.POST('/sessions/{id}/allow-from-log', { params: { path: { id } }, body })),
    publishSession: async (id, comment): Promise<PublishOutcome> => {
      const out = await client.POST('/sessions/{id}/publish', { params: { path: { id } }, body: { comment } })
        .catch((e: unknown) => {
          throw new ApiError(0, 'Network error', e instanceof Error ? e.message : String(e))
        })
      if (!out.response.ok) throw problemOf(out.error, out.response)
      return out.response.status === 202
        ? { status: 'approval', approval: out.data as Approval }
        : { status: 'published', revision: out.data as Revision }
    },
    // The contract declares no session header on /verify; the server reads it (else the caller's open session).
    verify: revision => call(client.GET('/verify', { params: { query: { revision } }, headers: revision === undefined ? read() : {} })),
    listRevisions: () => call(client.GET('/revisions')),
    getRevision: n => call(client.GET('/revisions/{n}', { params: { path: { n } } })),
    diffRevision: (n, against) => call(client.GET('/revisions/{n}/diff', { params: { path: { n }, query: { against } } })),
    revertToRevision: n => call(client.POST('/revisions/{n}/revert', { params: { path: { n } } })),
    policyStatus: () => call(client.GET('/policy/status')),
    listInstalls: (query = {}) => call(client.GET('/installs', { params: { query } })),
    install: (revision, gateways) => call(client.POST('/installs', { body: { revision, gateways } })),
    listApprovals: status => call(client.GET('/approvals', { params: { query: { status } } })),
    decideApproval: (id, approve, comment) => call(client.POST('/approvals/{id}/decision', { params: { path: { id } }, body: { approve, comment: comment ?? null } })),

    agentOverview: id => call(client.GET('/agents/{id}/overview', { params: { path: { id } } })),

    listAlerts: (query = {}) => call(client.GET('/alerts', { params: { query } })),
    acknowledgeAlert: id => call(client.POST('/alerts/{id}/ack', { params: { path: { id } } })),
    alertChannels: {
      list: () => call(client.GET('/alert-channels')),
      get: id => call(client.GET('/alert-channels/{id}', { params: { path: { id } } })),
      create: body => call(client.POST('/alert-channels', { body })),
      update: body => call(client.PUT('/alert-channels/{id}', { params: { path: { id: body.id } }, body })),
      remove: async (id) => {
        await call(client.DELETE('/alert-channels/{id}', { params: { path: { id } } }))
      },
    },
    internalMap: period => call(client.GET('/internal-map', { params: { query: { period } } })),

    listAudit: (query = {}) => call(client.GET('/audit', { params: { query } })),
    verifyAudit: () => call(client.GET('/audit/verify')),
    exportAudit: () => call(client.GET('/audit/export', { parseAs: 'blob', headers: { accept: 'application/x-ndjson' } })) as Promise<Blob>,

    listGateways: () => call(client.GET('/gateways')),
    deleteGateway: async (id) => {
      await call(client.DELETE('/gateways/{id}', { params: { path: { id } } }))
    },
    createRegistrationToken: name => call(client.POST('/gateways/registration-tokens', { body: { name } })),
    sendGatewayCommand: async (id, body) => {
      await call(client.POST('/gateways/{id}/commands', { params: { path: { id } }, body }))
    },
  }
}

export type { Page }
