import { ApiError, type AfwApi } from './client'
import type { FlowQuery, Page, StreamEvent } from './types'

export interface HttpOptions {
  /** Control-plane origin ("" = same origin). */
  baseUrl: string
  getToken: () => string | null
  fetch?: typeof globalThis.fetch
  /** Called on 401 so the console can send the user back to the login screen. */
  onUnauthorized?: () => void
}

type Query = Record<string, string | number | boolean | null | undefined>

function qs(query: Query): string {
  const parts = Object.entries(query)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v)).replace(/%2A/g, '*')}`)
  return parts.length ? `?${parts.join('&')}` : ''
}

/** Accepts both a bare array and a `Page<T>` from collection endpoints. */
function items<T>(v: T[] | Page<T>): T[] {
  return Array.isArray(v) ? v : v.items
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

export function createHttpApi(opts: HttpOptions): AfwApi {
  const doFetch = opts.fetch ?? globalThis.fetch.bind(globalThis)
  const root = `${opts.baseUrl.replace(/\/$/, '')}/api/v1`

  function headers(extra: Record<string, string> = {}): Headers {
    // Every console call is tagged so that the audit log records the interface (§8).
    const h = new Headers({ 'accept': 'application/json', 'x-afw-interface': 'ui', ...extra })
    const token = opts.getToken()
    if (token) h.set('authorization', `Bearer ${token}`)
    return h
  }

  async function request<T>(method: string, path: string, body?: unknown, query: Query = {}): Promise<T> {
    let res: Response
    try {
      res = await doFetch(`${root}${path}${qs(query)}`, {
        method,
        headers: headers(body === undefined ? {} : { 'content-type': 'application/json' }),
        body: body === undefined ? undefined : JSON.stringify(body),
      })
    }
    catch (e) {
      throw new ApiError(0, 'Network error', e instanceof Error ? e.message : String(e))
    }
    if (res.status === 401) opts.onUnauthorized?.()
    if (!res.ok) {
      let title = res.statusText || `HTTP ${res.status}`
      let detail: string | undefined
      try {
        const problem = await res.json() as { title?: string, detail?: string }
        title = problem.title ?? title
        detail = problem.detail
      }
      catch {
        // not a problem+json body
      }
      throw new ApiError(res.status, title, detail)
    }
    if (res.status === 204) return undefined as T
    const text = await res.text()
    return (text ? JSON.parse(text) : undefined) as T
  }

  const get = <T>(path: string, query: Query = {}) => request<T>('GET', path, undefined, query)
  const post = <T>(path: string, body: unknown = {}) => request<T>('POST', path, body)
  const flowQuery = (q: FlowQuery): Query => ({ ...q })
  const id = encodeURIComponent

  return {
    me: () => get('/me'),
    oidcLoginUrl: (redirect, state) => `${root}/auth/oidc/login${qs({ redirect, state })}`,
    policyStatus: () => get('/policy/status'),

    listFlows: q => get('/logs/flows', flowQuery(q)),
    flowStats: q => get('/logs/flows/stats', flowQuery(q)),
    getFlow: fid => get(`/logs/flows/${id(fid)}`),
    streamLogs: (onEvent) => {
      const controller = new AbortController()
      void (async () => {
        let retry = 1000
        while (!controller.signal.aborted) {
          try {
            const res = await doFetch(`${root}/logs/stream`, { headers: headers({ accept: 'text/event-stream' }), signal: controller.signal })
            if (res.status === 401) {
              opts.onUnauthorized?.()
              return
            }
            if (!res.ok || !res.body) throw new Error(`stream ${res.status}`)
            retry = 1000
            const reader = res.body.pipeThrough(new TextDecoderStream()).getReader()
            let buffer = ''
            for (;;) {
              const { value, done } = await reader.read()
              if (done) break
              const parsed = parseSse(buffer + value)
              buffer = parsed.rest
              for (const m of parsed.events) {
                try {
                  onEvent(JSON.parse(m.data) as StreamEvent)
                }
                catch {
                  // ignore malformed event
                }
              }
            }
          }
          catch {
            if (controller.signal.aborted) return
          }
          await new Promise(r => setTimeout(r, retry))
          retry = Math.min(retry * 2, 30_000)
        }
      })()
      return () => controller.abort()
    },
    startCapture: req => post('/captures', req),

    listObjects: async () => items(await get('/objects')),
    whereUsed: async oid => items(await get(`/objects/${id(oid)}/where-used`)),
    listZones: async () => items(await get('/zones')),

    getRulebase: q => get('/rules', { ...q }),
    getRule: rid => get(`/rules/${id(rid)}`),

    currentSession: async () => {
      try {
        return (await get('/sessions/current')) ?? null
      }
      catch (e) {
        if (e instanceof ApiError && e.status === 404) return null
        throw e
      }
    },
    openSession: name => post('/sessions', { name }),
    discardSession: sid => post(`/sessions/${id(sid)}/discard`),
    allowFromLog: (sid, req) => post(`/sessions/${id(sid)}/allow-from-log`, req),
    verify: revision => get('/verify', { revision }),
    publishSession: (sid, comment) => post(`/sessions/${id(sid)}/publish`, { comment }),
    listRevisions: async () => items(await get('/revisions')),
    getRevision: n => get(`/revisions/${n}`),
    install: (revision, gateways) => post('/installs', { revision, gateways }),

    listAgents: async () => items(await get('/agents')),
    agentOverview: aid => get(`/agents/${id(aid)}/overview`),

    listAlerts: async () => items(await get('/alerts')),
    acknowledgeAlert: aid => post(`/alerts/${id(aid)}/ack`),
    listAlertChannels: async () => items(await get('/alert-channels')),
    internalMap: period => get('/internal-map', { period }),

    listAudit: q => get('/audit', { ...q }),
    verifyAudit: () => get('/audit/verify'),
    exportAudit: async () => {
      let res: Response
      try {
        res = await doFetch(`${root}/audit/export`, { headers: headers({ accept: 'application/x-ndjson' }) })
      }
      catch (e) {
        throw new ApiError(0, 'Network error', e instanceof Error ? e.message : String(e))
      }
      if (res.status === 401) opts.onUnauthorized?.()
      if (!res.ok) throw new ApiError(res.status, res.statusText || `HTTP ${res.status}`)
      return await res.blob()
    },

    listGateways: async () => items(await get('/gateways')),
    listInstalls: async () => items(await get('/installs')),
    createRegistrationToken: () => post('/gateways/registration-tokens'),
    sendGatewayCommand: (gid, command) => post(`/gateways/${id(gid)}/commands`, { command }),
  }
}
