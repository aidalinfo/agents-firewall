/**
 * Stateful mock of the control plane (development, demo, console tests). Every value it returns
 * has the exact shape of the contract (types generated from docs/api/openapi.yaml), so the pages
 * are exercised against the real shapes. It simulates sessions with locks (423), publication
 * (201, or 202 when an approval is required), installation per gateway, allow-from-log, the
 * audit chain and the live log stream. The simulation of numbering, traces and verification is
 * simplified: the engine (`afw-engine`) and the API remain the reference.
 */
import { ApiError, type AfwApi, type PolicyCollection } from './client'
import {
  AGENT_IDS,
  KILLIAN,
  MARIE,
  SYSTEM,
  seedAlerts,
  seedChannels,
  seedDocument,
  seedGateways,
  seedLogs,
  seedTokens,
  uid,
} from './mock-data'
import type {
  Actor,
  Agent,
  Alert,
  AlertChannel,
  ApiToken,
  Approval,
  AuditEntry,
  Capture,
  Change,
  ChangeOp,
  DataClass,
  FlowDetail,
  FlowEvent,
  FlowListItem,
  FlowQuery,
  FlowStats,
  Gateway,
  HttpEvent,
  InspectionRule,
  Install,
  Me,
  NetObject,
  NetObjectSpec,
  Page,
  PolicyDocument,
  ResourceKind,
  ResourceRef,
  Revision,
  Rule,
  RuleSection,
  RuleView,
  Service,
  Session,
  SessionChange,
  StatsBucket,
  StreamEvent,
  TraceStep,
  Uuid,
  VerifyFinding,
  Zone,
} from './types'

export interface MockOptions {
  /** Simulated latency of every call (ms). */
  latencyMs?: number
  /** Interval of the simulated live traffic (ms); 0 disables it. */
  liveIntervalMs?: number
  /** Delay before a gateway acknowledges an installation (ms). */
  installAckMs?: number
}

/** Test and demo hooks (not part of the API). */
export interface MockControl {
  /** Another administrator opens a session that locks this resource (writes then get 423). */
  lockByOther(kind: ResourceKind, id: Uuid, owner?: Actor): void
  /** Publishing requires a human approval (EF-52): publish answers 202. */
  requireApproval(on: boolean): void
  /** Pushes a flow event on the live stream (or a `lagged` notice). */
  emit(event: StreamEvent): void
  /** Expires the caller's token: every call answers 401. */
  expireToken(): void
}

export type MockApi = AfwApi & { control: MockControl }

type Doc = PolicyDocument
type CollKey = 'objects' | 'services' | 'data_classes' | 'zones' | 'agents' | 'rules' | 'inspection_rules'
const KIND_OF: Record<CollKey, ResourceKind> = {
  objects: 'object', services: 'service', data_classes: 'data_class', zones: 'zone', agents: 'agent', rules: 'rule', inspection_rules: 'inspection_rule',
}

interface SessionState {
  session: Session
  draft: Doc
  changes: Map<string, SessionChange>
}

const clone = <T>(v: T): T => structuredClone(v)
const iso = (ms: number) => new Date(ms).toISOString()

/** Deterministic 64-hex digest (FNV-1a based): the mock's stand-in for SHA-256. */
function digest(input: string): string {
  let out = ''
  for (let round = 0; round < 8; round++) {
    let h = 0x811C9DC5 ^ round
    for (let i = 0; i < input.length; i++) {
      h ^= input.charCodeAt(i)
      h = Math.imul(h, 0x01000193) >>> 0
    }
    out += h.toString(16).padStart(8, '0')
  }
  return out
}

let seq = 0
const newId = () => {
  seq++
  const rand = Math.floor(Math.random() * 0xFFFFFF).toString(16).padStart(6, '0')
  return `a${rand}0-${(seq & 0xFFFF).toString(16).padStart(4, '0')}-4000-8000-${Date.now().toString(16).padStart(12, '0').slice(-12)}`
}

/** Display numbers as `PolicyDocument::rule_numbers` (baseline, then zones by name, by position). */
export function ruleNumbers(doc: Doc): Map<Uuid, number> {
  const zoneName = (id: Uuid) => doc.zones.find(z => z.id === id)?.name ?? ''
  const key = (r: Rule): [number, string, string, number, string] =>
    r.layer.type === 'baseline' ? [0, '', '', r.position, r.id] : [1, zoneName(r.layer.zone_id), r.layer.zone_id, r.position, r.id]
  const sorted = [...doc.rules].sort((a, b) => {
    const ka = key(a)
    const kb = key(b)
    for (let i = 0; i < ka.length; i++) {
      if (ka[i]! < kb[i]!) return -1
      if (ka[i]! > kb[i]!) return 1
    }
    return 0
  })
  return new Map(sorted.map((r, i) => [r.id, i + 1]))
}

function domainMatches(pattern: string, domain: string | null | undefined): boolean {
  if (!domain) return false
  const p = pattern.toLowerCase()
  return p.startsWith('*.') ? domain.endsWith(p.slice(1)) : domain === p
}

export function createMockApi(opts: MockOptions = {}): MockApi {
  const latency = opts.latencyMs ?? 0
  const now = Date.now()
  const me: Actor = KILLIAN

  // --- policy state ---
  const firstDoc = seedDocument()
  const revisions: { revision: Revision, document: Doc }[] = []
  const published = () => revisions.at(-1)!.document
  const sessions = new Map<Uuid, SessionState>()
  let current: Uuid | null = null
  let readSession: Uuid | null = null
  let approvalRequired = false
  let tokenExpired = false
  const approvals: Approval[] = []
  const locks = new Map<string, { session: Uuid, owner: Actor }>()
  /** Keys of the session changes made by the call in progress (allow-from-log returns them). */
  let touched: Set<string> | null = null

  // --- audit ---
  const audit: AuditEntry[] = []
  function record(action: string, target: string, diff: unknown = null, sessionId: Uuid | null = null, actor: Actor = me, iface: AuditEntry['interface'] = 'ui', at = Date.now()) {
    const prev = audit.at(-1)?.hash ?? '0'.repeat(64)
    const entry = { seq: audit.length + 1, at: iso(at), actor, interface: iface, session_id: sessionId, action, target, diff, prev_hash: prev }
    audit.push({ ...entry, hash: digest(prev + JSON.stringify(entry)) })
  }

  // Revisions 40–42 (history), 42 installed.
  for (const [n, comment, by, days] of [[40, 'Microsoft 365 pour bots-internes', me, 9], [41, 'Portail ACME', MARIE, 4], [42, 'Dépôts S3 (URL présignées)', me, 1]] as const) {
    const doc = clone(firstDoc)
    if (n < 42) doc.rules = doc.rules.filter(r => r.name !== 'Dépôts S3')
    if (n < 41) doc.rules = doc.rules.filter(r => r.name !== 'Portail ACME')
    const at = now - days * 86_400_000
    revisions.push({
      revision: { number: n, comment, interface: 'ui', published_at: iso(at), published_by: by, session_id: uid('a0000000', n), sha256: digest(JSON.stringify(doc)) },
      document: doc,
    })
    record('session.publish', `revision:${n}`, { comment }, uid('a0000000', n), by, 'ui', at)
  }

  const gateways: Gateway[] = seedGateways(now)
  const installs: Install[] = gateways.map((g, i) => ({
    id: uid('b0000000', i + 1), gateway_id: g.id, revision: 42, requested_at: iso(now - 86_400_000 + 60_000), requested_by: me,
    state: g.active_revision === 42 ? 'installed' : 'pending', acked_at: g.active_revision === 42 ? iso(now - 86_400_000 + 64_000) : null, error: null,
  }))

  // --- logs ---
  const numbers0 = ruleNumbers(firstDoc)
  const logs = seedLogs(now, id => (id ? numbers0.get(id) ?? null : null), id => firstDoc.rules.find(r => r.id === id)?.name ?? '')
  const flows: FlowEvent[] = logs.flows
  const http: HttpEvent[] = logs.http
  const alerts: Alert[] = seedAlerts(now)
  const channels: AlertChannel[] = seedChannels()
  const tokens: ApiToken[] = seedTokens(now)
  const captures: Capture[] = []
  const listeners = new Set<(e: StreamEvent) => void>()

  const delay = async <T>(fn: () => T): Promise<T> => {
    if (latency) await new Promise(r => setTimeout(r, latency))
    if (tokenExpired) throw new ApiError(401, 'Unauthorized')
    return fn()
  }
  const notFound = () => new ApiError(404, 'Not Found')

  // --- helpers on documents ---
  const coll = <K extends CollKey>(doc: Doc, k: K) => doc[k] as unknown as { id: Uuid, name: string }[]
  const viewDoc = (): Doc => (readSession && sessions.get(readSession)?.session.state === 'open' ? sessions.get(readSession)!.draft : published())
  const zoneName = (doc: Doc, id: Uuid | null | undefined) => (id ? doc.zones.find(z => z.id === id)?.name ?? null : null)
  const agentName = (doc: Doc, id: Uuid | null | undefined) => (id ? doc.agents.find(a => a.id === id)?.name ?? null : null)

  function openState(id: Uuid): SessionState {
    const s = sessions.get(id)
    if (!s) throw notFound()
    if (s.session.state !== 'open') throw new ApiError(409, 'Conflict', `session is ${s.session.state}`)
    return s
  }

  function lockFor(kind: ResourceKind, id: Uuid, s: SessionState) {
    const key = `${kind}:${id}`
    const l = locks.get(key)
    if (l && l.session !== s.session.id) throw new ApiError(423, 'Locked', `locked by ${l.owner.name}`)
    locks.set(key, { session: s.session.id, owner: s.session.owner })
  }

  function mutate<T extends { id: Uuid, name: string }>(s: SessionState, k: CollKey, id: Uuid, after: T | null) {
    const kind = KIND_OF[k]
    lockFor(kind, id, s)
    const list = coll(s.draft, k)
    const idx = list.findIndex(x => x.id === id)
    const before = idx === -1 ? null : list[idx]!
    if (after) {
      if (idx === -1) list.push(clone(after))
      else list[idx] = clone(after)
    }
    else if (idx !== -1) list.splice(idx, 1)
    const inPublished = coll(published(), k).some(x => x.id === id)
    const op: ChangeOp = !after ? 'delete' : inPublished ? 'update' : 'create'
    const key = `${kind}:${id}`
    touched?.add(key)
    if (!after && !inPublished) s.changes.delete(key)
    else s.changes.set(key, { op, resource: { kind, id, name: (after ?? before)?.name ?? '' }, after: after ? clone(after) : null })
    s.session.changes = s.changes.size
    s.session.locks = [...locks.entries()].filter(([, l]) => l.session === s.session.id).map(([key2]) => {
      const [kind2, id2] = key2.split(':') as [ResourceKind, Uuid]
      const res = coll(s.draft, (Object.keys(KIND_OF) as CollKey[]).find(c => KIND_OF[c] === kind2)!).find(x => x.id === id2)
      return { kind: kind2, id: id2, name: res?.name ?? '' }
    })
    record(`${kind}.${op}`, `${kind}:${id}`, after, s.session.id)
  }

  function validate(doc: Doc, k: CollKey, v: { id: Uuid, name: string }) {
    if (!v.name?.trim()) throw new ApiError(400, 'Bad Request', 'name must not be empty')
    if (coll(doc, k).some(x => x.id !== v.id && x.name === v.name && k !== 'rules')) throw new ApiError(409, 'Conflict', `a ${KIND_OF[k]} named ${v.name} already exists`)
    if (k === 'rules') {
      const r = v as Rule
      const layer = r.layer
      if (layer.type === 'zone' && r.sources.some(z => z !== layer.zone_id)) throw new ApiError(400, 'Bad Request', 'a zone rule may only have its own zone as source')
      if (layer.type === 'zone' && !doc.zones.some(z => z.id === layer.zone_id)) throw new ApiError(400, 'Bad Request', 'unknown zone')
    }
    if (k === 'agents' && !doc.zones.some(z => z.id === (v as Agent).zone_id)) throw new ApiError(400, 'Bad Request', 'unknown zone')
  }

  /** Renumbers the positions of a layer (1..n) after an insertion or a move. */
  function compact(s: SessionState, layerKey: string) {
    const layerRules = s.draft.rules.filter(r => (r.layer.type === 'baseline' ? 'baseline' : r.layer.zone_id) === layerKey).sort((a, b) => a.position - b.position)
    layerRules.forEach((r, i) => {
      if (r.position !== i + 1) {
        const moved = { ...r, position: i + 1 }
        mutate(s, 'rules', r.id, moved)
      }
    })
  }

  function collection<T extends { id: Uuid, name: string }>(k: CollKey): PolicyCollection<T> {
    return {
      list: () => delay(() => clone(coll(viewDoc(), k)) as unknown as T[]),
      get: id => delay(() => {
        const v = coll(viewDoc(), k).find(x => x.id === id)
        if (!v) throw notFound()
        return clone(v) as unknown as T
      }),
      create: (sid, value) => delay(() => {
        const s = openState(sid)
        const v = { ...clone(value), id: value.id || newId() }
        validate(s.draft, k, v)
        if (k === 'rules') {
          const r = v as unknown as Rule
          const layerKey = r.layer.type === 'baseline' ? 'baseline' : r.layer.zone_id
          for (const other of s.draft.rules.filter(x => (x.layer.type === 'baseline' ? 'baseline' : x.layer.zone_id) === layerKey && x.position >= r.position)) {
            mutate(s, 'rules', other.id, { ...other, position: other.position + 1 })
          }
          mutate(s, k, v.id, v)
          compact(s, layerKey)
        }
        else mutate(s, k, v.id, v)
        return clone(coll(s.draft, k).find(x => x.id === v.id)!) as unknown as T
      }),
      update: (sid, value) => delay(() => {
        const s = openState(sid)
        if (!coll(s.draft, k).some(x => x.id === value.id)) throw notFound()
        validate(s.draft, k, value)
        mutate(s, k, value.id, value)
        return clone(value)
      }),
      remove: (sid, id) => delay(() => {
        const s = openState(sid)
        if (!coll(s.draft, k).some(x => x.id === id)) throw notFound()
        if (k === 'objects' && (s.draft.rules.some(r => r.destinations.includes(id)) || s.draft.objects.some(o => o.spec.type === 'group' && o.spec.members.includes(id)))) {
          throw new ApiError(409, 'Conflict', 'object is still referenced')
        }
        if (k === 'zones' && s.draft.agents.some(a => a.zone_id === id)) throw new ApiError(409, 'Conflict', 'zone still holds agents')
        mutate(s, k, id, null)
      }),
    }
  }

  // --- rule views ---
  function hitsOf(ruleId: Uuid): { hits: number, last: string | null } {
    const matching = flows.filter(f => f.decision.rule_id === ruleId)
    return { hits: matching.length * 37, last: matching[0]?.started_at ?? null }
  }

  function ruleViews(doc: Doc): RuleView[] {
    const numbers = ruleNumbers(doc)
    const sess = readSession ? sessions.get(readSession) : undefined
    return [...doc.rules].sort((a, b) => numbers.get(a.id)! - numbers.get(b.id)!).map((r) => {
      const h = hitsOf(r.id)
      const lock = locks.get(`rule:${r.id}`)
      return {
        ...clone(r),
        number: numbers.get(r.id)!,
        hits: h.hits,
        last_hit_at: h.last,
        expired: !!r.expires_at && new Date(r.expires_at).getTime() < Date.now(),
        locked_by: lock && lock.session !== readSession ? lock.owner : null,
        pending_change: sess?.session.state === 'open' ? sess.changes.get(`rule:${r.id}`)?.op ?? null : null,
      }
    })
  }

  function sectionsOf(rules: RuleView[]): RuleSection[] {
    const out: RuleSection[] = []
    for (const r of rules) {
      const last = out.at(-1)
      if (last && (last.name ?? null) === (r.section ?? null)) last.rules.push(r)
      else out.push({ name: r.section ?? null, rules: [r] })
    }
    return out
  }

  // --- logs helpers ---
  function listItem(f: FlowEvent): FlowListItem {
    const doc = published()
    const tc = logs.toolCalls.find(t => t.flow_id === f.id)
    const d = f.decision
    const label = d.rule_number != null ? `${d.rule_number} · ${d.rule_name}` : d.layer === 'baseline' ? `socle · ${d.rule_name}` : f.verdict === 'deny' ? 'default-deny' : (d.rule_name || 'implicit')
    return {
      ...clone(f),
      agent_name: agentName(doc, f.agent_id),
      zone_name: zoneName(doc, f.zone_id),
      rule_label: label,
      tool: tc?.tool ?? null,
      conversation_id: tc?.conversation_id ?? null,
      correlation_confidence: tc ? (f.id.startsWith('8c21') ? 'certain' : 'probable') : null,
    }
  }

  function matchFlow(f: FlowEvent, q: FlowQuery): boolean {
    if (q.agent && f.agent_id !== q.agent) return false
    if (q.zone && f.zone_id !== q.zone) return false
    if (q.verdict && f.verdict !== q.verdict) return false
    if (q.rule && f.decision.rule_id !== q.rule) return false
    if (q.from && f.started_at < q.from) return false
    if (q.to && f.started_at > q.to) return false
    if (q.destination) {
      const d = q.destination.toLowerCase()
      const host = (f.domain ?? f.dst.replace(/:\d+$/, '')).toLowerCase()
      if (!(d.startsWith('*.') ? host.endsWith(d.slice(1)) : host === d || host.endsWith(`.${d}`))) return false
    }
    if (q.q) {
      const hay = `${f.domain ?? ''} ${f.sni ?? ''} ${f.dst}`.toLowerCase()
      if (!hay.includes(q.q.toLowerCase())) return false
    }
    return true
  }

  function trace(f: FlowEvent): TraceStep[] {
    const doc = published()
    const numbers = ruleNumbers(doc)
    const layerRules = doc.rules
      .filter(r => r.enabled && (r.layer.type === 'baseline' || r.layer.zone_id === f.zone_id))
      .sort((a, b) => numbers.get(a.id)! - numbers.get(b.id)!)
    const steps: TraceStep[] = []
    for (const r of layerRules) {
      const matched = r.id === f.decision.rule_id
      const n = numbers.get(r.id)!
      steps.push({ rule_id: r.id, rule_number: n, rule_label: `${n} · ${r.name}`, layer: r.layer.type, outcome: matched ? 'matched' : 'not_matched', reason: matched ? 'matched' : 'destination does not match' })
      if (matched) return steps
    }
    steps.push({ rule_id: null, rule_number: null, rule_label: f.observed ? 'observe' : 'default-deny', layer: 'implicit', outcome: 'matched', reason: f.observed ? 'observe mode: would be denied' : 'no rule matched: default deny' })
    return steps
  }

  function proposal(f: FlowEvent): FlowDetail['allow_proposal'] {
    if ((f.verdict !== 'deny' && !f.observed) || !f.zone_id) return null
    const doc = published()
    const domain = (f.domain ?? f.sni)?.toLowerCase() ?? null
    const [ip, port] = [f.dst.replace(/:\d+$/, ''), Number(f.dst.split(':').at(-1))]
    const destinations: NonNullable<FlowDetail['allow_proposal']>['destinations'] = []
    if (domain) {
      destinations.push({ kind: 'exact', label: domain, spec: { type: 'domain', pattern: domain }, object_id: null })
      const parent = domain.split('.').slice(1).join('.')
      if (parent.includes('.')) destinations.push({ kind: 'wildcard', label: `*.${parent}`, spec: { type: 'domain', pattern: `*.${parent}` }, object_id: null })
      for (const o of doc.objects) {
        if (o.spec.type === 'domain' && domainMatches(o.spec.pattern, domain)) destinations.push({ kind: 'existing', label: o.name, object_id: o.id, spec: null })
      }
    }
    else destinations.push({ kind: 'exact', label: ip, spec: { type: 'host', ip }, object_id: null })
    const svc = doc.services.find(s => s.protocol === f.protocol && s.ports.length === 1 && s.ports[0]!.start === port && s.ports[0]!.end === port)
    const numbers = ruleNumbers(doc)
    const zoneRules = doc.rules.filter(r => r.layer.type === 'zone' && r.layer.zone_id === f.zone_id).map(r => numbers.get(r.id)!)
    const before = Math.min(...zoneRules, Number.POSITIVE_INFINITY)
    return {
      zone_id: f.zone_id,
      zone_name: zoneName(doc, f.zone_id),
      destinations,
      service: { label: svc?.name ?? `tcp-${port}`, service_id: svc?.id ?? null, protocol: f.protocol, port },
      rule_number: Number.isFinite(before) ? before : (Math.max(0, ...numbers.values()) + 1),
    }
  }

  function bucketMs(b: StatsBucket) {
    return b === '1m' ? 60_000 : b === '5m' ? 300_000 : 3_600_000
  }

  function emit(e: StreamEvent) {
    if (e.kind === 'event' && e.event.type === 'flow') {
      const { type: _t, ...flow } = e.event
      flows.unshift(flow as FlowEvent)
    }
    for (const l of listeners) l(e)
  }

  // Simulated live traffic: one allowed flow of daniel-bot every few seconds.
  let liveTimer: ReturnType<typeof setInterval> | null = null
  function startLive() {
    if (liveTimer || !opts.liveIntervalMs) return
    liveTimer = setInterval(() => {
      const template = flows.find(f => f.verdict === 'allow' && f.agent_id === AGENT_IDS.daniel)
      if (!template) return
      emit({ kind: 'event', event: { ...clone(template), type: 'flow', id: newId(), started_at: iso(Date.now()), ended_at: iso(Date.now() + 120) } })
    }, opts.liveIntervalMs)
  }

  function sessionDto(s: SessionState): Session {
    return clone(s.session)
  }

  function pendingInstall(): number | null {
    const mine = revisions.filter(r => r.revision.published_by.id === me.id).at(-1)
    if (!mine) return null
    const installed = installs.some(i => i.revision >= mine.revision.number)
    return installed ? null : mine.revision.number
  }

  function publish(s: SessionState, comment: string): Revision {
    const number = revisions.at(-1)!.revision.number + 1
    const document = clone(s.draft)
    const revision: Revision = { number, comment, interface: 'ui', published_at: iso(Date.now()), published_by: s.session.owner, session_id: s.session.id, sha256: digest(JSON.stringify(document)) }
    revisions.push({ revision, document })
    s.session.state = 'published'
    s.session.closed_at = iso(Date.now())
    s.session.pending_install = number
    s.session.next_revision = null
    for (const [key, l] of locks) if (l.session === s.session.id) locks.delete(key)
    record('session.publish', `revision:${number}`, { comment }, s.session.id)
    return revision
  }

  function diff(from: Doc, to: Doc): Change[] {
    const out: Change[] = []
    for (const k of Object.keys(KIND_OF) as CollKey[]) {
      const a = coll(from, k)
      const b = coll(to, k)
      for (const x of b) {
        const before = a.find(y => y.id === x.id)
        const resource: ResourceRef = { kind: KIND_OF[k], id: x.id, name: x.name }
        if (!before) out.push({ kind: 'added', resource, before: null, after: clone(x) })
        else if (JSON.stringify(before) !== JSON.stringify(x)) out.push({ kind: 'modified', resource, before: clone(before), after: clone(x) })
      }
      for (const y of a) if (!b.some(x => x.id === y.id)) out.push({ kind: 'removed', resource: { kind: KIND_OF[k], id: y.id, name: y.name }, before: clone(y), after: null })
    }
    return out
  }

  const page = <T>(items: T[], limit = 100): Page<T> => ({ items: items.slice(0, limit), next_cursor: items.length > limit ? String(limit) : null })

  const api: MockApi = {
    setSession: (id) => {
      readSession = id
    },

    me: () => delay((): Me => ({ actor: me, role: 'admin', email: 'killian.stein@example.org', agent_id: null, writable_zones: null })),
    oidcConfig: () => delay(() => ({ enabled: false, issuer: '', client_id: '', scopes: 'openid profile email', authorization_endpoint: null, token_endpoint: null, end_session_endpoint: null })),
    listTokens: () => delay(() => clone(tokens)),
    createToken: req => delay(() => {
      if (!req.name.trim()) throw new ApiError(400, 'Bad Request', 'name must not be empty')
      const token: ApiToken = { id: newId(), name: req.name, role: req.role, agent_id: req.agent_id ?? null, expires_at: req.expires_at ?? null, created_at: iso(Date.now()), created_by: me, last_used_at: null }
      tokens.push(token)
      record('token.create', `token:${token.id}`, { name: req.name, role: req.role })
      return { token: clone(token), secret: `afw_${digest(token.id).slice(0, 40)}` }
    }),
    revokeToken: id => delay(() => {
      const i = tokens.findIndex(t => t.id === id)
      if (i === -1) throw notFound()
      tokens.splice(i, 1)
      record('token.revoke', `token:${id}`)
    }),

    listFlows: q => delay(() => page(flows.filter(f => matchFlow(f, q)).map(listItem), q.limit ?? 100)),
    flowStats: q => delay((): FlowStats => {
      const bucket: StatsBucket = q.bucket ?? '1m'
      const size = bucketMs(bucket)
      const to = q.to ? new Date(q.to).getTime() : Date.now()
      const span = bucket === '1m' ? 3_600_000 : bucket === '5m' ? 12 * 3_600_000 : 86_400_000
      const from = q.from ? new Date(q.from).getTime() : to - span
      const start = Math.floor(from / size) * size
      const points = [] as FlowStats['points']
      for (let t = start; t < to; t += size) points.push({ at: iso(t), allow: 0, deny: 0, observed: 0 })
      let allow = 0
      let deny = 0
      let observed = 0
      for (const f of flows) {
        const t = new Date(f.started_at).getTime()
        if (t < from || t > to || !matchFlow(f, { ...q, from: undefined, to: undefined })) continue
        const p = points[Math.floor((t - start) / size)]
        if (f.observed) {
          observed++
          if (p) p.observed++
        }
        else if (f.verdict === 'allow') {
          allow++
          if (p) p.allow++
        }
        else {
          deny++
          if (p) p.deny++
        }
      }
      return { bucket, from: iso(from), to: iso(to), points, total: allow + deny + observed, allow, deny, observed }
    }),
    getFlow: id => delay((): FlowDetail => {
      const f = flows.find(x => x.id === id)
      if (!f) throw notFound()
      const tc = logs.toolCalls.find(t => t.flow_id === f.id)
      const agent = agentName(published(), f.agent_id)
      const exchanges = http.filter(h => h.flow_id === f.id)
      const isHttp = f.app === 'http' || (f.app === 'https' && f.tls_inspected)
      record('flow.read_contents', `flow:${f.id}`)
      return {
        flow: clone(f),
        http: clone(exchanges),
        tool_call: tc ? (({ flow_id: _f, ...t }) => t)(clone(tc)) : null,
        correlation: tc ? { tool_call_id: tc.id, conversation_id: tc.conversation_id, confidence: listItem(f).correlation_confidence ?? 'uncertain' } : null,
        trace: trace(f),
        agent_message: f.verdict === 'deny' && isHttp ? `blocked by agents-firewall: ${f.domain ?? f.dst.replace(/:\d+$/, '')} not allowed for ${agent ?? f.src} (rule ${f.decision.rule_number ?? 'default-deny'})` : null,
        allow_proposal: proposal(f),
      }
    }),
    streamLogs: (onEvent) => {
      listeners.add(onEvent)
      startLive()
      return () => {
        listeners.delete(onEvent)
        if (!listeners.size && liveTimer) {
          clearInterval(liveTimer)
          liveTimer = null
        }
      }
    },
    listCaptures: () => delay(() => page(clone(captures))),
    startCapture: req => delay(() => {
      const a = published().agents.find(x => x.id === req.agent_id)
      if (!a?.gateway_id) throw new ApiError(409, 'Conflict', 'agent has no gateway')
      const c: Capture = { id: newId(), agent_id: req.agent_id, gateway_id: a.gateway_id, duration_secs: req.duration_secs, requested_at: iso(Date.now()), requested_by: me, state: 'pending', size: null, error: null }
      captures.unshift(c)
      record('capture.start', `capture:${c.id}`, req)
      return clone(c)
    }),

    objects: collection<NetObject>('objects'),
    services: collection<Service>('services'),
    dataClasses: collection<DataClass>('data_classes'),
    zones: collection<Zone>('zones'),
    agents: collection<Agent>('agents'),
    rules: collection<Rule>('rules'),
    inspectionRules: collection<InspectionRule>('inspection_rules'),
    whereUsed: id => delay(() => {
      const doc = viewDoc()
      const references: ResourceRef[] = []
      for (const r of doc.rules) if ([...r.destinations, ...r.services, ...r.data_classes, ...r.sources].includes(id)) references.push({ kind: 'rule', id: r.id, name: r.name })
      for (const o of doc.objects) if (o.spec.type === 'group' && o.spec.members.includes(id)) references.push({ kind: 'object', id: o.id, name: o.name })
      for (const i of doc.inspection_rules) if (i.destinations.includes(id) || i.zones.includes(id)) references.push({ kind: 'inspection_rule', id: i.id, name: i.name })
      return { references }
    }),
    listRules: (q = {}) => delay(() => ruleViews(viewDoc()).filter(r =>
      (!q.zone_id || (r.layer.type === 'zone' && r.layer.zone_id === q.zone_id))
      && (!q.q || `${r.name} ${r.comment} ${r.section ?? ''}`.toLowerCase().includes(q.q.toLowerCase())))),
    moveRule: (sid, id, req) => delay(() => {
      const s = openState(sid)
      const r = s.draft.rules.find(x => x.id === id)
      if (!r) throw notFound()
      const layer = req.layer ?? r.layer
      const oldKey = r.layer.type === 'baseline' ? 'baseline' : r.layer.zone_id
      const newKey = layer.type === 'baseline' ? 'baseline' : layer.zone_id
      const peers = s.draft.rules.filter(x => x.id !== id && (x.layer.type === 'baseline' ? 'baseline' : x.layer.zone_id) === newKey).sort((a, b) => a.position - b.position)
      const target = Math.max(1, Math.min(req.position, peers.length + 1))
      peers.splice(target - 1, 0, { ...r, layer, section: req.section !== undefined ? req.section : r.section })
      peers.forEach((p, i) => {
        const next = { ...p, position: i + 1 }
        if (p.id === id || p.position !== i + 1) mutate(s, 'rules', p.id, next)
      })
      if (oldKey !== newKey) compact(s, oldKey)
      return clone(s.draft.rules.find(x => x.id === id)!)
    }),
    getRulebase: () => delay(() => {
      const doc = viewDoc()
      const views = ruleViews(doc)
      const zones = [...doc.zones].sort((a, b) => a.name.localeCompare(b.name))
      let last = views.filter(v => v.layer.type === 'baseline').at(-1)?.number ?? 0
      return {
        baseline: { sections: sectionsOf(views.filter(v => v.layer.type === 'baseline')) },
        zones: zones.map((zone) => {
          const zr = views.filter(v => v.layer.type === 'zone' && v.layer.zone_id === zone.id)
          last = zr.at(-1)?.number ?? last
          return { zone: clone(zone), mode: zone.mode, sections: sectionsOf(zr), cleanup_number: last + 1 }
        }),
      }
    }),
    getSettings: () => delay(() => clone(viewDoc().settings)),
    updateSettings: (sid, settings) => delay(() => {
      const s = openState(sid)
      s.draft.settings = clone(settings)
      record('settings.update', 'settings', settings, sid)
      return clone(settings)
    }),

    currentSession: () => delay(() => {
      const s = current ? sessions.get(current) : undefined
      if (s && s.session.state === 'open') return { ...sessionDto(s), pending_install: s.session.pending_install ?? pendingInstall() }
      const pending = pendingInstall()
      if (!pending) return null
      const pub = [...sessions.values()].find(x => x.session.pending_install === pending)
      return pub ? sessionDto(pub) : null
    }),
    openSession: name => delay(() => {
      const existing = current ? sessions.get(current) : undefined
      if (existing?.session.state === 'open') throw new ApiError(409, 'Conflict', 'you already have an open session')
      const base = revisions.at(-1)!.revision.number
      const session: Session = { id: newId(), name, owner: me, interface: 'ui', state: 'open', opened_at: iso(Date.now()), closed_at: null, locks: [], changes: 0, approval_id: null, base_revision: base, next_revision: base + 1, pending_install: null }
      sessions.set(session.id, { session, draft: clone(published()), changes: new Map() })
      current = session.id
      record('session.open', `session:${session.id}`, { name }, session.id)
      return clone(session)
    }),
    getSession: id => delay(() => {
      const s = sessions.get(id)
      if (!s) throw notFound()
      return sessionDto(s)
    }),
    discardSession: id => delay(() => {
      const s = openState(id)
      s.session.state = 'discarded'
      s.session.closed_at = iso(Date.now())
      for (const [key, l] of locks) if (l.session === id) locks.delete(key)
      s.session.locks = []
      record('session.discard', `session:${id}`, null, id)
      return sessionDto(s)
    }),
    allowFromLog: (sid, req) => delay(() => {
      const s = openState(sid)
      const f = flows.find(x => x.id === req.flow_id)
      if (!f) throw notFound()
      if (!f.zone_id) throw new ApiError(400, 'Bad Request', 'flow has no zone')
      if (f.verdict !== 'deny' && !f.observed) throw new ApiError(400, 'Bad Request', 'flow was not denied')
      touched = new Set()
      const domain = (f.domain ?? f.sni)?.toLowerCase() ?? null
      let spec: NetObjectSpec = domain ? { type: 'domain', pattern: domain } : { type: 'host', ip: f.dst.replace(/:\d+$/, '') }
      if (req.destination === 'wildcard') {
        const parent = domain?.split('.').slice(1).join('.') ?? ''
        if (!parent.includes('.')) throw new ApiError(400, 'Bad Request', `wildcard of ${domain} would cover a whole public suffix`)
        spec = { type: 'domain', pattern: `*.${parent}` }
      }
      let created: NetObject | null = null
      let dest = s.draft.objects.find(o => JSON.stringify(o.spec) === JSON.stringify(spec))
      if (!dest) {
        created = { id: newId(), name: spec.type === 'domain' ? spec.pattern : f.dst.replace(/:\d+$/, ''), comment: '', category: null, spec }
        mutate(s, 'objects', created.id, created)
        dest = created
      }
      let destId = dest.id
      if (req.destination === 'group') {
        const zone = zoneName(s.draft, f.zone_id) ?? ''
        const name = `Autorisés depuis le journal — ${zone}`
        const group = s.draft.objects.find(o => o.name === name && o.spec.type === 'group') ?? { id: newId(), name, comment: '', category: null, spec: { type: 'group', members: [] } as NetObjectSpec }
        const members = group.spec.type === 'group' ? group.spec.members : []
        mutate(s, 'objects', group.id, { ...group, spec: { type: 'group', members: members.includes(destId) ? members : [...members, destId] } })
        destId = group.id
      }
      const port = Number(f.dst.split(':').at(-1))
      let svc = s.draft.services.find(x => x.protocol === f.protocol && x.ports.length === 1 && x.ports[0]!.start === port && x.ports[0]!.end === port)
      if (!svc) {
        svc = { id: newId(), name: `${f.protocol}-${port}`, comment: 'Créé depuis le journal', protocol: f.protocol, ports: [{ start: port, end: port }], app: null }
        mutate(s, 'services', svc.id, svc)
      }
      const rule: Rule = {
        id: newId(), name: `Autoriser ${domain ?? f.dst}`, layer: { type: 'zone', zone_id: f.zone_id }, section: null, position: 1,
        sources: [f.zone_id], destinations: [destId], services: [svc.id], data_classes: [], action: 'accept', track: req.track ?? 'detailed',
        expires_at: req.expires_in_days ? iso(Date.now() + req.expires_in_days * 86_400_000) : null, comment: `Autorisé depuis le journal, flux ${f.id}`, enabled: true,
      }
      for (const other of s.draft.rules.filter(x => x.layer.type === 'zone' && x.layer.zone_id === f.zone_id)) mutate(s, 'rules', other.id, { ...other, position: other.position + 1 })
      mutate(s, 'rules', rule.id, rule)
      const prev = readSession
      readSession = sid
      const view = ruleViews(s.draft).find(v => v.id === rule.id)!
      readSession = prev
      const keys = touched
      touched = null
      return { rule: view, created_object: created, changes: [...keys].map(k => clone(s.changes.get(k)!)).filter(Boolean) }
    }),
    publishSession: (id, comment) => delay(() => {
      const s = openState(id)
      if (!s.changes.size) throw new ApiError(409, 'Conflict', 'nothing to publish')
      if (s.session.approval_id) {
        const a = approvals.find(x => x.id === s.session.approval_id)!
        if (a.status === 'pending') throw new ApiError(409, 'Conflict', 'approval pending')
        if (a.status === 'rejected') throw new ApiError(409, 'Conflict', 'approval rejected')
      }
      else if (approvalRequired) {
        const approval: Approval = { id: newId(), session_id: id, status: 'pending', reason: 'widening change by the MCP agent', summary: `${s.changes.size} modification(s) élargissant l’accès`, requested_at: iso(Date.now()), requested_by: s.session.owner, decided_at: null, decided_by: null, comment: null }
        approvals.push(approval)
        s.session.approval_id = approval.id
        record('approval.request', `approval:${approval.id}`, null, id)
        return { status: 'approval' as const, approval: clone(approval) }
      }
      return { status: 'published' as const, revision: publish(s, comment) }
    }),
    verify: revision => delay(() => {
      const doc = revision === undefined ? viewDoc() : revisions.find(r => r.revision.number === revision)?.document
      if (!doc) throw notFound()
      const findings: VerifyFinding[] = []
      for (const r of doc.rules) if (r.expires_at && new Date(r.expires_at).getTime() < Date.now()) findings.push({ type: 'expired', rule: r.id })
      const used = new Set<Uuid>([...doc.rules.flatMap(r => r.destinations), ...doc.objects.flatMap(o => (o.spec.type === 'group' ? o.spec.members : [])), ...doc.inspection_rules.flatMap(i => i.destinations)])
      for (const o of doc.objects) if (!used.has(o.id)) findings.push({ type: 'unused_object', id: o.id })
      return { revision: revision ?? null, findings }
    }),
    listRevisions: () => delay(() => page([...revisions].reverse().map(r => clone(r.revision)))),
    getRevision: n => delay(() => {
      const r = revisions.find(x => x.revision.number === n)
      if (!r) throw notFound()
      return clone(r)
    }),
    diffRevision: (n, against) => delay(() => {
      const to = revisions.find(x => x.revision.number === n)
      if (!to) throw notFound()
      const fromN = against ?? n - 1
      const from = revisions.find(x => x.revision.number === fromN)?.document ?? { ...clone(to.document), objects: [], services: [], data_classes: [], zones: [], agents: [], rules: [], inspection_rules: [] }
      return { from: fromN, to: n, changes: diff(from, to.document) }
    }),
    revertToRevision: n => delay(() => {
      const r = revisions.find(x => x.revision.number === n)
      if (!r) throw notFound()
      const existing = current ? sessions.get(current) : undefined
      if (existing?.session.state === 'open') throw new ApiError(409, 'Conflict', 'you already have an open session')
      const base = revisions.at(-1)!.revision.number
      const session: Session = { id: newId(), name: 'revert', owner: me, interface: 'ui', state: 'open', opened_at: iso(Date.now()), closed_at: null, locks: [], changes: 0, approval_id: null, base_revision: base, next_revision: base + 1, pending_install: null }
      const st: SessionState = { session, draft: clone(published()), changes: new Map() }
      sessions.set(session.id, st)
      current = session.id
      for (const c of diff(published(), r.document)) {
        const k = (Object.keys(KIND_OF) as CollKey[]).find(x => KIND_OF[x] === c.resource.kind)!
        mutate(st, k, c.resource.id, (c.after as { id: Uuid, name: string } | null) ?? null)
      }
      record('revision.revert', `revision:${n}`, null, session.id)
      return sessionDto(st)
    }),
    policyStatus: () => delay(() => {
      const installedRevision = installs.reduce<number | null>((m, i) => (m === null || i.revision > m ? i.revision : m), null)
      return {
        latest_revision: revisions.at(-1)!.revision.number,
        installed_revision: installedRevision,
        gateways_total: gateways.length,
        gateways_on_revision: gateways.filter(g => g.active_revision === installedRevision).length,
        pending_installs: installs.filter(i => i.state === 'pending').length,
        p95_ms: 3.8,
      }
    }),
    listInstalls: (q = {}) => delay(() => page(installs.filter(i => (!q.gateway || i.gateway_id === q.gateway) && (q.revision == null || i.revision === q.revision)).slice().reverse().map(i => clone(i)), q.limit ?? 100)),
    install: (revision, gatewayIds) => delay(() => {
      if (!revisions.some(r => r.revision.number === revision)) throw notFound()
      const targets = gatewayIds.length ? gateways.filter(g => gatewayIds.includes(g.id)) : gateways
      const created = targets.map((g) => {
        g.desired_revision = revision
        const i: Install = { id: newId(), gateway_id: g.id, revision, requested_at: iso(Date.now()), requested_by: me, state: 'pending', acked_at: null, error: null }
        installs.push(i)
        if (g.status === 'online') {
          setTimeout(() => {
            i.state = 'installed'
            i.acked_at = iso(Date.now())
            g.active_revision = revision
          }, opts.installAckMs ?? 600)
        }
        return i
      })
      for (const s of sessions.values()) if (s.session.pending_install !== null && s.session.pending_install <= revision) s.session.pending_install = null
      record('install.request', `revision:${revision}`, { gateways: targets.map(g => g.id) })
      return { installs: created.map(i => clone(i)) }
    }),
    listApprovals: status => delay(() => clone(approvals.filter(a => !status || a.status === status))),
    decideApproval: (id, approve, comment) => delay(() => {
      const a = approvals.find(x => x.id === id)
      if (!a) throw notFound()
      if (a.status !== 'pending') throw new ApiError(409, 'Conflict', 'approval already decided')
      if (a.requested_by.id === me.id) throw new ApiError(403, 'Forbidden', 'the requester cannot decide')
      a.status = approve ? 'approved' : 'rejected'
      a.decided_at = iso(Date.now())
      a.decided_by = me
      a.comment = comment ?? null
      record('approval.decide', `approval:${id}`, { approve })
      return clone(a)
    }),

    agentOverview: id => delay(() => {
      const doc = published()
      const agent = doc.agents.find(a => a.id === id)
      if (!agent) throw notFound()
      const since = Date.now() - 86_400_000
      const mine = flows.filter(f => f.agent_id === id && new Date(f.started_at).getTime() >= since)
      const dests = new Map<string, { destination: string, flows: number, denied: number, bytes_out: number, bytes_in: number, last_seen_at: string }>()
      for (const f of mine) {
        const d = f.domain ?? f.dst.replace(/:\d+$/, '')
        const e = dests.get(d) ?? { destination: d, flows: 0, denied: 0, bytes_out: 0, bytes_in: 0, last_seen_at: f.started_at }
        e.flows++
        if (f.verdict === 'deny') e.denied++
        e.bytes_out += f.bytes_out
        e.bytes_in += f.bytes_in
        if (f.started_at > e.last_seen_at) e.last_seen_at = f.started_at
        dests.set(d, e)
      }
      return {
        agent: clone(agent),
        zone: clone(doc.zones.find(z => z.id === agent.zone_id)!),
        gateway: clone(gateways.find(g => g.id === agent.gateway_id) ?? null),
        last_seen_at: mine[0]?.started_at ?? null,
        flows_24h: mine.length,
        denied_24h: mine.filter(f => f.verdict === 'deny').length,
        bytes_out_24h: mine.reduce((n, f) => n + f.bytes_out, 0),
        bytes_in_24h: mine.reduce((n, f) => n + f.bytes_in, 0),
        top_destinations: [...dests.values()].sort((a, b) => b.flows - a.flows).slice(0, 10),
        recent_denied: clone(mine.filter(f => f.verdict === 'deny').slice(0, 10)),
        recent_tool_calls: logs.toolCalls.filter(t => t.agent === agent.name).map(({ flow_id: _f, ...t }) => clone(t)),
        alerts: alerts.filter(a => a.event.agent_id === id).map(a => clone(a.event)),
      }
    }),

    listAlerts: (q = {}) => delay(() => page(alerts.filter(a =>
      (!q.agent || a.event.agent_id === q.agent) && (!q.severity || a.event.severity === q.severity)
      && (q.acknowledged == null || a.acknowledged === q.acknowledged)).map(a => clone(a)), q.limit ?? 100)),
    acknowledgeAlert: id => delay(() => {
      const a = alerts.find(x => x.event.id === id)
      if (!a) throw notFound()
      a.acknowledged = true
      a.acknowledged_by = me
      record('alert.ack', `alert:${id}`)
      return clone(a)
    }),
    alertChannels: {
      list: () => delay(() => clone(channels)),
      get: id => delay(() => {
        const c = channels.find(x => x.id === id)
        if (!c) throw notFound()
        return clone(c)
      }),
      create: value => delay(() => {
        if (!/^https:\/\//.test(value.url)) throw new ApiError(400, 'Bad Request', 'channel URL must use https')
        const c = { ...clone(value), id: value.id || newId() }
        channels.push(c)
        record('alert_channel.create', `alert_channel:${c.id}`, { name: c.name })
        return clone(c)
      }),
      update: value => delay(() => {
        const i = channels.findIndex(x => x.id === value.id)
        if (i === -1) throw notFound()
        if (!/^https:\/\//.test(value.url) && !value.url.includes('****')) throw new ApiError(400, 'Bad Request', 'channel URL must use https')
        channels[i] = clone(value)
        record('alert_channel.update', `alert_channel:${value.id}`, { name: value.name })
        return clone(value)
      }),
      remove: id => delay(() => {
        const i = channels.findIndex(x => x.id === id)
        if (i === -1) throw notFound()
        channels.splice(i, 1)
        record('alert_channel.delete', `alert_channel:${id}`)
      }),
    },
    internalMap: period => delay(() => {
      const span = period === '1h' ? 3_600_000 : period === '7d' ? 7 * 86_400_000 : 86_400_000
      const doc = published()
      const internal = flows.filter(f => f.internal && f.agent_id && new Date(f.started_at).getTime() >= Date.now() - span)
      const nodes = new Map<string, { id: string, label: string, kind: 'agent' | 'internal', agent_id: Uuid | null, zone_id: Uuid | null, address: string | null }>()
      const edges = new Map<string, { source: string, target: string, protocol: FlowEvent['protocol'], port: number, app: FlowEvent['app'], flows: number, bytes: number, alerts: number, first_seen_at: string, last_seen_at: string, new: boolean }>()
      for (const f of internal) {
        const a = doc.agents.find(x => x.id === f.agent_id)
        nodes.set(f.agent_id!, { id: f.agent_id!, label: a?.name ?? f.agent_id!, kind: 'agent', agent_id: f.agent_id!, zone_id: f.zone_id ?? null, address: a?.addresses[0] ?? null })
        const ip = f.dst.replace(/:\d+$/, '')
        nodes.set(ip, { id: ip, label: f.domain ?? ip, kind: 'internal', agent_id: null, zone_id: null, address: ip })
        const port = Number(f.dst.split(':').at(-1))
        const key = `${f.agent_id}>${ip}:${port}`
        const e = edges.get(key) ?? { source: f.agent_id!, target: ip, protocol: f.protocol, port, app: f.app ?? null, flows: 0, bytes: 0, alerts: 0, first_seen_at: f.started_at, last_seen_at: f.started_at, new: port === 22 }
        e.flows++
        e.bytes += f.bytes_out + f.bytes_in
        if (f.started_at < e.first_seen_at) e.first_seen_at = f.started_at
        if (f.started_at > e.last_seen_at) e.last_seen_at = f.started_at
        if (port === 22) e.alerts = 1
        edges.set(key, e)
      }
      return { nodes: [...nodes.values()], edges: [...edges.values()] }
    }),

    listAudit: (q = {}) => delay(() => page(audit.filter(e =>
      (!q.actor || e.actor.name === q.actor || e.actor.id === q.actor)
      && (!q.interface || e.interface === q.interface)
      && (!q.action || (q.action.endsWith('*') ? e.action.startsWith(q.action.slice(0, -1)) : e.action === q.action))).map(e => clone(e)), q.limit ?? 100)),
    verifyAudit: () => delay(() => ({ ok: true, checked: audit.length, broken_at: null, head_seq: audit.at(-1)?.seq ?? null, head_hash: audit.at(-1)?.hash ?? null, anchor_sources: ['db', 'file'] as never })),
    exportAudit: () => delay(() => new Blob(audit.map(e => `${JSON.stringify(e)}\n`), { type: 'application/x-ndjson' })),

    listGateways: () => delay(() => clone(gateways)),
    deleteGateway: id => delay(() => {
      const i = gateways.findIndex(g => g.id === id)
      if (i === -1) throw notFound()
      gateways.splice(i, 1)
      record('gateway.delete', `gateway:${id}`)
    }),
    createRegistrationToken: name => delay(() => {
      record('gateway.registration_token', 'gateway', { name })
      return { token: `afw-reg-${digest(String(Date.now())).slice(0, 32)}`, expires_at: iso(Date.now() + 15 * 60_000) }
    }),
    sendGatewayCommand: (id, command) => delay(() => {
      if (!gateways.some(g => g.id === id)) throw notFound()
      record('gateway.command', `gateway:${id}`, command)
    }),

    control: {
      lockByOther(kind, id, owner = MARIE) {
        const sid = newId()
        sessions.set(sid, { session: { id: sid, name: 'autre session', owner, interface: 'ui', state: 'open', opened_at: iso(Date.now()), closed_at: null, locks: [], changes: 1, approval_id: null, base_revision: null, next_revision: null, pending_install: null }, draft: clone(published()), changes: new Map() })
        locks.set(`${kind}:${id}`, { session: sid, owner })
      },
      requireApproval(on) {
        approvalRequired = on
      },
      emit,
      expireToken() {
        tokenExpired = true
      },
    },
  }

  // The API audits the system start: the chain never starts empty.
  record('system.start', 'console', null, null, SYSTEM, 'system', now - 10 * 86_400_000)
  audit.sort((a, b) => a.at.localeCompare(b.at))
  audit.forEach((e, i) => {
    e.seq = i + 1
    e.prev_hash = i ? audit[i - 1]!.hash : '0'.repeat(64)
    e.hash = digest(e.prev_hash + JSON.stringify({ ...e, hash: undefined }))
  })
  return api
}
