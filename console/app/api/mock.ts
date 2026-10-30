/**
 * Stateful in-memory implementation of `AfwApi` for development, demos and tests.
 * It *simulates* the control plane (rule insertion, renumbering, publish, install, audit chain):
 * this logic lives here only because there is no server; the real one is in `afw-api`/`afw-engine`.
 */
import { ApiError, type AfwApi } from './client'
import {
  AGENT_IDS,
  KILLIAN,
  agentDescriptions,
  agents,
  buildAdminCalls,
  buildAlerts,
  buildAudit,
  buildFlows,
  buildGateways,
  buildRevisions,
  buildRules,
  gatewayNames,
  objects as baseObjects,
  zones,
  type MockFlow,
  type MockObject,
  type MockRule,
} from './mock-data'
import type {
  AgentListItem,
  AgentOverview,
  AlertView,
  AllowProposal,
  AuditEntry,
  DestinationOption,
  FlowDetail,
  FlowQuery,
  FlowStats,
  FlowSummary,
  Install,
  InternalMap,
  NetObjectView,
  Revision,
  RuleView,
  Session,
  SessionChange,
  StreamEvent,
  TraceStep,
  Uuid,
  VerifyFinding,
  WhereUsed,
  ZoneView,
} from './types'

export interface MockOptions {
  now?: Date
  /** Artificial latency per call (ms); 0 in tests. */
  latencyMs?: number
  /** Interval of the simulated live stream (ms). */
  streamIntervalMs?: number
}

const clone = <T>(v: T): T => (v === undefined ? v : (JSON.parse(JSON.stringify(v)) as T))

/** FNV-1a 64-bit, hex — stands in for sha256 in the simulated audit chain. */
function fnv(input: string): string {
  let h = 0xcbf29ce484222325n
  for (let i = 0; i < input.length; i++) {
    h ^= BigInt(input.charCodeAt(i))
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn
  }
  return h.toString(16).padStart(16, '0').repeat(4)
}

function globMatch(pattern: string, value: string): boolean {
  const re = new RegExp(`^${pattern.toLowerCase().replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`)
  return re.test(value.toLowerCase())
}

const zoneOf = (id: Uuid | null | undefined) => zones.find(z => z.id === id)

function ruleZoneId(r: MockRule): Uuid | null {
  return r.layer.type === 'zone' ? r.layer.zone_id : null
}

export function createMockApi(options: MockOptions = {}): AfwApi {
  const now = () => options.now ?? new Date()
  const t0 = now()
  const latency = options.latencyMs ?? 120

  const state = {
    rules: buildRules(t0),
    objects: clone(baseObjects) as MockObject[],
    flows: [] as MockFlow[],
    gateways: buildGateways(t0),
    revisions: buildRevisions(t0),
    audit: [] as AuditEntry[],
    alerts: buildAlerts(t0),
    session: null as Session | null,
    snapshot: null as { rules: MockRule[], objects: MockObject[] } | null,
    newRuleId: null as Uuid | null,
    streamSeq: 0,
  }
  state.flows = buildFlows(t0, state.rules)
  for (const e of buildAudit(t0)) appendAudit(e)

  function appendAudit(e: Omit<AuditEntry, 'prev_hash' | 'hash'> & Partial<AuditEntry>) {
    const prev = state.audit.at(-1)?.hash ?? '0'.repeat(64)
    const entry: AuditEntry = { ...e, seq: (state.audit.at(-1)?.seq ?? 999) + 1, prev_hash: prev, hash: '' }
    entry.hash = fnv(prev + JSON.stringify({ ...entry, hash: undefined }))
    state.audit.push(entry)
  }

  function audit(action: string, target: string, iface: AuditEntry['interface'] = 'ui') {
    appendAudit({ seq: 0, at: now().toISOString(), actor: iface === 'system' ? { kind: 'system', id: 'console', name: 'console' } : KILLIAN, interface: iface, session_id: state.session?.id.slice(0, 5) ?? null, action, target, diff: {} })
  }

  async function wait<T>(fn: () => T): Promise<T> {
    if (latency > 0) await new Promise(r => setTimeout(r, latency))
    return clone(fn())
  }

  // ---------------------------------------------------------------- helpers

  const objById = (id: Uuid) => state.objects.find(o => o.id === id)

  function zoneRules(zoneId: Uuid): MockRule[] {
    return state.rules.filter(r => ruleZoneId(r) === zoneId).sort((a, b) => a.position - b.position)
  }

  function baselineRules(): MockRule[] {
    return state.rules.filter(r => r.layer.type === 'baseline').sort((a, b) => a.position - b.position)
  }

  function lastHit(r: MockRule): string | null {
    return r.last_hit_s == null ? null : new Date(now().getTime() - r.last_hit_s * 1000).toISOString()
  }

  function ruleView(r: MockRule): RuleView {
    const zid = ruleZoneId(r)
    return {
      ...r,
      source_names: zid ? [zoneOf(zid)!.name] : [],
      destination_names: r.destinations.map(id => objById(id)?.name ?? id),
      last_hit_at: lastHit(r),
    }
  }

  function describeRule(r: MockRule): string {
    const zid = ruleZoneId(r)
    const dest = r.destinations.map(id => objById(id)?.name).join(', ') || 'toute destination'
    const svc = r.service_names.join(', ') || 'tout'
    return `${zid ? zoneOf(zid)!.name : 'toutes'} → ${dest} · ${svc} · ${r.action === 'accept' ? 'accepter' : 'refuser'}`
  }

  function usages(o: MockObject): WhereUsed[] {
    const fromRules: WhereUsed[] = state.rules
      .filter(r => r.destinations.includes(o.id) || r.data_classes.includes(o.id) || r.services.includes(o.id))
      .map(r => ({ kind: 'rule', ref: r.number, name: r.name, zone: ruleZoneId(r) ? zoneOf(ruleZoneId(r))!.name : null, hits: r.in_session ? null : r.hits, last_at: r.in_session ? null : lastHit(r), note: null }))
    return [...fromRules, ...o.extra_uses.map(u => ({ ...u, hits: null, last_at: null }))]
  }

  function objectView(o: MockObject): NetObjectView {
    return {
      id: o.id,
      name: o.name,
      kind: o.kind,
      value: o.value,
      comment: o.comment,
      members: o.members,
      in_session: !!o.in_session,
      used_in: usages(o).length,
      builtin: !!o.builtin,
      last_change: o.last_change
        ? { revision: o.last_change.revision, by: o.last_change.by, at: o.last_change.at_days_ago == null ? null : new Date(t0.getTime() - o.last_change.at_days_ago * 86_400_000).toISOString(), note: o.last_change.note }
        : null,
    }
  }

  function findFlow(id: Uuid): MockFlow {
    const f = state.flows.find(x => x.summary.id === id)
    if (!f) throw new ApiError(404, 'Not Found', `flow ${id}`)
    return f
  }

  function filterFlows(q: FlowQuery): FlowSummary[] {
    const text = q.q?.toLowerCase()
    return state.flows
      .map(f => f.summary)
      .filter(f => !q.agent || f.agent_name === q.agent || f.agent_id === q.agent)
      .filter(f => !q.zone || f.zone_name === q.zone || f.zone_id === q.zone)
      .filter(f => !q.verdict || f.verdict === q.verdict)
      .filter(f => !q.rule || f.rule_label.toLowerCase() === q.rule.toLowerCase())
      .filter(f => !q.alert || f.alert)
      .filter(f => !q.destination || globMatch(q.destination, f.domain ?? '') || globMatch(q.destination, f.dst.split(':')[0]!))
      .filter(f => !q.from || f.started_at >= q.from)
      .filter(f => !q.to || f.started_at <= q.to)
      .filter(f => !text || [f.domain, f.path, f.tool, f.agent_name, f.method, f.decision.rule_name, f.zone_name].some(v => v?.toLowerCase().includes(text)))
      .sort((a, b) => b.started_at.localeCompare(a.started_at))
  }

  function trace(f: FlowSummary): TraceStep[] {
    const label = f.rule_label
    const result: TraceStep['result'] = f.observed ? 'observe' : f.verdict === 'allow' ? 'accept' : 'deny'
    const base = baselineRules()
    if (f.decision.layer === 'baseline') {
      const idx = base.findIndex(r => r.number === label)
      return [
        ...base.slice(0, idx).map(r => ({ label: r.number, name: r.name, result: 'no_match' as const, rule_id: r.id, range: null })),
        { label, name: f.decision.rule_name, result, rule_id: f.decision.rule_id, range: null },
      ]
    }
    const steps: TraceStep[] = [{ label: `${base[0]!.number}–${base.at(-1)!.number}`, name: '', result: 'no_match', rule_id: null, range: { layer: 'baseline', count: base.length, zone: null } }]
    const zr = zoneRules(f.zone_id!).filter(r => !r.in_session)
    const idx = zr.findIndex(r => r.id === f.decision.rule_id)
    if (idx > 0) {
      steps.push({ label: `${zr[0]!.number}–${zr[idx - 1]!.number}`, name: '', result: 'no_match', rule_id: null, range: { layer: 'zone', count: idx, zone: f.zone_name } })
    }
    steps.push({ label, name: f.decision.rule_name, result, rule_id: f.decision.rule_id, range: null })
    return steps
  }

  function proposal(f: MockFlow): AllowProposal | null {
    const s = f.summary
    if (s.verdict !== 'deny' || s.decision.layer !== 'zone' || !s.zone_id) return null
    const dest = s.domain ?? s.dst.split(':')[0]!
    const exact = state.objects.find(o => o.kind === 'domain' && o.value === dest)
    const parts = dest.split('.')
    const wildcard = parts.length > 2 ? `*.${parts.slice(1).join('.')}` : `*.${dest}`
    const options: DestinationOption[] = [
      { key: 'exact', value: exact?.name ?? `dom-${dest}`, object_id: exact?.id ?? null, members: null, broadening: false },
    ]
    const group = s.app === 'https' && !s.internal ? state.objects.find(o => o.name === 'grp-portails-partenaires') : undefined
    if (group) options.push({ key: 'group', value: group.name, object_id: group.id, members: group.members.length, broadening: false })
    options.push({ key: 'wildcard', value: wildcard, object_id: null, members: null, broadening: true })
    return {
      zone: zoneOf(s.zone_id)!,
      zone_agents: agents.filter(a => a.zone_id === s.zone_id).map(a => a.name),
      destination_options: options,
      service: s.app ?? 'tcp',
      before_rule: s.rule_label,
      would_allow: f.extra.would_allow ?? { flows: 1, agents: [s.agent_name ?? ''] },
    }
  }

  function detail(f: MockFlow): FlowDetail {
    const s = f.summary
    const httpish = s.method !== 'SSH' && s.method !== 'TCP'
    const body = (data: string, size: number) => (data ? { encoding: 'utf8' as const, data, size, truncated: false, sha256: fnv(data).slice(0, 64) } : null)
    return {
      flow: s,
      http: httpish
        ? {
            id: `${s.id.slice(0, 8)}-http`, flow_id: s.id, gateway_id: s.gateway_id, agent_id: s.agent_id, at: s.started_at,
            method: s.method!, url: `${s.app}://${s.domain}${s.path}`, host: s.domain!, request_headers: f.extra.request_headers,
            request_body: body(f.extra.request_body, s.bytes_out), status: f.extra.status, response_headers: [],
            response_body: body(f.extra.response_body, s.bytes_in),
            findings: s.data_classes.includes('secret') ? [{ class: 'secret', category: 'secret', kind: 'api_key', fingerprint: '51be3c9a002f', location: 'body' }] : [],
            admin_action: s.domain === 'coolify.interne.lan' ? { system: 'coolify', action: 'deploy', resource: 'studio-preprod' } : null,
            websocket: false,
          }
        : null,
      dns: null,
      tool_call: s.correlation
        ? { id: `${s.id.slice(0, 8)}-tool`, agent: s.agent_name ?? '', conversation_id: s.correlation.conversation_id, tool: s.tool ?? '', args_summary: s.tool ?? '', started_at: s.started_at, ended_at: s.ended_at, status: s.verdict === 'deny' ? 'error' : 'ok' }
        : null,
      trace: trace(s),
      agent_message: s.verdict === 'deny' && httpish ? `blocked by agents-firewall: ${s.domain} not allowed for ${s.agent_name} (rule ${s.rule_label})` : null,
      allow_proposal: proposal(f),
      data_class_label: f.extra.data_class_label,
    }
  }

  function histogram(): FlowStats['histogram'] {
    const out: FlowStats['histogram'] = []
    const end = now().getTime()
    for (let i = 0; i < 60; i++) {
      const allowed = 30 + Math.round(12 * Math.sin(i / 5) + 6 * Math.sin(i * 1.7) + (i > 40 ? 5 : 0))
      const denied = i >= 57 ? 10 + (i - 57) * 4 : i % 13 === 4 ? 3 : i % 7 === 2 ? 1 : 0
      out.push({ at: new Date(end - (59 - i) * 60_000).toISOString(), allowed, denied })
    }
    return out
  }

  function requireSession(id: Uuid): Session {
    if (!state.session || state.session.id !== id || state.session.state !== 'open') throw new ApiError(404, 'Not Found', `session ${id}`)
    return state.session
  }

  function zoneView(z: (typeof zones)[number]): ZoneView {
    const zr = zoneRules(z.id)
    return {
      ...z,
      agents: agents.filter(a => a.zone_id === z.id).map(a => ({ id: a.id, name: a.name })),
      rule_count: zr.length,
      rules_in_session: zr.filter(r => r.in_session).length,
      expired_rules: zr.filter(r => r.expired).length,
      gateways: state.gateways.filter(g => g.zones.includes(z.name)).map(g => g.name),
      holds_mcp_agent: agents.some(a => a.zone_id === z.id && a.mcp_admin),
      observe_since: z.mode === 'observe' ? new Date(t0.getTime() - 3 * 86_400_000).toISOString() : null,
    }
  }

  function overview(id: Uuid): AgentOverview {
    const a = agents.find(x => x.id === id)
    if (!a) throw new ApiError(404, 'Not Found', `agent ${id}`)
    const isDaniel = a.id === AGENT_IDS.daniel
    const own = state.flows.filter(f => f.summary.agent_id === a.id).map(f => f.summary)
    const end = now().getTime()
    const ok = isDaniel ? [6, 8, 7, 5, 3, 2, 2, 1, 1, 0.5, 0.4, 0.4, 0.3, 0.3, 0.5, 1, 4, 9, 8, 7, 6, 5, 8, 19] : Array.from({ length: 24 }, (_, i) => 1 + ((i * 7) % 5))
    const ko = isDaniel ? [0, 0, 0.2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0.1, 0, 0, 0, 0, 0, 12] : Array.from({ length: 24 }, (_, i) => (i === 23 ? 0.5 : 0))
    const ago = (s: number) => new Date(end - s * 1000).toISOString()
    const destinations: AgentOverview['destinations'] = isDaniel
      ? [
          { destination: 'api.anthropic.com', rule_label: 'S3', verdict: 'allow', flows: 1940, bytes_out: null, last_at: ago(2), tags: [] },
          { destination: 'graph.microsoft.com', rule_label: '9', verdict: 'allow', flows: 612, bytes_out: 31_000_000, last_at: ago(46), tags: [] },
          { destination: 's3.fr-par.scw.cloud', rule_label: '7', verdict: 'allow', flows: 212, bytes_out: 96_000_000, last_at: ago(15), tags: [] },
          { destination: 'teams.microsoft.com', rule_label: '3', verdict: 'allow', flows: 188, bytes_out: 4_000_000, last_at: ago(180), tags: [] },
          { destination: 'glpi.interne.lan', rule_label: '10', verdict: 'allow', flows: 96, bytes_out: 1_000_000, last_at: ago(1200), tags: ['internal'] },
          { destination: 'pypi.org', rule_label: '2', verdict: 'allow', flows: 41, bytes_out: 200_000, last_at: ago(5 * 3600), tags: [] },
          { destination: 'api.exemple.com', rule_label: '12', verdict: 'deny', flows: 9, bytes_out: 12_000_000, last_at: ago(120), tags: ['new', 'denied'] },
          { destination: 'extranet.fournisseur-b.example', rule_label: '11', verdict: 'allow', flows: 4, bytes_out: 3_000_000, last_at: ago(2 * 86_400), tags: ['new'] },
        ]
      : own.map(f => ({ destination: f.domain ?? f.dst, rule_label: f.rule_label, verdict: f.verdict, flows: 1, bytes_out: f.bytes_out, last_at: f.started_at, tags: f.internal ? ['internal' as const] : [] }))
    const denials = own.filter(f => f.verdict === 'deny')
    return {
      agent: a,
      zone: zoneOf(a.zone_id)!,
      gateway_name: a.gateway_id ? gatewayNames[a.gateway_id] ?? null : null,
      description: agentDescriptions[a.id] ?? '',
      enrolled_at: new Date(t0.getTime() - 4 * 3_600_000).toISOString(),
      enrollment: a.kind,
      egress_guard: isDaniel ? new Date(t0.getTime() - 3 * 3_600_000).toISOString() : null,
      last_flow_at: own[0]?.started_at ?? null,
      flows_24h: isDaniel ? 3412 : 400 + own.length * 37,
      llm_flows_24h: isDaniel ? 1940 : 120,
      bytes_out_24h: isDaniel ? 182_000_000 : 12_000_000,
      bytes_in_24h: isDaniel ? 96_000_000 : 8_000_000,
      denied_24h: isDaniel ? 9 : denials.length,
      denied_destinations_24h: isDaniel ? 3 : new Set(denials.map(d => d.domain)).size,
      destinations_7d: isDaniel ? 23 : destinations.length,
      new_destinations_7d: isDaniel ? 2 : 0,
      volume: ok.map((v, i) => ({ at: new Date(end - (23 - i) * 3_600_000).toISOString(), allowed_bytes: v * 1_000_000, denied_bytes: ko[i]! * 1_000_000 })),
      volume_note: isDaniel ? 'Pic à 14 h : 19 Mo vers s3.fr-par.scw.cloud (accepté) et 12 Mo vers api.exemple.com (refusé, conversation « CR comité projet — ACME »).' : null,
      destinations,
      recent_denials: isDaniel
        ? [
            { destination: 'api.exemple.com', count: 6, last_at: ago(120), rule_label: '12', reason: 'no_rule', flow_id: state.flows[0]!.summary.id, can_allow: true },
            { destination: 'transfer.sh', count: 2, last_at: ago(3 * 3600), rule_label: 'S2', reason: 'global_denylist', flow_id: state.flows[0]!.summary.id, can_allow: false },
            { destination: 'docs.google.com', count: 1, last_at: ago(21 * 3600), rule_label: '12', reason: 'no_rule', flow_id: state.flows[0]!.summary.id, can_allow: true },
          ]
        : denials.map(d => ({ destination: d.domain ?? d.dst, count: 1, last_at: d.started_at, rule_label: d.rule_label, reason: d.decision.layer === 'baseline' ? 'baseline' : 'no_rule', flow_id: d.id, can_allow: d.decision.layer === 'zone' })),
      top_tools: isDaniel
        ? [
            { tool: 'upload_document', flows: 212, bytes_out: 96_000_000, denied: 0 },
            { tool: 'send_mail', flows: 148, bytes_out: 31_000_000, denied: 0 },
            { tool: 'terminal', flows: 64, bytes_out: 14_000_000, denied: 6 },
            { tool: 'web_request', flows: 51, bytes_out: 2_000_000, denied: 0 },
          ]
        : own.map(f => ({ tool: (f.tool ?? '').split(' ·')[0]!, flows: 1, bytes_out: f.bytes_out, denied: f.verdict === 'deny' ? 1 : 0 })),
    }
  }

  function internal(period: InternalMap['period']): InternalMap {
    return {
      period,
      nodes: [
        { id: 'daniel-bot', label: 'daniel-bot', sub: 'bots-internes', kind: 'agent', state: 'normal', href: `/agents/${AGENT_IDS.daniel}` },
        { id: 'laurent-bot', label: 'laurent-bot', sub: 'bots-internes', kind: 'agent', state: 'normal', href: `/agents/${AGENT_IDS.laurent}` },
        { id: 'hermes-acme', label: 'hermes-acme', sub: 'bots-clients', kind: 'agent', state: 'normal', href: `/agents/${AGENT_IDS.acme}` },
        { id: 'hermes-compta', label: 'hermes-compta', sub: 'nouveaux-bots', kind: 'agent', zone_mode: 'observe', state: 'normal', href: `/agents/${AGENT_IDS.compta}` },
        { id: 'vulcain-bot', label: 'vulcain-bot', sub: 'ops · agent agréé', kind: 'agent', state: 'normal', href: `/agents/${AGENT_IDS.vulcain}` },
        { id: 'k8s', label: 'API Kubernetes ecoprod', sub: '6443 · 4 018 requêtes · 2 exec', kind: 'system', state: 'normal', href: null },
        { id: 'coolify', label: 'API Coolify', sub: '443 · 96 requêtes · 3 redéploiements', kind: 'system', state: 'normal', href: null },
        { id: 'proxmox', label: 'VM Proxmox', sub: 'SSH · 4 sessions · 6 Mo', kind: 'system', state: 'normal', href: null },
        { id: 'postgres', label: 'postgres-ha · 5432', sub: 'port sensible · nouveau pour laurent-bot', kind: 'system', state: 'alert', href: null },
        { id: 'glpi', label: 'glpi.interne.lan', sub: '443 · 1 184 requêtes · 9 Mo', kind: 'system', state: 'normal', href: null },
        { id: 'dns', label: 'Résolveur DNS', sub: '53 · 41 220 requêtes', kind: 'system', state: 'normal', href: null },
        { id: 'host-new', label: '10.0.5.23', sub: 'nouvel hôte · 38 ports essayés', kind: 'system', state: 'new', href: null },
      ],
      edges: [
        { from: 'daniel-bot', to: 'glpi', weight: 2, state: 'usual' },
        { from: 'daniel-bot', to: 'dns', weight: 1.5, state: 'usual' },
        { from: 'laurent-bot', to: 'glpi', weight: 3, state: 'usual' },
        { from: 'laurent-bot', to: 'dns', weight: 1.5, state: 'usual' },
        { from: 'hermes-acme', to: 'dns', weight: 1.5, state: 'usual' },
        { from: 'hermes-compta', to: 'dns', weight: 1.5, state: 'usual' },
        { from: 'hermes-compta', to: 'glpi', weight: 1.5, state: 'new' },
        { from: 'vulcain-bot', to: 'k8s', weight: 6, state: 'usual' },
        { from: 'vulcain-bot', to: 'coolify', weight: 2.5, state: 'usual' },
        { from: 'vulcain-bot', to: 'proxmox', weight: 2, state: 'usual' },
        { from: 'vulcain-bot', to: 'postgres', weight: 3.5, state: 'usual' },
        { from: 'vulcain-bot', to: 'dns', weight: 1.5, state: 'usual' },
        { from: 'laurent-bot', to: 'postgres', weight: 2.5, state: 'alert' },
        { from: 'vulcain-bot', to: 'host-new', weight: 2.5, state: 'alert' },
        { from: 'hermes-acme', to: 'daniel-bot', weight: 2, state: 'alert' },
      ],
      admin_calls: buildAdminCalls(t0),
    }
  }

  // ---------------------------------------------------------------- API

  const api: AfwApi = {
    me: () => wait(() => ({ id: KILLIAN.id, name: KILLIAN.name, email: 'killian@example.org', role: 'admin' as const, auth: 'oidc' as const, tenant: 'pulse-myit / prod' })),
    oidcLoginUrl: () => null,

    listFlows: q => wait(() => {
      const all = filterFlows(q)
      const offset = q.cursor ? Number(q.cursor) : 0
      const limit = q.limit ?? 200
      const items = all.slice(offset, offset + limit)
      return { items, next_cursor: offset + limit < all.length ? String(offset + limit) : null, total: all.length }
    }),

    flowStats: q => wait(() => {
      const narrowed = q.agent || q.zone || q.destination || q.rule || q.q
      if (!narrowed) return { total: 1284 + state.streamSeq, allowed: 1251 + state.streamSeq, denied: 33, alerts: 2, per_minute: 142, histogram: histogram() }
      const list = filterFlows({ ...q, verdict: undefined, alert: undefined })
      const denied = list.filter(f => f.verdict === 'deny').length
      return { total: list.length, allowed: list.length - denied, denied, alerts: list.filter(f => f.alert).length, per_minute: list.length, histogram: histogram() }
    }),

    getFlow: id => wait(() => {
      const f = findFlow(id)
      if (f.extra.request_body) audit('content_view', `flux f-${id.replace(/-/g, '').slice(0, 6)} · corps HTTP`)
      return detail(f)
    }),

    streamLogs: (onEvent: (e: StreamEvent) => void) => {
      const timer = setInterval(() => {
        const source = state.flows.find(f => f.summary.id === state.flows[2]?.summary.id) ?? state.flows[0]!
        state.streamSeq++
        const id = `${(0x9a0000 + state.streamSeq).toString(16)}a0-0000-4000-8000-${state.streamSeq.toString(16).padStart(12, '0')}`
        const flow: MockFlow = clone(source)
        flow.summary.id = id
        flow.summary.started_at = new Date().toISOString()
        flow.summary.ended_at = new Date(Date.now() + 5_000).toISOString()
        state.flows.unshift(flow)
        onEvent({ type: 'flow', flow: clone(flow.summary) })
      }, options.streamIntervalMs ?? 6_000)
      return () => clearInterval(timer)
    },

    startCapture: req => wait(() => ({ id: crypto.randomUUID(), agent_id: req.agent_id, duration_secs: req.duration_secs, state: 'pending' as const, created_at: now().toISOString() })),

    listObjects: () => wait(() => state.objects.map(objectView)),
    whereUsed: id => wait(() => {
      const o = objById(id)
      if (!o) throw new ApiError(404, 'Not Found', `object ${id}`)
      return usages(o)
    }),
    listZones: () => wait(() => zones.map(zoneView)),

    getRulebase: q => wait(() => {
      const zoneId = q.zone_id ?? zones[0]!.id
      const z = zoneOf(zoneId)
      if (!z) throw new ApiError(404, 'Not Found', `zone ${zoneId}`)
      const text = q.q?.toLowerCase()
      const match = (r: RuleView) => !text || [r.name, r.number, r.comment, ...r.destination_names].some(v => v.toLowerCase().includes(text))
      return {
        baseline: baselineRules().map(ruleView).filter(match),
        zone: zoneRules(zoneId).map(ruleView).filter(match),
        zone_id: zoneId,
        observation: z.mode === 'observe' ? { since: new Date(t0.getTime() - 3 * 86_400_000).toISOString(), destinations: 37, uncovered: 9 } : null,
      }
    }),
    getRule: id => wait(() => {
      const r = state.rules.find(x => x.id === id)
      if (!r) throw new ApiError(404, 'Not Found', `rule ${id}`)
      return ruleView(r)
    }),

    currentSession: () => wait(() => (state.session?.state === 'open' ? state.session : null)),
    openSession: name => wait(() => {
      if (state.session?.state === 'open') return state.session
      state.snapshot = { rules: clone(state.rules), objects: clone(state.objects) }
      state.session = { id: crypto.randomUUID(), name, owner: KILLIAN, opened_at: now().toISOString(), changes: [], locked_objects: 0, state: 'open' }
      audit('session_open', `« ${name} »`)
      return state.session
    }),
    discardSession: id => wait(() => {
      requireSession(id)
      if (state.snapshot) {
        state.rules = state.snapshot.rules
        state.objects = state.snapshot.objects
      }
      state.session = null
      state.snapshot = null
      audit('session_discard', id.slice(0, 5))
    }).then(() => undefined),

    allowFromLog: (sessionId, req) => wait(() => {
      const session = requireSession(sessionId)
      const f = findFlow(req.flow_id)
      const prop = proposal(f)
      if (!prop) throw new ApiError(409, 'Conflict', 'only flows denied by a zone rule can be allowed from the log')
      const opt = prop.destination_options.find(o => o.key === req.destination)
      if (!opt) throw new ApiError(422, 'Unprocessable Entity', `destination option ${req.destination} not offered`)
      const zoneId = f.summary.zone_id!
      const zr = zoneRules(zoneId)
      const deny = zr.find(r => r.id === f.summary.decision.rule_id)!
      const changes: SessionChange[] = []

      let destObj = opt.object_id ? objById(opt.object_id) : undefined
      let createdObj: MockObject | undefined
      if (!destObj) {
        const value = req.destination === 'wildcard' ? opt.value : f.summary.domain!
        createdObj = {
          id: crypto.randomUUID(), name: req.destination === 'wildcard' ? `dom-${value}` : opt.value, kind: 'domain', value,
          comment: `Créé depuis le journal (flux f-${f.summary.id.replace(/-/g, '').slice(0, 6)}), dans votre session.`,
          members: [], last_change: null, extra_uses: [], in_session: true,
        }
        state.objects.unshift(createdObj)
        destObj = createdObj
      }

      const before = zr[zr.indexOf(deny) - 1]
      const number = deny.number
      for (const r of zr.filter(x => x.position >= deny.position)) {
        r.previous_number = r.previous_number ?? r.number
        r.position += 1
        r.number = String(Number(r.number) + 1)
      }
      const svc = prop.service.toUpperCase()
      const newRule: MockRule = {
        id: crypto.randomUUID(),
        name: `${before?.section === 'Partenaires et portails' ? 'Portail partenaire — ' : ''}${f.summary.domain}`,
        layer: { type: 'zone', zone_id: zoneId },
        section: before?.section ?? null,
        position: deny.position - 1,
        sources: [zoneId],
        destinations: [destObj.id],
        services: [],
        data_classes: [],
        action: 'accept',
        track: req.track,
        expires_at: req.expires_in_days == null ? null : new Date(now().getTime() + req.expires_in_days * 86_400_000).toISOString(),
        comment: req.comment ?? `Ouvert depuis le journal, flux f-${f.summary.id.replace(/-/g, '').slice(0, 6)}`,
        enabled: true,
        number,
        service_names: [svc],
        data_class_names: [],
        inspection: f.summary.app === 'https' ? 'inspect' : null,
        hits: 0,
        last_hit_s: null,
        hit_ratio: 0,
        expired: false,
        in_session: true,
        previous_number: null,
      }
      state.rules.push(newRule)
      state.newRuleId = newRule.id

      changes.push({ op: 'add', kind: 'rule', target: newRule.name, summary: `Règle ${number}`, before: null, after: `${describeRule(newRule)} · section ${newRule.section ?? '—'}` })
      if (createdObj) changes.push({ op: 'add', kind: 'object', target: createdObj.name, summary: 'Objet', before: null, after: `${createdObj.value} (domaine exact)` })
      changes.push({ op: 'renumber', kind: 'rule', target: deny.name, summary: `Règle ${deny.previous_number}`, before: `n° ${deny.previous_number}`, after: `n° ${deny.number}` })
      session.changes.push(...changes)
      session.locked_objects = session.changes.filter(c => c.kind === 'object').length + 1
      audit('rule_create', `${zoneOf(zoneId)!.name} / règle ${number}`)
      if (createdObj) audit('object_create', createdObj.name)
      return { rule: ruleView(newRule), changes }
    }),

    verify: revision => wait(() => {
      const findings: VerifyFinding[] = []
      for (const r of state.rules.filter(x => x.expired && x.enabled)) {
        const z = zoneOf(ruleZoneId(r))?.name ?? ''
        findings.push({ severity: 'warning', code: 'expired_rule', message: `Règle expirée encore en place : ${r.number} « ${r.name} » (zone ${z})`, params: { rule: r.number, name: r.name, zone: z } })
      }
      for (const o of state.objects.filter(x => x.kind !== 'agent' && usages(x).length === 0)) {
        findings.push({ severity: 'warning', code: 'unused_object', message: `Objet inutilisé : ${o.name}`, params: { object: o.name } })
      }
      return { revision: revision ?? null, ok: !findings.some(f => f.severity === 'error'), findings }
    }),

    publishSession: (id, comment) => wait(() => {
      const session = requireSession(id)
      const number = Math.max(...state.revisions.map(r => r.number)) + 1
      const rev: Revision = {
        number, title: session.name, comment, author: KILLIAN, interface: 'ui', published_at: now().toISOString(), session_id: session.id.slice(0, 5),
        changes: session.changes, approval: null, installed: false, installs: [],
      }
      state.revisions.unshift(rev)
      for (const r of state.rules) {
        r.in_session = false
        r.previous_number = null
      }
      for (const o of state.objects) o.in_session = false
      audit('publish', `révision ${number}`)
      session.state = 'published'
      state.session = null
      state.snapshot = null
      return rev
    }),

    listRevisions: () => wait(() => [...state.revisions].sort((a, b) => b.number - a.number)),
    getRevision: n => wait(() => {
      const r = state.revisions.find(x => x.number === n)
      if (!r) throw new ApiError(404, 'Not Found', `revision ${n}`)
      return r
    }),

    install: (revision, gatewayIds) => wait(() => {
      const rev = state.revisions.find(x => x.number === revision)
      if (!rev) throw new ApiError(404, 'Not Found', `revision ${revision}`)
      const at = now().toISOString()
      const results = state.gateways.filter(g => gatewayIds.includes(g.id)).map((g, i) => {
        g.revision = revision
        g.revision_installed_at = at
        return { gateway_id: g.id, gateway_name: g.name, revision, ok: true, error: null, duration_ms: [1200, 900, 1600][i] ?? 1000, at, by: KILLIAN.name }
      })
      for (const r of state.revisions) r.installed = r.number === revision
      rev.installs = results
      const fresh = state.rules.find(r => r.id === state.newRuleId)
      if (fresh) {
        fresh.hits = 3
        fresh.last_hit_s = 4
        fresh.hit_ratio = 0.02
      }
      audit('install', `révision ${revision} → ${results.length}/${state.gateways.length} passerelles`, 'system')
      const install: Install = { id: crypto.randomUUID(), revision, requested_by: KILLIAN.name, requested_at: at, results }
      return install
    }),

    listAgents: () => wait(() => agents.map((a): AgentListItem => {
      const own = state.flows.filter(f => f.summary.agent_id === a.id)
      return {
        agent: a,
        zone_name: zoneOf(a.zone_id)!.name,
        gateway_name: a.gateway_id ? gatewayNames[a.gateway_id] ?? null : null,
        last_flow_at: own[0]?.summary.started_at ?? new Date(t0.getTime() - 40_000).toISOString(),
        flows_24h: a.id === AGENT_IDS.daniel ? 3412 : 400 + own.length * 37,
        denied_24h: a.id === AGENT_IDS.daniel ? 9 : own.filter(f => f.summary.verdict === 'deny').length,
        description: agentDescriptions[a.id] ?? '',
      }
    })),
    agentOverview: id => wait(() => overview(id)),

    listAlerts: () => wait(() => state.alerts),
    acknowledgeAlert: id => wait(() => {
      const a = state.alerts.find(x => x.id === id)
      if (!a) throw new ApiError(404, 'Not Found', `alert ${id}`)
      a.acknowledged_by = KILLIAN.name
      a.resolved = true
      audit('alert_ack', a.summary.slice(0, 48))
      return a as AlertView
    }),
    listAlertChannels: () => wait(() => [
      { id: 'ch-webhook', kind: 'webhook' as const, name: 'webhook', enabled: true },
      { id: 'ch-teams', kind: 'teams' as const, name: 'Teams', enabled: true },
    ]),
    internalMap: period => wait(() => internal(period)),

    listAudit: q => wait(() => {
      const all = [...state.audit]
        .reverse()
        .filter(e => !q.interface || e.interface === q.interface)
        .filter(e => !q.actor || e.actor.name === q.actor)
      const offset = q.cursor ? Number(q.cursor) : 0
      const limit = q.limit ?? 100
      return { items: all.slice(offset, offset + limit), next_cursor: offset + limit < all.length ? String(offset + limit) : null, total: all.length }
    }),
    verifyAudit: () => wait(() => {
      let prev = '0'.repeat(64)
      let ok = true
      for (const e of state.audit) {
        if (e.prev_hash !== prev || fnv(prev + JSON.stringify({ ...e, hash: undefined })) !== e.hash) ok = false
        prev = e.hash
      }
      const anchor = new Date(now())
      anchor.setMinutes(0, 0, 0)
      return { ok, checked: state.audit.length, anchor_exported_at: anchor.toISOString() }
    }),
    auditExportUrl: () => `data:application/x-ndjson;charset=utf-8,${encodeURIComponent(state.audit.map(e => JSON.stringify(e)).join('\n'))}`,

    listGateways: () => wait(() => state.gateways),
    listInstalls: () => wait(() => state.revisions
      .filter(r => r.installs.length)
      .sort((a, b) => b.number - a.number)
      .map(r => ({ id: `inst-${r.number}`, revision: r.number, requested_by: r.installs[0]!.by, requested_at: r.installs[0]!.at, results: r.installs }))),
    createRegistrationToken: () => wait(() => {
      const token = `afw_rt_${Math.random().toString(16).slice(2, 14)}`
      return { token, expires_at: new Date(now().getTime() + 15 * 60_000).toISOString(), command: `afw gateway register --token ${token}` }
    }),
    sendGatewayCommand: (id, command) => wait(() => {
      const g = state.gateways.find(x => x.id === id)
      if (!g) throw new ApiError(404, 'Not Found', `gateway ${id}`)
      audit('gateway_command', `${g.name} · ${command}`)
    }).then(() => undefined),
  }
  return api
}
