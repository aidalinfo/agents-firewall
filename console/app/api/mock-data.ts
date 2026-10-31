/**
 * Demo dataset of the mock API, in the exact shapes of the contract (generated types).
 * Agents daniel-bot, laurent-bot, vulcain-bot, hermes-acme, hermes-compta; zones bots-internes,
 * bots-clients, nouveaux-bots (observation), ops; gateways gw-hermes-01/02, gw-ops-01.
 * Timestamps are offsets from "now" so that the console looks live. Free-text values (comments,
 * summaries) are API data and are therefore not translated.
 */
import type {
  Actor,
  Agent,
  AgentKind,
  AlertChannel,
  AlertEvent,
  AlertKind,
  ApiToken,
  DataClass,
  FlowEvent,
  Gateway,
  HttpEvent,
  InspectionRule,
  NetObject,
  NetObjectSpec,
  PolicyDocument,
  Rule,
  Service,
  Severity,
  ToolCallEvent,
  Uuid,
  Zone,
} from './types'

export const uid = (prefix: string, n: number) => `${prefix}-0000-4000-8000-${n.toString(16).padStart(12, '0')}`

export const ZONE_IDS = {
  internes: uid('20000000', 1),
  clients: uid('20000000', 2),
  nouveaux: uid('20000000', 3),
  ops: uid('20000000', 4),
} as const

export const GW_IDS = {
  hermes01: uid('40000000', 1),
  hermes02: uid('40000000', 2),
  ops01: uid('40000000', 3),
} as const

export const AGENT_IDS = {
  daniel: uid('30000000', 1),
  laurent: uid('30000000', 2),
  vulcain: uid('30000000', 3),
  acme: uid('30000000', 4),
  compta: uid('30000000', 5),
} as const

export const OBJ = {
  anthropic: uid('50000000', 1),
  openai: uid('50000000', 2),
  llm: uid('50000000', 3),
  metadata: uid('50000000', 4),
  s3: uid('50000000', 5),
  graph: uid('50000000', 6),
  login: uid('50000000', 7),
  m365: uid('50000000', 8),
  github: uid('50000000', 9),
  glpi: uid('50000000', 10),
  lan: uid('50000000', 11),
  coolify: uid('50000000', 12),
  acme: uid('50000000', 13),
} as const

export const SVC = {
  https: uid('60000000', 1),
  http: uid('60000000', 2),
  ssh: uid('60000000', 3),
  postgres: uid('60000000', 4),
} as const

export const DC = {
  secrets: uid('70000000', 1),
  personal: uid('70000000', 2),
} as const

export const FLOW_IDS = {
  upload: '8c21e4a0-0000-4000-8000-000000000001',
  llm: '8c2187a0-0000-4000-8000-000000000003',
  s3: '8c2161a0-0000-4000-8000-000000000004',
  metadata: '8c2150a0-0000-4000-8000-000000000005',
  coolify: '8c2139a0-0000-4000-8000-000000000006',
  graph: '8c20f8a0-0000-4000-8000-000000000008',
  glpi: '8c20d2a0-0000-4000-8000-000000000009',
  ssh: '8c209aa0-0000-4000-8000-00000000000a',
  observed: '8c2061a0-0000-4000-8000-00000000000b',
} as const

export const KILLIAN: Actor = { kind: 'human', id: 'u-killian', name: 'Killian Stein' }
export const MARIE: Actor = { kind: 'human', id: 'u-marie', name: 'Marie Durand' }
export const VULCAIN: Actor = { kind: 'agent', id: AGENT_IDS.vulcain, name: 'vulcain-bot' }
export const SYSTEM: Actor = { kind: 'system', id: 'console', name: 'console' }

const zones: Zone[] = [
  { id: ZONE_IDS.internes, name: 'bots-internes', comment: 'Bots Hermes internes', mode: 'enforce', delegated_to_mcp: true },
  { id: ZONE_IDS.clients, name: 'bots-clients', comment: 'Bots dédiés aux clients', mode: 'enforce', delegated_to_mcp: true },
  { id: ZONE_IDS.nouveaux, name: 'nouveaux-bots', comment: 'Accueil des nouveaux bots', mode: 'observe', delegated_to_mcp: false },
  { id: ZONE_IDS.ops, name: 'ops', comment: 'Exploitation', mode: 'enforce', delegated_to_mcp: false },
]

const agent = (id: Uuid, name: string, zone: Uuid, gw: Uuid, kind: AgentKind, ip: string, extra: Partial<Agent> = {}): Agent => ({
  id, name, zone_id: zone, kind, gateway_id: gw, addresses: [ip], labels: {}, hermes: true, mcp_admin: false, ...extra,
})

const agents: Agent[] = [
  agent(AGENT_IDS.daniel, 'daniel-bot', ZONE_IDS.internes, GW_IDS.hermes01, 'docker_compose', '172.20.0.14', { labels: { container: 'hermes-daniel' } }),
  agent(AGENT_IDS.laurent, 'laurent-bot', ZONE_IDS.internes, GW_IDS.hermes01, 'docker_compose', '172.20.0.15'),
  agent(AGENT_IDS.vulcain, 'vulcain-bot', ZONE_IDS.ops, GW_IDS.ops01, 'kubernetes', '10.42.3.17', { mcp_admin: true, hermes: false }),
  agent(AGENT_IDS.acme, 'hermes-acme', ZONE_IDS.clients, GW_IDS.hermes02, 'coolify', '172.21.0.9'),
  agent(AGENT_IDS.compta, 'hermes-compta', ZONE_IDS.nouveaux, GW_IDS.hermes02, 'coolify', '172.21.0.12'),
]

const o = (id: Uuid, name: string, spec: NetObjectSpec, comment = '', category: NetObject['category'] = null): NetObject => ({ id, name, spec, comment, category })

const objects: NetObject[] = [
  o(OBJ.anthropic, 'api.anthropic.com', { type: 'domain', pattern: 'api.anthropic.com' }, '', 'llm_provider'),
  o(OBJ.openai, 'api.openai.com', { type: 'domain', pattern: 'api.openai.com' }, '', 'llm_provider'),
  o(OBJ.llm, 'grp-fournisseurs-llm', { type: 'group', members: [OBJ.anthropic, OBJ.openai] }, 'Journalisé en détail, exempté du blocage par classe de donnée (EF-25).', 'llm_provider'),
  o(OBJ.metadata, 'metadonnees-cloud', { type: 'host', ip: '169.254.169.254' }, 'Service de métadonnées des clouds.', 'cloud_metadata'),
  o(OBJ.s3, 'dom-s3-scaleway-fr-par', { type: 'domain', pattern: 's3.fr-par.scw.cloud' }, 'Envois par URL présignée.'),
  o(OBJ.graph, 'graph.microsoft.com', { type: 'domain', pattern: 'graph.microsoft.com' }),
  o(OBJ.login, 'login.microsoftonline.com', { type: 'domain', pattern: 'login.microsoftonline.com' }),
  o(OBJ.m365, 'grp-microsoft-365', { type: 'group', members: [OBJ.graph, OBJ.login] }, 'Graph, Outlook et ressources Microsoft 365.'),
  o(OBJ.github, 'dom-github-api', { type: 'domain', pattern: 'api.github.com' }),
  o(OBJ.glpi, 'hote-glpi', { type: 'host', ip: '10.0.4.12' }, 'Serveur de tickets.', 'internal'),
  o(OBJ.lan, 'reseau-lan', { type: 'network', cidr: '10.0.0.0/16' }, 'LAN d’exploitation.', 'internal'),
  o(OBJ.coolify, 'coolify-interne', { type: 'domain', pattern: 'coolify.interne.lan' }, 'API d’administration Coolify.', 'internal'),
  o(OBJ.acme, 'dom-portail-acme', { type: 'domain', pattern: 'portail.acme.example' }, 'Portail du client ACME.'),
]

const services: Service[] = [
  { id: SVC.https, name: 'https', comment: '', protocol: 'tcp', ports: [{ start: 443, end: 443 }], app: { proto: 'https', methods: [], path_prefixes: [] } },
  { id: SVC.http, name: 'http', comment: '', protocol: 'tcp', ports: [{ start: 80, end: 80 }], app: { proto: 'http', methods: [], path_prefixes: [] } },
  { id: SVC.ssh, name: 'ssh', comment: '', protocol: 'tcp', ports: [{ start: 22, end: 22 }], app: null },
  { id: SVC.postgres, name: 'postgres', comment: 'PostgreSQL', protocol: 'tcp', ports: [{ start: 5432, end: 5432 }], app: null },
]

const dataClasses: DataClass[] = [
  { id: DC.secrets, name: 'secrets', comment: 'Clés et jetons', category: 'secret', detectors: [{ type: 'builtin', id: 'aws_access_key' }, { type: 'builtin', id: 'private_key' }, { type: 'builtin', id: 'jwt' }] },
  { id: DC.personal, name: 'donnees-personnelles', comment: '', category: 'personal', detectors: [{ type: 'builtin', id: 'iban' }, { type: 'regex', name: 'numero-secu', pattern: '[12]\\d{12}' }] },
]

let rulePos = 0
const rule = (n: number, name: string, layer: Rule['layer'], section: string | null, extra: Partial<Rule>): Rule => ({
  id: uid('80000000', n), name, layer, section, position: ++rulePos, sources: [], destinations: [], services: [], data_classes: [],
  action: 'accept', track: 'detailed', expires_at: null, comment: '', enabled: true, ...extra,
})
const zoneLayer = (zone_id: Uuid): Rule['layer'] => ({ type: 'zone', zone_id })

export const RULE_IDS = {
  metadata: uid('80000000', 1),
  secrets: uid('80000000', 2),
  llm: uid('80000000', 3),
  m365: uid('80000000', 10),
  s3: uid('80000000', 11),
  github: uid('80000000', 12),
  acme: uid('80000000', 20),
  glpi: uid('80000000', 30),
  coolify: uid('80000000', 31),
  lan: uid('80000000', 32),
} as const

const baseline = (): Rule['layer'] => ({ type: 'baseline' })
const rules: Rule[] = [
  rule(1, 'Métadonnées cloud', baseline(), 'Socle', { destinations: [OBJ.metadata], action: 'deny', comment: 'Jamais d’accès aux métadonnées d’instance' }),
  rule(2, 'Secrets sortants', baseline(), 'Socle', { data_classes: [DC.secrets], action: 'deny', comment: 'Aucun secret ne sort (sauf fournisseurs LLM, EF-25)' }),
  rule(3, 'Fournisseurs LLM', baseline(), 'Socle', { destinations: [OBJ.llm], services: [SVC.https] }),
]
rulePos = 0
rules.push(
  rule(10, 'Microsoft 365', zoneLayer(ZONE_IDS.internes), 'Messagerie', { sources: [ZONE_IDS.internes], destinations: [OBJ.m365], services: [SVC.https] }),
  rule(11, 'Dépôts S3', zoneLayer(ZONE_IDS.internes), 'Stockage', { sources: [ZONE_IDS.internes], destinations: [OBJ.s3], services: [SVC.https], track: 'log' }),
  rule(12, 'GitHub API', zoneLayer(ZONE_IDS.internes), 'Stockage', { sources: [ZONE_IDS.internes], destinations: [OBJ.github], services: [SVC.https], expires_at: new Date(Date.now() - 2 * 86_400_000).toISOString(), comment: 'Temporaire (migration)' }),
)
rulePos = 0
rules.push(rule(20, 'Portail ACME', zoneLayer(ZONE_IDS.clients), null, { sources: [ZONE_IDS.clients], destinations: [OBJ.acme], services: [SVC.https] }))
rulePos = 0
rules.push(
  rule(30, 'GLPI', zoneLayer(ZONE_IDS.ops), 'Outils', { sources: [ZONE_IDS.ops], destinations: [OBJ.glpi], services: [SVC.https] }),
  rule(31, 'API Coolify', zoneLayer(ZONE_IDS.ops), 'Outils', { sources: [ZONE_IDS.ops], destinations: [OBJ.coolify], services: [SVC.https] }),
  rule(32, 'LAN en SSH', zoneLayer(ZONE_IDS.ops), 'Outils', { sources: [ZONE_IDS.ops], destinations: [OBJ.lan], services: [SVC.ssh], enabled: false }),
)

const inspectionRules: InspectionRule[] = [
  { id: uid('81000000', 1), name: 'Pas de déchiffrement des fournisseurs LLM épinglés', position: 1, zones: [], destinations: [OBJ.anthropic], action: 'bypass' },
]

/** Revision 42: the installed policy. */
export function seedDocument(): PolicyDocument {
  return structuredClone({
    objects, services, data_classes: dataClasses, zones, agents, rules, inspection_rules: inspectionRules,
    settings: {
      internal_networks: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'],
      max_buffered_body: 1_048_576,
      max_stored_body: 262_144,
      retention_days: { flows: 30, http: 14, captures: 7 },
    },
  })
}

export function seedGateways(now: number): Gateway[] {
  const stats = (flows: number, denied: number) => ({ uptime_secs: 86_400 * 6, active_flows: 12, flows_total: flows, denied_total: denied, bytes_in: flows * 9_000, bytes_out: flows * 2_400, events_queued: 0, events_dropped: 0, p50_ms: 1.2, p95_ms: 3.8 })
  return [
    { id: GW_IDS.hermes01, name: 'gw-hermes-01', hostname: 'hermes-01.interne.lan', status: 'online', version: '0.1.0', active_revision: 42, desired_revision: 42, last_seen_at: new Date(now - 4_000).toISOString(), registered_at: new Date(now - 30 * 86_400_000).toISOString(), ca_fingerprint: 'sha256:4f2a…9c1d', stats: stats(48_210, 312) },
    { id: GW_IDS.hermes02, name: 'gw-hermes-02', hostname: 'hermes-02.interne.lan', status: 'online', version: '0.1.0', active_revision: 42, desired_revision: 42, last_seen_at: new Date(now - 7_000).toISOString(), registered_at: new Date(now - 30 * 86_400_000).toISOString(), ca_fingerprint: 'sha256:4f2a…9c1d', stats: stats(12_877, 95) },
    { id: GW_IDS.ops01, name: 'gw-ops-01', hostname: 'ops-01.k8s.lan', status: 'offline', version: '0.1.0', active_revision: 41, desired_revision: 42, last_seen_at: new Date(now - 26 * 60_000).toISOString(), registered_at: new Date(now - 20 * 86_400_000).toISOString(), ca_fingerprint: null, stats: null },
  ]
}

interface FlowSeed {
  id: Uuid
  agent: Uuid
  dest: string
  ip: string
  port: number
  app: FlowEvent['app']
  verdict: FlowEvent['verdict']
  rule: Uuid | null
  layer: 'baseline' | 'zone' | 'implicit'
  reason: string
  minutesAgo: number
  bytesOut: number
  observed?: boolean
  internal?: boolean
  llm?: boolean
  method?: string
  path?: string
  status?: number
  tool?: { name: string, args: string, conversation: string }
  findings?: HttpEvent['findings']
}

const FLOW_SEEDS: FlowSeed[] = [
  { id: FLOW_IDS.upload, agent: AGENT_IDS.daniel, dest: 'upload.fichiers-partage.example', ip: '203.0.113.40', port: 443, app: 'https', verdict: 'deny', rule: null, layer: 'implicit', reason: 'cleanup of zone bots-internes', minutesAgo: 1, bytesOut: 412, method: 'PUT', path: '/v1/files/rapport-q3.pdf', status: 403, tool: { name: 'upload_file', args: 'path: rapport-q3.pdf', conversation: 'c-7f21' } },
  { id: FLOW_IDS.llm, agent: AGENT_IDS.daniel, dest: 'api.anthropic.com', ip: '160.79.104.10', port: 443, app: 'https', verdict: 'allow', rule: RULE_IDS.llm, layer: 'baseline', reason: 'matched', minutesAgo: 2, bytesOut: 18_400, llm: true, method: 'POST', path: '/v1/messages', status: 200, tool: { name: 'llm_call', args: 'model: claude', conversation: 'c-7f21' } },
  { id: FLOW_IDS.s3, agent: AGENT_IDS.daniel, dest: 's3.fr-par.scw.cloud', ip: '51.159.62.10', port: 443, app: 'https', verdict: 'allow', rule: RULE_IDS.s3, layer: 'zone', reason: 'matched', minutesAgo: 4, bytesOut: 4_100_000, method: 'PUT', path: '/compte-rendus/2026-10-31.pdf', status: 200, tool: { name: 'upload_file', args: 'path: 2026-10-31.pdf', conversation: 'c-7f20' } },
  { id: FLOW_IDS.metadata, agent: AGENT_IDS.acme, dest: '169.254.169.254', ip: '169.254.169.254', port: 80, app: 'http', verdict: 'deny', rule: RULE_IDS.metadata, layer: 'baseline', reason: 'matched', minutesAgo: 6, bytesOut: 312, method: 'GET', path: '/latest/meta-data/iam/', status: 403 },
  { id: FLOW_IDS.coolify, agent: AGENT_IDS.vulcain, dest: 'coolify.interne.lan', ip: '10.0.4.20', port: 443, app: 'https', verdict: 'allow', rule: RULE_IDS.coolify, layer: 'zone', reason: 'matched', minutesAgo: 9, bytesOut: 2_300, internal: true, method: 'POST', path: '/api/v1/applications/restart', status: 200 },
  { id: FLOW_IDS.graph, agent: AGENT_IDS.laurent, dest: 'graph.microsoft.com', ip: '20.190.151.6', port: 443, app: 'https', verdict: 'allow', rule: RULE_IDS.m365, layer: 'zone', reason: 'matched', minutesAgo: 12, bytesOut: 9_400, method: 'POST', path: '/v1.0/me/sendMail', status: 202, tool: { name: 'send_mail', args: 'to: support@exemple.fr', conversation: 'c-81aa' } },
  { id: FLOW_IDS.glpi, agent: AGENT_IDS.vulcain, dest: '10.0.4.12', ip: '10.0.4.12', port: 443, app: 'https', verdict: 'allow', rule: RULE_IDS.glpi, layer: 'zone', reason: 'matched', minutesAgo: 15, bytesOut: 1_200, internal: true, method: 'GET', path: '/apirest.php/Ticket', status: 200 },
  { id: FLOW_IDS.ssh, agent: AGENT_IDS.vulcain, dest: '10.0.2.31', ip: '10.0.2.31', port: 22, app: 'ssh', verdict: 'deny', rule: null, layer: 'implicit', reason: 'cleanup of zone ops', minutesAgo: 18, bytesOut: 0, internal: true },
  { id: FLOW_IDS.observed, agent: AGENT_IDS.compta, dest: 'api.pennylane.example', ip: '198.51.100.7', port: 443, app: 'https', verdict: 'allow', rule: null, layer: 'implicit', reason: 'observe mode: would be denied', minutesAgo: 22, bytesOut: 5_600, observed: true, method: 'GET', path: '/api/external/v1/invoices', status: 200 },
]

const ZONE_OF: Record<Uuid, Uuid> = Object.fromEntries(agents.map(a => [a.id, a.zone_id]))
const GW_OF: Record<Uuid, Uuid> = Object.fromEntries(agents.map(a => [a.id, a.gateway_id!]))
const IP_OF: Record<Uuid, string> = Object.fromEntries(agents.map(a => [a.id, a.addresses[0]!]))

export interface SeedLogs {
  flows: FlowEvent[]
  http: HttpEvent[]
  toolCalls: (ToolCallEvent & { flow_id: Uuid })[]
}

function flowOf(s: FlowSeed, now: number, ruleNumber: (id: Uuid | null) => number | null, ruleName: (id: Uuid | null) => string): FlowEvent {
  const started = now - s.minutesAgo * 60_000 - 7_000
  const isDomain = /[a-z]/i.test(s.dest)
  return {
    id: s.id,
    gateway_id: GW_OF[s.agent]!,
    agent_id: s.agent,
    zone_id: ZONE_OF[s.agent]!,
    src: `${IP_OF[s.agent]}:${40_000 + (s.minutesAgo * 37) % 20_000}`,
    dst: `${s.ip}:${s.port}`,
    protocol: 'tcp',
    app: s.app,
    domain: isDomain ? s.dest : null,
    sni: isDomain && s.app === 'https' ? s.dest : null,
    bytes_out: s.bytesOut,
    bytes_in: Math.round(s.bytesOut * 0.6) + 300,
    started_at: new Date(started).toISOString(),
    ended_at: new Date(started + 180).toISOString(),
    verdict: s.verdict,
    decision: { rule_id: s.rule, rule_number: ruleNumber(s.rule), rule_name: s.rule ? ruleName(s.rule) : (s.verdict === 'deny' ? 'cleanup' : 'observe'), layer: s.layer, reason: s.reason, revision: 42 },
    internal: !!s.internal,
    llm_provider: !!s.llm,
    observed: !!s.observed,
    tls_inspected: s.app === 'https' && !s.llm,
    // Raw TCP relays (internal SSH, metadata-only flows) carry no analysed content.
    content_inspected: s.app === 'http' || (s.app === 'https' && !s.llm),
    data_classes: [],
  }
}

/** Journal: the named flows above plus background traffic over the last 60 minutes. */
export function seedLogs(now: number, ruleNumber: (id: Uuid | null) => number | null, ruleName: (id: Uuid | null) => string): SeedLogs {
  const flows: FlowEvent[] = []
  const http: HttpEvent[] = []
  const toolCalls: SeedLogs['toolCalls'] = []
  const background: FlowSeed[] = []
  const templates = FLOW_SEEDS.filter(s => s.verdict === 'allow' && !s.observed)
  for (let i = 0; i < 160; i++) {
    const t = templates[i % templates.length]!
    background.push({ ...t, id: uid('8d000000', i + 1), minutesAgo: (i * 7) % 57 + 2 + (i % 3) / 3, tool: undefined, bytesOut: t.bytesOut + (i * 113) % 4000 })
  }
  for (let i = 0; i < 14; i++) {
    background.push({ ...FLOW_SEEDS[0]!, id: uid('8e000000', i + 1), minutesAgo: (i * 11) % 58 + 2, tool: undefined, dest: `cdn${i % 3}.fichiers-partage.example` })
  }
  for (const s of [...FLOW_SEEDS, ...background]) {
    const f = flowOf(s, now, ruleNumber, ruleName)
    flows.push(f)
    if (s.method) {
      const reqBody = s.method === 'GET' ? null : { encoding: 'utf8' as const, data: s.findings ? '{"key":"AKIA****************"}' : '{"name":"rapport-q3.pdf"}', size: 62, truncated: false, sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' }
      http.push({
        id: uid('8f000000', http.length + 1),
        flow_id: f.id,
        gateway_id: f.gateway_id,
        agent_id: f.agent_id,
        at: f.started_at,
        method: s.method,
        url: `https://${s.dest}${s.path ?? '/'}`,
        host: s.dest,
        request_headers: [['host', s.dest], ['user-agent', 'hermes-agent/1.4'], ['authorization', 'Bearer ****']],
        request_body: reqBody,
        status: s.status ?? null,
        response_headers: s.verdict === 'deny' ? [['content-type', 'text/plain'], ['x-afw-rule', String(f.decision.rule_number ?? 'default-deny')]] : [['content-type', 'application/json']],
        response_body: s.verdict === 'deny' ? { encoding: 'utf8', data: `blocked by agents-firewall: ${s.dest} not allowed for ${agents.find(a => a.id === s.agent)!.name} (rule ${f.decision.rule_number ?? 'default-deny'})`, size: 90, truncated: false, sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' } : null,
        findings: s.findings ?? [],
        admin_action: s.dest === 'coolify.interne.lan' ? { system: 'coolify', action: 'restart', resource: 'applications/hermes-acme' } : null,
        websocket: false,
      })
    }
    if (s.tool) {
      toolCalls.push({ id: uid('8a000000', toolCalls.length + 1), flow_id: f.id, agent: agents.find(a => a.id === s.agent)!.name, conversation_id: s.tool.conversation, tool: s.tool.name, args_summary: s.tool.args, started_at: new Date(new Date(f.started_at).getTime() - 300).toISOString(), ended_at: f.ended_at, status: 'ok' })
    }
  }
  flows.sort((a, b) => b.started_at.localeCompare(a.started_at))
  return { flows, http, toolCalls }
}

export function seedAlerts(now: number): { event: AlertEvent, gateway_id: Uuid | null, acknowledged: boolean, acknowledged_by: Actor | null }[] {
  const a = (n: number, kind: AlertKind, severity: Severity, min: number, agentId: Uuid, summary: string, details: unknown = null, ack: Actor | null = null) => ({
    event: { id: uid('90000000', n), at: new Date(now - min * 60_000).toISOString(), kind, severity, agent_id: agentId, summary, details },
    gateway_id: GW_OF[agentId] ?? null,
    acknowledged: !!ack,
    acknowledged_by: ack,
  })
  return [
    a(1, 'cloud_metadata', 'critical', 6, AGENT_IDS.acme, 'hermes-acme a tenté de joindre 169.254.169.254 (métadonnées cloud)', { destination: '169.254.169.254' }),
    a(2, 'deny_burst', 'warning', 9, AGENT_IDS.daniel, '15 refus en 5 minutes vers *.fichiers-partage.example', { count: 15 }),
    a(3, 'unusual_admin_action', 'warning', 9, AGENT_IDS.vulcain, 'vulcain-bot a redémarré une application Coolify (action inhabituelle)', { system: 'coolify', action: 'restart' }),
    a(4, 'new_internal_host', 'info', 18, AGENT_IDS.vulcain, 'vulcain-bot a contacté un nouvel hôte interne 10.0.2.31:22', { destination: '10.0.2.31:22' }),
    a(5, 'new_destination', 'info', 300, AGENT_IDS.compta, 'hermes-compta : nouvelle destination api.pennylane.example', null, KILLIAN),
  ]
}

export function seedChannels(): AlertChannel[] {
  return [
    { id: uid('91000000', 1), kind: 'webhook', name: 'webhook-soc', url: 'https://soc.exemple.fr/hooks/****', min_severity: 'warning', enabled: true },
    { id: uid('91000000', 2), kind: 'teams', name: 'teams-exploitation', url: 'https://exemple.webhook.office.com/****', min_severity: 'critical', enabled: true },
  ]
}

export function seedTokens(now: number): ApiToken[] {
  return [
    { id: uid('92000000', 1), name: 'ci-politique', role: 'admin', created_at: new Date(now - 12 * 86_400_000).toISOString(), created_by: KILLIAN, last_used_at: new Date(now - 3_600_000).toISOString(), expires_at: null, agent_id: null },
    { id: uid('92000000', 2), name: 'mcp-vulcain', role: 'mcp_agent', created_at: new Date(now - 20 * 86_400_000).toISOString(), created_by: KILLIAN, last_used_at: new Date(now - 600_000).toISOString(), expires_at: null, agent_id: AGENT_IDS.vulcain },
  ]
}
