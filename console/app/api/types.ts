/**
 * Types mirroring the shared contracts of the V1 plan (docs/superpowers/plans/2026-10-30-agents-firewall-v1.md §3).
 * Field names are the snake_case JSON names produced by `afw-core` (serde `rename_all = "snake_case"`).
 *
 * L3b replaces this file with types generated from docs/api/openapi.yaml (openapi-typescript).
 * Until then, choices not fixed by §3 (enum tagging, read views) are documented in ADR 0014.
 */

export type Uuid = string
/** RFC 3339 timestamp. */
export type DateTime = string

// ---------------------------------------------------------------------------
// §3.1 Policy model
// ---------------------------------------------------------------------------

export type DestCategory = 'llm_provider' | 'cloud_metadata' | 'internal'

/** Internally tagged on `type` (ADR 0014). */
export type NetObjectSpec =
  | { type: 'domain', pattern: string }
  | { type: 'host', ip: string }
  | { type: 'network', cidr: string }
  | { type: 'range', start: string, end: string }
  | { type: 'group', members: Uuid[] }
  | { type: 'any' }

export interface NetObject {
  id: Uuid
  name: string
  comment: string
  category: DestCategory | null
  spec: NetObjectSpec
}

export type L4Proto = 'tcp' | 'udp' | 'any'
export type AppProto = 'http' | 'https' | 'dns' | 'ssh' | 'tls' | 'other'

export interface PortRange {
  start: number
  end: number
}

export interface AppMatch {
  proto: AppProto
  methods: string[]
  path_prefixes: string[]
}

export interface Service {
  id: Uuid
  name: string
  comment: string
  protocol: L4Proto
  ports: PortRange[]
  app: AppMatch | null
}

export type DataCategory = 'secret' | 'infra' | 'commercial' | 'personal' | 'custom'

export type Detector =
  | { type: 'builtin', id: string }
  | { type: 'regex', name: string, pattern: string }

export interface DataClass {
  id: Uuid
  name: string
  comment: string
  category: DataCategory
  detectors: Detector[]
}

export type ZoneMode = 'enforce' | 'observe'

export interface Zone {
  id: Uuid
  name: string
  comment: string
  mode: ZoneMode
  delegated_to_mcp: boolean
}

export type AgentKind = 'docker_compose' | 'coolify' | 'kubernetes' | 'container'

export interface Agent {
  id: Uuid
  name: string
  zone_id: Uuid
  kind: AgentKind
  gateway_id: Uuid | null
  addresses: string[]
  labels: Record<string, string>
  hermes: boolean
  mcp_admin: boolean
}

export type Layer = { type: 'baseline' } | { type: 'zone', zone_id: Uuid }
export type Action = 'accept' | 'deny'
export type Track = 'none' | 'log' | 'detailed' | 'capture'

export interface Rule {
  id: Uuid
  name: string
  layer: Layer
  section: string | null
  position: number
  /** Zones; empty = all (baseline only). */
  sources: Uuid[]
  /** Objects; empty = any. */
  destinations: Uuid[]
  /** Services; empty = any. */
  services: Uuid[]
  /** Data classes; empty = no content condition. */
  data_classes: Uuid[]
  action: Action
  track: Track
  expires_at: DateTime | null
  comment: string
  enabled: boolean
}

export type InspectionAction = 'inspect' | 'bypass'

export interface InspectionRule {
  id: Uuid
  name: string
  position: number
  zones: Uuid[]
  destinations: Uuid[]
  action: InspectionAction
}

export interface Retention {
  flows: number
  http: number
  captures: number
}

export interface PolicySettings {
  internal_networks: string[]
  max_buffered_body: number
  max_stored_body: number
  retention_days: Retention
}

// ---------------------------------------------------------------------------
// §3.3 Events
// ---------------------------------------------------------------------------

export type Verdict = 'allow' | 'deny'

export interface DecisionRef {
  rule_id: Uuid | null
  rule_number: number | null
  rule_name: string
  /** baseline | zone | implicit */
  layer: 'baseline' | 'zone' | 'implicit'
  reason: string
}

export interface FlowEvent {
  id: Uuid
  gateway_id: Uuid
  agent_id: Uuid | null
  zone_id: Uuid | null
  /** "ip:port" */
  src: string
  /** "ip:port" */
  dst: string
  protocol: L4Proto
  app: AppProto | null
  domain: string | null
  sni: string | null
  bytes_out: number
  bytes_in: number
  started_at: DateTime
  ended_at: DateTime | null
  verdict: Verdict
  decision: DecisionRef
  internal: boolean
  llm_provider: boolean
  tls_inspected: boolean
  data_classes: string[]
  observed: boolean
}

export interface DnsEvent {
  id: Uuid
  gateway_id: Uuid
  agent_id: Uuid | null
  at: DateTime
  qname: string
  qtype: string
  answers: string[]
  verdict: Verdict
  decision: DecisionRef
}

export interface Body {
  encoding: 'utf8' | 'base64'
  data: string
  size: number
  truncated: boolean
  sha256: string
}

export interface Finding {
  class: string
  category: DataCategory
  kind: string
  fingerprint: string
  location: string
}

export interface AdminAction {
  system: 'kubernetes' | 'coolify' | 'docker' | 'proxmox'
  action: string
  resource: string
}

export interface HttpEvent {
  id: Uuid
  flow_id: Uuid
  gateway_id: Uuid
  agent_id: Uuid | null
  at: DateTime
  method: string
  url: string
  host: string
  request_headers: [string, string][]
  request_body: Body | null
  status: number | null
  response_headers: [string, string][]
  response_body: Body | null
  findings: Finding[]
  admin_action: AdminAction | null
  websocket: boolean
}

export type AlertKind =
  | 'new_destination'
  | 'volume_spike'
  | 'deny_burst'
  | 'cloud_metadata'
  | 'secret_detected'
  | 'port_scan'
  | 'new_internal_host'
  | 'sensitive_port'
  | 'internal_burst'
  | 'unusual_admin_action'

export type Severity = 'info' | 'warning' | 'critical'

export interface AlertEvent {
  id: Uuid
  at: DateTime
  kind: AlertKind
  severity: Severity
  agent_id: Uuid | null
  summary: string
  details: Record<string, unknown>
}

export interface ToolCallEvent {
  id: Uuid
  agent: string
  conversation_id: string
  tool: string
  args_summary: string
  started_at: DateTime
  ended_at: DateTime | null
  status: string | null
}

export type ActorKind = 'human' | 'cli' | 'agent' | 'system'
export type Interface = 'ui' | 'cli' | 'mcp' | 'api' | 'system'

export interface Actor {
  kind: ActorKind
  id: string
  name: string
}

export interface AuditEntry {
  seq: number
  at: DateTime
  actor: Actor
  interface: Interface
  session_id: string | null
  action: string
  target: string
  diff: unknown
  prev_hash: string
  hash: string
}

// ---------------------------------------------------------------------------
// §3.4 REST read views (shapes returned by /api/v1, see ADR 0014)
// ---------------------------------------------------------------------------

export interface Page<T> {
  items: T[]
  next_cursor: string | null
  /** Total matching items when the server can count them cheaply. */
  total: number | null
}

export interface FlowQuery {
  agent?: string
  zone?: string
  destination?: string
  verdict?: Verdict
  rule?: string
  /** Only flows that raised an alert. */
  alert?: boolean
  from?: DateTime
  to?: DateTime
  q?: string
  cursor?: string
  limit?: number
}

/** A flow row of the journal: the event plus the names the UI shows and the correlated tool call. */
export interface FlowSummary extends FlowEvent {
  agent_name: string | null
  zone_name: string | null
  gateway_name: string
  /** Display number of the matched rule: "S3" for the baseline, "12" for a zone rule. */
  rule_label: string
  method: string | null
  path: string | null
  tool: string | null
  correlation: Correlation | null
  alert: boolean
}

export interface Correlation {
  /** certain = call id propagated by the Hermes plugin; uncertain = time-window match. */
  confidence: 'certain' | 'uncertain'
  method: string
  conversation_id: string
  conversation_title: string
  /** Untrusted input that triggered the action (mail, ticket, web page…). */
  trigger_source: string | null
  trigger_text: string | null
  reasoning: string | null
}

export interface FlowStats {
  total: number
  allowed: number
  denied: number
  alerts: number
  per_minute: number
  /** One bucket per minute, oldest first. */
  histogram: { at: DateTime, allowed: number, denied: number }[]
}

export type TraceResult = 'no_match' | 'accept' | 'deny' | 'observe'

/** One line of the evaluation trace computed by the engine (never by the console). */
export interface TraceStep {
  /** "S1", "S1–S5", "1–11", "12"… */
  label: string
  /** Rule name; empty for a collapsed range (see `range`). */
  name: string
  result: TraceResult
  rule_id: Uuid | null
  /** Set when several non-matching rules are collapsed into one line. */
  range: { layer: 'baseline' | 'zone', count: number, zone: string | null } | null
}

export interface DestinationOption {
  key: 'exact' | 'group' | 'wildcard'
  value: string
  object_id: Uuid | null
  /** Members count for an existing group. */
  members: number | null
  broadening: boolean
}

/** Pre-filled rule offered by the API for a denied flow (EF-42). */
export interface AllowProposal {
  zone: Zone
  zone_agents: string[]
  destination_options: DestinationOption[]
  service: string
  /** Display number of the rule the new one is inserted before. */
  before_rule: string
  would_allow: { flows: number, agents: string[] }
}

export interface FlowDetail {
  flow: FlowSummary
  http: HttpEvent | null
  dns: DnsEvent | null
  tool_call: ToolCallEvent | null
  trace: TraceStep[]
  /** Message received by the agent (EF-21), when denied. */
  agent_message: string | null
  /** Present when the flow was denied by a rule that may be overridden (never the baseline). */
  allow_proposal: AllowProposal | null
  data_class_label: string | null
}

export interface AllowFromLogRequest {
  flow_id: Uuid
  destination: DestinationOption['key']
  expires_in_days: number | null
  track: Track
  comment?: string
}

export interface RuleView extends Rule {
  /** Global display number ("S1", "12"). */
  number: string
  source_names: string[]
  destination_names: string[]
  service_names: string[]
  data_class_names: string[]
  inspection: InspectionAction | null
  hits: number
  last_hit_at: DateTime | null
  /** Share of the busiest rule, 0..1, computed by the API for the usage bar. */
  hit_ratio: number
  expired: boolean
  /** Rule added or changed in the caller's open session. */
  in_session: boolean
  /** Renumbered by the caller's session: former number. */
  previous_number: string | null
}

export interface RuleQuery {
  zone_id?: Uuid
  q?: string
}

export interface Rulebase {
  baseline: RuleView[]
  zone: RuleView[]
  zone_id: Uuid | null
  /** Observation summary for an observe-mode zone. */
  observation: { since: DateTime, destinations: number, uncovered: number } | null
}

export interface WhereUsed {
  kind: 'rule' | 'inspection' | 'alert' | 'map' | 'zone' | 'gateway' | 'masking'
  /** Rule display number, zone or gateway name… */
  ref: string | null
  name: string
  zone: string | null
  hits: number | null
  last_at: DateTime | null
  note: string | null
}

export interface NetObjectView {
  id: Uuid
  name: string
  kind: 'domain' | 'host' | 'network' | 'range' | 'group' | 'any' | 'service' | 'data_class' | 'agent'
  value: string
  comment: string
  members: string[]
  in_session: boolean
  used_in: number
  builtin: boolean
  last_change: { revision: number, by: string, at: DateTime | null, note: string | null } | null
}

export interface ZoneView extends Zone {
  agents: { id: Uuid, name: string }[]
  rule_count: number
  rules_in_session: number
  expired_rules: number
  gateways: string[]
  /** The zone holds the approved MCP agent itself: it can never be delegated. */
  holds_mcp_agent: boolean
  observe_since: DateTime | null
}

export interface SessionChange {
  op: 'add' | 'update' | 'delete' | 'renumber'
  kind: 'rule' | 'object' | 'zone' | 'group' | 'service' | 'data_class' | 'agent'
  target: string
  summary: string
  before: string | null
  after: string | null
}

export interface Session {
  id: Uuid
  name: string
  owner: Actor
  opened_at: DateTime
  changes: SessionChange[]
  locked_objects: number
  state: 'open' | 'published' | 'discarded'
  /** Revision the session was opened on (differences are computed against it). */
  base_revision: number
  /** Number the revision will get if this session is published now (given by the API). */
  next_revision: number
}

/** Installed policy as the control plane sees it (GET /policy/status). */
export interface PolicyStatus {
  latest_revision: number
  installed_revision: number | null
  gateways_on_revision: number
  gateways_total: number
  /** Added latency, p95 over all gateways, computed by the API. */
  latency_p95_ms: number | null
}

export interface VerifyFinding {
  severity: 'error' | 'warning'
  code: 'shadowed_rule' | 'expired_rule' | 'unused_object' | 'missing_cleanup' | 'empty_group' | string
  /** Server message (fallback when the console has no translation for `code`). */
  message: string
  /** Values for the translated message (rule number, name, zone, object…). */
  params: Record<string, string>
}

export interface VerifyReport {
  revision: number | null
  ok: boolean
  findings: VerifyFinding[]
}

export interface Revision {
  number: number
  title: string
  comment: string
  author: Actor
  interface: Interface
  published_at: DateTime
  session_id: string
  changes: SessionChange[]
  /** Human approval note for a broadening change made by the MCP agent (EF-52). */
  approval: string | null
  installed: boolean
  installs: InstallResult[]
}

export interface InstallResult {
  gateway_id: Uuid
  gateway_name: string
  revision: number
  ok: boolean
  error: string | null
  duration_ms: number | null
  at: DateTime
  by: string
}

export interface Install {
  id: Uuid
  revision: number
  requested_by: string
  requested_at: DateTime
  results: InstallResult[]
}

export type GatewayStatus = 'online' | 'degraded' | 'offline'

export interface GatewayStats {
  flows_per_min: number
  bytes_out_per_min: number
  latency_p50_ms: number
  latency_p95_ms: number
}

export interface Gateway {
  id: Uuid
  name: string
  hostname: string
  environment: string
  kind: AgentKind
  status: GatewayStatus
  status_detail: string | null
  version: string
  update_available: string | null
  revision: number | null
  revision_installed_at: DateTime | null
  last_seen_at: DateTime | null
  link: string
  agents: string[]
  zones: string[]
  stats: GatewayStats
  tls: string
  isolation: string
}

export interface RegistrationToken {
  token: string
  expires_at: DateTime
  command: string
}

export type GatewayCommandKind = 'reinstall' | 'self_test' | 'start_capture'

export interface AlertView extends AlertEvent {
  title: string
  agent_name: string | null
  context: string
  acknowledged_by: string | null
  resolved: boolean
}

export interface AlertChannel {
  id: Uuid
  kind: 'webhook' | 'teams' | 'pulse_chat'
  name: string
  enabled: boolean
}

export interface InternalNode {
  id: string
  label: string
  sub: string
  kind: 'agent' | 'system'
  zone_mode?: ZoneMode
  state: 'normal' | 'alert' | 'new'
  href: string | null
}

export interface InternalEdge {
  from: string
  to: string
  /** Relative volume 1..6 for the stroke width. */
  weight: number
  state: 'usual' | 'new' | 'alert'
}

export interface AdminCall {
  at: DateTime
  agent_name: string
  api: string
  action: string
  resource: string
  signal: 'unusual' | null
}

export interface InternalMap {
  period: '1h' | '24h' | '7d'
  nodes: InternalNode[]
  edges: InternalEdge[]
  admin_calls: AdminCall[]
}

export interface AgentListItem {
  agent: Agent
  zone_name: string
  gateway_name: string | null
  last_flow_at: DateTime | null
  flows_24h: number
  denied_24h: number
  description: string
}

export interface AgentDestination {
  destination: string
  rule_label: string
  rule_layer: DecisionRef['layer']
  verdict: Verdict
  flows: number
  bytes_out: number | null
  last_at: DateTime
  tags: ('new' | 'internal' | 'denied')[]
}

export interface AgentOverview {
  agent: Agent
  zone: Zone
  gateway_name: string | null
  description: string
  enrolled_at: DateTime
  enrollment: string
  egress_guard: string | null
  last_flow_at: DateTime | null
  flows_24h: number
  llm_flows_24h: number
  bytes_out_24h: number
  bytes_in_24h: number
  denied_24h: number
  denied_destinations_24h: number
  destinations_7d: number
  new_destinations_7d: number
  /** 24 hourly buckets, oldest first, excluding LLM providers. */
  volume: { at: DateTime, allowed_bytes: number, denied_bytes: number }[]
  volume_note: string | null
  destinations: AgentDestination[]
  recent_denials: { destination: string, count: number, last_at: DateTime, rule_label: string, rule_layer: DecisionRef['layer'], reason: string, flow_id: Uuid, can_allow: boolean }[]
  top_tools: { tool: string, flows: number, bytes_out: number, denied: number }[]
}

export interface CaptureRequest {
  agent_id: Uuid
  duration_secs: number
}

export interface Capture {
  id: Uuid
  agent_id: Uuid
  duration_secs: number
  state: 'pending' | 'running' | 'done' | 'failed'
  created_at: DateTime
}

export interface Me {
  id: string
  name: string
  email: string | null
  role: 'admin' | 'auditor' | 'viewer' | 'mcp_agent'
  auth: 'oidc' | 'token'
  tenant: string
}

export interface AuditQuery {
  actor?: string
  interface?: Interface
  cursor?: string
  limit?: number
}

export interface AuditVerify {
  ok: boolean
  checked: number
  anchor_exported_at: DateTime | null
}

export interface ApiProblem {
  type?: string
  title: string
  status: number
  detail?: string
}

/** Events pushed by GET /logs/stream (SSE). */
export type StreamEvent = { type: 'flow', flow: FlowSummary } | { type: 'alert', alert: AlertView }
