import type {
  AgentListItem,
  AgentOverview,
  AlertChannel,
  AlertView,
  AllowFromLogRequest,
  AuditEntry,
  AuditQuery,
  AuditVerify,
  Capture,
  CaptureRequest,
  FlowDetail,
  FlowQuery,
  FlowStats,
  FlowSummary,
  Gateway,
  GatewayCommandKind,
  Install,
  InternalMap,
  Me,
  NetObjectView,
  Page,
  PolicyStatus,
  RegistrationToken,
  Revision,
  RuleQuery,
  Rulebase,
  RuleView,
  Session,
  SessionChange,
  StreamEvent,
  Uuid,
  VerifyReport,
  WhereUsed,
  ZoneView,
} from './types'

/**
 * Everything the console needs from the control-plane REST API (`/api/v1`, plan §3.4).
 * One method per resource/operation; implemented by `mock.ts` (development, demo, tests) and
 * `http.ts` (real API). The console holds no policy logic: every derived value (evaluation
 * trace, counters, allow proposal, verification) comes from here.
 */
export interface AfwApi {
  // --- auth (`me`, `tokens`) ---
  /** GET /me — validates the bearer token. */
  me(): Promise<Me>
  /** URL of the OIDC login entry point (with the anti-CSRF `state`), or null when the mode does not use OIDC. */
  oidcLoginUrl(redirect: string, state: string): string | null
  /** GET /policy/status — installed revision and gateway coverage as reported by the control plane. */
  policyStatus(): Promise<PolicyStatus>

  // --- logs ---
  /** GET /logs/flows */
  listFlows(query: FlowQuery): Promise<Page<FlowSummary>>
  /** GET /logs/flows/stats — counters and per-minute histogram for the journal header. */
  flowStats(query: FlowQuery): Promise<FlowStats>
  /** GET /logs/flows/{id} — detail + http + tool call + correlation + evaluation trace. */
  getFlow(id: Uuid): Promise<FlowDetail>
  /** GET /logs/stream (SSE). Returns an unsubscribe function. */
  streamLogs(onEvent: (event: StreamEvent) => void): () => void
  /** POST /captures */
  startCapture(req: CaptureRequest): Promise<Capture>

  // --- policy objects ---
  /** GET /objects (+ services, data classes and agents as browseable objects). */
  listObjects(): Promise<NetObjectView[]>
  /** GET /objects/{id}/where-used */
  whereUsed(id: Uuid): Promise<WhereUsed[]>
  /** GET /zones */
  listZones(): Promise<ZoneView[]>

  // --- rules ---
  /** GET /rules?zone_id=… — baseline + one zone layer, with counters. */
  getRulebase(query: RuleQuery): Promise<Rulebase>
  /** GET /rules/{id} */
  getRule(id: Uuid): Promise<RuleView>

  // --- sessions, publish, install ---
  /** GET /sessions/current — null when the caller has no open session. */
  currentSession(): Promise<Session | null>
  /** POST /sessions */
  openSession(name: string): Promise<Session>
  /** POST /sessions/{id}/discard */
  discardSession(id: Uuid): Promise<void>
  /** POST /sessions/{id}/allow-from-log (EF-42) — adds the pre-filled rule to the session. */
  allowFromLog(sessionId: Uuid, req: AllowFromLogRequest): Promise<{ rule: RuleView, changes: SessionChange[] }>
  /** GET /verify — checks before install (on the session draft when revision is omitted). */
  verify(revision?: number): Promise<VerifyReport>
  /** POST /sessions/{id}/publish */
  publishSession(id: Uuid, comment: string): Promise<Revision>
  /** GET /revisions */
  listRevisions(): Promise<Revision[]>
  /** GET /revisions/{n} */
  getRevision(n: number): Promise<Revision>
  /** POST /installs */
  install(revision: number, gatewayIds: Uuid[]): Promise<Install>

  // --- agents ---
  /** GET /agents */
  listAgents(): Promise<AgentListItem[]>
  /** GET /agents/{id}/overview (EF-43) */
  agentOverview(id: Uuid): Promise<AgentOverview>

  // --- monitoring ---
  /** GET /alerts */
  listAlerts(): Promise<AlertView[]>
  /** POST /alerts/{id}/ack */
  acknowledgeAlert(id: Uuid): Promise<AlertView>
  /** GET /alert-channels */
  listAlertChannels(): Promise<AlertChannel[]>
  /** GET /internal-map */
  internalMap(period: '1h' | '24h' | '7d'): Promise<InternalMap>

  // --- audit ---
  /** GET /audit */
  listAudit(query: AuditQuery): Promise<Page<AuditEntry>>
  /** GET /audit/verify */
  verifyAudit(): Promise<AuditVerify>
  /** GET /audit/export (NDJSON), fetched with the caller's token. */
  exportAudit(): Promise<Blob>

  // --- gateways ---
  /** GET /gateways */
  listGateways(): Promise<Gateway[]>
  /** GET /installs */
  listInstalls(): Promise<Install[]>
  /** POST /gateways/registration-tokens */
  createRegistrationToken(): Promise<RegistrationToken>
  /** POST /gateways/{id}/commands */
  sendGatewayCommand(id: Uuid, command: GatewayCommandKind): Promise<void>
}

export type ApiMode = 'mock' | 'http'

/** Error raised for `application/problem+json` answers (or network failures, status 0). */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly title: string,
    readonly detail?: string,
  ) {
    super(detail ? `${title}: ${detail}` : title)
    this.name = 'ApiError'
  }
}
