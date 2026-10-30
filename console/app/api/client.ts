import type {
  AgentOverview,
  Agent,
  Alert,
  AlertChannel,
  AlertQuery,
  AllowFromLogRequest,
  AllowFromLogResponse,
  ApiToken,
  Approval,
  ApprovalStatus,
  AuditEntry,
  AuditQuery,
  AuditVerify,
  Capture,
  CaptureRequest,
  CreateApiToken,
  CreatedApiToken,
  DataClass,
  FlowDetail,
  FlowListItem,
  FlowQuery,
  FlowStats,
  FlowStatsQuery,
  Gateway,
  GatewayCommand,
  InspectionRule,
  Install,
  InstallQuery,
  InstallResult,
  InternalMap,
  MapPeriod,
  Me,
  MoveRuleRequest,
  NetObject,
  OidcConfig,
  Page,
  PolicySettings,
  PolicyStatus,
  PublishOutcome,
  RegistrationToken,
  Revision,
  RevisionDetail,
  RevisionDiff,
  Rule,
  RuleQuery,
  Rulebase,
  RuleView,
  Service,
  Session,
  StreamEvent,
  StreamQuery,
  Uuid,
  VerifyReport,
  WhereUsed,
  Zone,
} from './types'

/** CRUD of a policy resource inside an editing session (`X-Afw-Session` required on writes). */
export interface PolicyCollection<T extends { id: Uuid }> {
  /** GET (draft of the current session when one is open, else the last published revision). */
  list(): Promise<T[]>
  get(id: Uuid): Promise<T>
  create(sessionId: Uuid, value: T): Promise<T>
  update(sessionId: Uuid, value: T): Promise<T>
  remove(sessionId: Uuid, id: Uuid): Promise<void>
}

/**
 * Everything the console needs from the control-plane REST API (`/api/v1`, `docs/api/openapi.yaml`).
 * Every type comes from the generated contract (`schema.d.ts`). Implemented by `http.ts`
 * (openapi-fetch) and `mock.ts` (development, demo, tests). The console holds no policy logic:
 * evaluation trace, counters, allow proposal, verification, numbering all come from here.
 *
 * Policy reads carry the caller's open session (`X-Afw-Session`, set with `setSession`) so that
 * they show the draft; writes take the session explicitly.
 */
export interface AfwApi {
  /** Session sent on policy reads (`null`: published policy). */
  setSession(id: Uuid | null): void

  // --- auth ---
  me(): Promise<Me>
  /** GET /auth/oidc/config (public). */
  oidcConfig(): Promise<OidcConfig>
  listTokens(): Promise<ApiToken[]>
  createToken(req: CreateApiToken): Promise<CreatedApiToken>
  revokeToken(id: Uuid): Promise<void>

  // --- logs ---
  listFlows(query: FlowQuery): Promise<Page<FlowListItem>>
  flowStats(query: FlowStatsQuery): Promise<FlowStats>
  getFlow(id: Uuid): Promise<FlowDetail>
  /** GET /logs/stream (SSE, reconnects with backoff). Returns an unsubscribe function. */
  streamLogs(onEvent: (event: StreamEvent) => void, query?: StreamQuery): () => void
  listCaptures(): Promise<Page<Capture>>
  startCapture(req: CaptureRequest): Promise<Capture>

  // --- policy resources ---
  objects: PolicyCollection<NetObject>
  services: PolicyCollection<Service>
  dataClasses: PolicyCollection<DataClass>
  zones: PolicyCollection<Zone>
  agents: PolicyCollection<Agent>
  rules: PolicyCollection<Rule>
  inspectionRules: PolicyCollection<InspectionRule>
  whereUsed(id: Uuid): Promise<WhereUsed>
  listRules(query?: RuleQuery): Promise<RuleView[]>
  moveRule(sessionId: Uuid, id: Uuid, req: MoveRuleRequest): Promise<Rule>
  getRulebase(): Promise<Rulebase>
  getSettings(): Promise<PolicySettings>
  updateSettings(sessionId: Uuid, settings: PolicySettings): Promise<PolicySettings>

  // --- sessions, revisions, installs ---
  /** GET /sessions/current — `null` when the caller has neither an open session nor a revision to install. */
  currentSession(): Promise<Session | null>
  openSession(name: string | null): Promise<Session>
  getSession(id: Uuid): Promise<Session>
  discardSession(id: Uuid): Promise<Session>
  allowFromLog(sessionId: Uuid, req: AllowFromLogRequest): Promise<AllowFromLogResponse>
  /** 201 → published revision, 202 → pending approval (EF-52). */
  publishSession(id: Uuid, comment: string): Promise<PublishOutcome>
  /** GET /verify — the open session's draft when `revision` is omitted. */
  verify(revision?: number): Promise<VerifyReport>
  listRevisions(): Promise<Page<Revision>>
  getRevision(n: number): Promise<RevisionDetail>
  diffRevision(n: number, against?: number): Promise<RevisionDiff>
  revertToRevision(n: number): Promise<Session>
  policyStatus(): Promise<PolicyStatus>
  listInstalls(query?: InstallQuery): Promise<Page<Install>>
  /** POST /installs (empty list = all gateways). */
  install(revision: number, gateways: Uuid[]): Promise<InstallResult>
  listApprovals(status?: ApprovalStatus): Promise<Approval[]>
  decideApproval(id: Uuid, approve: boolean, comment?: string): Promise<Approval>

  // --- agents ---
  agentOverview(id: Uuid): Promise<AgentOverview>

  // --- monitoring ---
  listAlerts(query?: AlertQuery): Promise<Page<Alert>>
  acknowledgeAlert(id: Uuid): Promise<Alert>
  alertChannels: Omit<PolicyCollection<AlertChannel>, 'create' | 'update' | 'remove'> & {
    create(value: AlertChannel): Promise<AlertChannel>
    update(value: AlertChannel): Promise<AlertChannel>
    remove(id: Uuid): Promise<void>
  }
  internalMap(period: MapPeriod): Promise<InternalMap>

  // --- audit ---
  listAudit(query?: AuditQuery): Promise<Page<AuditEntry>>
  verifyAudit(): Promise<AuditVerify>
  /** GET /audit/export (NDJSON), fetched with the caller's token. */
  exportAudit(): Promise<Blob>

  // --- gateways ---
  listGateways(): Promise<Gateway[]>
  deleteGateway(id: Uuid): Promise<void>
  createRegistrationToken(name: string | null): Promise<RegistrationToken>
  sendGatewayCommand(id: Uuid, command: GatewayCommand): Promise<void>
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

  /** Owner of the lock for a 423 answer ("locked by <name>"), else null. */
  get lockedBy(): string | null {
    if (this.status !== 423) return null
    const m = /^locked by (.+)$/.exec(this.detail ?? '')
    return m ? m[1]! : null
  }
}
