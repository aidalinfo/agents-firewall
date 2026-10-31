/**
 * Aliases of the types generated from the API contract (`docs/api/openapi.yaml` → `schema.d.ts`,
 * `pnpm gen:api`). No response shape is written by hand here: when the contract changes, regenerate.
 * The few console-side types (query objects, stream messages, publish outcome) are built from the
 * generated ones.
 */
import type { components, operations } from './schema'

type S = components['schemas']

export type Uuid = string
/** RFC 3339 timestamp. */
export type DateTime = string

// --- policy model ---
export type Action = S['Action']
export type Agent = S['Agent']
export type AgentKind = S['AgentKind']
export type AppMatch = S['AppMatch']
export type AppProto = S['AppProto']
export type DataCategory = S['DataCategory']
export type DataClass = S['DataClass']
export type DestCategory = S['DestCategory']
export type Detector = S['Detector']
export type InspectionAction = S['InspectionAction']
export type InspectionRule = S['InspectionRule']
export type L4Proto = S['L4Proto']
export type Layer = S['Layer']
export type NetObject = S['NetObject']
export type NetObjectSpec = S['NetObjectSpec']
export type PolicyDocument = S['PolicyDocument']
export type PolicySettings = S['PolicySettings']
export type PortRange = S['PortRange']
export type Rule = S['Rule']
export type Service = S['Service']
export type Track = S['Track']
export type Zone = S['Zone']
export type ZoneMode = S['ZoneMode']

// --- rule base and views ---
export type ChangeOp = S['ChangeOp']
export type MoveRuleRequest = S['MoveRuleRequest']
export type ResourceKind = S['ResourceKind']
export type ResourceRef = S['ResourceRef']
export type RuleSection = S['RuleSection']
export type RuleView = S['RuleView']
export type Rulebase = S['Rulebase']
export type ZoneLayerView = S['ZoneLayerView']
export type WhereUsed = S['WhereUsed']

// --- sessions, revisions, installs, approvals ---
export type AllowDestination = S['AllowDestination']
export type AllowFromLogRequest = S['AllowFromLogRequest']
export type AllowFromLogResponse = S['AllowFromLogResponse']
export type AllowProposal = S['AllowProposal']
export type Approval = S['Approval']
export type ApprovalStatus = S['ApprovalStatus']
export type Change = S['Change']
export type Install = S['Install']
export type InstallResult = S['InstallResult']
export type InstallState = S['InstallState']
export type PolicyStatus = S['PolicyStatus']
export type ProposedDestination = S['ProposedDestination']
export type Revision = S['Revision']
export type RevisionDetail = S['RevisionDetail']
export type RevisionDiff = S['RevisionDiff']
export type Session = S['Session']
export type SessionChange = S['SessionChange']
export type VerifyFinding = S['VerifyFinding']
export type VerifyReport = S['VerifyReport']

// --- logs ---
export type AdminAction = S['AdminAction']
export type Alert = S['Alert']
export type AlertEvent = S['AlertEvent']
export type AlertKind = S['AlertKind']
export type Body = S['Body']
export type Capture = S['Capture']
export type CaptureRequest = S['CaptureRequest']
export type Confidence = S['Confidence']
export type Correlation = S['Correlation']
export type DecisionRef = S['DecisionRef']
export type DestinationStat = S['DestinationStat']
export type DnsEvent = S['DnsEvent']
export type Finding = S['Finding']
export type FlowDetail = S['FlowDetail']
export type FlowEvent = S['FlowEvent']
export type FlowListItem = S['FlowListItem']
export type FlowStats = S['FlowStats']
export type FlowStatsPoint = S['FlowStatsPoint']
export type GatewayEvent = S['GatewayEvent']
export type HttpEvent = S['HttpEvent']
export type InternalMap = S['InternalMap']
export type MapEdge = S['MapEdge']
export type MapNode = S['MapNode']
export type MapPeriod = S['MapPeriod']
export type Severity = S['Severity']
export type StatsBucket = S['StatsBucket']
export type ToolCallEvent = S['ToolCallEvent']
export type TraceStep = S['TraceStep']
export type Verdict = S['Verdict']
export type AgentOverview = S['AgentOverview']

// --- monitoring, gateways, auth, audit ---
export type Actor = S['Actor']
export type AlertChannel = S['AlertChannel']
export type AlertChannelKind = S['AlertChannelKind']
export type ApiToken = S['ApiToken']
export type AuditEntry = S['AuditEntry']
export type AuditVerifyResult = S['AuditVerifyResult']
export type CreateApiToken = S['CreateApiToken']
export type CreatedApiToken = S['CreatedApiToken']
export type Gateway = S['Gateway']
export type GatewayCommand = S['GatewayCommand']
export type GatewayStats = S['GatewayStats']
export type GatewayStatus = S['GatewayStatus']
export type Interface = S['Interface']
export type Me = S['Me']
export type Problem = S['Problem']
export type RegistrationToken = S['RegistrationToken']
export type Role = S['Role']

/** `GET /audit/verify` (result + compared anchor sources). */
export type AuditVerify = operations['verifyAudit']['responses'][200]['content']['application/json']
/** `GET /auth/oidc/config`. */
export type OidcConfig = operations['oidcConfig']['responses'][200]['content']['application/json']

/** Cursor page as returned by the paginated collections (no total: the contract does not count). */
export interface Page<T> {
  items: T[]
  next_cursor?: string | null
}

// --- query objects (the query strings of the contract) ---
type Query<K extends keyof operations> = NonNullable<operations[K]['parameters']['query']>
export type FlowQuery = Query<'listFlows'>
export type FlowStatsQuery = Query<'flowStats'>
export type StreamQuery = Query<'streamLogs'>
export type AlertQuery = Query<'listAlerts'>
export type AuditQuery = Query<'listAudit'>
export type InstallQuery = Query<'listInstalls'>
export type RuleQuery = Query<'listRules'>

/**
 * Message of `GET /logs/stream`: the SSE `event:` name with its `GatewayEvent`, or the server's
 * `lagged` notice (events were skipped: the client reloads instead of trusting the stream).
 */
export type StreamEvent =
  | { kind: 'event', event: GatewayEvent }
  | { kind: 'lagged', skipped: number }

/** `POST /sessions/{id}/publish`: 201 (revision) or 202 (an approval is pending, EF-52). */
export type PublishOutcome =
  | { status: 'published', revision: Revision }
  | { status: 'approval', approval: Approval }
