//! REST DTOs of `/api/v1` shared by the API, the CLI, the MCP server and (through the OpenAPI
//! contract) the console. Policy resources themselves (objects, rules…) are the types of
//! [`crate::policy`].

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::events::{
    Actor, AlertEvent, DnsEvent, FlowEvent, HttpEvent, Interface, Severity, ToolCallEvent, Verdict,
};
use crate::policy::{
    Agent, AgentKind, AppProto, L4Proto, Layer, PolicyDocument, Rule, Track, Zone, ZoneMode,
};
use crate::protocol::{GatewayCommand, GatewayStats};

// ---------------------------------------------------------------------------------------------
// Generic

/// Cursor pagination: pass `next_cursor` as `cursor` to get the next page; `null` = last page.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

/// RFC 7807 error body (`application/problem+json`).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Problem {
    /// Problem type URI (`about:blank` when unspecified).
    #[serde(rename = "type", default = "about_blank")]
    pub kind: String,
    pub title: String,
    pub status: u16,
    pub detail: Option<String>,
    pub instance: Option<String>,
}

fn about_blank() -> String {
    "about:blank".to_owned()
}

/// Kind of policy resource (locks, diffs, where-used, audit targets).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Object,
    Service,
    DataClass,
    Zone,
    Agent,
    Rule,
    InspectionRule,
    Settings,
}

/// Reference to a policy resource.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ResourceRef {
    pub kind: ResourceKind,
    pub id: Uuid,
    pub name: String,
}

/// `GET /objects/{id}/where-used`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct WhereUsed {
    pub references: Vec<ResourceRef>,
}

/// `POST /rules/{id}/move`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct MoveRuleRequest {
    pub position: u32,
    /// New layer; unchanged when absent.
    pub layer: Option<Layer>,
    /// New section; unchanged when absent.
    pub section: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Sessions, revisions, verification, installation

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Open,
    Published,
    Discarded,
}

/// Editing session: changes are visible and applicable only once published; resources
/// modified in a session are locked for other sessions.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Session {
    pub id: Uuid,
    pub owner: Actor,
    pub interface: Interface,
    pub state: SessionState,
    pub opened_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    /// Resources locked by this session.
    #[serde(default)]
    pub locks: Vec<ResourceRef>,
    /// Number of pending changes.
    pub changes: u32,
    /// Set when the session needs an approval before publishing (EF-52).
    pub approval_id: Option<Uuid>,
    /// Name given when the session was opened.
    #[serde(default)]
    pub name: Option<String>,
    /// Revision published by this session (or, for `GET /sessions/current`, the caller's last
    /// published revision) that has not been installed yet: lets a client resume the
    /// "Install" step after a reload.
    #[serde(default)]
    pub pending_install: Option<u64>,
    /// Last published revision when the session was opened (its draft started from it).
    #[serde(default)]
    pub base_revision: Option<u64>,
    /// Number the session would get if published now (open sessions only).
    #[serde(default)]
    pub next_revision: Option<u64>,
}

/// `GET /policy/status`: what is published and what runs on the gateways.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct PolicyStatus {
    /// Last published revision.
    pub latest_revision: Option<u64>,
    /// Revision of the most recent installation request.
    pub installed_revision: Option<u64>,
    /// Registered (not deleted) gateways.
    pub gateways_total: u32,
    /// Gateways whose active revision is `installed_revision`.
    pub gateways_on_revision: u32,
    /// Installations still waiting for the gateway's acknowledgement.
    pub pending_installs: u32,
    /// Highest decision-latency p95 (milliseconds) reported by the gateways in their
    /// statistics (`stats.p95_ms`); `null` when none reports it.
    pub p95_ms: Option<f64>,
}

/// `POST /sessions` (optional body).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct OpenSessionRequest {
    #[serde(default)]
    pub name: Option<String>,
}

/// Operation of a pending session change, relative to the last published revision.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOp {
    Create,
    Update,
    Delete,
}

/// A pending change of a session.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct SessionChange {
    pub op: ChangeOp,
    pub resource: ResourceRef,
    /// State after the change; `null` for a deletion.
    pub after: Option<serde_json::Value>,
}

/// Read view of a rule: the rule plus what the console displays next to it.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct RuleView {
    #[serde(flatten)]
    pub rule: Rule,
    /// Displayed global number ([`PolicyDocument::rule_numbers`]).
    pub number: u32,
    /// Hits reported by the gateways (EF-06).
    pub hits: u64,
    pub last_hit_at: Option<DateTime<Utc>>,
    pub expired: bool,
    /// Owner of the session holding a lock on the rule, if any.
    pub locked_by: Option<Actor>,
    /// Pending change of the rule in the session given by `X-Afw-Session`.
    pub pending_change: Option<ChangeOp>,
}

/// Consecutive rules of a layer sharing the same section.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct RuleSection {
    /// Section name; `null` for rules outside any section.
    pub name: Option<String>,
    pub rules: Vec<RuleView>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct BaselineLayerView {
    pub sections: Vec<RuleSection>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ZoneLayerView {
    pub zone: Zone,
    pub mode: ZoneMode,
    pub sections: Vec<RuleSection>,
    /// Display number of the zone's implicit cleanup rule ("deny everything"): the number
    /// following the zone's last rule (display only, not part of the global numbering).
    pub cleanup_number: u32,
}

/// `GET /rulebase`: the whole rule base in evaluation order (baseline, then zones by name).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Rulebase {
    pub baseline: BaselineLayerView,
    pub zones: Vec<ZoneLayerView>,
}

/// `POST /sessions/{id}/publish`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PublishRequest {
    pub comment: String,
}

/// `POST /sessions/{id}/allow-from-log` (EF-42): creates a prefilled rule in the session.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AllowFromLogRequest {
    pub flow_id: Uuid,
    /// How the destination is expressed (default `exact`).
    #[serde(default)]
    pub destination: AllowDestination,
    /// Expiry of the created rule, in days from now.
    #[serde(default)]
    pub expires_in_days: Option<u32>,
    /// Track level of the created rule (default `detailed`).
    #[serde(default)]
    pub track: Option<Track>,
}

/// Destination of a rule created from the log.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum AllowDestination {
    /// The exact domain (or host IP) of the flow.
    #[default]
    Exact,
    /// `*.<parent domain>` (refused when the parent is a top-level domain).
    Wildcard,
    /// The exact domain added to the zone's "allowed from log" group.
    Group,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct AllowFromLogResponse {
    pub rule: RuleView,
    /// Object created for the destination when no existing object matched.
    pub created_object: Option<crate::policy::NetObject>,
    /// Session changes made by this call.
    #[serde(default)]
    pub changes: Vec<SessionChange>,
}

/// Published revision (metadata).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Revision {
    pub number: u64,
    pub published_at: DateTime<Utc>,
    pub published_by: Actor,
    pub interface: Interface,
    pub session_id: Option<Uuid>,
    pub comment: String,
    /// SHA-256 of the canonical JSON of the document (`afw_core::installed::document_sha256`).
    pub sha256: String,
}

/// `GET /revisions/{n}`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct RevisionDetail {
    pub revision: Revision,
    pub document: PolicyDocument,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Change {
    pub kind: ChangeKind,
    pub resource: ResourceRef,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
}

/// `GET /revisions/{n}/diff?against=m`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct RevisionDiff {
    pub from: u64,
    pub to: u64,
    pub changes: Vec<Change>,
}

/// Pre-install verification finding (EF-11), produced by `afw-engine`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VerifyFinding {
    /// `rule` can never match because `by` (earlier) matches everything it matches.
    Shadowed {
        rule: Uuid,
        by: Uuid,
    },
    UnusedObject {
        id: Uuid,
    },
    Expired {
        rule: Uuid,
    },
}

/// `GET /verify?revision=n`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct VerifyReport {
    /// Verified revision; absent = current session draft.
    pub revision: Option<u64>,
    pub findings: Vec<VerifyFinding>,
}

/// `POST /installs`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InstallRequest {
    pub revision: u64,
    /// Target gateways; empty = all gateways.
    #[serde(default)]
    pub gateways: Vec<Uuid>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum InstallState {
    Pending,
    Installed,
    Failed,
}

/// Installation of a revision on one gateway (desired vs. acknowledged).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Install {
    pub id: Uuid,
    pub revision: u64,
    pub gateway_id: Uuid,
    pub requested_at: DateTime<Utc>,
    pub requested_by: Actor,
    pub state: InstallState,
    pub acked_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

/// Response of `POST /installs`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct InstallResult {
    pub installs: Vec<Install>,
}

// ---------------------------------------------------------------------------------------------
// Gateways

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GatewayStatus {
    Online,
    Offline,
    /// Registered but never seen.
    Pending,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Gateway {
    pub id: Uuid,
    pub name: String,
    pub hostname: String,
    pub status: GatewayStatus,
    pub version: Option<String>,
    pub desired_revision: Option<u64>,
    pub active_revision: Option<u64>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub registered_at: DateTime<Utc>,
    pub ca_fingerprint: Option<String>,
    pub stats: Option<GatewayStats>,
}

/// `POST /gateways/registration-tokens`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CreateRegistrationToken {
    /// Expected gateway name (informative).
    pub name: Option<String>,
}

/// One-time gateway registration token (valid 15 minutes).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct RegistrationToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// `POST /gateways/{id}/commands` body.
pub type GatewayCommandRequest = GatewayCommand;

// ---------------------------------------------------------------------------------------------
// Logs

/// Filters of `GET /logs/flows` and `GET /logs/dns` (query string).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub struct FlowQuery {
    pub agent: Option<Uuid>,
    pub zone: Option<Uuid>,
    /// Destination domain, IP or CIDR.
    pub destination: Option<String>,
    pub verdict: Option<Verdict>,
    pub rule: Option<Uuid>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// Free text search.
    pub q: Option<String>,
    pub cursor: Option<String>,
    /// Page size (default 100, max 1000).
    pub limit: Option<u32>,
}

pub type FlowPage = Page<FlowEvent>;
pub type DnsPage = Page<DnsEvent>;

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Certain,
    Probable,
    Uncertain,
}

/// Flow <-> tool call correlation (ADR 0007).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Correlation {
    pub tool_call_id: Uuid,
    pub conversation_id: String,
    pub confidence: Confidence,
}

/// `GET /logs/flows/{id}`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct FlowDetail {
    pub flow: FlowEvent,
    pub http: Vec<HttpEvent>,
    pub tool_call: Option<ToolCallEvent>,
    pub correlation: Option<Correlation>,
    /// Rules examined for this flow, in evaluation order, recomputed on the flow's revision
    /// (empty when the revision or the engine is unavailable).
    #[serde(default)]
    pub trace: Vec<TraceStep>,
    /// Exact text received by the agent when the flow was denied over HTTP(S) (EF-21).
    #[serde(default)]
    pub agent_message: Option<String>,
    /// Prefilled proposal behind the "Allow" button (denied or observed flows).
    #[serde(default)]
    pub allow_proposal: Option<AllowProposal>,
}

/// Item of `GET /logs/flows`: the flow plus display fields computed by the API.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct FlowListItem {
    #[serde(flatten)]
    pub flow: FlowEvent,
    pub agent_name: Option<String>,
    pub zone_name: Option<String>,
    /// `12 · name`, `socle · name` (baseline rule without number) or `default-deny`.
    pub rule_label: String,
    /// Correlated tool call (ADR 0007).
    pub tool: Option<String>,
    pub conversation_id: Option<String>,
    pub correlation_confidence: Option<Confidence>,
}

pub type FlowListPage = Page<FlowListItem>;

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TraceOutcome {
    Matched,
    NotMatched,
    /// Not evaluated (disabled, expired, or after the matching rule).
    Skipped,
}

/// One rule examined while evaluating a flow.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct TraceStep {
    pub rule_id: Option<Uuid>,
    pub rule_number: Option<u32>,
    pub rule_label: String,
    /// `baseline`, `zone` or `implicit`.
    pub layer: String,
    pub outcome: TraceOutcome,
    /// Why it matched or not (e.g. `destination not in api-objects`).
    pub reason: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProposedDestinationKind {
    /// New object matching exactly the flow's domain or IP.
    Exact,
    /// New wildcard domain object (`*.parent`).
    Wildcard,
    /// Existing object (or group) of the policy that already matches the destination.
    Existing,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ProposedDestination {
    pub kind: ProposedDestinationKind,
    pub label: String,
    /// Object to create (`exact`, `wildcard`).
    pub spec: Option<crate::policy::NetObjectSpec>,
    /// Existing object (`existing`).
    pub object_id: Option<Uuid>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ProposedService {
    pub label: String,
    /// Existing service matching the protocol and port, if any.
    pub service_id: Option<Uuid>,
    pub protocol: L4Proto,
    pub port: u16,
}

/// Rule proposed by the "Allow" button: source = the agent's zone, accept, inserted at the
/// top of the zone layer (see `POST /sessions/{id}/allow-from-log`).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct AllowProposal {
    pub zone_id: Uuid,
    pub zone_name: Option<String>,
    /// Choices, most specific first: exact, wildcard, then existing objects.
    pub destinations: Vec<ProposedDestination>,
    pub service: ProposedService,
    /// Number the new rule would get in the current policy.
    pub rule_number: Option<u32>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StatsBucket {
    #[serde(rename = "1m")]
    OneMinute,
    #[serde(rename = "5m")]
    FiveMinutes,
    #[serde(rename = "1h")]
    OneHour,
}

impl StatsBucket {
    pub fn seconds(self) -> i64 {
        match self {
            Self::OneMinute => 60,
            Self::FiveMinutes => 300,
            Self::OneHour => 3600,
        }
    }
}

/// Flow counts of one histogram bucket (`allow` excludes `observed`).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct FlowStatsPoint {
    pub at: DateTime<Utc>,
    pub allow: u64,
    pub deny: u64,
    /// Allowed only because the zone is in observation mode (would have been denied).
    pub observed: u64,
}

/// `GET /logs/flows/stats`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct FlowStats {
    pub bucket: StatsBucket,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub points: Vec<FlowStatsPoint>,
    pub total: u64,
    pub allow: u64,
    pub deny: u64,
    pub observed: u64,
}

/// Period shortcut of `GET /internal-map` (`from`/`to` take precedence).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MapPeriod {
    #[serde(rename = "1h")]
    OneHour,
    #[serde(rename = "24h")]
    OneDay,
    #[serde(rename = "7d")]
    SevenDays,
}

/// `POST /ingest/tool-calls` (agent token).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ToolCallBatch {
    pub events: Vec<ToolCallEvent>,
}

/// `POST /captures`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CaptureRequest {
    pub agent_id: Uuid,
    pub duration_secs: u32,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    Pending,
    Running,
    Done,
    Failed,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Capture {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub gateway_id: Uuid,
    pub requested_at: DateTime<Utc>,
    pub requested_by: Actor,
    pub duration_secs: u32,
    pub state: CaptureState,
    pub size: Option<u64>,
    pub error: Option<String>,
}

/// Alert as listed by the API: the event plus its acknowledgement.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Alert {
    pub event: AlertEvent,
    pub gateway_id: Option<Uuid>,
    pub acknowledged: bool,
    pub acknowledged_by: Option<Actor>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AlertChannelKind {
    Webhook,
    Teams,
    PulseChat,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AlertChannel {
    pub id: Uuid,
    pub name: String,
    pub kind: AlertChannelKind,
    /// Target URL (secret parts masked on read).
    pub url: String,
    pub min_severity: Severity,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct DestinationStat {
    pub destination: String,
    pub flows: u64,
    pub denied: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub last_seen_at: DateTime<Utc>,
}

/// `GET /agents/{id}/overview` (EF-43).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct AgentOverview {
    pub agent: Agent,
    pub zone: Zone,
    pub gateway: Option<Gateway>,
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Counters over the last 24 hours.
    pub flows_24h: u64,
    pub denied_24h: u64,
    pub bytes_out_24h: u64,
    pub bytes_in_24h: u64,
    pub top_destinations: Vec<DestinationStat>,
    pub recent_denied: Vec<FlowEvent>,
    pub recent_tool_calls: Vec<ToolCallEvent>,
    pub alerts: Vec<AlertEvent>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MapNodeKind {
    Agent,
    /// Internal host that is not an agent (database, VM, Kubernetes API…).
    Internal,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct MapNode {
    /// Stable node id: the agent id, or the internal IP address.
    pub id: String,
    pub label: String,
    pub kind: MapNodeKind,
    pub agent_id: Option<Uuid>,
    pub zone_id: Option<Uuid>,
    pub address: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct MapEdge {
    pub source: String,
    pub target: String,
    pub protocol: L4Proto,
    pub port: u16,
    pub app: Option<AppProto>,
    pub flows: u64,
    pub bytes: u64,
    pub alerts: u32,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    /// First seen within the requested period (lateral movement hint).
    pub new: bool,
}

/// `GET /internal-map`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct InternalMap {
    pub nodes: Vec<MapNode>,
    pub edges: Vec<MapEdge>,
}

// ---------------------------------------------------------------------------------------------
// Audit, approvals, identity

/// `GET /audit/verify`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct AuditVerifyResult {
    pub ok: bool,
    pub checked: u64,
    /// `seq` of the first broken entry.
    pub broken_at: Option<i64>,
    pub head_seq: Option<i64>,
    pub head_hash: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
}

/// Approval required before publishing a widening change (EF-52).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Approval {
    pub id: Uuid,
    pub session_id: Uuid,
    pub requested_by: Actor,
    pub requested_at: DateTime<Utc>,
    pub summary: String,
    pub reason: String,
    pub status: ApprovalStatus,
    pub decided_by: Option<Actor>,
    pub decided_at: Option<DateTime<Utc>>,
    pub comment: Option<String>,
}

/// `POST /approvals/{id}/decision`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ApprovalDecision {
    pub approve: bool,
    pub comment: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Auditor,
    Viewer,
    /// The single approved administration agent (MCP), restricted to delegated zones that are
    /// not its own (EF-51).
    McpAgent,
    /// Hermes plugin token: only `POST /ingest/tool-calls` and `GET /intent-policy`.
    AgentPlugin,
}

/// API token (the secret is only returned once, at creation).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ApiToken {
    pub id: Uuid,
    pub name: String,
    pub role: Role,
    /// Agent bound to the token (`mcp_agent` role or Hermes plugin token).
    pub agent_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub created_by: Actor,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// `POST /tokens`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CreateApiToken {
    pub name: String,
    pub role: Role,
    pub agent_id: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct CreatedApiToken {
    pub token: ApiToken,
    /// Bearer secret, shown once.
    pub secret: String,
}

/// `GET /me`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Me {
    pub actor: Actor,
    pub email: Option<String>,
    pub role: Role,
    /// Agent identity for the `mcp_agent` role.
    pub agent_id: Option<Uuid>,
    /// Zones the caller may modify (`mcp_agent`: delegated zones except its own).
    pub writable_zones: Option<Vec<Uuid>>,
}

// ---------------------------------------------------------------------------------------------
// Hermes intent policy and enrollment

/// Decision of an action class (strictest wins: deny > gate > log > allow).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IntentDecision {
    Allow,
    Log,
    /// Blocked with a "submitted to human validation" message.
    Gate,
    Deny,
}

/// Class of tool actions evaluated by the Hermes plugin (format of ADR 0015). Applies when
/// (`tools` is empty or a case-insensitive glob matches the tool name) and (`patterns` is
/// empty or a regex matches the subject: tool name line, then one `key: value` line per
/// argument). The same `id` may appear in several entries with different tool scopes.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ActionClass {
    pub id: String,
    pub name: String,
    pub tools: Vec<String>,
    pub patterns: Vec<String>,
    pub decision: IntentDecision,
}

/// `GET /intent-policy` (plugin token): served to the Hermes plugin, cached on its side.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct IntentPolicy {
    pub version: u64,
    pub action_classes: Vec<ActionClass>,
}

/// `POST /enrollments`: creates the agent (in an open session) and, for Hermes agents,
/// a plugin token.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub name: String,
    pub zone_id: Uuid,
    pub kind: AgentKind,
    pub gateway_id: Uuid,
    #[serde(default)]
    pub hermes: bool,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Enrollment {
    pub agent: Agent,
    pub session_id: Uuid,
    /// Hermes plugin bearer token, shown once.
    pub plugin_token: Option<String>,
}
