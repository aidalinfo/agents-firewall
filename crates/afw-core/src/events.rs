//! Events: what gateways report (flows, DNS, HTTP, alerts, rule hits), tool calls reported by
//! the Hermes plugin, and audit entries (plan §3.3).

use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::policy::{AppProto, DataCategory, L4Proto};

/// Event sent by a gateway in `POST /gw/v1/events`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GatewayEvent {
    Flow(FlowEvent),
    Dns(DnsEvent),
    Http(HttpEvent),
    Alert(AlertEvent),
    /// Struct variant (not a newtype over `Vec`): serde cannot internally tag a sequence.
    RuleHits {
        hits: Vec<RuleHit>,
    },
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct FlowEvent {
    pub id: Uuid,
    pub gateway_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub zone_id: Option<Uuid>,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub protocol: L4Proto,
    pub app: Option<AppProto>,
    pub domain: Option<String>,
    pub sni: Option<String>,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub verdict: Verdict,
    pub decision: DecisionRef,
    pub internal: bool,
    pub llm_provider: bool,
    pub tls_inspected: bool,
    /// Names of the data classes detected in the flow.
    #[serde(default)]
    pub data_classes: Vec<String>,
    pub observed: bool,
    /// The content of the flow was analysed (inspected HTTP/HTTPS). `false` for raw TCP relays
    /// (internal flows, explicitly non-HTTP services) and TLS not inspected.
    #[serde(default)]
    pub content_inspected: bool,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
}

/// Which rule (or implicit rule) decided a flow.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct DecisionRef {
    pub rule_id: Option<Uuid>,
    pub rule_number: Option<u32>,
    pub rule_name: String,
    /// Policy revision that took the decision; `None` when the gateway had no valid policy.
    pub revision: Option<u64>,
    /// `baseline`, `zone` or `implicit`.
    pub layer: String,
    pub reason: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct DnsEvent {
    pub id: Uuid,
    pub gateway_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub zone_id: Option<Uuid>,
    pub at: DateTime<Utc>,
    pub qname: String,
    pub qtype: String,
    #[serde(default)]
    pub answers: Vec<String>,
    pub verdict: Verdict,
    pub decision: DecisionRef,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct HttpEvent {
    pub id: Uuid,
    pub flow_id: Uuid,
    pub gateway_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub at: DateTime<Utc>,
    pub method: String,
    pub url: String,
    pub host: String,
    /// `[name, value]` pairs, in order (secrets masked).
    #[serde(default)]
    #[schemars(with = "Vec<[String; 2]>")]
    pub request_headers: Vec<(String, String)>,
    pub request_body: Option<Body>,
    pub status: Option<u16>,
    /// `[name, value]` pairs, in order (secrets masked).
    #[serde(default)]
    #[schemars(with = "Vec<[String; 2]>")]
    pub response_headers: Vec<(String, String)>,
    pub response_body: Option<Body>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    pub admin_action: Option<AdminAction>,
    #[serde(default)]
    pub websocket: bool,
}

/// Captured body, already masked before leaving the gateway.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Body {
    pub encoding: BodyEncoding,
    pub data: String,
    /// Original size in bytes.
    pub size: u64,
    pub truncated: bool,
    /// SHA-256 (hex) of the original, unmasked body.
    pub sha256: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BodyEncoding {
    Utf8,
    Base64,
}

/// A data-class detection. Never contains the secret itself.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Finding {
    /// Data class name.
    pub class: String,
    pub category: DataCategory,
    /// Detector kind (e.g. `aws_access_key`).
    pub kind: String,
    /// SHA-256 of the matched value truncated to 12 hex characters.
    pub fingerprint: String,
    /// Where it was found (e.g. `request.body`, `request.header:authorization`, `url`).
    pub location: String,
}

/// Recognised infrastructure administration call (internal flows, EF-82).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct AdminAction {
    pub system: AdminSystem,
    pub action: String,
    pub resource: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AdminSystem {
    Kubernetes,
    Coolify,
    Docker,
    Proxmox,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct AlertEvent {
    pub id: Uuid,
    pub at: DateTime<Utc>,
    pub kind: AlertKind,
    pub severity: Severity,
    pub agent_id: Option<Uuid>,
    pub summary: String,
    #[serde(default)]
    pub details: serde_json::Value,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    NewDestination,
    VolumeSpike,
    DenyBurst,
    CloudMetadata,
    SecretDetected,
    PortScan,
    NewInternalHost,
    SensitivePort,
    InternalBurst,
    UnusualAdminAction,
}

#[derive(
    Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// Rule hit counters aggregated by a gateway since its previous report.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct RuleHit {
    pub rule_id: Uuid,
    pub revision: u64,
    pub hits: u64,
    pub last_hit_at: DateTime<Utc>,
}

/// Tool call reported by the Hermes plugin (`POST /api/v1/ingest/tool-calls`).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ToolCallEvent {
    pub id: Uuid,
    /// Agent name or id.
    pub agent: String,
    pub conversation_id: String,
    pub tool: String,
    pub args_summary: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub status: Option<String>,
}

/// Hash-chained audit entry: `hash = sha256(prev_hash || canonical_json(entry without hash))`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct AuditEntry {
    pub seq: i64,
    pub at: DateTime<Utc>,
    pub actor: Actor,
    pub interface: Interface,
    pub session_id: Option<Uuid>,
    pub action: String,
    pub target: String,
    #[serde(default)]
    pub diff: serde_json::Value,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct Actor {
    pub kind: ActorKind,
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    Human,
    Cli,
    Agent,
    System,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Interface {
    Ui,
    Cli,
    Mcp,
    Api,
    System,
}
