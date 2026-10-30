//! Gateway <-> control plane protocol (`/gw/v1`, mutual TLS; plan §3.2, ADR 0004).
//!
//! - `POST /gw/v1/register` [`RegisterRequest`] -> [`RegisterResponse`] (no client certificate,
//!   one-time token valid [`REGISTRATION_TOKEN_TTL_SECS`]).
//! - `GET /gw/v1/policy?have=<rev>` ([`PolicyQuery`]) -> `200` [`crate::InstalledPolicy`] or
//!   `204` after a long poll of [`POLICY_LONG_POLL_SECS`].
//! - `POST /gw/v1/policy/ack` [`PolicyAck`].
//! - `POST /gw/v1/events` [`EventBatch`].
//! - `POST /gw/v1/heartbeat` [`Heartbeat`] -> [`HeartbeatResponse`].
//! - `POST /gw/v1/captures/{id}` raw pcap body (`application/vnd.tcpdump.pcap`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::events::GatewayEvent;

pub const GATEWAY_API_PREFIX: &str = "/gw/v1";
pub const POLICY_LONG_POLL_SECS: u64 = 25;
pub const REGISTRATION_TOKEN_TTL_SECS: u64 = 15 * 60;

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct RegisterRequest {
    pub token: String,
    pub name: String,
    pub hostname: String,
    pub csr_pem: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct RegisterResponse {
    pub gateway_id: Uuid,
    /// Gateway client certificate signed by the console CA.
    pub cert_pem: String,
    /// Console CA certificate (trust anchor for the gateway).
    pub ca_pem: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub struct PolicyQuery {
    /// Revision the gateway already has; absent when it has none.
    pub have: Option<u64>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct PolicyAck {
    pub revision: u64,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct EventBatch {
    pub events: Vec<GatewayEvent>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Heartbeat {
    /// Gateway software version.
    pub version: String,
    /// Active policy revision; absent when the gateway has no valid policy (deny all).
    pub revision: Option<u64>,
    pub stats: GatewayStats,
    /// SHA-256 fingerprint of the gateway's inspection CA certificate.
    pub ca_fingerprint: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub struct GatewayStats {
    pub uptime_secs: u64,
    pub active_flows: u64,
    pub flows_total: u64,
    pub denied_total: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Events waiting in the bounded disk buffer.
    pub events_queued: u64,
    /// Events dropped because the buffer was full.
    pub events_dropped: u64,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub struct HeartbeatResponse {
    pub commands: Vec<GatewayCommand>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GatewayCommand {
    StartCapture {
        capture_id: Uuid,
        agent_id: Uuid,
        duration_secs: u32,
    },
    Reinstall,
    SelfTest,
}
