//! `LogStore`: storage of the high-volume events (flows, DNS, HTTP exchanges, tool calls) and
//! the aggregates computed on them (ADR 0006). Implementations: PostgreSQL (default) and
//! ClickHouse over HTTP, selected by `AFW_LOG_STORE`.
//!
//! The low-volume console state (alerts, alert channels, captures, rule counters, known
//! destinations per agent) always lives in PostgreSQL, whatever the store.

use std::future::Future;
use std::net::IpAddr;

use afw_core::api::{Confidence, DestinationStat};
use afw_core::events::{DnsEvent, FlowEvent, HttpEvent, ToolCallEvent, Verdict};
use afw_core::policy::{AppProto, L4Proto};
use anyhow::Result;
use base64::Engine;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use uuid::Uuid;

use super::clickhouse::ClickHouseLogStore;
use super::postgres::PgLogStore;

/// Destination filter: a CIDR, an IP address or a domain (also matching its subdomains).
#[derive(Clone, Debug, PartialEq)]
pub enum Destination {
    Cidr(IpNet),
    Ip(IpAddr),
    Domain(String),
}

impl Destination {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Some(Self::Ip(ip));
        }
        if let Ok(net) = s.parse::<IpNet>() {
            return Some(Self::Cidr(net.trunc()));
        }
        let d = s
            .trim_start_matches("*.")
            .trim_end_matches('.')
            .to_ascii_lowercase();
        (!d.is_empty()).then_some(Self::Domain(d))
    }

    /// Whether a domain name (`None` = no name) matches this filter.
    pub fn matches_domain(&self, name: Option<&str>) -> bool {
        match (self, name) {
            (Self::Domain(d), Some(n)) => {
                let n = n.trim_end_matches('.').to_ascii_lowercase();
                n == *d || n.ends_with(&format!(".{d}"))
            }
            _ => false,
        }
    }

    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        match self {
            Self::Ip(x) => *x == ip,
            Self::Cidr(n) => n.contains(&ip),
            Self::Domain(_) => false,
        }
    }
}

/// Filters of the log searches (`GET /logs/flows`, `GET /logs/dns`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LogFilter {
    pub agent: Option<Uuid>,
    pub zone: Option<Uuid>,
    pub destination: Option<Destination>,
    pub verdict: Option<Verdict>,
    pub rule: Option<Uuid>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// Free text, matched case-insensitively against domains, SNI, IPs and HTTP URLs.
    pub q: Option<String>,
}

/// Keyset pagination position: items strictly older than `(at, id)` (newest first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub at: DateTime<Utc>,
    pub id: Uuid,
}

impl Cursor {
    pub fn encode(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(
            "{}|{}",
            self.at.timestamp_micros(),
            self.id
        ))
    }

    pub fn decode(s: &str) -> Option<Self> {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.trim())
            .ok()?;
        let raw = String::from_utf8(raw).ok()?;
        let (micros, id) = raw.split_once('|')?;
        Some(Self {
            at: DateTime::from_timestamp_micros(micros.parse().ok()?)?,
            id: id.parse().ok()?,
        })
    }
}

/// HTTP exchange as stored: metadata in clear (contents stripped) and the sealed contents
/// (headers and bodies, see [`super::crypto`]); `content` is `None` when no data key is set.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredHttp {
    pub event: HttpEvent,
    pub content: Option<Vec<u8>>,
}

/// Flow with its materialized correlation.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredFlow {
    pub flow: FlowEvent,
    pub correlation: Option<(Uuid, Confidence)>,
}

/// One histogram bucket: `(start, allow, deny, observed)`.
pub type HistogramRow = (DateTime<Utc>, u64, u64, u64);

/// Counters of an agent over a period.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AgentActivity {
    pub flows: u64,
    pub denied: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Aggregated internal flows between a source (agent, or IP when no agent) and a target IP.
#[derive(Clone, Debug, PartialEq)]
pub struct EdgeRow {
    pub agent_id: Option<Uuid>,
    pub zone_id: Option<Uuid>,
    /// Source IP (used when `agent_id` is `None`).
    pub src: String,
    pub dst: String,
    pub protocol: L4Proto,
    pub port: u16,
    pub app: Option<AppProto>,
    pub flows: u64,
    pub bytes: u64,
    /// First time this edge was seen, over the whole retention.
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

/// Largest number of edges returned by the internal map (busiest first).
pub const MAX_MAP_EDGES: u32 = 2000;

/// Destination key of a flow: domain, else SNI, else destination IP.
pub fn flow_destination(f: &FlowEvent) -> String {
    f.domain
        .as_deref()
        .or(f.sni.as_deref())
        .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_else(|| f.dst.ip().to_string())
}

/// Storage of the high-volume events. Every insert is idempotent on the event `id`.
pub trait LogStore: Send + Sync {
    /// Inserts flows, returns the ids that were not already stored.
    fn insert_flows(&self, flows: &[FlowEvent]) -> impl Future<Output = Result<Vec<Uuid>>> + Send;
    fn insert_dns(&self, events: &[DnsEvent]) -> impl Future<Output = Result<()>> + Send;
    fn insert_http(&self, events: &[StoredHttp]) -> impl Future<Output = Result<()>> + Send;
    /// Upserts tool calls of `agent_id` by id: a later event never resets `ended_at`/`status`
    /// to null, and a call owned by another agent is left untouched.
    fn upsert_tool_calls(
        &self,
        agent_id: Uuid,
        calls: &[ToolCallEvent],
    ) -> impl Future<Output = Result<()>> + Send;
    /// Calls of `agent_id` started in `[from, to]`.
    fn tool_calls_between(
        &self,
        agent_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> impl Future<Output = Result<Vec<ToolCallEvent>>> + Send;
    fn get_tool_call(&self, id: Uuid)
    -> impl Future<Output = Result<Option<ToolCallEvent>>> + Send;
    fn recent_tool_calls(
        &self,
        agent_id: Uuid,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<ToolCallEvent>>> + Send;
    fn set_correlation(
        &self,
        flow_id: Uuid,
        correlation: Option<(Uuid, Confidence)>,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Flows of `agent_id` started in `[from, to]`.
    fn flows_of_agent_between(
        &self,
        agent_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> impl Future<Output = Result<Vec<FlowEvent>>> + Send;
    /// Newest first, at most `limit`, strictly before `cursor`.
    fn search_flows(
        &self,
        filter: &LogFilter,
        cursor: Option<Cursor>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<StoredFlow>>> + Send;
    /// Histogram of the flows matching `filter` in `[from, to)`: `(bucket start, allow (not
    /// observed), deny, observed)`, only non-empty buckets, ordered by time.
    fn flow_histogram(
        &self,
        filter: &LogFilter,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        bucket_secs: i64,
    ) -> impl Future<Output = Result<Vec<HistogramRow>>> + Send;
    fn tool_calls_by_ids(
        &self,
        ids: &[Uuid],
    ) -> impl Future<Output = Result<Vec<ToolCallEvent>>> + Send;
    fn search_dns(
        &self,
        filter: &LogFilter,
        cursor: Option<Cursor>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<DnsEvent>>> + Send;
    fn get_flow(&self, id: Uuid) -> impl Future<Output = Result<Option<StoredFlow>>> + Send;
    fn http_for_flow(&self, flow_id: Uuid) -> impl Future<Output = Result<Vec<StoredHttp>>> + Send;
    fn agent_activity(
        &self,
        agent_id: Uuid,
        since: DateTime<Utc>,
    ) -> impl Future<Output = Result<AgentActivity>> + Send;
    fn top_destinations(
        &self,
        agent_id: Uuid,
        since: DateTime<Utc>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<DestinationStat>>> + Send;
    fn recent_flows(
        &self,
        agent_id: Uuid,
        verdict: Option<Verdict>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<FlowEvent>>> + Send;
    fn bytes_out(
        &self,
        agent_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> impl Future<Output = Result<u64>> + Send;
    fn count_flows(
        &self,
        agent_id: Uuid,
        verdict: Option<Verdict>,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> impl Future<Output = Result<u64>> + Send;
    /// Internal flows started in `[from, to)`, optionally from zone `zone`.
    fn internal_edges(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        zone: Option<Uuid>,
    ) -> impl Future<Output = Result<Vec<EdgeRow>>> + Send;
    /// Gateway of the latest flow of the agent.
    fn last_gateway_of_agent(
        &self,
        agent_id: Uuid,
    ) -> impl Future<Output = Result<Option<Uuid>>> + Send;
    /// Deletes flows, DNS events and tool calls older than `flows_before`, HTTP exchanges older
    /// than `http_before`. Returns the number of deleted rows (approximate for ClickHouse).
    fn purge(
        &self,
        flows_before: DateTime<Utc>,
        http_before: DateTime<Utc>,
    ) -> impl Future<Output = Result<u64>> + Send;
}

/// The configured store.
#[derive(Clone, Debug)]
pub enum AnyLogStore {
    Postgres(PgLogStore),
    ClickHouse(ClickHouseLogStore),
}

macro_rules! delegate {
    ($self:ident, $s:ident => $call:expr) => {
        match $self {
            AnyLogStore::Postgres($s) => $call.await,
            AnyLogStore::ClickHouse($s) => $call.await,
        }
    };
}

impl AnyLogStore {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Postgres(_) => "postgres",
            Self::ClickHouse(_) => "clickhouse",
        }
    }

    /// Creates the store's own schema (ClickHouse); PostgreSQL uses the sqlx migrations.
    pub async fn init(&self) -> Result<()> {
        match self {
            Self::Postgres(_) => Ok(()),
            Self::ClickHouse(s) => s.migrate().await,
        }
    }
}

impl LogStore for AnyLogStore {
    async fn insert_flows(&self, flows: &[FlowEvent]) -> Result<Vec<Uuid>> {
        delegate!(self, s => s.insert_flows(flows))
    }
    async fn insert_dns(&self, events: &[DnsEvent]) -> Result<()> {
        delegate!(self, s => s.insert_dns(events))
    }
    async fn insert_http(&self, events: &[StoredHttp]) -> Result<()> {
        delegate!(self, s => s.insert_http(events))
    }
    async fn upsert_tool_calls(&self, agent_id: Uuid, calls: &[ToolCallEvent]) -> Result<()> {
        delegate!(self, s => s.upsert_tool_calls(agent_id, calls))
    }
    async fn tool_calls_between(
        &self,
        agent_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<ToolCallEvent>> {
        delegate!(self, s => s.tool_calls_between(agent_id, from, to))
    }
    async fn get_tool_call(&self, id: Uuid) -> Result<Option<ToolCallEvent>> {
        delegate!(self, s => s.get_tool_call(id))
    }
    async fn recent_tool_calls(&self, agent_id: Uuid, limit: u32) -> Result<Vec<ToolCallEvent>> {
        delegate!(self, s => s.recent_tool_calls(agent_id, limit))
    }
    async fn set_correlation(
        &self,
        flow_id: Uuid,
        correlation: Option<(Uuid, Confidence)>,
    ) -> Result<()> {
        delegate!(self, s => s.set_correlation(flow_id, correlation))
    }
    async fn flows_of_agent_between(
        &self,
        agent_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<FlowEvent>> {
        delegate!(self, s => s.flows_of_agent_between(agent_id, from, to))
    }
    async fn search_flows(
        &self,
        filter: &LogFilter,
        cursor: Option<Cursor>,
        limit: u32,
    ) -> Result<Vec<StoredFlow>> {
        delegate!(self, s => s.search_flows(filter, cursor, limit))
    }
    async fn flow_histogram(
        &self,
        filter: &LogFilter,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        bucket_secs: i64,
    ) -> Result<Vec<HistogramRow>> {
        delegate!(self, s => s.flow_histogram(filter, from, to, bucket_secs))
    }
    async fn tool_calls_by_ids(&self, ids: &[Uuid]) -> Result<Vec<ToolCallEvent>> {
        delegate!(self, s => s.tool_calls_by_ids(ids))
    }
    async fn search_dns(
        &self,
        filter: &LogFilter,
        cursor: Option<Cursor>,
        limit: u32,
    ) -> Result<Vec<DnsEvent>> {
        delegate!(self, s => s.search_dns(filter, cursor, limit))
    }
    async fn get_flow(&self, id: Uuid) -> Result<Option<StoredFlow>> {
        delegate!(self, s => s.get_flow(id))
    }
    async fn http_for_flow(&self, flow_id: Uuid) -> Result<Vec<StoredHttp>> {
        delegate!(self, s => s.http_for_flow(flow_id))
    }
    async fn agent_activity(&self, agent_id: Uuid, since: DateTime<Utc>) -> Result<AgentActivity> {
        delegate!(self, s => s.agent_activity(agent_id, since))
    }
    async fn top_destinations(
        &self,
        agent_id: Uuid,
        since: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<DestinationStat>> {
        delegate!(self, s => s.top_destinations(agent_id, since, limit))
    }
    async fn recent_flows(
        &self,
        agent_id: Uuid,
        verdict: Option<Verdict>,
        limit: u32,
    ) -> Result<Vec<FlowEvent>> {
        delegate!(self, s => s.recent_flows(agent_id, verdict, limit))
    }
    async fn bytes_out(
        &self,
        agent_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<u64> {
        delegate!(self, s => s.bytes_out(agent_id, from, to))
    }
    async fn count_flows(
        &self,
        agent_id: Uuid,
        verdict: Option<Verdict>,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<u64> {
        delegate!(self, s => s.count_flows(agent_id, verdict, from, to))
    }
    async fn internal_edges(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        zone: Option<Uuid>,
    ) -> Result<Vec<EdgeRow>> {
        delegate!(self, s => s.internal_edges(from, to, zone))
    }
    async fn last_gateway_of_agent(&self, agent_id: Uuid) -> Result<Option<Uuid>> {
        delegate!(self, s => s.last_gateway_of_agent(agent_id))
    }
    async fn purge(&self, flows_before: DateTime<Utc>, http_before: DateTime<Utc>) -> Result<u64> {
        delegate!(self, s => s.purge(flows_before, http_before))
    }
}

/// Text form of enums serialized as JSON strings (`allow`, `tcp`…).
pub fn enum_str<T: serde::Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

pub fn parse_enum<T: serde::de::DeserializeOwned>(s: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(s.to_owned()))
        .map_err(|_| anyhow::anyhow!("invalid stored value {s:?}"))
}

/// `%…%` pattern for a case-insensitive `LIKE`/`ILIKE`, with `\`, `%` and `_` escaped.
pub fn like_pattern(q: &str) -> String {
    let mut out = String::from("%");
    for c in q.to_lowercase().chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

/// Saturating `u64` -> `i64` for database columns.
pub fn i64_of(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_parsing() {
        assert_eq!(
            Destination::parse("10.0.0.1"),
            Some(Destination::Ip("10.0.0.1".parse().unwrap()))
        );
        assert_eq!(
            Destination::parse("10.0.0.7/8"),
            Some(Destination::Cidr("10.0.0.0/8".parse().unwrap()))
        );
        assert_eq!(
            Destination::parse("*.Example.COM."),
            Some(Destination::Domain("example.com".into()))
        );
        assert_eq!(Destination::parse("  "), None);
        let d = Destination::parse("example.com").unwrap();
        assert!(d.matches_domain(Some("api.example.com")));
        assert!(d.matches_domain(Some("EXAMPLE.com")));
        assert!(!d.matches_domain(Some("badexample.com")));
        assert!(!d.matches_domain(None));
    }

    #[test]
    fn cursor_round_trip_and_garbage() {
        let c = Cursor {
            at: DateTime::from_timestamp_micros(1_800_000_000_123_456).unwrap(),
            id: Uuid::new_v4(),
        };
        assert_eq!(Cursor::decode(&c.encode()), Some(c));
        assert_eq!(Cursor::decode("garbage!"), None);
        assert_eq!(Cursor::decode(""), None);
    }

    #[test]
    fn like_pattern_escapes_wildcards() {
        assert_eq!(like_pattern("A_b%c\\"), "%a\\_b\\%c\\\\%");
    }
}
