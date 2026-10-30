//! ClickHouse [`LogStore`] over the HTTP interface (`AFW_LOG_STORE=clickhouse`, ENF-04).
//!
//! Every value is passed as a typed query parameter (`{name:Type}` + `param_name=`), never
//! interpolated in the SQL. Rows are exchanged as `JSONEachRow`. Inserts are idempotent: ids
//! already present are skipped. Tool calls and correlations are append-only and merged on read
//! (a later event never resets `ended_at`/`status`, as in PostgreSQL).

use std::collections::HashSet;

use afw_core::api::{Confidence, DestinationStat};
use afw_core::events::{DnsEvent, FlowEvent, HttpEvent, ToolCallEvent, Verdict};
use anyhow::{Context, Result, bail};
use base64::Engine;
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use uuid::Uuid;

use super::store::{
    AgentActivity, Cursor, Destination, EdgeRow, HistogramRow, LogFilter, LogStore, StoredFlow,
    StoredHttp, enum_str, flow_destination, like_pattern, parse_enum,
};

/// Connection settings (`AFW_CLICKHOUSE_URL`, `_USER`, `_PASSWORD`, `_DATABASE`).
#[derive(Clone, Debug)]
pub struct ClickHouseLogStore {
    http: reqwest::Client,
    url: String,
    user: Option<String>,
    password: Option<String>,
    database: String,
}

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
}

fn parse_ts(s: &str) -> Result<DateTime<Utc>> {
    Ok(NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
        .with_context(|| format!("invalid ClickHouse datetime {s:?}"))?
        .and_utc())
}

fn de_ts<'de, D: serde::Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
    let s = String::deserialize(d)?;
    parse_ts(&s).map_err(serde::de::Error::custom)
}

fn de_opt_ts<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<DateTime<Utc>>, D::Error> {
    let s = Option::<String>::deserialize(d)?;
    s.map(|s| parse_ts(&s).map_err(serde::de::Error::custom))
        .transpose()
}

/// SQL with typed parameters.
#[derive(Default)]
struct Q {
    sql: String,
    params: Vec<(String, String)>,
}

impl Q {
    fn new(sql: &str) -> Self {
        Self {
            sql: sql.to_owned(),
            params: Vec::new(),
        }
    }
    /// Appends `{pN:ty}` bound to `value`.
    fn bind(&mut self, ty: &str, value: impl ToString) -> &mut Self {
        let name = format!("p{}", self.params.len());
        self.sql.push_str(&format!("{{{name}:{ty}}}"));
        self.params.push((name, value.to_string()));
        self
    }
    fn push(&mut self, s: &str) -> &mut Self {
        self.sql.push_str(s);
        self
    }
}

#[derive(Deserialize)]
struct EventRow {
    event: String,
}

#[derive(Deserialize)]
struct ToolCallRow {
    id: Uuid,
    agent: String,
    conversation_id: String,
    tool: String,
    args_summary: String,
    #[serde(deserialize_with = "de_ts")]
    started_at: DateTime<Utc>,
    #[serde(deserialize_with = "de_opt_ts")]
    ended_at: Option<DateTime<Utc>>,
    status: Option<String>,
}

impl From<ToolCallRow> for ToolCallEvent {
    fn from(r: ToolCallRow) -> Self {
        Self {
            id: r.id,
            agent: r.agent,
            conversation_id: r.conversation_id,
            tool: r.tool,
            args_summary: r.args_summary,
            started_at: r.started_at,
            ended_at: r.ended_at,
            status: r.status,
        }
    }
}

/// Merged view of the append-only `tool_calls` table, per (id, agent): the first agent that
/// reported an id owns it.
const TOOL_CALLS_MERGED: &str = "SELECT id, any(agent) AS agent, any(conversation_id) AS conversation_id, \
     any(tool) AS tool, any(args_summary) AS args_summary, min(started_at) AS started_at, \
     max(ended_at) AS ended_at, max(status) AS status, min(received_at) AS first_received \
     FROM tool_calls";

impl ClickHouseLogStore {
    pub fn new(
        url: &str,
        user: Option<String>,
        password: Option<String>,
        database: Option<String>,
    ) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            url: url.trim_end_matches('/').to_owned(),
            user,
            password,
            database: database.unwrap_or_else(|| "default".to_owned()),
        }
    }

    async fn exec(&self, q: &Q, body: Option<String>) -> Result<String> {
        let mut params: Vec<(String, String)> = vec![
            ("database".into(), self.database.clone()),
            ("output_format_json_quote_64bit_integers".into(), "0".into()),
            ("date_time_output_format".into(), "simple".into()),
            // Aliases (`count() AS flows`, `any(agent_id) AS agent_id`) never shadow columns.
            ("prefer_column_name_to_alias".into(), "1".into()),
        ];
        for (k, v) in &q.params {
            params.push((format!("param_{k}"), v.clone()));
        }
        let payload = match body {
            // Insert: the statement goes in the URL, the rows in the body.
            Some(rows) => {
                params.push(("query".into(), q.sql.clone()));
                rows
            }
            None => q.sql.clone(),
        };
        let mut req = self.http.post(&self.url).query(&params).body(payload);
        if let Some(u) = &self.user {
            req = req.header("X-ClickHouse-User", u);
        }
        if let Some(p) = &self.password {
            req = req.header("X-ClickHouse-Key", p);
        }
        let res = req.send().await.context("ClickHouse request")?;
        let status = res.status();
        let text = res.text().await.context("ClickHouse response")?;
        if !status.is_success() {
            bail!("ClickHouse error {status}: {}", text.trim());
        }
        Ok(text)
    }

    async fn rows<T: DeserializeOwned>(&self, q: &mut Q) -> Result<Vec<T>> {
        q.push(" FORMAT JSONEachRow");
        let text = self.exec(q, None).await?;
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).with_context(|| format!("ClickHouse row {l}")))
            .collect()
    }

    async fn insert(&self, table: &str, rows: Vec<Value>) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let body = rows
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        self.exec(
            &Q::new(&format!("INSERT INTO {table} FORMAT JSONEachRow")),
            Some(body),
        )
        .await?;
        Ok(())
    }

    async fn existing_ids(&self, table: &str, ids: &[Uuid]) -> Result<HashSet<Uuid>> {
        #[derive(Deserialize)]
        struct R {
            id: Uuid,
        }
        let mut found = HashSet::new();
        for chunk in ids.chunks(1000) {
            let list = chunk
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let mut q = Q::new(&format!(
                "SELECT id FROM {table} WHERE has(splitByChar(',', "
            ));
            q.bind("String", list).push("), toString(id))");
            found.extend(self.rows::<R>(&mut q).await?.into_iter().map(|r| r.id));
        }
        Ok(found)
    }

    /// Creates the tables (idempotent).
    pub async fn migrate(&self) -> Result<()> {
        let ddl = [
            "CREATE TABLE IF NOT EXISTS flows (id UUID, gateway_id UUID, agent_id Nullable(UUID), \
             zone_id Nullable(UUID), src_ip String, dst_ip String, dst_port UInt16, protocol String, \
             app Nullable(String), dest String, domain Nullable(String), sni Nullable(String), \
             search String, started_at DateTime64(6, 'UTC'), verdict String, rule_id Nullable(UUID), \
             internal Bool, observed Bool, bytes_out UInt64, bytes_in UInt64, event String) \
             ENGINE = MergeTree PARTITION BY toYYYYMM(started_at) ORDER BY (started_at, id)",
            "CREATE TABLE IF NOT EXISTS dns_events (id UUID, gateway_id UUID, agent_id Nullable(UUID), \
             zone_id Nullable(UUID), at DateTime64(6, 'UTC'), qname String, answer_ips Array(String), \
             verdict String, rule_id Nullable(UUID), event String) \
             ENGINE = MergeTree PARTITION BY toYYYYMM(at) ORDER BY (at, id)",
            "CREATE TABLE IF NOT EXISTS http_events (id UUID, flow_id UUID, gateway_id UUID, \
             agent_id Nullable(UUID), at DateTime64(6, 'UTC'), url String, event String, \
             content Nullable(String)) ENGINE = MergeTree PARTITION BY toYYYYMM(at) ORDER BY (flow_id, at, id)",
            "CREATE TABLE IF NOT EXISTS tool_calls (id UUID, agent_id UUID, agent String, \
             conversation_id String, tool String, args_summary String, started_at DateTime64(6, 'UTC'), \
             ended_at Nullable(DateTime64(6, 'UTC')), status Nullable(String), \
             received_at DateTime64(6, 'UTC')) ENGINE = MergeTree ORDER BY (agent_id, started_at, id)",
            "CREATE TABLE IF NOT EXISTS flow_correlations (flow_id UUID, tool_call_id Nullable(UUID), \
             confidence Nullable(String), at DateTime64(6, 'UTC')) \
             ENGINE = ReplacingMergeTree(at) ORDER BY flow_id",
        ];
        for sql in ddl {
            self.exec(&Q::new(sql), None).await?;
        }
        Ok(())
    }

    async fn correlations(&self, ids: &[Uuid]) -> Result<Vec<(Uuid, Option<(Uuid, Confidence)>)>> {
        #[derive(Deserialize)]
        struct R {
            flow_id: Uuid,
            tc: Option<Uuid>,
            conf: Option<String>,
        }
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let list = ids
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut q = Q::new(
            "SELECT flow_id, argMax(tool_call_id, at) AS tc, argMax(confidence, at) AS conf \
             FROM flow_correlations WHERE has(splitByChar(',', ",
        );
        q.bind("String", list)
            .push("), toString(flow_id)) GROUP BY flow_id");
        Ok(self
            .rows::<R>(&mut q)
            .await?
            .into_iter()
            .map(|r| {
                let c =
                    r.tc.zip(r.conf.and_then(|c| parse_enum::<Confidence>(&c).ok()));
                (r.flow_id, c)
            })
            .collect())
    }

    async fn attach_correlations(&self, flows: Vec<FlowEvent>) -> Result<Vec<StoredFlow>> {
        let ids: Vec<Uuid> = flows.iter().map(|f| f.id).collect();
        let corr: std::collections::HashMap<Uuid, Option<(Uuid, Confidence)>> =
            self.correlations(&ids).await?.into_iter().collect();
        Ok(flows
            .into_iter()
            .map(|f| StoredFlow {
                correlation: corr.get(&f.id).copied().flatten(),
                flow: f,
            })
            .collect())
    }

    async fn events<T: DeserializeOwned>(&self, q: &mut Q) -> Result<Vec<T>> {
        self.rows::<EventRow>(q)
            .await?
            .into_iter()
            .map(|r| serde_json::from_str(&r.event).context("stored event"))
            .collect()
    }
}

fn push_flow_filter(q: &mut Q, f: &LogFilter) {
    if let Some(a) = f.agent {
        q.push(" AND agent_id = ").bind("UUID", a);
    }
    if let Some(z) = f.zone {
        q.push(" AND zone_id = ").bind("UUID", z);
    }
    if let Some(v) = f.verdict {
        q.push(" AND verdict = ").bind("String", enum_str(&v));
    }
    if let Some(r) = f.rule {
        q.push(" AND rule_id = ").bind("UUID", r);
    }
    if let Some(from) = f.from {
        q.push(" AND started_at >= ")
            .bind("DateTime64(6, 'UTC')", ts(from));
    }
    if let Some(to) = f.to {
        q.push(" AND started_at <= ")
            .bind("DateTime64(6, 'UTC')", ts(to));
    }
    match &f.destination {
        Some(Destination::Ip(ip)) => {
            q.push(" AND dst_ip = ").bind("String", ip);
        }
        Some(Destination::Cidr(n)) => {
            q.push(" AND isIPAddressInRange(dst_ip, ")
                .bind("String", n)
                .push(")");
        }
        Some(Destination::Domain(d)) => {
            let suffix = format!(".{d}");
            q.push(" AND (lower(ifNull(domain, '')) = ")
                .bind("String", d)
                .push(" OR endsWith(lower(ifNull(domain, '')), ")
                .bind("String", &suffix)
                .push(") OR lower(ifNull(sni, '')) = ")
                .bind("String", d)
                .push(" OR endsWith(lower(ifNull(sni, '')), ")
                .bind("String", &suffix)
                .push("))");
        }
        None => {}
    }
    if let Some(text) = f.q.as_deref().filter(|q| !q.trim().is_empty()) {
        let p = like_pattern(text.trim());
        q.push(" AND (search LIKE ")
            .bind("String", &p)
            .push(" OR id IN (SELECT flow_id FROM http_events WHERE lower(url) LIKE ")
            .bind("String", &p)
            .push("))");
    }
}

fn opt_str<T: serde::Serialize>(v: &Option<T>) -> Value {
    v.as_ref().map(enum_str).map_or(Value::Null, Value::String)
}

impl LogStore for ClickHouseLogStore {
    async fn insert_flows(&self, flows: &[FlowEvent]) -> Result<Vec<Uuid>> {
        let ids: Vec<Uuid> = flows.iter().map(|f| f.id).collect();
        let existing = self.existing_ids("flows", &ids).await?;
        let mut seen = HashSet::new();
        let new: Vec<&FlowEvent> = flows
            .iter()
            .filter(|f| !existing.contains(&f.id) && seen.insert(f.id))
            .collect();
        let rows = new
            .iter()
            .map(|f| {
                json!({
                    "id": f.id, "gateway_id": f.gateway_id, "agent_id": f.agent_id,
                    "zone_id": f.zone_id, "src_ip": f.src.ip().to_string(),
                    "dst_ip": f.dst.ip().to_string(), "dst_port": f.dst.port(),
                    "protocol": enum_str(&f.protocol), "app": opt_str(&f.app),
                    "dest": flow_destination(f), "domain": f.domain, "sni": f.sni,
                    "search": format!("{} {} {}", f.domain.as_deref().unwrap_or(""),
                        f.sni.as_deref().unwrap_or(""), f.dst.ip()).to_lowercase(),
                    "started_at": ts(f.started_at), "verdict": enum_str(&f.verdict),
                    "rule_id": f.decision.rule_id, "internal": f.internal, "observed": f.observed,
                    "bytes_out": f.bytes_out, "bytes_in": f.bytes_in,
                    "event": serde_json::to_string(f).unwrap_or_default(),
                })
            })
            .collect();
        self.insert("flows", rows).await?;
        Ok(new.into_iter().map(|f| f.id).collect())
    }

    async fn insert_dns(&self, events: &[DnsEvent]) -> Result<()> {
        let ids: Vec<Uuid> = events.iter().map(|e| e.id).collect();
        let existing = self.existing_ids("dns_events", &ids).await?;
        let rows = events
            .iter()
            .filter(|e| !existing.contains(&e.id))
            .map(|e| {
                let ips: Vec<String> = e
                    .answers
                    .iter()
                    .filter_map(|a| a.parse::<std::net::IpAddr>().ok())
                    .map(|ip| ip.to_string())
                    .collect();
                json!({
                    "id": e.id, "gateway_id": e.gateway_id, "agent_id": e.agent_id,
                    "zone_id": e.zone_id, "at": ts(e.at),
                    "qname": e.qname.trim_end_matches('.').to_ascii_lowercase(),
                    "answer_ips": ips, "verdict": enum_str(&e.verdict),
                    "rule_id": e.decision.rule_id,
                    "event": serde_json::to_string(e).unwrap_or_default(),
                })
            })
            .collect();
        self.insert("dns_events", rows).await
    }

    async fn insert_http(&self, events: &[StoredHttp]) -> Result<()> {
        let ids: Vec<Uuid> = events.iter().map(|e| e.event.id).collect();
        let existing = self.existing_ids("http_events", &ids).await?;
        let rows = events
            .iter()
            .filter(|h| !existing.contains(&h.event.id))
            .map(|h| {
                let e = &h.event;
                json!({
                    "id": e.id, "flow_id": e.flow_id, "gateway_id": e.gateway_id,
                    "agent_id": e.agent_id, "at": ts(e.at), "url": e.url,
                    "event": serde_json::to_string(e).unwrap_or_default(),
                    "content": h.content.as_ref().map(|c| B64.encode(c)),
                })
            })
            .collect();
        self.insert("http_events", rows).await
    }

    async fn upsert_tool_calls(&self, agent_id: Uuid, calls: &[ToolCallEvent]) -> Result<()> {
        let now = ts(Utc::now());
        let rows = calls
            .iter()
            .map(|c| {
                json!({
                    "id": c.id, "agent_id": agent_id, "agent": c.agent,
                    "conversation_id": c.conversation_id, "tool": c.tool,
                    "args_summary": c.args_summary, "started_at": ts(c.started_at),
                    "ended_at": c.ended_at.map(ts), "status": c.status, "received_at": now,
                })
            })
            .collect();
        self.insert("tool_calls", rows).await
    }

    async fn tool_calls_between(
        &self,
        agent_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<ToolCallEvent>> {
        // Ownership: only ids whose first report came from this agent.
        let mut q = Q::new(&format!(
            "SELECT * FROM ({TOOL_CALLS_MERGED} WHERE id IN (SELECT id FROM tool_calls GROUP BY id HAVING argMin(agent_id, received_at) = "
        ));
        q.bind("UUID", agent_id)
            .push(") AND agent_id = ")
            .bind("UUID", agent_id)
            .push(" GROUP BY id) WHERE started_at >= ")
            .bind("DateTime64(6, 'UTC')", ts(from))
            .push(" AND started_at <= ")
            .bind("DateTime64(6, 'UTC')", ts(to))
            .push(" ORDER BY started_at");
        Ok(self
            .rows::<ToolCallRow>(&mut q)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    async fn get_tool_call(&self, id: Uuid) -> Result<Option<ToolCallEvent>> {
        Ok(self.tool_calls_by_ids(&[id]).await?.into_iter().next())
    }

    async fn tool_calls_by_ids(&self, ids: &[Uuid]) -> Result<Vec<ToolCallEvent>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let list = ids
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut q = Q::new(&format!(
            "SELECT * FROM ({TOOL_CALLS_MERGED} WHERE has(splitByChar(',', "
        ));
        q.bind("String", list)
            .push("), toString(id)) GROUP BY id, agent_id) ORDER BY first_received LIMIT 1 BY id");
        Ok(self
            .rows::<ToolCallRow>(&mut q)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    async fn recent_tool_calls(&self, agent_id: Uuid, limit: u32) -> Result<Vec<ToolCallEvent>> {
        let mut q = Q::new(&format!(
            "SELECT * FROM ({TOOL_CALLS_MERGED} WHERE agent_id = "
        ));
        q.bind("UUID", agent_id)
            .push(" GROUP BY id) ORDER BY started_at DESC LIMIT ")
            .bind("UInt32", limit);
        Ok(self
            .rows::<ToolCallRow>(&mut q)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    async fn set_correlation(
        &self,
        flow_id: Uuid,
        correlation: Option<(Uuid, Confidence)>,
    ) -> Result<()> {
        self.insert(
            "flow_correlations",
            vec![json!({
                "flow_id": flow_id,
                "tool_call_id": correlation.map(|c| c.0),
                "confidence": correlation.map(|c| enum_str(&c.1)),
                "at": ts(Utc::now()),
            })],
        )
        .await
    }

    async fn flows_of_agent_between(
        &self,
        agent_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<FlowEvent>> {
        let mut q = Q::new("SELECT event FROM flows WHERE agent_id = ");
        q.bind("UUID", agent_id)
            .push(" AND started_at >= ")
            .bind("DateTime64(6, 'UTC')", ts(from))
            .push(" AND started_at <= ")
            .bind("DateTime64(6, 'UTC')", ts(to))
            .push(" ORDER BY started_at");
        self.events(&mut q).await
    }

    async fn search_flows(
        &self,
        filter: &LogFilter,
        cursor: Option<Cursor>,
        limit: u32,
    ) -> Result<Vec<StoredFlow>> {
        let mut q = Q::new("SELECT event FROM flows WHERE 1");
        push_flow_filter(&mut q, filter);
        if let Some(c) = cursor {
            q.push(" AND (started_at, id) < (")
                .bind("DateTime64(6, 'UTC')", ts(c.at))
                .push(", ")
                .bind("UUID", c.id)
                .push(")");
        }
        q.push(" ORDER BY started_at DESC, id DESC LIMIT ")
            .bind("UInt32", limit);
        let flows = self.events(&mut q).await?;
        self.attach_correlations(flows).await
    }

    async fn flow_histogram(
        &self,
        filter: &LogFilter,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        bucket_secs: i64,
    ) -> Result<Vec<HistogramRow>> {
        #[derive(Deserialize)]
        struct R {
            at: i64,
            n_allow: u64,
            n_deny: u64,
            n_observed: u64,
        }
        let mut q = Q::new("SELECT intDiv(toUnixTimestamp(started_at), ");
        q.bind("Int64", bucket_secs)
            .push(") * ")
            .bind("Int64", bucket_secs)
            .push(
                " AS at, countIf(verdict = 'allow' AND NOT observed) AS n_allow, \
                 countIf(verdict = 'deny') AS n_deny, countIf(observed) AS n_observed \
                 FROM flows WHERE started_at >= ",
            )
            .bind("DateTime64(6, 'UTC')", ts(from))
            .push(" AND started_at < ")
            .bind("DateTime64(6, 'UTC')", ts(to));
        push_flow_filter(&mut q, filter);
        q.push(" GROUP BY at ORDER BY at");
        self.rows::<R>(&mut q)
            .await?
            .into_iter()
            .map(|r| {
                let at = DateTime::from_timestamp(r.at, 0).context("bucket")?;
                Ok((at, r.n_allow, r.n_deny, r.n_observed))
            })
            .collect()
    }

    async fn search_dns(
        &self,
        filter: &LogFilter,
        cursor: Option<Cursor>,
        limit: u32,
    ) -> Result<Vec<DnsEvent>> {
        let mut q = Q::new("SELECT event FROM dns_events WHERE 1");
        if let Some(a) = filter.agent {
            q.push(" AND agent_id = ").bind("UUID", a);
        }
        if let Some(z) = filter.zone {
            q.push(" AND zone_id = ").bind("UUID", z);
        }
        if let Some(v) = filter.verdict {
            q.push(" AND verdict = ").bind("String", enum_str(&v));
        }
        if let Some(r) = filter.rule {
            q.push(" AND rule_id = ").bind("UUID", r);
        }
        if let Some(from) = filter.from {
            q.push(" AND at >= ").bind("DateTime64(6, 'UTC')", ts(from));
        }
        if let Some(to) = filter.to {
            q.push(" AND at <= ").bind("DateTime64(6, 'UTC')", ts(to));
        }
        match &filter.destination {
            Some(Destination::Ip(ip)) => {
                q.push(" AND has(answer_ips, ").bind("String", ip).push(")");
            }
            Some(Destination::Cidr(n)) => {
                q.push(" AND arrayExists(a -> isIPAddressInRange(a, ")
                    .bind("String", n)
                    .push("), answer_ips)");
            }
            Some(Destination::Domain(d)) => {
                q.push(" AND (qname = ")
                    .bind("String", d)
                    .push(" OR endsWith(qname, ")
                    .bind("String", format!(".{d}"))
                    .push("))");
            }
            None => {}
        }
        if let Some(text) = filter.q.as_deref().filter(|q| !q.trim().is_empty()) {
            q.push(" AND qname LIKE ")
                .bind("String", like_pattern(text.trim()));
        }
        if let Some(c) = cursor {
            q.push(" AND (at, id) < (")
                .bind("DateTime64(6, 'UTC')", ts(c.at))
                .push(", ")
                .bind("UUID", c.id)
                .push(")");
        }
        q.push(" ORDER BY at DESC, id DESC LIMIT ")
            .bind("UInt32", limit);
        self.events(&mut q).await
    }

    async fn get_flow(&self, id: Uuid) -> Result<Option<StoredFlow>> {
        let mut q = Q::new("SELECT event FROM flows WHERE id = ");
        q.bind("UUID", id).push(" LIMIT 1");
        let flows: Vec<FlowEvent> = self.events(&mut q).await?;
        Ok(self.attach_correlations(flows).await?.into_iter().next())
    }

    async fn http_for_flow(&self, flow_id: Uuid) -> Result<Vec<StoredHttp>> {
        #[derive(Deserialize)]
        struct R {
            event: String,
            content: Option<String>,
        }
        let mut q = Q::new("SELECT event, content FROM http_events WHERE flow_id = ");
        q.bind("UUID", flow_id)
            .push(" ORDER BY at, id LIMIT 1 BY id");
        self.rows::<R>(&mut q)
            .await?
            .into_iter()
            .map(|r| {
                Ok(StoredHttp {
                    event: serde_json::from_str::<HttpEvent>(&r.event)?,
                    content: r.content.map(|c| B64.decode(c)).transpose()?,
                })
            })
            .collect()
    }

    async fn agent_activity(&self, agent_id: Uuid, since: DateTime<Utc>) -> Result<AgentActivity> {
        #[derive(Deserialize)]
        struct R {
            flows: u64,
            denied: u64,
            bytes_out: u64,
            bytes_in: u64,
            #[serde(deserialize_with = "de_opt_ts")]
            last_seen: Option<DateTime<Utc>>,
        }
        let mut q = Q::new(
            "SELECT count() AS flows, countIf(verdict = 'deny') AS denied, sum(bytes_out) AS bytes_out, \
             sum(bytes_in) AS bytes_in, if(count() = 0, NULL, toString(max(started_at))) AS last_seen \
             FROM flows WHERE agent_id = ",
        );
        q.bind("UUID", agent_id)
            .push(" AND started_at >= ")
            .bind("DateTime64(6, 'UTC')", ts(since));
        let r = self
            .rows::<R>(&mut q)
            .await?
            .into_iter()
            .next()
            .context("empty aggregate")?;
        Ok(AgentActivity {
            flows: r.flows,
            denied: r.denied,
            bytes_out: r.bytes_out,
            bytes_in: r.bytes_in,
            last_seen_at: r.last_seen,
        })
    }

    async fn top_destinations(
        &self,
        agent_id: Uuid,
        since: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<DestinationStat>> {
        #[derive(Deserialize)]
        struct R {
            dest: String,
            flows: u64,
            denied: u64,
            bytes_out: u64,
            bytes_in: u64,
            #[serde(deserialize_with = "de_ts")]
            last_seen: DateTime<Utc>,
        }
        let mut q = Q::new(
            "SELECT dest, count() AS flows, countIf(verdict = 'deny') AS denied, \
             sum(bytes_out) AS bytes_out, sum(bytes_in) AS bytes_in, toString(max(started_at)) AS last_seen \
             FROM flows WHERE agent_id = ",
        );
        q.bind("UUID", agent_id)
            .push(" AND started_at >= ")
            .bind("DateTime64(6, 'UTC')", ts(since))
            .push(" GROUP BY dest ORDER BY flows DESC, dest LIMIT ")
            .bind("UInt32", limit);
        Ok(self
            .rows::<R>(&mut q)
            .await?
            .into_iter()
            .map(|r| DestinationStat {
                destination: r.dest,
                flows: r.flows,
                denied: r.denied,
                bytes_out: r.bytes_out,
                bytes_in: r.bytes_in,
                last_seen_at: r.last_seen,
            })
            .collect())
    }

    async fn recent_flows(
        &self,
        agent_id: Uuid,
        verdict: Option<Verdict>,
        limit: u32,
    ) -> Result<Vec<FlowEvent>> {
        let mut q = Q::new("SELECT event FROM flows WHERE agent_id = ");
        q.bind("UUID", agent_id);
        if let Some(v) = verdict {
            q.push(" AND verdict = ").bind("String", enum_str(&v));
        }
        q.push(" ORDER BY started_at DESC, id DESC LIMIT ")
            .bind("UInt32", limit);
        self.events(&mut q).await
    }

    async fn bytes_out(
        &self,
        agent_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<u64> {
        #[derive(Deserialize)]
        struct R {
            v: u64,
        }
        let mut q = Q::new("SELECT sum(bytes_out) AS v FROM flows WHERE agent_id = ");
        q.bind("UUID", agent_id)
            .push(" AND started_at >= ")
            .bind("DateTime64(6, 'UTC')", ts(from))
            .push(" AND started_at < ")
            .bind("DateTime64(6, 'UTC')", ts(to));
        Ok(self.rows::<R>(&mut q).await?.first().map_or(0, |r| r.v))
    }

    async fn count_flows(
        &self,
        agent_id: Uuid,
        verdict: Option<Verdict>,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<u64> {
        #[derive(Deserialize)]
        struct R {
            v: u64,
        }
        let mut q = Q::new("SELECT count() AS v FROM flows WHERE agent_id = ");
        q.bind("UUID", agent_id);
        if let Some(v) = verdict {
            q.push(" AND verdict = ").bind("String", enum_str(&v));
        }
        q.push(" AND started_at >= ")
            .bind("DateTime64(6, 'UTC')", ts(from))
            .push(" AND started_at < ")
            .bind("DateTime64(6, 'UTC')", ts(to));
        Ok(self.rows::<R>(&mut q).await?.first().map_or(0, |r| r.v))
    }

    async fn internal_edges(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        zone: Option<Uuid>,
    ) -> Result<Vec<EdgeRow>> {
        #[derive(Deserialize)]
        struct R {
            agent_id: Option<Uuid>,
            zone_id: Option<Uuid>,
            src: String,
            dst: String,
            protocol: String,
            dst_port: u16,
            app: Option<String>,
            flows: u64,
            bytes: u64,
            #[serde(deserialize_with = "de_ts")]
            first_seen: DateTime<Utc>,
            #[serde(deserialize_with = "de_ts")]
            last_seen: DateTime<Utc>,
        }
        let mut q = Q::new(
            "SELECT p.agent_id AS agent_id, p.zone_id AS zone_id, p.src AS src, p.dst AS dst, \
             p.protocol AS protocol, p.dst_port AS dst_port, p.app AS app, p.flows AS flows, \
             p.bytes AS bytes, toString(a.first_seen) AS first_seen, toString(p.last_seen) AS last_seen \
             FROM (SELECT ifNull(toString(agent_id), src_ip) AS skey, any(agent_id) AS agent_id, \
               any(zone_id) AS zone_id, min(src_ip) AS src, dst_ip AS dst, protocol, dst_port, \
               max(app) AS app, count() AS flows, sum(bytes_out + bytes_in) AS bytes, \
               max(started_at) AS last_seen FROM flows WHERE internal AND started_at >= ",
        );
        q.bind("DateTime64(6, 'UTC')", ts(from))
            .push(" AND started_at < ")
            .bind("DateTime64(6, 'UTC')", ts(to));
        if let Some(z) = zone {
            q.push(" AND zone_id = ").bind("UUID", z);
        }
        q.push(
            " GROUP BY skey, dst, protocol, dst_port) AS p \
             INNER JOIN (SELECT ifNull(toString(agent_id), src_ip) AS skey, dst_ip AS dst, protocol, \
               dst_port, min(started_at) AS first_seen FROM flows WHERE internal \
               GROUP BY skey, dst, protocol, dst_port) AS a \
             ON p.skey = a.skey AND p.dst = a.dst AND p.protocol = a.protocol AND p.dst_port = a.dst_port \
             ORDER BY flows DESC LIMIT ",
        );
        q.bind("UInt32", super::store::MAX_MAP_EDGES);
        self.rows::<R>(&mut q)
            .await?
            .into_iter()
            .map(|r| {
                Ok(EdgeRow {
                    agent_id: r.agent_id,
                    zone_id: r.zone_id,
                    src: r.src,
                    dst: r.dst,
                    protocol: parse_enum(&r.protocol)?,
                    port: r.dst_port,
                    app: r.app.as_deref().map(parse_enum).transpose()?,
                    flows: r.flows,
                    bytes: r.bytes,
                    first_seen_at: r.first_seen,
                    last_seen_at: r.last_seen,
                })
            })
            .collect()
    }

    async fn last_gateway_of_agent(&self, agent_id: Uuid) -> Result<Option<Uuid>> {
        #[derive(Deserialize)]
        struct R {
            gateway_id: Uuid,
        }
        let mut q = Q::new("SELECT gateway_id FROM flows WHERE agent_id = ");
        q.bind("UUID", agent_id)
            .push(" ORDER BY started_at DESC LIMIT 1");
        Ok(self.rows::<R>(&mut q).await?.first().map(|r| r.gateway_id))
    }

    async fn purge(&self, flows_before: DateTime<Utc>, http_before: DateTime<Utc>) -> Result<u64> {
        // Lightweight deletes; ClickHouse does not report the number of deleted rows.
        for (table, col, before) in [
            ("http_events", "at", http_before.min(flows_before)),
            ("flows", "started_at", flows_before),
            ("dns_events", "at", flows_before),
            ("tool_calls", "started_at", flows_before),
        ] {
            let mut q = Q::new(&format!("DELETE FROM {table} WHERE {col} < "));
            q.bind("DateTime64(6, 'UTC')", ts(before));
            self.exec(&q, None).await?;
        }
        self.exec(
            &Q::new("DELETE FROM flow_correlations WHERE flow_id NOT IN (SELECT id FROM flows)"),
            None,
        )
        .await?;
        Ok(0)
    }
}
