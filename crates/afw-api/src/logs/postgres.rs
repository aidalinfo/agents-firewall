//! PostgreSQL [`LogStore`] (default, `AFW_LOG_STORE=postgres`). Tables: `migrations/0002_logs.sql`.

use std::net::IpAddr;

use afw_core::api::{Confidence, DestinationStat};
use afw_core::events::{DnsEvent, FlowEvent, HttpEvent, ToolCallEvent, Verdict};
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::types::Json;
use sqlx::types::ipnetwork::IpNetwork;
use sqlx::{PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

use super::store::{
    AgentActivity, Cursor, Destination, EdgeRow, HistogramRow, LogFilter, LogStore, StoredFlow,
    StoredHttp, enum_str, flow_destination, i64_of, like_pattern, parse_enum,
};

#[derive(Clone, Debug)]
pub struct PgLogStore {
    pool: PgPool,
}

impl PgLogStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn net(ip: IpAddr) -> IpNetwork {
    IpNetwork::from(ip)
}

fn cidr(n: &ipnet::IpNet) -> IpNetwork {
    IpNetwork::new(n.network(), n.prefix_len()).expect("valid prefix")
}

fn u64_of(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// Appends the filter clauses on the `flows` table (alias `f`).
fn push_flow_filter(b: &mut QueryBuilder<'_, Postgres>, f: &LogFilter) {
    if let Some(a) = f.agent {
        b.push(" AND f.agent_id = ").push_bind(a);
    }
    if let Some(z) = f.zone {
        b.push(" AND f.zone_id = ").push_bind(z);
    }
    if let Some(v) = f.verdict {
        b.push(" AND f.verdict = ").push_bind(enum_str(&v));
    }
    if let Some(r) = f.rule {
        b.push(" AND f.rule_id = ").push_bind(r);
    }
    if let Some(from) = f.from {
        b.push(" AND f.started_at >= ").push_bind(from);
    }
    if let Some(to) = f.to {
        b.push(" AND f.started_at <= ").push_bind(to);
    }
    match &f.destination {
        Some(Destination::Ip(ip)) => {
            b.push(" AND f.dst_ip = ").push_bind(net(*ip));
        }
        Some(Destination::Cidr(n)) => {
            b.push(" AND f.dst_ip <<= ").push_bind(cidr(n));
        }
        Some(Destination::Domain(d)) => {
            let suffix = format!(".{d}");
            b.push(" AND (lower(f.domain) = ")
                .push_bind(d.clone())
                .push(" OR right(lower(f.domain), ")
                .push_bind(suffix.len() as i32)
                .push(") = ")
                .push_bind(suffix.clone())
                .push(" OR lower(f.sni) = ")
                .push_bind(d.clone())
                .push(" OR right(lower(f.sni), ")
                .push_bind(suffix.len() as i32)
                .push(") = ")
                .push_bind(suffix)
                .push(")");
        }
        None => {}
    }
    if let Some(q) = f.q.as_deref().filter(|q| !q.trim().is_empty()) {
        let p = like_pattern(q.trim());
        b.push(" AND (f.search LIKE ")
            .push_bind(p.clone())
            .push(" OR EXISTS (SELECT 1 FROM http_events h WHERE h.flow_id = f.id AND lower(h.url) LIKE ")
            .push_bind(p)
            .push("))");
    }
}

type ToolCallRow = (
    Uuid,
    String,
    String,
    String,
    String,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<String>,
);

const TOOL_CALL_COLS: &str =
    "id, agent, conversation_id, tool, args_summary, started_at, ended_at, status";

fn tool_call(r: ToolCallRow) -> ToolCallEvent {
    ToolCallEvent {
        id: r.0,
        agent: r.1,
        conversation_id: r.2,
        tool: r.3,
        args_summary: r.4,
        started_at: r.5,
        ended_at: r.6,
        status: r.7,
    }
}

fn stored_flow(event: Json<FlowEvent>, tc: Option<Uuid>, conf: Option<String>) -> StoredFlow {
    StoredFlow {
        flow: event.0,
        correlation: tc.zip(conf.and_then(|c| parse_enum::<Confidence>(&c).ok())),
    }
}

impl LogStore for PgLogStore {
    async fn insert_flows(&self, flows: &[FlowEvent]) -> Result<Vec<Uuid>> {
        let mut inserted = Vec::new();
        for chunk in flows.chunks(500) {
            let mut b = QueryBuilder::<Postgres>::new(
                "INSERT INTO flows (id, gateway_id, agent_id, zone_id, src_ip, dst_ip, dst_port, \
                 protocol, app, dest, domain, sni, search, started_at, verdict, rule_id, internal, \
                 observed, bytes_out, bytes_in, event) ",
            );
            b.push_values(chunk, |mut row, f| {
                let search = format!(
                    "{} {} {}",
                    f.domain.as_deref().unwrap_or(""),
                    f.sni.as_deref().unwrap_or(""),
                    f.dst.ip()
                )
                .to_lowercase();
                row.push_bind(f.id)
                    .push_bind(f.gateway_id)
                    .push_bind(f.agent_id)
                    .push_bind(f.zone_id)
                    .push_bind(net(f.src.ip()))
                    .push_bind(net(f.dst.ip()))
                    .push_bind(i32::from(f.dst.port()))
                    .push_bind(enum_str(&f.protocol))
                    .push_bind(f.app.as_ref().map(enum_str))
                    .push_bind(flow_destination(f))
                    .push_bind(f.domain.clone())
                    .push_bind(f.sni.clone())
                    .push_bind(search)
                    .push_bind(f.started_at)
                    .push_bind(enum_str(&f.verdict))
                    .push_bind(f.decision.rule_id)
                    .push_bind(f.internal)
                    .push_bind(f.observed)
                    .push_bind(i64_of(f.bytes_out))
                    .push_bind(i64_of(f.bytes_in))
                    .push_bind(Json(f));
            });
            b.push(" ON CONFLICT (id) DO NOTHING RETURNING id");
            let ids: Vec<(Uuid,)> = b.build_query_as().fetch_all(&self.pool).await?;
            inserted.extend(ids.into_iter().map(|r| r.0));
        }
        Ok(inserted)
    }

    async fn insert_dns(&self, events: &[DnsEvent]) -> Result<()> {
        for chunk in events.chunks(500) {
            let mut b = QueryBuilder::<Postgres>::new(
                "INSERT INTO dns_events (id, gateway_id, agent_id, zone_id, at, qname, answer_ips, \
                 verdict, rule_id, event) ",
            );
            b.push_values(chunk, |mut row, e| {
                let ips: Vec<IpNetwork> = e
                    .answers
                    .iter()
                    .filter_map(|a| a.parse::<IpAddr>().ok())
                    .map(net)
                    .collect();
                row.push_bind(e.id)
                    .push_bind(e.gateway_id)
                    .push_bind(e.agent_id)
                    .push_bind(e.zone_id)
                    .push_bind(e.at)
                    .push_bind(e.qname.trim_end_matches('.').to_ascii_lowercase())
                    .push_bind(ips)
                    .push_bind(enum_str(&e.verdict))
                    .push_bind(e.decision.rule_id)
                    .push_bind(Json(e));
            });
            b.push(" ON CONFLICT (id) DO NOTHING");
            b.build().execute(&self.pool).await?;
        }
        Ok(())
    }

    async fn insert_http(&self, events: &[StoredHttp]) -> Result<()> {
        for chunk in events.chunks(500) {
            let mut b = QueryBuilder::<Postgres>::new(
                "INSERT INTO http_events (id, flow_id, gateway_id, agent_id, at, url, event, content) ",
            );
            b.push_values(chunk, |mut row, h| {
                let e = &h.event;
                row.push_bind(e.id)
                    .push_bind(e.flow_id)
                    .push_bind(e.gateway_id)
                    .push_bind(e.agent_id)
                    .push_bind(e.at)
                    .push_bind(e.url.clone())
                    .push_bind(Json(e))
                    .push_bind(h.content.clone());
            });
            b.push(" ON CONFLICT (id) DO NOTHING");
            b.build().execute(&self.pool).await?;
        }
        Ok(())
    }

    async fn upsert_tool_calls(&self, agent_id: Uuid, calls: &[ToolCallEvent]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for c in calls {
            sqlx::query(
                "INSERT INTO tool_calls (id, agent_id, agent, conversation_id, tool, args_summary, \
                 started_at, ended_at, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT (id) DO UPDATE SET \
                   ended_at = COALESCE(EXCLUDED.ended_at, tool_calls.ended_at), \
                   status = COALESCE(EXCLUDED.status, tool_calls.status), \
                   started_at = LEAST(tool_calls.started_at, EXCLUDED.started_at) \
                 WHERE tool_calls.agent_id = EXCLUDED.agent_id",
            )
            .bind(c.id)
            .bind(agent_id)
            .bind(&c.agent)
            .bind(&c.conversation_id)
            .bind(&c.tool)
            .bind(&c.args_summary)
            .bind(c.started_at)
            .bind(c.ended_at)
            .bind(&c.status)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn tool_calls_between(
        &self,
        agent_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<ToolCallEvent>> {
        let rows: Vec<ToolCallRow> = sqlx::query_as(&format!(
            "SELECT {TOOL_CALL_COLS} FROM tool_calls WHERE agent_id = $1 \
             AND started_at >= $2 AND started_at <= $3 ORDER BY started_at"
        ))
        .bind(agent_id)
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(tool_call).collect())
    }

    async fn get_tool_call(&self, id: Uuid) -> Result<Option<ToolCallEvent>> {
        let row: Option<ToolCallRow> = sqlx::query_as(&format!(
            "SELECT {TOOL_CALL_COLS} FROM tool_calls WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(tool_call))
    }

    async fn tool_calls_by_ids(&self, ids: &[Uuid]) -> Result<Vec<ToolCallEvent>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows: Vec<ToolCallRow> = sqlx::query_as(&format!(
            "SELECT {TOOL_CALL_COLS} FROM tool_calls WHERE id = ANY($1)"
        ))
        .bind(ids)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(tool_call).collect())
    }

    async fn recent_tool_calls(&self, agent_id: Uuid, limit: u32) -> Result<Vec<ToolCallEvent>> {
        let rows: Vec<ToolCallRow> = sqlx::query_as(&format!(
            "SELECT {TOOL_CALL_COLS} FROM tool_calls WHERE agent_id = $1 \
             ORDER BY started_at DESC LIMIT $2"
        ))
        .bind(agent_id)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(tool_call).collect())
    }

    async fn set_correlation(
        &self,
        flow_id: Uuid,
        correlation: Option<(Uuid, Confidence)>,
    ) -> Result<()> {
        sqlx::query("UPDATE flows SET tool_call_id = $2, confidence = $3 WHERE id = $1")
            .bind(flow_id)
            .bind(correlation.map(|c| c.0))
            .bind(correlation.map(|c| enum_str(&c.1)))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn flows_of_agent_between(
        &self,
        agent_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<FlowEvent>> {
        let rows: Vec<(Json<FlowEvent>,)> = sqlx::query_as(
            "SELECT event FROM flows WHERE agent_id = $1 AND started_at >= $2 \
             AND started_at <= $3 ORDER BY started_at",
        )
        .bind(agent_id)
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.0.0).collect())
    }

    async fn search_flows(
        &self,
        filter: &LogFilter,
        cursor: Option<Cursor>,
        limit: u32,
    ) -> Result<Vec<StoredFlow>> {
        let mut b = QueryBuilder::<Postgres>::new(
            "SELECT f.event, f.tool_call_id, f.confidence FROM flows f WHERE true",
        );
        push_flow_filter(&mut b, filter);
        if let Some(c) = cursor {
            b.push(" AND (f.started_at, f.id) < (")
                .push_bind(c.at)
                .push(", ")
                .push_bind(c.id)
                .push(")");
        }
        b.push(" ORDER BY f.started_at DESC, f.id DESC LIMIT ")
            .push_bind(i64::from(limit));
        let rows: Vec<(Json<FlowEvent>, Option<Uuid>, Option<String>)> =
            b.build_query_as().fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|(e, tc, c)| stored_flow(e, tc, c))
            .collect())
    }

    async fn flow_histogram(
        &self,
        filter: &LogFilter,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        bucket_secs: i64,
    ) -> Result<Vec<HistogramRow>> {
        let mut b = QueryBuilder::<Postgres>::new(
            "SELECT to_timestamp(floor(extract(epoch FROM f.started_at) / ",
        );
        b.push_bind(bucket_secs as f64)
            .push(") * ")
            .push_bind(bucket_secs as f64)
            .push(
                ") AS at, \
                 count(*) FILTER (WHERE f.verdict = 'allow' AND NOT f.observed), \
                 count(*) FILTER (WHERE f.verdict = 'deny'), \
                 count(*) FILTER (WHERE f.observed) \
                 FROM flows f WHERE f.started_at >= ",
            )
            .push_bind(from)
            .push(" AND f.started_at < ")
            .push_bind(to);
        push_flow_filter(&mut b, filter);
        b.push(" GROUP BY 1 ORDER BY 1");
        let rows: Vec<(DateTime<Utc>, i64, i64, i64)> =
            b.build_query_as().fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|r| (r.0, u64_of(r.1), u64_of(r.2), u64_of(r.3)))
            .collect())
    }

    async fn search_dns(
        &self,
        filter: &LogFilter,
        cursor: Option<Cursor>,
        limit: u32,
    ) -> Result<Vec<DnsEvent>> {
        let mut b = QueryBuilder::<Postgres>::new("SELECT d.event FROM dns_events d WHERE true");
        if let Some(a) = filter.agent {
            b.push(" AND d.agent_id = ").push_bind(a);
        }
        if let Some(z) = filter.zone {
            b.push(" AND d.zone_id = ").push_bind(z);
        }
        if let Some(v) = filter.verdict {
            b.push(" AND d.verdict = ").push_bind(enum_str(&v));
        }
        if let Some(r) = filter.rule {
            b.push(" AND d.rule_id = ").push_bind(r);
        }
        if let Some(from) = filter.from {
            b.push(" AND d.at >= ").push_bind(from);
        }
        if let Some(to) = filter.to {
            b.push(" AND d.at <= ").push_bind(to);
        }
        match &filter.destination {
            Some(Destination::Ip(ip)) => {
                b.push(" AND ")
                    .push_bind(net(*ip))
                    .push(" = ANY(d.answer_ips)");
            }
            Some(Destination::Cidr(n)) => {
                b.push(" AND EXISTS (SELECT 1 FROM unnest(d.answer_ips) a WHERE a <<= ")
                    .push_bind(cidr(n))
                    .push(")");
            }
            Some(Destination::Domain(dom)) => {
                let suffix = format!(".{dom}");
                b.push(" AND (d.qname = ")
                    .push_bind(dom.clone())
                    .push(" OR right(d.qname, ")
                    .push_bind(suffix.len() as i32)
                    .push(") = ")
                    .push_bind(suffix)
                    .push(")");
            }
            None => {}
        }
        if let Some(q) = filter.q.as_deref().filter(|q| !q.trim().is_empty()) {
            b.push(" AND d.qname LIKE ")
                .push_bind(like_pattern(q.trim()));
        }
        if let Some(c) = cursor {
            b.push(" AND (d.at, d.id) < (")
                .push_bind(c.at)
                .push(", ")
                .push_bind(c.id)
                .push(")");
        }
        b.push(" ORDER BY d.at DESC, d.id DESC LIMIT ")
            .push_bind(i64::from(limit));
        let rows: Vec<(Json<DnsEvent>,)> = b.build_query_as().fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(|r| r.0.0).collect())
    }

    async fn get_flow(&self, id: Uuid) -> Result<Option<StoredFlow>> {
        let row: Option<(Json<FlowEvent>, Option<Uuid>, Option<String>)> =
            sqlx::query_as("SELECT event, tool_call_id, confidence FROM flows WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(e, tc, c)| stored_flow(e, tc, c)))
    }

    async fn http_for_flow(&self, flow_id: Uuid) -> Result<Vec<StoredHttp>> {
        let rows: Vec<(Json<HttpEvent>, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT event, content FROM http_events WHERE flow_id = $1 ORDER BY at, id",
        )
        .bind(flow_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(e, content)| StoredHttp {
                event: e.0,
                content,
            })
            .collect())
    }

    async fn agent_activity(&self, agent_id: Uuid, since: DateTime<Utc>) -> Result<AgentActivity> {
        let r: (i64, i64, i64, i64, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT count(*), count(*) FILTER (WHERE verdict = 'deny'), \
             COALESCE(sum(bytes_out), 0)::bigint, COALESCE(sum(bytes_in), 0)::bigint, \
             max(started_at) FROM flows WHERE agent_id = $1 AND started_at >= $2",
        )
        .bind(agent_id)
        .bind(since)
        .fetch_one(&self.pool)
        .await?;
        Ok(AgentActivity {
            flows: u64_of(r.0),
            denied: u64_of(r.1),
            bytes_out: u64_of(r.2),
            bytes_in: u64_of(r.3),
            last_seen_at: r.4,
        })
    }

    async fn top_destinations(
        &self,
        agent_id: Uuid,
        since: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<DestinationStat>> {
        let rows: Vec<(String, i64, i64, i64, i64, DateTime<Utc>)> = sqlx::query_as(
            "SELECT dest, count(*), count(*) FILTER (WHERE verdict = 'deny'), \
             COALESCE(sum(bytes_out), 0)::bigint, COALESCE(sum(bytes_in), 0)::bigint, \
             max(started_at) FROM flows WHERE agent_id = $1 AND started_at >= $2 \
             GROUP BY dest ORDER BY count(*) DESC, dest LIMIT $3",
        )
        .bind(agent_id)
        .bind(since)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| DestinationStat {
                destination: r.0,
                flows: u64_of(r.1),
                denied: u64_of(r.2),
                bytes_out: u64_of(r.3),
                bytes_in: u64_of(r.4),
                last_seen_at: r.5,
            })
            .collect())
    }

    async fn recent_flows(
        &self,
        agent_id: Uuid,
        verdict: Option<Verdict>,
        limit: u32,
    ) -> Result<Vec<FlowEvent>> {
        let rows: Vec<(Json<FlowEvent>,)> = sqlx::query_as(
            "SELECT event FROM flows WHERE agent_id = $1 AND ($2::text IS NULL OR verdict = $2) \
             ORDER BY started_at DESC, id DESC LIMIT $3",
        )
        .bind(agent_id)
        .bind(verdict.map(|v| enum_str(&v)))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.0.0).collect())
    }

    async fn bytes_out(
        &self,
        agent_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<u64> {
        let (v,): (i64,) = sqlx::query_as(
            "SELECT COALESCE(sum(bytes_out), 0)::bigint FROM flows WHERE agent_id = $1 \
             AND started_at >= $2 AND started_at < $3",
        )
        .bind(agent_id)
        .bind(from)
        .bind(to)
        .fetch_one(&self.pool)
        .await?;
        Ok(u64_of(v))
    }

    async fn count_flows(
        &self,
        agent_id: Uuid,
        verdict: Option<Verdict>,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<u64> {
        let (v,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM flows WHERE agent_id = $1 AND ($2::text IS NULL OR verdict = $2) \
             AND started_at >= $3 AND started_at < $4",
        )
        .bind(agent_id)
        .bind(verdict.map(|v| enum_str(&v)))
        .bind(from)
        .bind(to)
        .fetch_one(&self.pool)
        .await?;
        Ok(u64_of(v))
    }

    async fn internal_edges(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        zone: Option<Uuid>,
    ) -> Result<Vec<EdgeRow>> {
        type Row = (
            Option<Uuid>,
            Option<Uuid>,
            String,
            String,
            String,
            i32,
            Option<String>,
            i64,
            i64,
            DateTime<Utc>,
            DateTime<Utc>,
        );
        let rows: Vec<Row> = sqlx::query_as(
            "WITH p AS ( \
               SELECT COALESCE(agent_id::text, host(src_ip)) AS skey, \
                 (array_agg(agent_id))[1] AS agent_id, (array_agg(zone_id))[1] AS zone_id, \
                 min(host(src_ip)) AS src, host(dst_ip) AS dst, protocol, dst_port, \
                 max(app) AS app, count(*) AS flows, \
                 COALESCE(sum(bytes_out + bytes_in), 0)::bigint AS bytes, \
                 max(started_at) AS last_seen \
               FROM flows WHERE internal AND started_at >= $1 AND started_at < $2 \
                 AND ($3::uuid IS NULL OR zone_id = $3) \
               GROUP BY skey, host(dst_ip), protocol, dst_port) \
             SELECT p.agent_id, p.zone_id, p.src, p.dst, p.protocol, p.dst_port, p.app, p.flows, \
               p.bytes, \
               (SELECT min(f.started_at) FROM flows f WHERE f.internal \
                  AND COALESCE(f.agent_id::text, host(f.src_ip)) = p.skey \
                  AND host(f.dst_ip) = p.dst AND f.protocol = p.protocol \
                  AND f.dst_port = p.dst_port) AS first_seen, \
               p.last_seen \
             FROM p ORDER BY p.flows DESC LIMIT $4",
        )
        .bind(from)
        .bind(to)
        .bind(zone)
        .bind(i64::from(super::store::MAX_MAP_EDGES))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(EdgeRow {
                    agent_id: r.0,
                    zone_id: r.1,
                    src: r.2,
                    dst: r.3,
                    protocol: parse_enum(&r.4)?,
                    port: u16::try_from(r.5).unwrap_or(0),
                    app: r.6.as_deref().map(parse_enum).transpose()?,
                    flows: u64_of(r.7),
                    bytes: u64_of(r.8),
                    first_seen_at: r.9,
                    last_seen_at: r.10,
                })
            })
            .collect()
    }

    async fn last_gateway_of_agent(&self, agent_id: Uuid) -> Result<Option<Uuid>> {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT gateway_id FROM flows WHERE agent_id = $1 ORDER BY started_at DESC LIMIT 1",
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.0))
    }

    async fn purge(&self, flows_before: DateTime<Utc>, http_before: DateTime<Utc>) -> Result<u64> {
        let mut n = 0;
        n += sqlx::query("DELETE FROM http_events WHERE at < $1")
            .bind(http_before)
            .execute(&self.pool)
            .await?
            .rows_affected();
        for sql in [
            "DELETE FROM http_events WHERE flow_id IN (SELECT id FROM flows WHERE started_at < $1)",
            "DELETE FROM flows WHERE started_at < $1",
            "DELETE FROM dns_events WHERE at < $1",
            "DELETE FROM tool_calls WHERE started_at < $1",
        ] {
            n += sqlx::query(sql)
                .bind(flows_before)
                .execute(&self.pool)
                .await?
                .rows_affected();
        }
        Ok(n)
    }
}
