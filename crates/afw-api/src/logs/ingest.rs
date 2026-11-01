//! Ingestion of gateway events and Hermes tool calls.

use std::collections::{BTreeMap, HashSet};

use afw_core::api::Correlation;
use afw_core::events::{
    Body, DnsEvent, FlowEvent, GatewayEvent, HttpEvent, RuleHit, ToolCallEvent,
};
use afw_core::protocol::EventBatch;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use super::correlation::{MAX_OPEN_CALL, UNCERTAIN_WINDOW, correlate};
use super::crypto::Purpose;
use super::store::{LogStore, StoredHttp, i64_of};
use super::{AnyLogStore, alerts};
use crate::AppState;
use crate::error::ApiError;

/// Maximum number of tool-call events per request.
pub const MAX_TOOL_CALLS_PER_BATCH: usize = 1000;

/// What an ingestion stored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IngestReport {
    /// Newly stored flows (already known ids are skipped).
    pub flows: usize,
    pub dns: usize,
    pub http: usize,
    pub alerts: usize,
    pub rule_hits: usize,
    /// The batch had already been ingested (nothing done).
    pub duplicate: bool,
}

pub(crate) fn pool(state: &AppState) -> Result<&PgPool, ApiError> {
    state
        .pool
        .as_ref()
        .ok_or_else(|| ApiError::Internal("no database configured".into()))
}

/// Stored precision (microseconds), so that cursors and comparisons are exact.
fn micros(t: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(t.timestamp_micros()).unwrap_or(t)
}

/// Sealed part of an HTTP exchange (headers and bodies).
#[derive(Serialize, Deserialize, Default)]
pub(crate) struct HttpContent {
    pub request_headers: Vec<(String, String)>,
    pub request_body: Option<Body>,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Option<Body>,
}

/// Splits an exchange into its clear metadata and its contents.
pub(crate) fn strip_content(mut e: HttpEvent) -> (HttpEvent, HttpContent) {
    let content = HttpContent {
        request_headers: std::mem::take(&mut e.request_headers),
        request_body: e.request_body.take(),
        response_headers: std::mem::take(&mut e.response_headers),
        response_body: e.response_body.take(),
    };
    (e, content)
}

pub(crate) fn restore_content(mut e: HttpEvent, c: HttpContent) -> HttpEvent {
    e.request_headers = c.request_headers;
    e.request_body = c.request_body;
    e.response_headers = c.response_headers;
    e.response_body = c.response_body;
    e
}

/// Ingests a gateway batch once: a batch re-sent after a timeout (same `batch_id`) is skipped.
pub async fn ingest_gateway_batch(
    state: &AppState,
    gateway_id: Uuid,
    batch: EventBatch,
) -> Result<IngestReport, ApiError> {
    let pool = pool(state)?;
    // Reserve the batch first (atomic against a concurrent re-send); released on failure.
    let reserved = sqlx::query(
        "INSERT INTO ingested_batches (gateway_id, batch_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(gateway_id)
    .bind(batch.batch_id)
    .execute(pool)
    .await?
    .rows_affected()
        == 1;
    if !reserved {
        return Ok(IngestReport {
            duplicate: true,
            ..IngestReport::default()
        });
    }
    let report = match ingest_gateway_events(state, gateway_id, batch.events).await {
        Ok(r) => r,
        Err(e) => {
            sqlx::query("DELETE FROM ingested_batches WHERE gateway_id = $1 AND batch_id = $2")
                .bind(gateway_id)
                .bind(batch.batch_id)
                .execute(pool)
                .await?;
            return Err(e);
        }
    };
    Ok(report)
}

/// Ingests events reported by gateway `gateway_id` (authenticated by mTLS: the gateway id
/// carried by the events is overwritten with it). Idempotent per event id, except rule hit
/// counters (use [`ingest_gateway_batch`] for exactly-once counting).
pub async fn ingest_gateway_events(
    state: &AppState,
    gateway_id: Uuid,
    events: Vec<GatewayEvent>,
) -> Result<IngestReport, ApiError> {
    let store = state.logs.store()?;
    let pool = pool(state)?;
    let mut flows: Vec<FlowEvent> = Vec::new();
    let mut dns: Vec<DnsEvent> = Vec::new();
    let mut http: Vec<HttpEvent> = Vec::new();
    let mut alert_events = Vec::new();
    let mut hits: Vec<RuleHit> = Vec::new();
    for ev in events {
        match ev {
            GatewayEvent::Flow(mut f) => {
                f.gateway_id = gateway_id;
                f.started_at = micros(f.started_at);
                f.ended_at = f.ended_at.map(micros);
                flows.push(f);
            }
            GatewayEvent::Dns(mut d) => {
                d.gateway_id = gateway_id;
                d.at = micros(d.at);
                dns.push(d);
            }
            GatewayEvent::Http(mut h) => {
                h.gateway_id = gateway_id;
                h.at = micros(h.at);
                http.push(h);
            }
            GatewayEvent::Alert(mut a) => {
                a.at = micros(a.at);
                alert_events.push(a);
            }
            GatewayEvent::RuleHits { hits: h } => hits.extend(h),
        }
    }
    let mut report = IngestReport::default();

    // Flows: idempotent, only new ones go further (correlation, alerts, stream).
    let new_ids: HashSet<Uuid> = store.insert_flows(&flows).await?.into_iter().collect();
    let new_flows: Vec<FlowEvent> = flows
        .into_iter()
        .filter(|f| new_ids.contains(&f.id))
        .collect();
    report.flows = new_flows.len();
    correlate_new_flows(store, &new_flows).await?;

    store.insert_dns(&dns).await?;
    report.dns = dns.len();

    let mut stored_http = Vec::with_capacity(http.len());
    let mut live_http = Vec::with_capacity(http.len());
    for h in http {
        let (meta, content) = strip_content(h);
        let sealed = match &state.logs.cipher {
            Some(c) => Some(c.seal(
                Purpose::HttpContent,
                meta.id.as_bytes(),
                &serde_json::to_vec(&content).map_err(|e| ApiError::Internal(e.to_string()))?,
            )),
            None => {
                tracing::warn!(http_event = %meta.id, "no AFW_DATA_KEY: HTTP contents dropped");
                None
            }
        };
        live_http.push(meta.clone());
        stored_http.push(StoredHttp {
            event: meta,
            content: sealed,
        });
    }
    store.insert_http(&stored_http).await?;
    report.http = stored_http.len();

    for hit in &hits {
        sqlx::query(
            "INSERT INTO rule_hits (rule_id, gateway_id, revision, hits, last_hit_at) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (rule_id, gateway_id, revision) DO UPDATE SET \
             hits = rule_hits.hits + EXCLUDED.hits, \
             last_hit_at = GREATEST(rule_hits.last_hit_at, EXCLUDED.last_hit_at)",
        )
        .bind(hit.rule_id)
        .bind(gateway_id)
        .bind(i64_of(hit.revision))
        .bind(i64_of(hit.hits))
        .bind(hit.last_hit_at)
        .execute(pool)
        .await?;
    }
    report.rule_hits = hits.len();

    // Live stream: contents are never broadcast.
    for f in &new_flows {
        let _ = state.logs.events.send(GatewayEvent::Flow(f.clone()));
    }
    for d in dns {
        let _ = state.logs.events.send(GatewayEvent::Dns(d));
    }
    for h in live_http {
        let _ = state.logs.events.send(GatewayEvent::Http(h));
    }

    for a in alert_events {
        if alerts::raise(state, a, Some(gateway_id), alerts::Source::Gateway).await? {
            report.alerts += 1;
        }
    }
    report.alerts += alerts::after_flows(state, &new_flows).await?;
    Ok(report)
}

async fn correlate_new_flows(store: &AnyLogStore, flows: &[FlowEvent]) -> Result<(), ApiError> {
    let mut by_agent: BTreeMap<Uuid, Vec<&FlowEvent>> = BTreeMap::new();
    for f in flows {
        if let Some(a) = f.agent_id {
            by_agent.entry(a).or_default().push(f);
        }
    }
    for (agent, flows) in by_agent {
        let min = flows.iter().map(|f| f.started_at).min().expect("non-empty");
        let max = flows.iter().map(|f| f.started_at).max().expect("non-empty");
        let calls = store
            .tool_calls_between(agent, min - MAX_OPEN_CALL, max)
            .await?;
        for f in flows {
            if let Some((_, c)) = correlate(f.started_at, &calls) {
                store
                    .set_correlation(f.id, Some((c.tool_call_id, c.confidence)))
                    .await?;
            }
        }
    }
    Ok(())
}

/// Ingests tool calls reported by the Hermes plugin of agent `agent_id` (from the token, never
/// from the payload), then recomputes the correlation of the flows they may cover.
pub async fn ingest_tool_calls(
    state: &AppState,
    agent_id: Uuid,
    calls: Vec<ToolCallEvent>,
) -> Result<(), ApiError> {
    if calls.len() > MAX_TOOL_CALLS_PER_BATCH {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_TOOL_CALLS_PER_BATCH} events per request"
        )));
    }
    let clip = |s: &str, n: usize| s.chars().take(n).collect::<String>();
    let calls: Vec<ToolCallEvent> = calls
        .into_iter()
        .map(|c| ToolCallEvent {
            agent: clip(&c.agent, 256),
            conversation_id: clip(&c.conversation_id, 256),
            tool: clip(&c.tool, 256),
            args_summary: clip(&c.args_summary, 4096),
            status: c.status.map(|s| clip(&s, 64)),
            started_at: micros(c.started_at),
            ended_at: c.ended_at.map(micros),
            ..c
        })
        .collect();
    for c in &calls {
        if c.ended_at.is_some_and(|e| e < c.started_at) {
            return Err(ApiError::BadRequest(format!(
                "tool call {}: ended_at before started_at",
                c.id
            )));
        }
    }
    if calls.is_empty() {
        return Ok(());
    }
    let store = state.logs.store()?;
    store.upsert_tool_calls(agent_id, &calls).await?;

    // Re-correlate the flows of the window covered by these calls.
    let from = calls.iter().map(|c| c.started_at).min().expect("non-empty");
    let to = calls
        .iter()
        .map(|c| c.ended_at.unwrap_or(c.started_at + MAX_OPEN_CALL))
        .max()
        .expect("non-empty")
        + UNCERTAIN_WINDOW;
    let flows = store.flows_of_agent_between(agent_id, from, to).await?;
    if flows.is_empty() {
        return Ok(());
    }
    let all_calls = store
        .tool_calls_between(agent_id, from - MAX_OPEN_CALL, to)
        .await?;
    for f in flows {
        let c = correlate(f.started_at, &all_calls).map(|(_, c)| (c.tool_call_id, c.confidence));
        store.set_correlation(f.id, c).await?;
    }
    Ok(())
}

/// Correlation of a flow computed now from the stored tool calls (ADR 0007).
pub(crate) async fn correlation_now(
    store: &AnyLogStore,
    flow: &FlowEvent,
) -> Result<Option<(ToolCallEvent, Correlation)>, ApiError> {
    let Some(agent) = flow.agent_id else {
        return Ok(None);
    };
    let calls = store
        .tool_calls_between(agent, flow.started_at - MAX_OPEN_CALL, flow.started_at)
        .await?;
    Ok(correlate(flow.started_at, &calls).map(|(call, c)| (call.clone(), c)))
}

/// A stored flow (for `POST /sessions/{id}/allow-from-log`, lot L7a).
pub async fn get_flow(state: &AppState, id: Uuid) -> Result<Option<FlowEvent>, ApiError> {
    Ok(state.logs.store()?.get_flow(id).await?.map(|f| f.flow))
}
