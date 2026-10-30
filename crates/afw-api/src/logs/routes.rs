//! Log search routes: `/logs/flows`, `/logs/flows/stats`, `/logs/flows/{id}`, `/logs/dns`,
//! `/ingest/tool-calls`.

use std::collections::HashMap;

use afw_core::api::{
    FlowDetail, FlowListItem, FlowStats, FlowStatsPoint, Page, Role, StatsBucket, ToolCallBatch,
};
use afw_core::events::{DnsEvent, HttpEvent, Verdict};
use axum::Json;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use super::crypto::Purpose;
use super::ingest::{
    HttpContent, correlation_now, ingest_tool_calls as ingest_calls, restore_content,
};
use super::store::{Cursor, Destination, LogFilter, LogStore};
use super::views;
use crate::AppState;
use crate::audit;
use crate::auth::Principal;
use crate::error::ApiError;

pub const DEFAULT_LIMIT: u32 = 100;
pub const MAX_LIMIT: u32 = 1000;
pub const MAX_BUCKETS: i64 = 2000;

pub fn page_limit(limit: Option<u32>) -> Result<u32, ApiError> {
    match limit {
        None => Ok(DEFAULT_LIMIT),
        Some(n) if (1..=MAX_LIMIT).contains(&n) => Ok(n),
        Some(_) => Err(ApiError::BadRequest(format!(
            "limit must be 1 to {MAX_LIMIT}"
        ))),
    }
}

/// Query string of the log searches (`FlowQuery` plus `bucket` for the stats).
#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct LogQuery {
    pub agent: Option<Uuid>,
    pub zone: Option<Uuid>,
    pub destination: Option<String>,
    pub verdict: Option<Verdict>,
    pub rule: Option<Uuid>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub q: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub bucket: Option<StatsBucket>,
}

impl LogQuery {
    pub fn filter(&self) -> Result<LogFilter, ApiError> {
        let destination = match self.destination.as_deref() {
            None => None,
            Some(d) if d.trim().is_empty() => None,
            Some(d) => Some(
                Destination::parse(d)
                    .ok_or_else(|| ApiError::BadRequest("invalid destination".into()))?,
            ),
        };
        if let Some(q) = &self.q
            && q.len() > 256
        {
            return Err(ApiError::BadRequest(
                "q is limited to 256 characters".into(),
            ));
        }
        Ok(LogFilter {
            agent: self.agent,
            zone: self.zone,
            destination,
            verdict: self.verdict,
            rule: self.rule,
            from: self.from,
            to: self.to,
            q: self.q.clone(),
        })
    }

    fn cursor(&self) -> Result<Option<Cursor>, ApiError> {
        self.cursor
            .as_deref()
            .map(|c| Cursor::decode(c).ok_or_else(|| ApiError::BadRequest("invalid cursor".into())))
            .transpose()
    }
}

pub(crate) fn query<T>(q: Result<Query<T>, QueryRejection>) -> Result<T, ApiError> {
    q.map(|Query(v)| v)
        .map_err(|e| ApiError::BadRequest(e.body_text()))
}

/// `GET /logs/flows`: newest first, enriched for display.
pub async fn list_flows(
    p: Principal,
    State(state): State<AppState>,
    q: Result<Query<LogQuery>, QueryRejection>,
) -> Result<Json<Page<FlowListItem>>, ApiError> {
    p.require(Role::Viewer)?;
    let q = query(q)?;
    if q.bucket.is_some() {
        return Err(ApiError::BadRequest(
            "bucket only applies to /logs/flows/stats".into(),
        ));
    }
    let limit = page_limit(q.limit)?;
    let store = state.logs.store()?;
    let mut rows = store
        .search_flows(&q.filter()?, q.cursor()?, limit + 1)
        .await?;
    let next_cursor = if rows.len() > limit as usize {
        rows.truncate(limit as usize);
        rows.last().map(|r| {
            Cursor {
                at: r.flow.started_at,
                id: r.flow.id,
            }
            .encode()
        })
    } else {
        None
    };
    let doc = state.logs.load_policy(None).await;
    let ids: Vec<Uuid> = rows
        .iter()
        .filter_map(|r| r.correlation.map(|c| c.0))
        .collect();
    let calls: HashMap<Uuid, _> = store
        .tool_calls_by_ids(&ids)
        .await?
        .into_iter()
        .map(|c| (c.id, c))
        .collect();
    let items = rows
        .into_iter()
        .map(|r| {
            let call = r.correlation.and_then(|c| calls.get(&c.0));
            FlowListItem {
                agent_name: views::agent_name(doc.as_ref(), r.flow.agent_id),
                zone_name: views::zone_name(doc.as_ref(), r.flow.zone_id),
                rule_label: views::rule_label(&r.flow.decision, r.flow.verdict),
                tool: call.map(|c| c.tool.clone()),
                conversation_id: call.map(|c| c.conversation_id.clone()),
                correlation_confidence: call.and(r.correlation.map(|c| c.1)),
                flow: r.flow,
            }
        })
        .collect();
    Ok(Json(Page { items, next_cursor }))
}

/// `GET /logs/flows/stats`: histogram and totals.
pub async fn flow_stats(
    p: Principal,
    State(state): State<AppState>,
    q: Result<Query<LogQuery>, QueryRejection>,
) -> Result<Json<FlowStats>, ApiError> {
    p.require(Role::Viewer)?;
    let q = query(q)?;
    if q.cursor.is_some() || q.limit.is_some() {
        return Err(ApiError::BadRequest(
            "cursor and limit do not apply to stats".into(),
        ));
    }
    let mut filter = q.filter()?;
    let to = filter.to.unwrap_or_else(Utc::now);
    let bucket = q.bucket.unwrap_or(StatsBucket::FiveMinutes);
    let from = filter.from.unwrap_or_else(|| {
        to - match bucket {
            StatsBucket::OneMinute => Duration::hours(1),
            StatsBucket::FiveMinutes => Duration::hours(12),
            StatsBucket::OneHour => Duration::hours(24),
        }
    });
    if from >= to {
        return Err(ApiError::BadRequest("from must be before to".into()));
    }
    let secs = bucket.seconds();
    // Align on bucket boundaries.
    let start = DateTime::from_timestamp(from.timestamp().div_euclid(secs) * secs, 0)
        .ok_or_else(|| ApiError::BadRequest("invalid from".into()))?;
    if (to - start).num_seconds() / secs > MAX_BUCKETS {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_BUCKETS} buckets: widen the bucket or narrow the period"
        )));
    }
    filter.from = None;
    filter.to = None;
    let rows = state
        .logs
        .store()?
        .flow_histogram(&filter, from, to, secs)
        .await?;
    let by_at: HashMap<i64, (u64, u64, u64)> = rows
        .into_iter()
        .map(|(at, a, d, o)| (at.timestamp(), (a, d, o)))
        .collect();
    let mut points = Vec::new();
    let mut t = start;
    while t < to {
        let (allow, deny, observed) = by_at.get(&t.timestamp()).copied().unwrap_or_default();
        points.push(FlowStatsPoint {
            at: t,
            allow,
            deny,
            observed,
        });
        t += Duration::seconds(secs);
    }
    let (allow, deny, observed) = points.iter().fold((0, 0, 0), |acc, p| {
        (acc.0 + p.allow, acc.1 + p.deny, acc.2 + p.observed)
    });
    Ok(Json(FlowStats {
        bucket,
        from,
        to,
        points,
        total: allow + deny + observed,
        allow,
        deny,
        observed,
    }))
}

/// `GET /logs/flows/{id}`: contents only for admin/auditor, and that access is audited (EF-54).
pub async fn get_flow_detail(
    p: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<FlowDetail>, ApiError> {
    p.require(Role::Viewer)?;
    let store = state.logs.store()?;
    let stored = store.get_flow(id).await?.ok_or(ApiError::NotFound)?;
    let flow = stored.flow;
    // Event ids are chosen by gateways: only exchanges reported by the flow's own gateway.
    let stored_http: Vec<_> = store
        .http_for_flow(id)
        .await?
        .into_iter()
        .filter(|h| h.event.gateway_id == flow.gateway_id)
        .collect();
    let with_content = p.can_see_content() && stored_http.iter().any(|h| h.content.is_some());
    let mut http: Vec<HttpEvent> = Vec::with_capacity(stored_http.len());
    for h in stored_http {
        match (&h.content, with_content, &state.logs.cipher) {
            (Some(sealed), true, Some(cipher)) => {
                let plain = cipher
                    .open(Purpose::HttpContent, h.event.id.as_bytes(), sealed)
                    .map_err(|e| ApiError::Internal(format!("http {}: {e}", h.event.id)))?;
                let content: HttpContent = serde_json::from_slice(&plain)
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
                http.push(restore_content(h.event, content));
            }
            // Contents hidden (viewer, MCP agent) or not stored.
            _ => http.push(h.event),
        }
    }
    if with_content {
        audit::record_content_access(state.pool.as_ref().ok_or(ApiError::Unauthorized)?, &p, id)
            .await?;
    }
    // Correlation recomputed at read time (calls may have arrived after the flow).
    let (tool_call, correlation) = match correlation_now(store, &flow).await? {
        Some((call, c)) => (Some(call), Some(c)),
        None => (None, None),
    };
    let current = state.logs.load_policy(None).await;
    let at_revision = match flow.decision.revision {
        Some(r) => state.logs.load_policy(Some(r)).await,
        None => None,
    };
    let name_doc = at_revision.as_ref().or(current.as_ref());
    let agent = views::agent_name(name_doc, flow.agent_id);
    Ok(Json(FlowDetail {
        agent_message: views::agent_message(&flow, agent.as_deref()),
        allow_proposal: views::allow_proposal(&flow, current.as_ref()),
        trace: match (&at_revision, flow.decision.revision) {
            (Some(doc), Some(rev)) => views::trace(&flow, doc, rev, http.first()),
            _ => Vec::new(),
        },
        flow,
        http,
        tool_call,
        correlation,
    }))
}

/// `GET /logs/dns`.
pub async fn list_dns(
    p: Principal,
    State(state): State<AppState>,
    q: Result<Query<LogQuery>, QueryRejection>,
) -> Result<Json<Page<DnsEvent>>, ApiError> {
    p.require(Role::Viewer)?;
    let q = query(q)?;
    if q.bucket.is_some() {
        return Err(ApiError::BadRequest(
            "bucket does not apply to /logs/dns".into(),
        ));
    }
    let limit = page_limit(q.limit)?;
    let mut items = state
        .logs
        .store()?
        .search_dns(&q.filter()?, q.cursor()?, limit + 1)
        .await?;
    let next_cursor = if items.len() > limit as usize {
        items.truncate(limit as usize);
        items.last().map(|d| Cursor { at: d.at, id: d.id }.encode())
    } else {
        None
    };
    Ok(Json(Page { items, next_cursor }))
}

/// `POST /ingest/tool-calls` (Hermes plugin token only; the agent is the token's).
pub async fn ingest_tool_calls(
    p: Principal,
    State(state): State<AppState>,
    b: Result<Json<ToolCallBatch>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    p.require_plugin()?;
    let agent = p
        .agent_id
        .ok_or_else(|| ApiError::Forbidden("agent plugin token required".into()))?;
    let Json(batch) = b.map_err(|e| ApiError::BadRequest(e.body_text()))?;
    ingest_calls(&state, agent, batch.events).await?;
    Ok(StatusCode::ACCEPTED)
}
