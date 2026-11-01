//! Alerts: storage, console-side detection (EF-36) and routes `GET /alerts`,
//! `POST /alerts/{id}/ack`.
//!
//! Console-side detections, in addition to the gateway's own alerts:
//! - `new_destination`: an agent reaches a destination never seen for it, once the agent has
//!   at least [`LEARNING_PERIOD`] of history (no flood on a new agent);
//! - `volume_spike`: bytes sent in the last hour > 3x the hourly average of the previous
//!   7 days and > 10 MB;
//! - `deny_burst`: at least [`DENY_BURST`] denied flows within a minute.

use afw_core::api::{Alert, Page, Role};
use afw_core::events::{Actor, AlertEvent, AlertKind, FlowEvent, GatewayEvent, Severity, Verdict};
use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use sqlx::types::Json as SqlJson;
use uuid::Uuid;

use super::ingest::pool;
use super::store::{Cursor, LogStore, enum_str, flow_destination, parse_enum};
use super::{channels, routes::page_limit};
use crate::AppState;
use crate::audit;
use crate::auth::Principal;
use crate::error::ApiError;

pub const LEARNING_PERIOD: Duration = Duration::hours(24);
pub const VOLUME_SPIKE_MIN_BYTES: u64 = 10 * 1024 * 1024;
pub const VOLUME_SPIKE_FACTOR: u64 = 3;
pub const DENY_BURST: u64 = 20;
pub const DENY_BURST_WINDOW: Duration = Duration::seconds(60);
/// At most this many alerts per agent and kind per hour; then one summary alert.
pub const ALERT_CAP_PER_HOUR: i64 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Gateway,
    Console,
}

/// Stores an alert (idempotent on its id), publishes it on the live stream and sends it to the
/// alert channels. Returns whether it was new.
pub async fn raise(
    state: &AppState,
    event: AlertEvent,
    gateway_id: Option<Uuid>,
    source: Source,
) -> Result<bool, ApiError> {
    let pool = pool(state)?;
    let mut event = event;
    // Flood control per (agent, kind) over the last hour.
    let since = Utc::now() - Duration::hours(1);
    let (recent, summarized): (i64, bool) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE NOT COALESCE((event->'details'->>'capped')::boolean, false)), \
         bool_or(COALESCE((event->'details'->>'capped')::boolean, false)) IS TRUE \
         FROM alerts WHERE agent_id IS NOT DISTINCT FROM $1 AND kind = $2 AND at > $3",
    )
    .bind(event.agent_id)
    .bind(enum_str(&event.kind))
    .bind(since)
    .fetch_one(pool)
    .await?;
    if recent >= ALERT_CAP_PER_HOUR {
        if summarized {
            return Ok(false);
        }
        event = AlertEvent {
            id: Uuid::new_v4(),
            summary: format!(
                "{} alerts: more than {ALERT_CAP_PER_HOUR} in the last hour, further ones suppressed for this hour",
                enum_str(&event.kind)
            ),
            details: serde_json::json!({"capped": true, "cap_per_hour": ALERT_CAP_PER_HOUR}),
            ..event
        };
    }
    let inserted = sqlx::query(
        "INSERT INTO alerts (id, at, kind, severity, agent_id, gateway_id, source, event) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (id) DO NOTHING",
    )
    .bind(event.id)
    .bind(event.at)
    .bind(enum_str(&event.kind))
    .bind(enum_str(&event.severity))
    .bind(event.agent_id)
    .bind(gateway_id)
    .bind(match source {
        Source::Gateway => "gateway",
        Source::Console => "console",
    })
    .bind(SqlJson(&event))
    .execute(pool)
    .await?
    .rows_affected()
        == 1;
    if inserted {
        let _ = state.logs.events.send(GatewayEvent::Alert(event.clone()));
        let alert = Alert {
            event,
            gateway_id,
            acknowledged: false,
            acknowledged_by: None,
        };
        channels::dispatch(state, alert).await?;
    }
    Ok(inserted)
}

async fn recently_alerted(
    state: &AppState,
    agent: Uuid,
    kind: AlertKind,
    since: DateTime<Utc>,
) -> Result<bool, ApiError> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM alerts WHERE agent_id = $1 AND kind = $2 AND at > $3 LIMIT 1",
    )
    .bind(agent)
    .bind(enum_str(&kind))
    .bind(since)
    .fetch_optional(pool(state)?)
    .await?;
    Ok(row.is_some())
}

fn console_alert(
    kind: AlertKind,
    severity: Severity,
    agent: Uuid,
    summary: String,
    details: serde_json::Value,
) -> AlertEvent {
    let now = Utc::now();
    AlertEvent {
        id: Uuid::new_v4(),
        at: DateTime::from_timestamp_micros(now.timestamp_micros()).unwrap_or(now),
        kind,
        severity,
        agent_id: Some(agent),
        summary,
        details,
    }
}

/// Console-side detections on newly ingested flows. Returns the number of alerts raised.
pub async fn after_flows(state: &AppState, flows: &[FlowEvent]) -> Result<usize, ApiError> {
    let pool = pool(state)?;
    let store = state.logs.store()?;
    let mut raised = 0;
    let mut agents = std::collections::BTreeSet::new();
    for f in flows {
        let Some(agent) = f.agent_id else { continue };
        agents.insert(agent);
        if f.internal {
            // Internal flows: lateral-movement alerts come from the gateway (EF-82).
            continue;
        }
        let dest = flow_destination(f);
        let (inserted,): (bool,) = sqlx::query_as(
            "INSERT INTO agent_destinations (agent_id, destination, first_seen_at, last_seen_at) \
             VALUES ($1, $2, $3, $3) ON CONFLICT (agent_id, destination) DO UPDATE SET \
             first_seen_at = LEAST(agent_destinations.first_seen_at, EXCLUDED.first_seen_at), \
             last_seen_at = GREATEST(agent_destinations.last_seen_at, EXCLUDED.last_seen_at) \
             RETURNING (xmax = 0)",
        )
        .bind(agent)
        .bind(&dest)
        .bind(f.started_at)
        .fetch_one(pool)
        .await?;
        if !inserted {
            continue;
        }
        let (oldest,): (Option<DateTime<Utc>>,) =
            sqlx::query_as("SELECT min(first_seen_at) FROM agent_destinations WHERE agent_id = $1")
                .bind(agent)
                .fetch_one(pool)
                .await?;
        if oldest.is_some_and(|o| o <= f.started_at - LEARNING_PERIOD) {
            let ev = console_alert(
                AlertKind::NewDestination,
                Severity::Warning,
                agent,
                format!("new destination {dest}"),
                serde_json::json!({
                    "destination": dest,
                    "flow_id": f.id,
                    "verdict": f.verdict,
                    "dst_ip": f.dst.ip().to_string(),
                }),
            );
            if raise(state, ev, Some(f.gateway_id), Source::Console).await? {
                raised += 1;
            }
        }
    }
    let now = Utc::now();
    for agent in agents {
        // Volume spike.
        let last_hour = store
            .bytes_out(agent, now - Duration::hours(1), now)
            .await?;
        if last_hour > VOLUME_SPIKE_MIN_BYTES {
            let before = store
                .bytes_out(agent, now - Duration::days(7), now - Duration::hours(1))
                .await?;
            let hourly_avg = before / (7 * 24 - 1);
            if last_hour > VOLUME_SPIKE_FACTOR * hourly_avg
                && !recently_alerted(
                    state,
                    agent,
                    AlertKind::VolumeSpike,
                    now - Duration::hours(1),
                )
                .await?
            {
                let ev = console_alert(
                    AlertKind::VolumeSpike,
                    Severity::Warning,
                    agent,
                    format!("outgoing volume spike: {last_hour} bytes in the last hour"),
                    serde_json::json!({"bytes_last_hour": last_hour, "hourly_average_7d": hourly_avg}),
                );
                if raise(state, ev, None, Source::Console).await? {
                    raised += 1;
                }
            }
        }
        // Deny burst, on the flows' own time (a delayed batch is still a burst).
        let Some(last_deny) = flows
            .iter()
            .filter(|f| f.agent_id == Some(agent) && f.verdict == Verdict::Deny)
            .map(|f| f.started_at)
            .max()
        else {
            continue;
        };
        let denied = store
            .count_flows(
                agent,
                Some(Verdict::Deny),
                last_deny - DENY_BURST_WINDOW,
                last_deny + Duration::microseconds(1),
            )
            .await?;
        if denied >= DENY_BURST
            && !recently_alerted(
                state,
                agent,
                AlertKind::DenyBurst,
                now - Duration::minutes(10),
            )
            .await?
        {
            let ev = console_alert(
                AlertKind::DenyBurst,
                Severity::Warning,
                agent,
                format!("{denied} denied flows within a minute"),
                serde_json::json!({"denied": denied, "window_secs": DENY_BURST_WINDOW.num_seconds(), "until": last_deny}),
            );
            if raise(state, ev, None, Source::Console).await? {
                raised += 1;
            }
        }
    }
    Ok(raised)
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AlertQuery {
    pub agent: Option<Uuid>,
    pub severity: Option<Severity>,
    pub acknowledged: Option<bool>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

type AlertRow = (
    SqlJson<afw_core::events::AlertEvent>,
    Option<Uuid>,
    bool,
    Option<SqlJson<Actor>>,
);

fn alert_of(r: AlertRow) -> Alert {
    Alert {
        event: r.0.0,
        gateway_id: r.1,
        acknowledged: r.2,
        acknowledged_by: r.3.map(|a| a.0),
    }
}

/// `GET /alerts` (newest first).
pub async fn list(
    p: Principal,
    State(state): State<AppState>,
    q: Result<Query<AlertQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Page<Alert>>, ApiError> {
    p.require(Role::Viewer)?;
    let Query(q) = q.map_err(|e| ApiError::BadRequest(e.body_text()))?;
    let limit = page_limit(q.limit)?;
    let cursor = q
        .cursor
        .as_deref()
        .map(|c| Cursor::decode(c).ok_or_else(|| ApiError::BadRequest("invalid cursor".into())))
        .transpose()?;
    let mut b = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT event, gateway_id, acknowledged, acknowledged_by FROM alerts WHERE true",
    );
    if let Some(a) = q.agent {
        b.push(" AND agent_id = ").push_bind(a);
    }
    if let Some(s) = q.severity {
        b.push(" AND severity = ").push_bind(enum_str(&s));
    }
    if let Some(ack) = q.acknowledged {
        b.push(" AND acknowledged = ").push_bind(ack);
    }
    if let Some(f) = q.from {
        b.push(" AND at >= ").push_bind(f);
    }
    if let Some(t) = q.to {
        b.push(" AND at <= ").push_bind(t);
    }
    if let Some(c) = cursor {
        b.push(" AND (at, id) < (")
            .push_bind(c.at)
            .push(", ")
            .push_bind(c.id)
            .push(")");
    }
    b.push(" ORDER BY at DESC, id DESC LIMIT ")
        .push_bind(i64::from(limit) + 1);
    let rows: Vec<AlertRow> = b.build_query_as().fetch_all(pool(&state)?).await?;
    let mut items: Vec<Alert> = rows.into_iter().map(alert_of).collect();
    let next_cursor = if items.len() > limit as usize {
        items.truncate(limit as usize);
        items.last().map(|a| {
            Cursor {
                at: a.event.at,
                id: a.event.id,
            }
            .encode()
        })
    } else {
        None
    };
    Ok(Json(Page { items, next_cursor }))
}

/// `POST /alerts/{id}/ack` (auditor or admin; audited).
pub async fn ack(
    p: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Alert>, ApiError> {
    p.require(Role::Auditor)?;
    let pool = pool(&state)?;
    let mut tx = pool.begin().await?;
    let row: Option<AlertRow> = sqlx::query_as(
        "UPDATE alerts SET acknowledged = true, acknowledged_by = COALESCE(acknowledged_by, $2), \
         acknowledged_at = COALESCE(acknowledged_at, now()) WHERE id = $1 \
         RETURNING event, gateway_id, acknowledged, acknowledged_by",
    )
    .bind(id)
    .bind(SqlJson(&p.actor))
    .fetch_optional(&mut *tx)
    .await?;
    let alert = alert_of(row.ok_or(ApiError::NotFound)?);
    audit::record(
        &mut tx,
        &p,
        None,
        "alert.ack",
        &format!("alert:{id}"),
        serde_json::json!({"kind": alert.event.kind}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(alert))
}

/// Recent alerts of an agent (agent overview).
pub async fn recent_for_agent(
    state: &AppState,
    agent: Uuid,
    limit: u32,
) -> Result<Vec<AlertEvent>, ApiError> {
    let rows: Vec<(SqlJson<AlertEvent>,)> =
        sqlx::query_as("SELECT event FROM alerts WHERE agent_id = $1 ORDER BY at DESC LIMIT $2")
            .bind(agent)
            .bind(i64::from(limit))
            .fetch_all(pool(state)?)
            .await?;
    Ok(rows.into_iter().map(|r| r.0.0).collect())
}

/// Number of alerts per (agent, address) in a period, for the internal map.
pub async fn count_by_agent_address(
    state: &AppState,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<std::collections::HashMap<(Uuid, String), u32>, ApiError> {
    let rows: Vec<(Uuid, String, i64)> = sqlx::query_as(
        "SELECT agent_id, COALESCE(event->'details'->>'dst_ip', event->'details'->>'destination'), \
         count(*) FROM alerts WHERE agent_id IS NOT NULL AND at >= $1 AND at < $2 \
         AND COALESCE(event->'details'->>'dst_ip', event->'details'->>'destination') IS NOT NULL \
         GROUP BY 1, 2",
    )
    .bind(from)
    .bind(to)
    .fetch_all(pool(state)?)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(a, d, n)| ((a, d), u32::try_from(n).unwrap_or(u32::MAX)))
        .collect())
}

/// Parses a stored severity (internal).
pub fn severity_of(s: &str) -> Result<Severity, ApiError> {
    parse_enum(s).map_err(ApiError::from)
}
