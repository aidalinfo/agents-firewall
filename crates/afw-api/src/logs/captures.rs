//! Packet captures on demand (EF-33): request (admin), command for the gateway (heartbeat),
//! upload by the gateway (sealed with AES-256-GCM before storage), audited download.

use afw_core::api::{Capture, CaptureRequest, CaptureState, Page, Role};
use afw_core::events::Actor;
use afw_core::protocol::GatewayCommand;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::PgPool;
use sqlx::types::Json as SqlJson;
use uuid::Uuid;

use super::crypto::Purpose;
use super::ingest::pool;
use super::routes::page_limit;
use super::store::{Cursor, LogStore, parse_enum};
use crate::AppState;
use crate::audit;
use crate::auth::Principal;
use crate::error::ApiError;

pub const MAX_CAPTURE_SECS: u32 = 3600;
/// Largest accepted pcap upload.
pub const MAX_CAPTURE_BYTES: usize = 256 * 1024 * 1024;
/// Delay after the end of a capture before it is declared failed if never uploaded.
const UPLOAD_GRACE_SECS: i64 = 300;

type CaptureRow = (
    Uuid,
    Uuid,
    Uuid,
    DateTime<Utc>,
    SqlJson<Actor>,
    i32,
    String,
    Option<i64>,
    Option<String>,
);

const COLS: &str =
    "id, agent_id, gateway_id, requested_at, requested_by, duration_secs, state, size, error";

fn capture_of(r: CaptureRow) -> Result<Capture, ApiError> {
    Ok(Capture {
        id: r.0,
        agent_id: r.1,
        gateway_id: r.2,
        requested_at: r.3,
        requested_by: r.4.0,
        duration_secs: u32::try_from(r.5).unwrap_or(0),
        state: parse_enum(&r.6)?,
        size: r.7.and_then(|s| u64::try_from(s).ok()),
        error: r.8,
    })
}

/// Marks as failed the captures dispatched but never uploaded in time.
pub async fn expire_stale(pool: &PgPool) -> Result<u64, ApiError> {
    Ok(sqlx::query(
        "UPDATE captures SET state = 'failed', error = 'capture not uploaded in time', \
         completed_at = now() WHERE state = 'running' \
         AND dispatched_at + make_interval(secs => duration_secs + $1) < now()",
    )
    .bind(UPLOAD_GRACE_SECS as f64)
    .execute(pool)
    .await?
    .rows_affected())
}

/// Commands waiting for gateway `gateway_id` (sent in the heartbeat response, lot L7c).
/// Pending captures become `running` once handed over.
pub async fn pending_commands(
    pool: &PgPool,
    gateway_id: Uuid,
) -> Result<Vec<GatewayCommand>, ApiError> {
    expire_stale(pool).await?;
    let rows: Vec<(Uuid, Uuid, i32)> = sqlx::query_as(
        "UPDATE captures SET state = 'running', dispatched_at = now() \
         WHERE gateway_id = $1 AND state = 'pending' RETURNING id, agent_id, duration_secs",
    )
    .bind(gateway_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(capture_id, agent_id, d)| GatewayCommand::StartCapture {
            capture_id,
            agent_id,
            duration_secs: u32::try_from(d).unwrap_or(0),
        })
        .collect())
}

/// Stores the pcap uploaded by gateway `gateway_id` for capture `capture_id`
/// (`POST /gw/v1/captures/{id}`, lot L7c). Never stored in clear: without `AFW_DATA_KEY` the
/// capture fails.
pub async fn store_capture(
    state: &AppState,
    gateway_id: Uuid,
    capture_id: Uuid,
    data: &[u8],
) -> Result<Capture, ApiError> {
    let pool = pool(state)?;
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT gateway_id, state FROM captures WHERE id = $1")
            .bind(capture_id)
            .fetch_optional(pool)
            .await?;
    let (owner, st) = row.ok_or(ApiError::NotFound)?;
    if owner != gateway_id {
        return Err(ApiError::NotFound);
    }
    if !matches!(st.as_str(), "pending" | "running") {
        return Err(ApiError::Conflict {
            message: format!("capture is {st}"),
        });
    }
    let fail = |msg: &str| {
        sqlx::query(
            "UPDATE captures SET state = 'failed', error = $2, completed_at = now() \
             WHERE id = $1 AND state IN ('pending', 'running')",
        )
        .bind(capture_id)
        .bind(msg.to_owned())
        .execute(pool)
    };
    if data.len() > MAX_CAPTURE_BYTES {
        fail("capture too large").await?;
        return Err(ApiError::BadRequest("capture too large".into()));
    }
    let Some(cipher) = &state.logs.cipher else {
        fail("AFW_DATA_KEY not configured: capture not stored").await?;
        return Err(ApiError::Conflict {
            message: "AFW_DATA_KEY not configured".into(),
        });
    };
    let sealed = cipher.seal(Purpose::Capture, capture_id.as_bytes(), data);
    // State guard in the update itself: a concurrent upload or expiry wins only once.
    let row: Option<CaptureRow> = sqlx::query_as(&format!(
        "UPDATE captures SET state = 'done', size = $2, data = $3, completed_at = now(), \
         error = NULL WHERE id = $1 AND gateway_id = $4 AND state IN ('pending', 'running') \
         RETURNING {COLS}"
    ))
    .bind(capture_id)
    .bind(i64::try_from(data.len()).unwrap_or(i64::MAX))
    .bind(sealed)
    .bind(gateway_id)
    .fetch_optional(pool)
    .await?;
    capture_of(row.ok_or_else(|| ApiError::Conflict {
        message: "capture is no longer pending".into(),
    })?)
}

/// `POST /captures` (admin, audited): the gateway is the one that last saw the agent.
pub async fn create(
    p: Principal,
    State(state): State<AppState>,
    b: Result<Json<CaptureRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Capture>), ApiError> {
    p.require(Role::Admin)?;
    let Json(req) = b.map_err(|e| ApiError::BadRequest(e.body_text()))?;
    if req.duration_secs == 0 || req.duration_secs > MAX_CAPTURE_SECS {
        return Err(ApiError::BadRequest(format!(
            "duration_secs must be 1 to {MAX_CAPTURE_SECS}"
        )));
    }
    let gateway = state
        .logs
        .store()?
        .last_gateway_of_agent(req.agent_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let now = Utc::now();
    let now = DateTime::from_timestamp_micros(now.timestamp_micros()).unwrap_or(now);
    let capture = Capture {
        id: Uuid::new_v4(),
        agent_id: req.agent_id,
        gateway_id: gateway,
        requested_at: now,
        requested_by: p.actor.clone(),
        duration_secs: req.duration_secs,
        state: CaptureState::Pending,
        size: None,
        error: None,
    };
    let mut tx = pool(&state)?.begin().await?;
    sqlx::query(
        "INSERT INTO captures (id, agent_id, gateway_id, requested_at, requested_by, \
         duration_secs, state) VALUES ($1, $2, $3, $4, $5, $6, 'pending')",
    )
    .bind(capture.id)
    .bind(capture.agent_id)
    .bind(capture.gateway_id)
    .bind(capture.requested_at)
    .bind(SqlJson(&capture.requested_by))
    .bind(i32::try_from(capture.duration_secs).unwrap_or(i32::MAX))
    .execute(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        &p,
        None,
        "capture.request",
        &format!("capture:{}", capture.id),
        serde_json::json!({"agent_id": capture.agent_id, "duration_secs": capture.duration_secs}),
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(capture)))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

pub async fn list(
    p: Principal,
    State(state): State<AppState>,
    q: Result<Query<ListQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Page<Capture>>, ApiError> {
    p.require(Role::Viewer)?;
    let Query(q) = q.map_err(|e| ApiError::BadRequest(e.body_text()))?;
    let limit = page_limit(q.limit)?;
    let cursor = q
        .cursor
        .as_deref()
        .map(|c| Cursor::decode(c).ok_or_else(|| ApiError::BadRequest("invalid cursor".into())))
        .transpose()?;
    let pool = pool(&state)?;
    expire_stale(pool).await?;
    let rows: Vec<CaptureRow> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM captures WHERE ($1::timestamptz IS NULL OR (requested_at, id) < ($1, $2)) \
         ORDER BY requested_at DESC, id DESC LIMIT $3"
    ))
    .bind(cursor.map(|c| c.at))
    .bind(cursor.map(|c| c.id).unwrap_or_default())
    .bind(i64::from(limit) + 1)
    .fetch_all(pool)
    .await?;
    let mut items: Vec<Capture> = rows.into_iter().map(capture_of).collect::<Result<_, _>>()?;
    let next_cursor = if items.len() > limit as usize {
        items.truncate(limit as usize);
        items.last().map(|c| {
            Cursor {
                at: c.requested_at,
                id: c.id,
            }
            .encode()
        })
    } else {
        None
    };
    Ok(Json(Page { items, next_cursor }))
}

pub async fn get_one(
    p: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Capture>, ApiError> {
    p.require(Role::Viewer)?;
    let pool = pool(&state)?;
    expire_stale(pool).await?;
    let row: Option<CaptureRow> =
        sqlx::query_as(&format!("SELECT {COLS} FROM captures WHERE id = $1"))
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(Json(capture_of(row.ok_or(ApiError::NotFound)?)?))
}

/// `GET /captures/{id}/download`: contents, so auditor or admin only; audited (EF-54).
pub async fn download(
    p: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    p.require(Role::Auditor)?;
    if !p.can_see_content() {
        return Err(ApiError::Forbidden(
            "contents require auditor or admin".into(),
        ));
    }
    let pool = pool(&state)?;
    let row: Option<(String, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT state, data FROM captures WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    let (st, data) = row.ok_or(ApiError::NotFound)?;
    let (Some(data), "done") = (data, st.as_str()) else {
        return Err(ApiError::Conflict {
            message: format!("capture is {st}"),
        });
    };
    let cipher = state
        .logs
        .cipher
        .as_ref()
        .ok_or_else(|| ApiError::Internal("AFW_DATA_KEY not configured".into()))?;
    let pcap = cipher
        .open(Purpose::Capture, id.as_bytes(), &data)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let mut tx = pool.begin().await?;
    audit::record(
        &mut tx,
        &p,
        None,
        "capture.download",
        &format!("capture:{id}"),
        serde_json::json!({"size": pcap.len()}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        [
            (
                header::CONTENT_TYPE,
                "application/vnd.tcpdump.pcap".to_owned(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"capture-{id}.pcap\""),
            ),
        ],
        pcap,
    )
        .into_response())
}

/// Deletes captures requested before `before` (retention).
pub async fn purge(pool: &PgPool, before: DateTime<Utc>) -> Result<u64, ApiError> {
    Ok(sqlx::query("DELETE FROM captures WHERE requested_at < $1")
        .bind(before)
        .execute(pool)
        .await?
        .rows_affected())
}
