//! Installation of revisions on gateways (desired / acknowledged), rollback, and the functions
//! the gateway protocol (`/gw/v1`, lot L7c) uses: [`installed_policy_for`],
//! [`record_install_ack`], [`gateway_policy_state`].

use afw_core::api::{Install, InstallRequest, InstallResult, InstallState, Page, Role};
use afw_core::events::Actor;
use afw_core::installed::{INSTALLED_POLICY_FORMAT, InstalledPolicy, installed_sha256};
use afw_core::protocol::PolicyAck;
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::types::Json as SqlJson;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::model::parse;
use super::revisions::load_revision;
use super::store::{self, enum_str, parse_enum};
use super::{body_json, pool};
use crate::AppState;
use crate::audit;
use crate::auth::Principal;
use crate::error::ApiError;

pub fn routes() -> Router<AppState> {
    Router::new().route("/installs", get(list_installs).post(install))
}

/// Desired and active revision of a gateway.
#[derive(Clone, Debug, PartialEq)]
pub struct GatewayPolicyState {
    pub desired_revision: u64,
    /// The desired revision is older than the latest one (deliberate rollback).
    pub rollback: bool,
    pub active_revision: Option<u64>,
    pub updated_at: DateTime<Utc>,
}

pub async fn gateway_policy_state(
    pool: &PgPool,
    gateway_id: Uuid,
) -> Result<Option<GatewayPolicyState>, ApiError> {
    let row: Option<(i64, bool, Option<i64>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT desired_revision, rollback, active_revision, updated_at FROM gateway_policy_state \
         WHERE gateway_id = $1",
    )
    .bind(gateway_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(d, rollback, a, updated_at)| GatewayPolicyState {
        desired_revision: d as u64,
        rollback,
        active_revision: a.map(|a| a as u64),
        updated_at,
    }))
}

/// Policy to serve to `gateway_id` (its desired revision), `None` when nothing is installed.
pub async fn installed_policy_for(
    pool: &PgPool,
    gateway_id: Uuid,
) -> Result<Option<InstalledPolicy>, ApiError> {
    let Some(state) = gateway_policy_state(pool, gateway_id).await? else {
        return Ok(None);
    };
    let mut conn = pool.acquire().await?;
    let detail = load_revision(&mut conn, state.desired_revision).await?;
    let revision = detail.revision.number;
    Ok(Some(InstalledPolicy {
        format: INSTALLED_POLICY_FORMAT,
        revision,
        published_at: detail.revision.published_at,
        published_by: detail.revision.published_by.name,
        sha256: installed_sha256(revision, state.rollback, &detail.document),
        rollback: state.rollback,
        document: detail.document,
    }))
}

/// Records a gateway's acknowledgement: the pending installs of that revision become
/// `installed` (and the revision active) or `failed` with the error.
pub async fn record_install_ack(
    pool: &PgPool,
    gateway_id: Uuid,
    ack: &PolicyAck,
) -> Result<(), ApiError> {
    let mut tx = pool.begin().await?;
    let (state, error) = if ack.ok {
        (InstallState::Installed, None)
    } else {
        (
            InstallState::Failed,
            Some(ack.error.clone().unwrap_or_else(|| "failed".into())),
        )
    };
    sqlx::query(
        "UPDATE installs SET state = $3, error = $4, acked_at = now() \
         WHERE gateway_id = $1 AND revision = $2 AND state = 'pending'",
    )
    .bind(gateway_id)
    .bind(ack.revision as i64)
    .bind(enum_str(&state))
    .bind(error)
    .execute(&mut *tx)
    .await?;
    if ack.ok {
        sqlx::query(
            "UPDATE gateway_policy_state SET active_revision = $2, updated_at = now() \
             WHERE gateway_id = $1",
        )
        .bind(gateway_id)
        .bind(ack.revision as i64)
        .execute(&mut *tx)
        .await?;
        if gateways_table_exists(&mut tx).await? {
            sqlx::query("UPDATE gateways SET active_revision = $2 WHERE id = $1")
                .bind(gateway_id)
                .bind(ack.revision as i64)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

/// Every known gateway: the `gateways` table of lot L7c when present, gateways that already
/// have an install, and gateways referenced by agents of the revision.
async fn known_gateways(
    conn: &mut PgConnection,
    doc_gateways: &[Uuid],
) -> Result<Vec<Uuid>, ApiError> {
    let mut ids: Vec<Uuid> = sqlx::query_scalar("SELECT gateway_id FROM gateway_policy_state")
        .fetch_all(&mut *conn)
        .await?;
    if gateways_table_exists(conn).await? {
        let more: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM gateways WHERE deleted_at IS NULL")
                .fetch_all(&mut *conn)
                .await?;
        ids.extend(more);
    }
    ids.extend_from_slice(doc_gateways);
    ids.sort();
    ids.dedup();
    Ok(ids)
}

async fn gateways_table_exists(conn: &mut PgConnection) -> Result<bool, ApiError> {
    Ok(
        sqlx::query_scalar("SELECT to_regclass('public.gateways') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?,
    )
}

type RawInstall = (
    Uuid,
    i64,
    Uuid,
    DateTime<Utc>,
    SqlJson<Actor>,
    String,
    Option<DateTime<Utc>>,
    Option<String>,
);

const COLUMNS: &str =
    "id, revision, gateway_id, requested_at, requested_by, state, acked_at, error";

fn from_raw(r: RawInstall) -> Result<Install, ApiError> {
    Ok(Install {
        id: r.0,
        revision: r.1 as u64,
        gateway_id: r.2,
        requested_at: r.3,
        requested_by: r.4.0,
        state: parse_enum(&r.5)?,
        acked_at: r.6,
        error: r.7,
    })
}

/// Installs a revision (human admin; the MCP agent only the latest revision, never a
/// rollback). An older revision is installed as a rollback.
async fn install(
    State(state): State<AppState>,
    p: Principal,
    body: Bytes,
) -> Result<(StatusCode, Json<InstallResult>), ApiError> {
    let req: InstallRequest = parse(body_json(&body)?)?;
    if p.role != Role::McpAgent {
        p.require(Role::Admin)?;
    }
    let mut tx = pool(&state)?.begin().await?;
    let latest = store::latest_revision(&mut tx)
        .await?
        .map(|(n, _)| n)
        .unwrap_or(0);
    let detail = load_revision(&mut tx, req.revision).await?;
    if p.role == Role::McpAgent && req.revision != latest {
        return Err(ApiError::Forbidden(
            "the MCP agent may only install the latest revision".into(),
        ));
    }
    let gateways = if req.gateways.is_empty() {
        let in_doc: Vec<Uuid> = detail
            .document
            .agents
            .iter()
            .filter_map(|a| a.gateway_id)
            .collect();
        known_gateways(&mut tx, &in_doc).await?
    } else {
        if gateways_table_exists(&mut tx).await? {
            for g in &req.gateways {
                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM gateways WHERE id = $1 AND deleted_at IS NULL)",
                )
                .bind(g)
                .fetch_one(&mut *tx)
                .await?;
                if !exists {
                    return Err(ApiError::NotFound);
                }
            }
        }
        let mut g = req.gateways.clone();
        g.sort();
        g.dedup();
        g
    };
    let rollback = req.revision < latest;
    let mut installs = Vec::new();
    for g in &gateways {
        sqlx::query(
            "UPDATE installs SET state = 'failed', error = 'superseded by a later install' \
             WHERE gateway_id = $1 AND state = 'pending'",
        )
        .bind(g)
        .execute(&mut *tx)
        .await?;
        let id = Uuid::new_v4();
        let sql = format!(
            "INSERT INTO installs (id, revision, gateway_id, requested_by, requested_at, state) \
             VALUES ($1, $2, $3, $4, date_trunc('milliseconds', now()), 'pending') RETURNING {COLUMNS}"
        );
        let raw: RawInstall = sqlx::query_as(&sql)
            .bind(id)
            .bind(req.revision as i64)
            .bind(g)
            .bind(SqlJson(&p.actor))
            .fetch_one(&mut *tx)
            .await?;
        installs.push(from_raw(raw)?);
        sqlx::query(
            "INSERT INTO gateway_policy_state (gateway_id, desired_revision, rollback) \
             VALUES ($1, $2, $3) ON CONFLICT (gateway_id) DO UPDATE SET \
             desired_revision = EXCLUDED.desired_revision, rollback = EXCLUDED.rollback, \
             updated_at = now()",
        )
        .bind(g)
        .bind(req.revision as i64)
        .bind(rollback)
        .execute(&mut *tx)
        .await?;
    }
    // Desired revision mirrored on the gateway registry of lot L7c (linked by value).
    if gateways_table_exists(&mut tx).await? {
        sqlx::query("UPDATE gateways SET desired_revision = $2 WHERE id = ANY($1)")
            .bind(&gateways)
            .bind(req.revision as i64)
            .execute(&mut *tx)
            .await?;
    }
    audit::record(
        &mut tx,
        &p,
        None,
        "install.request",
        &format!("revision:{}", req.revision),
        json!({"gateways": gateways, "rollback": rollback}),
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(InstallResult { installs })))
}

#[derive(Deserialize)]
struct InstallQuery {
    gateway: Option<Uuid>,
    revision: Option<u64>,
    cursor: Option<String>,
    limit: Option<u32>,
}

async fn list_installs(
    State(state): State<AppState>,
    p: Principal,
    Query(q): Query<InstallQuery>,
) -> Result<Json<Page<Install>>, ApiError> {
    p.require(Role::Viewer)?;
    let limit = i64::from(q.limit.unwrap_or(100).clamp(1, 1000));
    let offset: i64 = match &q.cursor {
        Some(c) => c
            .parse()
            .map_err(|_| ApiError::BadRequest("invalid cursor".into()))?,
        None => 0,
    };
    let mut conn = pool(&state)?.acquire().await?;
    let sql = format!(
        "SELECT {COLUMNS} FROM installs WHERE ($1::uuid IS NULL OR gateway_id = $1) \
         AND ($2::bigint IS NULL OR revision = $2) ORDER BY requested_at DESC, id \
         LIMIT $3 OFFSET $4"
    );
    let rows: Vec<RawInstall> = sqlx::query_as(&sql)
        .bind(q.gateway)
        .bind(q.revision.map(|r| r as i64))
        .bind(limit + 1)
        .bind(offset)
        .fetch_all(&mut *conn)
        .await?;
    let mut items: Vec<Install> = rows.into_iter().map(from_raw).collect::<Result<_, _>>()?;
    let next_cursor = (items.len() as i64 > limit).then(|| {
        items.truncate(limit as usize);
        (offset + limit).to_string()
    });
    Ok(Json(Page { items, next_cursor }))
}
