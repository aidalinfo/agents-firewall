//! Gateway management routes (`/api/v1/gateways…`).

use afw_core::api::{CreateRegistrationToken, Gateway, GatewayStatus, RegistrationToken, Role};
use afw_core::protocol::{GatewayCommand, GatewayStats, REGISTRATION_TOKEN_TTL_SECS};
use afw_core::sha256_hex;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use sqlx::types::Json as SqlJson;
use uuid::Uuid;

use crate::AppState;
use crate::audit;
use crate::auth::Principal;
use crate::auth::extract::{JsonBody, new_secret};
use crate::auth::tokens::pool;
use crate::error::ApiError;

/// Prefix of gateway registration tokens.
pub const REGISTRATION_TOKEN_PREFIX: &str = "afw_rt_";

type GatewayRow = (
    Uuid,
    String,
    String,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<SqlJson<GatewayStats>>,
);

const GATEWAY_COLUMNS: &str = "id, name, hostname, registered_at, last_seen_at, version, \
    active_revision, desired_revision, ca_fingerprint, stats";

fn to_gateway(state: &AppState, r: GatewayRow) -> Gateway {
    let offline_after = chrono::Duration::from_std(state.gateways.offline_after)
        .unwrap_or(chrono::Duration::seconds(90));
    let status = match r.4 {
        None => GatewayStatus::Pending,
        Some(seen) if Utc::now() - seen <= offline_after => GatewayStatus::Online,
        Some(_) => GatewayStatus::Offline,
    };
    let rev = |v: Option<i64>| v.and_then(|n| u64::try_from(n).ok());
    Gateway {
        id: r.0,
        name: r.1,
        hostname: r.2,
        status,
        version: r.5,
        desired_revision: rev(r.7),
        active_revision: rev(r.6),
        last_seen_at: r.4,
        registered_at: r.3,
        ca_fingerprint: r.8,
        stats: r.9.map(|s| s.0),
    }
}

/// `GET /gateways` (viewer).
pub async fn list(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<Json<Vec<Gateway>>, ApiError> {
    principal.require(Role::Viewer)?;
    let rows: Vec<GatewayRow> = sqlx::query_as(&format!(
        "SELECT {GATEWAY_COLUMNS} FROM gateways WHERE deleted_at IS NULL ORDER BY name, id"
    ))
    .fetch_all(pool(&state)?)
    .await?;
    Ok(Json(
        rows.into_iter().map(|r| to_gateway(&state, r)).collect(),
    ))
}

/// `GET /gateways/{id}` (viewer).
pub async fn get_one(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<Gateway>, ApiError> {
    principal.require(Role::Viewer)?;
    let row: Option<GatewayRow> = sqlx::query_as(&format!(
        "SELECT {GATEWAY_COLUMNS} FROM gateways WHERE id = $1 AND deleted_at IS NULL"
    ))
    .bind(id)
    .fetch_optional(pool(&state)?)
    .await?;
    row.map(|r| Json(to_gateway(&state, r)))
        .ok_or(ApiError::NotFound)
}

/// `DELETE /gateways/{id}` (admin): the gateway's certificate stops authenticating at once.
pub async fn remove(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    principal.require(Role::Admin)?;
    let mut tx = pool(&state)?.begin().await?;
    let name: Option<String> = sqlx::query_scalar(
        "UPDATE gateways SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL \
         RETURNING name",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let name = name.ok_or(ApiError::NotFound)?;
    audit::record(
        &mut tx,
        &principal,
        None,
        "gateway.delete",
        &format!("gateway:{id}"),
        serde_json::json!({"before": {"id": id, "name": name}}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /gateways/registration-tokens` (admin): one-time token valid 15 minutes, shown once.
pub async fn create_registration_token(
    State(state): State<AppState>,
    principal: Principal,
    JsonBody(req): JsonBody<CreateRegistrationToken>,
) -> Result<(StatusCode, Json<RegistrationToken>), ApiError> {
    principal.require(Role::Admin)?;
    let token = new_secret(REGISTRATION_TOKEN_PREFIX);
    let ttl = chrono::Duration::seconds(REGISTRATION_TOKEN_TTL_SECS as i64);
    let mut tx = pool(&state)?.begin().await?;
    let (id, expires_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO gateway_registration_tokens (token_sha256, name, created_by, expires_at) \
         VALUES ($1, $2, $3, now() + $4) RETURNING id, expires_at",
    )
    .bind(sha256_hex(token.as_bytes()))
    .bind(req.name.as_deref())
    .bind(SqlJson(&principal.actor))
    .bind(ttl)
    .fetch_one(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        &principal,
        None,
        "gateway.registration_token.create",
        &format!("registration_token:{id}"),
        serde_json::json!({"after": {"id": id, "name": req.name, "expires_at": expires_at}}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(RegistrationToken { token, expires_at }),
    ))
}

/// `POST /gateways/{id}/commands` (admin): queued, delivered once with the next heartbeat.
pub async fn send_command(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
    JsonBody(command): JsonBody<GatewayCommand>,
) -> Result<StatusCode, ApiError> {
    principal.require(Role::Admin)?;
    let mut tx = pool(&state)?.begin().await?;
    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM gateways WHERE id = $1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    exists.ok_or(ApiError::NotFound)?;
    let command_id: Uuid = sqlx::query_scalar(
        "INSERT INTO gateway_commands (gateway_id, command, created_by) VALUES ($1, $2, $3) \
         RETURNING id",
    )
    .bind(id)
    .bind(SqlJson(&command))
    .bind(SqlJson(&principal.actor))
    .fetch_one(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        &principal,
        None,
        "gateway.command",
        &format!("gateway:{id}"),
        serde_json::json!({"after": {"command_id": command_id, "command": command}}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::ACCEPTED)
}
