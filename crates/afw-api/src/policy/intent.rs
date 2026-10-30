//! Hermes intent policy (`GET /intent-policy`, `PUT /intent-policy`, ADR 0015). Versioned in
//! the `intent_policy` table; without any version, the plugin's built-in policy (version 0).

use afw_core::api::{IntentPolicy, Role};
use afw_core::events::Actor;
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::routing::get;
use serde_json::json;
use sqlx::PgConnection;
use sqlx::types::Json as SqlJson;

use super::model::parse;
use super::store::enum_str;
use super::{body_json, pool};
use crate::AppState;
use crate::audit;
use crate::auth::Principal;
use crate::error::ApiError;

/// Built-in policy of the Hermes plugin (`afw_hermes.intent.DEFAULT_POLICY_DOC`).
const DEFAULT_JSON: &str = include_str!("intent_default.json");

pub fn default_intent_policy() -> IntentPolicy {
    serde_json::from_str(DEFAULT_JSON).expect("built-in intent policy is valid")
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/intent-policy", get(get_intent).put(put_intent))
}

/// Current intent policy (latest version, or the built-in one).
pub async fn current_intent_policy(conn: &mut PgConnection) -> Result<IntentPolicy, ApiError> {
    let row: Option<(i64, SqlJson<IntentPolicy>)> =
        sqlx::query_as("SELECT version, document FROM intent_policy ORDER BY version DESC LIMIT 1")
            .fetch_optional(&mut *conn)
            .await?;
    Ok(match row {
        Some((v, d)) => IntentPolicy {
            version: v as u64,
            ..d.0
        },
        None => default_intent_policy(),
    })
}

/// Plugin token, or any reading role (viewer and above, MCP agent).
async fn get_intent(
    State(state): State<AppState>,
    p: Principal,
) -> Result<Json<IntentPolicy>, ApiError> {
    if p.require_plugin().is_err() {
        p.require(Role::Viewer)?;
    }
    let mut conn = pool(&state)?.acquire().await?;
    Ok(Json(current_intent_policy(&mut conn).await?))
}

/// Replaces the intent policy (human admin, audited). The version is assigned by the server.
async fn put_intent(
    State(state): State<AppState>,
    p: Principal,
    body: Bytes,
) -> Result<Json<IntentPolicy>, ApiError> {
    p.require(Role::Admin)?;
    let mut policy: IntentPolicy = parse(body_json(&body)?)?;
    for c in &policy.action_classes {
        if c.id.trim().is_empty() || c.name.trim().is_empty() {
            return Err(ApiError::BadRequest(
                "action class id and name are required".into(),
            ));
        }
    }
    let mut tx = pool(&state)?.begin().await?;
    sqlx::query("LOCK TABLE intent_policy IN EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;
    let before = current_intent_policy(&mut tx).await?;
    policy.version = before.version + 1;
    sqlx::query(
        "INSERT INTO intent_policy (version, document, updated_by, interface) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(policy.version as i64)
    .bind(SqlJson(&policy))
    .bind(SqlJson::<&Actor>(&p.actor))
    .bind(enum_str(&p.interface))
    .execute(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        &p,
        None,
        "intent_policy.update",
        &format!("intent_policy:{}", policy.version),
        json!({"before": before, "after": policy}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(policy))
}
