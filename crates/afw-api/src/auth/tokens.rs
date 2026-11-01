//! API tokens: `GET/POST /tokens`, `DELETE /tokens/{id}`. Secrets are shown once and stored
//! as SHA-256 only.

use afw_core::api::{ApiToken, CreateApiToken, CreatedApiToken, Role};
use afw_core::events::{Actor, ActorKind};
use afw_core::sha256_hex;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use sqlx::types::Json as SqlJson;
use uuid::Uuid;

use super::extract::{JsonBody, new_secret};
use crate::AppState;
use crate::audit;
use crate::auth::Principal;
use crate::error::ApiError;

/// Prefix of API token secrets.
pub const TOKEN_PREFIX: &str = "afw_";
/// Prefix of agent token secrets (Hermes plugin, MCP agent).
pub const AGENT_TOKEN_PREFIX: &str = "afw_at_";

pub(crate) fn role_str(role: Role) -> &'static str {
    match role {
        Role::Admin => "admin",
        Role::Auditor => "auditor",
        Role::Viewer => "viewer",
        Role::McpAgent => "mcp_agent",
        Role::AgentPlugin => "agent_plugin",
    }
}

pub(crate) fn pool(state: &AppState) -> Result<&sqlx::PgPool, ApiError> {
    state
        .pool
        .as_ref()
        .ok_or_else(|| ApiError::Internal("no database configured".into()))
}

pub(crate) fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.code().as_deref() == Some("23505"))
}

fn validate(req: &CreateApiToken) -> Result<(), ApiError> {
    if req.name.trim().is_empty() || req.name.len() > 200 {
        return Err(ApiError::BadRequest(
            "name must be 1 to 200 characters".into(),
        ));
    }
    let agent_role = matches!(req.role, Role::McpAgent | Role::AgentPlugin);
    match (agent_role, req.agent_id) {
        (true, None) => {
            return Err(ApiError::BadRequest(
                "agent_id is required for agent roles".into(),
            ));
        }
        (false, Some(_)) => {
            return Err(ApiError::BadRequest(
                "agent_id is only allowed for agent roles".into(),
            ));
        }
        _ => {}
    }
    if req.expires_at.is_some_and(|e| e <= Utc::now()) {
        return Err(ApiError::BadRequest("expires_at is in the past".into()));
    }
    Ok(())
}

/// Validates and inserts a token, records `token.create` in the audit chain (same connection,
/// call it inside the caller's transaction) and returns the secret once.
pub async fn create_token(
    conn: &mut PgConnection,
    principal: &Principal,
    session_id: Option<Uuid>,
    req: &CreateApiToken,
) -> Result<CreatedApiToken, ApiError> {
    validate(req)?;
    let agent_role = matches!(req.role, Role::McpAgent | Role::AgentPlugin);
    let secret = new_secret(if agent_role {
        AGENT_TOKEN_PREFIX
    } else {
        TOKEN_PREFIX
    });
    if req.role == Role::McpAgent {
        // An expired mcp_agent token still counts for the single-active-token index: revoke the
        // expired ones first, in the same transaction, so a new one can be issued.
        let expired: Vec<(Uuid, String)> = sqlx::query_as(
            "UPDATE api_tokens SET revoked_at = now() WHERE role = 'mcp_agent' \
             AND revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= now() \
             RETURNING id, name",
        )
        .fetch_all(&mut *conn)
        .await?;
        for (id, name) in expired {
            audit::record(
                conn,
                principal,
                session_id,
                "token.revoke",
                &format!("token:{id}"),
                serde_json::json!({"before": {"id": id, "name": name, "role": "mcp_agent"},
                                   "reason": "expired"}),
            )
            .await?;
        }
    }
    // Tokens of human roles are used by tools (CLI, automation): their actor kind is `cli`.
    let actor_kind = if agent_role { "agent" } else { "cli" };
    let row: (Uuid, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO api_tokens (name, token_sha256, role, actor_kind, actor_name, agent_id, \
         created_by, expires_at) VALUES ($1, $2, $3, $4, $1, $5, $6, $7) \
         RETURNING id, created_at",
    )
    .bind(req.name.trim())
    .bind(sha256_hex(secret.as_bytes()))
    .bind(role_str(req.role))
    .bind(actor_kind)
    .bind(req.agent_id)
    .bind(SqlJson(&principal.actor))
    .bind(req.expires_at)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        if is_unique_violation(&e) {
            ApiError::Conflict {
                message: "an active mcp_agent token already exists".into(),
            }
        } else {
            e.into()
        }
    })?;
    let token = ApiToken {
        id: row.0,
        name: req.name.trim().to_owned(),
        role: req.role,
        agent_id: req.agent_id,
        created_at: row.1,
        created_by: principal.actor.clone(),
        expires_at: req.expires_at,
        last_used_at: None,
    };
    audit::record(
        conn,
        principal,
        session_id,
        "token.create",
        &format!("token:{}", token.id),
        serde_json::json!({"after": token}),
    )
    .await?;
    Ok(CreatedApiToken { token, secret })
}

type Row = (
    Uuid,
    String,
    String,
    Option<Uuid>,
    DateTime<Utc>,
    SqlJson<serde_json::Value>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

fn to_api_token(r: Row) -> Result<ApiToken, ApiError> {
    let role = serde_json::from_value(serde_json::Value::String(r.2.clone()))
        .map_err(|_| ApiError::Internal(format!("invalid stored role {:?}", r.2)))?;
    let created_by = serde_json::from_value(r.5.0).unwrap_or(Actor {
        kind: ActorKind::System,
        id: "system".into(),
        name: "unknown".into(),
    });
    Ok(ApiToken {
        id: r.0,
        name: r.1,
        role,
        agent_id: r.3,
        created_at: r.4,
        created_by,
        expires_at: r.6,
        last_used_at: r.7,
    })
}

/// `GET /tokens` (admin): active tokens, never their secrets.
pub async fn list(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<Json<Vec<ApiToken>>, ApiError> {
    principal.require(Role::Admin)?;
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, name, role, agent_id, created_at, created_by, expires_at, last_used_at \
         FROM api_tokens WHERE revoked_at IS NULL ORDER BY created_at, id",
    )
    .fetch_all(pool(&state)?)
    .await?;
    rows.into_iter()
        .map(to_api_token)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

/// `POST /tokens` (admin).
pub async fn create(
    State(state): State<AppState>,
    principal: Principal,
    JsonBody(req): JsonBody<CreateApiToken>,
) -> Result<(StatusCode, Json<CreatedApiToken>), ApiError> {
    principal.require(Role::Admin)?;
    validate(&req)?;
    if let Some(agent) = req.agent_id {
        // The agent must exist in the published policy (fail closed when it is unknown).
        let known = state
            .ports
            .policy
            .current_policy(&state)
            .await?
            .is_some_and(|doc| doc.agents.iter().any(|a| a.id == agent));
        if !known {
            return Err(ApiError::BadRequest(format!(
                "agent {agent} is not in the published policy"
            )));
        }
    }
    let mut tx = pool(&state)?.begin().await?;
    let created = create_token(&mut tx, &principal, None, &req).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(created)))
}

/// `DELETE /tokens/{id}` (admin): immediate revocation.
pub async fn revoke(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    principal.require(Role::Admin)?;
    let mut tx = pool(&state)?.begin().await?;
    let revoked: Option<(String, String)> = sqlx::query_as(
        "UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL \
         RETURNING name, role",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let (name, role) = revoked.ok_or(ApiError::NotFound)?;
    audit::record(
        &mut tx,
        &principal,
        None,
        "token.revoke",
        &format!("token:{id}"),
        serde_json::json!({"before": {"id": id, "name": name, "role": role}}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
