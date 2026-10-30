//! Authenticated caller, extracted from `Authorization: Bearer <token>`.

use afw_core::api::Role;
use afw_core::events::{Actor, ActorKind, Interface};
use afw_core::sha256_hex;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;
use crate::error::ApiError;

/// Header telling which interface the call comes from (`ui`, `cli`, `mcp`, `api`).
pub const INTERFACE_HEADER: &str = "x-afw-interface";

#[derive(Clone, Debug, PartialEq)]
pub struct Principal {
    pub actor: Actor,
    pub role: Role,
    pub interface: Interface,
    pub token_id: Option<Uuid>,
    /// Zones delegated to the MCP agent (`mcp_agent` role).
    pub delegated_zones: Vec<Uuid>,
    /// Zone of the MCP agent itself: never writable by it (EF-51).
    pub own_zone: Option<Uuid>,
}

fn rank(role: Role) -> u8 {
    match role {
        Role::Viewer => 1,
        Role::Auditor => 2,
        // The MCP agent counts as admin here; its zone restrictions are enforced elsewhere.
        Role::Admin | Role::McpAgent => 3,
    }
}

impl Principal {
    /// Requires at least `min` (Admin > Auditor > Viewer).
    pub fn require(&self, min: Role) -> Result<(), ApiError> {
        if rank(self.role) >= rank(min) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!("role {min:?} required")))
        }
    }

    /// Whether the caller may read captured contents (bodies, headers).
    pub fn can_see_content(&self) -> bool {
        matches!(self.role, Role::Admin | Role::Auditor)
    }

    /// Principal for tests, without a database.
    pub fn for_tests(role: Role) -> Self {
        Self {
            actor: Actor {
                kind: if role == Role::McpAgent {
                    ActorKind::Agent
                } else {
                    ActorKind::Human
                },
                id: "test".to_owned(),
                name: "test".to_owned(),
            },
            role,
            interface: if role == Role::McpAgent {
                Interface::Mcp
            } else {
                Interface::Api
            },
            token_id: None,
            delegated_zones: Vec::new(),
            own_zone: None,
        }
    }
}

fn parse_enum<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, ApiError> {
    serde_json::from_value(serde_json::Value::String(s.to_owned()))
        .map_err(|_| ApiError::Internal(format!("invalid stored value {s:?}")))
}

type TokenRow = (
    Uuid,
    String,
    String,
    String,
    Option<Uuid>,
    Vec<Uuid>,
    Option<Uuid>,
);

impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or(ApiError::Unauthorized)?;
        let pool = state.pool.as_ref().ok_or(ApiError::Unauthorized)?;
        let row: Option<TokenRow> = sqlx::query_as(
            "SELECT id, role, actor_kind, actor_name, agent_id, delegated_zones, own_zone \
             FROM api_tokens WHERE token_sha256 = $1 AND revoked_at IS NULL",
        )
        .bind(sha256_hex(token.as_bytes()))
        .fetch_optional(pool)
        .await?;
        let (id, role, actor_kind, actor_name, agent_id, delegated_zones, own_zone) =
            row.ok_or(ApiError::Unauthorized)?;
        let role: Role = parse_enum(&role)?;
        let interface = if role == Role::McpAgent {
            Interface::Mcp
        } else {
            match parts
                .headers
                .get(INTERFACE_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim().to_ascii_lowercase())
                .as_deref()
            {
                Some("ui") => Interface::Ui,
                Some("cli") => Interface::Cli,
                Some("mcp") => Interface::Mcp,
                _ => Interface::Api,
            }
        };
        Ok(Self {
            actor: Actor {
                kind: parse_enum(&actor_kind)?,
                id: agent_id.unwrap_or(id).to_string(),
                name: actor_name,
            },
            role,
            interface,
            token_id: Some(id),
            delegated_zones,
            own_zone,
        })
    }
}

/// Creates or refreshes the `bootstrap` admin token (`AFW_BOOTSTRAP_ADMIN_TOKEN`); any other
/// bootstrap token is revoked.
pub async fn upsert_bootstrap_token(pool: &PgPool, token: &str) -> Result<(), ApiError> {
    let digest = sha256_hex(token.as_bytes());
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE api_tokens SET revoked_at = now() \
         WHERE name = 'bootstrap' AND token_sha256 <> $1 AND revoked_at IS NULL",
    )
    .bind(&digest)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO api_tokens (name, token_sha256, role, actor_kind, actor_name) \
         VALUES ('bootstrap', $1, 'admin', 'human', 'bootstrap') \
         ON CONFLICT (token_sha256) DO UPDATE SET revoked_at = NULL, role = 'admin'",
    )
    .bind(&digest)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
