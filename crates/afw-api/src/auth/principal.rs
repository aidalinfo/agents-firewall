//! Authenticated caller, extracted from `Authorization: Bearer <token>`.

use afw_core::api::Role;
use afw_core::events::{Actor, ActorKind, Interface};
use afw_core::policy::PolicyDocument;
use afw_core::sha256_hex;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;
use crate::error::ApiError;

/// Header telling which interface the call comes from (`ui`, `cli`, `mcp`, `api`).
/// Declarative only: recorded in the audit log, it must never drive an authorization decision.
pub const INTERFACE_HEADER: &str = "x-afw-interface";

#[derive(Clone, Debug, PartialEq)]
pub struct Principal {
    pub actor: Actor,
    pub role: Role,
    pub interface: Interface,
    pub token_id: Option<Uuid>,
    /// Agent bound to the token (`mcp_agent`, `agent_plugin`).
    pub agent_id: Option<Uuid>,
}

/// Read level of a role for [`Principal::require`]: Admin > Auditor > Viewer. The MCP agent
/// reads like a viewer; the plugin token has no general access.
fn rank(role: Role) -> u8 {
    match role {
        Role::AgentPlugin => 0,
        Role::Viewer | Role::McpAgent => 1,
        Role::Auditor => 2,
        Role::Admin => 3,
    }
}

fn forbidden(msg: &str) -> ApiError {
    ApiError::Forbidden(msg.to_owned())
}

impl Principal {
    /// Requires at least `min` in Admin > Auditor > Viewer. `McpAgent` only passes `Viewer`
    /// (policy writes go through [`Self::require_policy_write`]); `AgentPlugin` never passes.
    pub fn require(&self, min: Role) -> Result<(), ApiError> {
        if matches!(min, Role::McpAgent | Role::AgentPlugin) {
            return Err(forbidden("invalid role requirement"));
        }
        if rank(self.role) >= rank(min) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!("role {min:?} required")))
        }
    }

    /// Admin or MCP agent. For the MCP agent the caller MUST then check every zone touched by
    /// the change with [`Self::require_zone_write`].
    pub fn require_policy_write(&self) -> Result<(), ApiError> {
        match self.role {
            Role::Admin | Role::McpAgent => Ok(()),
            _ => Err(forbidden("policy write requires admin")),
        }
    }

    /// Whether the caller may modify zone `zone_id` (its rules, its agents, the zone itself).
    /// Admin: always. MCP agent: only a zone delegated to the MCP that is not its own zone; an
    /// MCP agent whose own zone is unknown (`None`) is refused (fail closed, EF-51).
    pub fn require_zone_write(
        &self,
        zone_id: Uuid,
        current_policy_own_zone: Option<Uuid>,
        delegated: &[Uuid],
    ) -> Result<(), ApiError> {
        match self.role {
            Role::Admin => Ok(()),
            Role::McpAgent => match current_policy_own_zone {
                None => Err(forbidden("MCP agent is not an agent of the current policy")),
                Some(own) if own == zone_id => {
                    Err(forbidden("the MCP agent cannot modify its own zone"))
                }
                Some(_) if delegated.contains(&zone_id) => Ok(()),
                Some(_) => Err(forbidden("zone not delegated to the MCP agent")),
            },
            _ => Err(forbidden("policy write requires admin")),
        }
    }

    /// Own zone and MCP-delegated zones of the caller, computed from `policy` (single source:
    /// `Agent.zone_id` and `Zone.delegated_to_mcp`).
    pub fn zone_scope(&self, policy: &PolicyDocument) -> (Option<Uuid>, Vec<Uuid>) {
        let own = self
            .agent_id
            .and_then(|id| policy.agents.iter().find(|a| a.id == id).map(|a| a.zone_id));
        let delegated = policy
            .zones
            .iter()
            .filter(|z| z.delegated_to_mcp)
            .map(|z| z.id)
            .collect();
        (own, delegated)
    }

    /// [`Self::require_zone_write`] with the scope computed from `policy`.
    pub fn require_zone_write_in(
        &self,
        policy: &PolicyDocument,
        zone_id: Uuid,
    ) -> Result<(), ApiError> {
        let (own, delegated) = self.zone_scope(policy);
        self.require_zone_write(zone_id, own, &delegated)
    }

    /// Hermes plugin token only (`/ingest/tool-calls`, `/intent-policy`).
    pub fn require_plugin(&self) -> Result<(), ApiError> {
        if self.role == Role::AgentPlugin && self.agent_id.is_some() {
            Ok(())
        } else {
            Err(forbidden("agent plugin token required"))
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
                kind: if matches!(role, Role::McpAgent | Role::AgentPlugin) {
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
            agent_id: matches!(role, Role::McpAgent | Role::AgentPlugin).then(Uuid::nil),
        }
    }
}

fn parse_enum<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, ApiError> {
    serde_json::from_value(serde_json::Value::String(s.to_owned()))
        .map_err(|_| ApiError::Internal(format!("invalid stored value {s:?}")))
}

type TokenRow = (Uuid, String, String, String, Option<Uuid>);

/// Token of an `Authorization: Bearer <token>` header (scheme case-insensitive).
fn bearer_token(parts: &Parts) -> Option<&str> {
    let value = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.trim().split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = bearer_token(parts).ok_or(ApiError::Unauthorized)?;
        let pool = state.pool.as_ref().ok_or(ApiError::Unauthorized)?;
        let row: Option<TokenRow> = sqlx::query_as(
            "SELECT id, role, actor_kind, actor_name, agent_id FROM api_tokens \
             WHERE token_sha256 = $1 AND revoked_at IS NULL \
             AND (expires_at IS NULL OR expires_at > now())",
        )
        .bind(sha256_hex(token.as_bytes()))
        .fetch_optional(pool)
        .await?;
        let (id, role, actor_kind, actor_name, agent_id) = row.ok_or(ApiError::Unauthorized)?;
        let role: Role = parse_enum(&role)?;
        // At most one write per token per minute.
        sqlx::query(
            "UPDATE api_tokens SET last_used_at = now() WHERE id = $1 \
             AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')",
        )
        .bind(id)
        .execute(pool)
        .await?;
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
            agent_id,
        })
    }
}

/// Creates the `bootstrap` admin token (`AFW_BOOTSTRAP_ADMIN_TOKEN`) and revokes any other
/// bootstrap token. A bootstrap token that was revoked is never reactivated.
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
        "INSERT INTO api_tokens (name, token_sha256, role, actor_kind, actor_name, created_by) \
         VALUES ('bootstrap', $1, 'admin', 'human', 'bootstrap', \
         '{\"kind\":\"system\",\"id\":\"system\",\"name\":\"bootstrap\"}') \
         ON CONFLICT (token_sha256) DO NOTHING",
    )
    .bind(&digest)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
