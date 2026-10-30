//! Authentication and authorization: OIDC, API tokens, roles, `/me`, enrollments (lot L7c).
//! [`Principal`] is the authenticated caller extractor.

use afw_core::api::{CreateApiToken, Enrollment, EnrollmentRequest, Me, Role};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};

use crate::AppState;
use crate::error::ApiError;

pub mod extract;
pub mod oidc;
pub mod principal;
pub mod tokens;

pub use principal::{AuthDetails, Principal};

/// Routes of this module, nested by [`crate::router`].
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/oidc/config", get(oidc_config))
        .route("/me", get(me))
        .route("/tokens", get(tokens::list).post(tokens::create))
        .route("/tokens/{id}", delete(tokens::revoke))
        .route("/enrollments", post(enroll))
}

/// `GET /auth/oidc/config` (public): parameters of the console's OIDC login (PKCE).
async fn oidc_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(oidc::public_config(state.oidc.as_ref()).await)
}

/// `GET /me`.
async fn me(
    State(state): State<AppState>,
    principal: Principal,
    details: Option<Extension<AuthDetails>>,
) -> Result<Json<Me>, ApiError> {
    principal.require(Role::Viewer)?;
    let writable_zones = match principal.role {
        Role::Admin => None,
        Role::McpAgent => {
            // Fail closed: without a current policy the MCP agent may write nowhere.
            let zones = match state.ports.policy.current_policy(&state).await? {
                Some(doc) => {
                    let (own, delegated) = principal.zone_scope(&doc);
                    match own {
                        Some(own) => delegated.into_iter().filter(|z| *z != own).collect(),
                        None => vec![],
                    }
                }
                None => vec![],
            };
            Some(zones)
        }
        _ => Some(vec![]),
    };
    Ok(Json(Me {
        actor: principal.actor.clone(),
        email: details.and_then(|Extension(d)| d.email),
        role: principal.role,
        agent_id: principal.agent_id,
        writable_zones,
    }))
}

/// `POST /enrollments`: the agent is created in a session by the policy module (port); for a
/// Hermes agent, a plugin token bound to it is minted here (shown once).
async fn enroll(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    extract::JsonBody(req): extract::JsonBody<EnrollmentRequest>,
) -> Result<(StatusCode, Json<Enrollment>), ApiError> {
    principal.require_policy_write()?;
    if principal.role == Role::McpAgent {
        // EF-51: checked here before anything is created, from the current policy (fail
        // closed when it is unknown); the policy module checks again inside the session.
        let doc = state
            .ports
            .policy
            .current_policy(&state)
            .await?
            .ok_or_else(|| ApiError::Forbidden("no current policy".into()))?;
        if !doc.zones.iter().any(|z| z.id == req.zone_id) {
            return Err(ApiError::Forbidden("unknown zone".into()));
        }
        principal.require_zone_write_in(&doc, req.zone_id)?;
    }
    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    let session = extract::session_header(&headers)?;
    let (agent, session_id) = state
        .ports
        .policy
        .create_agent(&state, &principal, session, &req)
        .await?;
    let plugin_token = if req.hermes {
        let mut tx = tokens::pool(&state)?.begin().await?;
        let created = tokens::create_token(
            &mut tx,
            &principal,
            Some(session_id),
            &CreateApiToken {
                name: format!("plugin:{}", agent.name),
                role: Role::AgentPlugin,
                agent_id: Some(agent.id),
                expires_at: None,
            },
        )
        .await?;
        tx.commit().await?;
        Some(created.secret)
    } else {
        None
    };
    Ok((
        StatusCode::CREATED,
        Json(Enrollment {
            agent,
            session_id,
            plugin_token,
        }),
    ))
}
