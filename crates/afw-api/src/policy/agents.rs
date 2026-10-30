//! Agent creation for enrollments (`POST /enrollments`, lot L7c, EF-60/EF-64).

use afw_core::policy::Agent;
use sqlx::PgConnection;
use uuid::Uuid;

use super::model::{Kind, get, parse, value};
use super::store::{self, Mutation, apply, session_for_write};
use super::validate::normalize;
use crate::auth::Principal;
use crate::error::ApiError;

/// Creates `agent` in the caller's open session `session_id` (same checks as `POST /agents`:
/// rights, zone delegation for the MCP agent, unique addresses, lock, audit). Call inside the
/// transaction of the enrollment.
pub async fn create_agent(
    conn: &mut PgConnection,
    principal: &Principal,
    session_id: Uuid,
    agent: Agent,
) -> Result<Agent, ApiError> {
    let session = session_for_write(conn, principal, session_id).await?;
    let published = store::published(conn).await?;
    let doc = store::draft(conn, session_id, &published).await?;
    if get(&doc, Kind::Agent, agent.id).is_some() {
        return Err(ApiError::Conflict {
            message: format!("agent {} already exists", agent.id),
        });
    }
    let v = normalize(Kind::Agent, agent.id, value(&agent), &doc)?;
    let (doc, _) = apply(
        conn,
        principal,
        &session,
        vec![Mutation {
            kind: Kind::Agent,
            id: agent.id,
            after: Some(v),
        }],
    )
    .await?;
    parse(
        get(&doc, Kind::Agent, agent.id)
            .ok_or_else(|| ApiError::Internal("agent missing".into()))?,
    )
}
