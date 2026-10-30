//! Policy resources: objects, services, data classes, zones, agents, rules, sessions, revisions,
//! verification, installs, approvals (lot L7a, ADR 0020).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use afw_core::events::FlowEvent;
use axum::Router;
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;
use crate::error::ApiError;

pub mod agents;
pub mod approvals;
pub mod authz;
pub mod diff;
pub mod engine;
pub mod install;
pub mod intent;
pub mod model;
pub mod port;
pub mod resources;
pub mod revisions;
pub mod sessions;
pub mod store;
pub mod validate;

/// Header carrying the editing session (`docs/api/openapi.yaml`).
pub const SESSION_HEADER: &str = "x-afw-session";

pub type FlowFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<FlowEvent>, ApiError>> + Send + 'a>>;

/// Reads a logged flow by id (`allow-from-log`, EF-42). The logs store (`crate::logs::get_flow`)
/// is used unless [`AppState::flow_lookup`] overrides it (tests).
pub trait FlowLookup: Send + Sync {
    fn get_flow(&self, id: Uuid) -> FlowFuture<'_>;
}

/// Hits and last hit per rule id.
pub type RuleStats = HashMap<Uuid, (u64, Option<DateTime<Utc>>)>;

pub type StatsFuture<'a> = Pin<Box<dyn Future<Output = Result<RuleStats, ApiError>> + Send + 'a>>;

/// Rule hit counters (EF-06). The logs store (`crate::logs::views::rule_stats`) is used unless
/// [`AppState::rule_stats`] overrides it (tests).
pub trait RuleStatsSource: Send + Sync {
    fn rule_stats(&self) -> StatsFuture<'_>;
}

/// Routes of this module, nested by [`crate::router`].
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(resources::routes())
        .merge(sessions::routes())
        .merge(revisions::routes())
        .merge(install::routes())
        .merge(approvals::routes())
        .merge(intent::routes())
}

pub(crate) fn pool(state: &AppState) -> Result<&PgPool, ApiError> {
    state
        .pool
        .as_ref()
        .ok_or_else(|| ApiError::Internal("no database configured".into()))
}

pub(crate) fn session_header(headers: &HeaderMap) -> Result<Option<Uuid>, ApiError> {
    headers
        .get(SESSION_HEADER)
        .map(|v| {
            v.to_str()
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .ok_or_else(|| ApiError::BadRequest("invalid X-Afw-Session header".into()))
        })
        .transpose()
}

pub(crate) fn required_session(headers: &HeaderMap) -> Result<Uuid, ApiError> {
    session_header(headers)?
        .ok_or_else(|| ApiError::BadRequest("the X-Afw-Session header is required".into()))
}

pub(crate) fn body_json(body: &[u8]) -> Result<Value, ApiError> {
    serde_json::from_slice(body).map_err(|e| ApiError::BadRequest(format!("invalid JSON: {e}")))
}
