//! Policy resources: objects, services, data classes, zones, agents, rules, sessions, revisions, verification, installs, approvals (lot L7a).

use axum::Router;

use crate::AppState;

/// Routes of this module, nested by [`crate::router`].
pub fn routes() -> Router<AppState> {
    Router::new()
}
