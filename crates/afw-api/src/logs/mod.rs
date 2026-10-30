//! Logs: flows, DNS, SSE stream, captures, alerts, alert channels, internal map, agent overview, tool-call ingestion (lot L7b).

use axum::Router;

use crate::AppState;

/// Routes of this module, nested by [`crate::router`].
pub fn routes() -> Router<AppState> {
    Router::new()
}
