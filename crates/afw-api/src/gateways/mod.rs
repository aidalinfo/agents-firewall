//! Gateways: registration tokens, commands, and the mTLS gateway protocol `/gw/v1` (lot L7c).

use axum::Router;

use crate::AppState;

/// Routes of this module, nested by [`crate::router`].
pub fn routes() -> Router<AppState> {
    Router::new()
}

/// Gateway protocol routes, mounted at the root: each route path starts with `/gw/v1`
/// (`afw_core::protocol::GATEWAY_API_PREFIX`). Served over mutual TLS.
pub fn gw_routes() -> Router<AppState> {
    Router::new()
}
