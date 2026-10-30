//! Authentication and authorization: OIDC, API tokens, roles, `/me`, enrollments, intent
//! policy (lot L7c). [`Principal`] is the authenticated caller extractor.

use axum::Router;

use crate::AppState;

pub mod principal;

pub use principal::Principal;

/// Routes of this module, nested by [`crate::router`].
pub fn routes() -> Router<AppState> {
    Router::new()
}
