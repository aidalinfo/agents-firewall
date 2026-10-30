//! agents-firewall control-plane API (axum). Each lot owns one module and its routes:
//! `policy` (L7a), `logs` (L7b), `auth`, `gateways` and `audit` (L7c).

use std::sync::Arc;

use axum::{Router, routing::get};
use sqlx::PgPool;

pub mod audit;
pub mod auth;
pub mod error;
pub mod gateways;
pub mod logs;
pub mod policy;

pub use error::ApiError;

/// REST API prefix (`docs/api/openapi.yaml`).
pub const API_PREFIX: &str = "/api/v1";

/// Runtime configuration, read from the environment (extended by the lots that need it).
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// `AFW_LISTEN`, default `0.0.0.0:8080`.
    pub listen: String,
    /// `AFW_DATABASE_URL` (or `DATABASE_URL`); `None` runs without a database.
    pub database_url: Option<String>,
    /// `AFW_DATA_KEY`: base64 AES-256-GCM key encrypting stored contents.
    pub data_key: Option<String>,
    /// `AFW_PUBLIC_URL`: external URL of the console/API.
    pub public_url: Option<String>,
    /// `AFW_BOOTSTRAP_ADMIN_TOKEN`: admin token created at startup.
    pub bootstrap_admin_token: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Self {
            listen: var("AFW_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".to_owned()),
            database_url: var("AFW_DATABASE_URL").or_else(|| var("DATABASE_URL")),
            data_key: var("AFW_DATA_KEY"),
            public_url: var("AFW_PUBLIC_URL"),
            bootstrap_admin_token: var("AFW_BOOTSTRAP_ADMIN_TOKEN"),
        }
    }
}

/// Shared application state.
#[derive(Clone, Default)]
pub struct AppState {
    pub pool: Option<PgPool>,
    pub config: Arc<Config>,
    /// OIDC token verifier (`AFW_OIDC_*`); `None`: only API tokens are accepted (lot L7c).
    pub oidc: Option<Arc<auth::oidc::OidcVerifier>>,
    /// Gateway PKI and protocol timings (lot L7c).
    pub gateways: gateways::GatewayContext,
    /// Links from the gateway protocol and enrollments to the policy and logs modules.
    pub ports: gateways::ports::Ports,
    /// Export of the audit chain head to immutable storage (lot L7c).
    pub audit_export: Arc<audit::export::AuditExportConfig>,
}

impl AppState {
    pub fn new(config: Config, pool: Option<PgPool>) -> Self {
        Self {
            pool,
            config: Arc::new(config),
            ..Default::default()
        }
    }
}

/// Runs the embedded SQL migrations (`crates/afw-api/migrations`).
pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

/// Public router: `/healthz` and `/api/v1/...` (policy, logs, auth, audit, gateways management).
/// The gateway protocol `/gw/v1/...` is NOT served here: only by the mutual-TLS listener
/// ([`gateways::tls::serve`]), the only place where a gateway identity can be established.
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .merge(policy::routes())
        .merge(logs::routes())
        .merge(auth::routes())
        .merge(audit::routes())
        .merge(gateways::routes());
    Router::new()
        .route("/healthz", get(healthz))
        .nest(API_PREFIX, api)
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}
