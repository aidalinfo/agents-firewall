//! Logs: flows, DNS, SSE stream, captures, alerts, alert channels, internal map, agent
//! overview, tool-call ingestion (lot L7b, ADR 0006, 0007, 0021).
//!
//! Interfaces for the other lots:
//! - [`ingest_gateway_events`] / [`ingest_gateway_batch`] (route `/gw/v1/events`, lot L7c);
//! - [`captures::pending_commands`] (heartbeat) and [`captures::store_capture`]
//!   (`/gw/v1/captures/{id}`), lot L7c;
//! - [`views::rule_stats`] (rule counters) and [`get_flow`] (allow-from-log), lot L7a.

use std::sync::Arc;

use afw_core::events::GatewayEvent;
use afw_core::policy::PolicyDocument;
use axum::Router;
use axum::routing::{get, post};
use futures::future::BoxFuture;
use sqlx::PgPool;
use tokio::sync::broadcast;

use crate::error::ApiError;
use crate::{AppState, Config};

pub mod alerts;
pub mod captures;
pub mod channels;
pub mod clickhouse;
pub mod correlation;
pub mod crypto;
pub mod ingest;
pub mod port;
pub mod postgres;
pub mod retention;
pub mod routes;
pub mod ssrf;
pub mod store;
pub mod stream;
pub mod views;

pub use ingest::{IngestReport, get_flow, ingest_gateway_batch, ingest_gateway_events};
pub use store::{AnyLogStore, LogStore};

/// Loads a published policy document: `Some(n)` = revision `n`, `None` = the latest one.
/// `Ok(None)` when unavailable. Replaceable (tests, wiring with the policy module).
pub type PolicyLoader = Arc<
    dyn Fn(Option<u64>) -> BoxFuture<'static, anyhow::Result<Option<PolicyDocument>>> + Send + Sync,
>;

/// Capacity of the live event channel feeding `GET /logs/stream`.
const STREAM_CAPACITY: usize = 4096;

/// State of the logs module, part of [`AppState`].
#[derive(Clone)]
pub struct LogsHandle {
    /// `None` without a database.
    pub store: Option<Arc<AnyLogStore>>,
    /// `None` when `AFW_DATA_KEY` is not set: contents are then never stored.
    pub cipher: Option<Arc<crypto::DataCipher>>,
    /// Live events (flows, DNS, HTTP without contents, alerts).
    pub events: broadcast::Sender<GatewayEvent>,
    pub policy: PolicyLoader,
    /// HMAC-SHA256 key of generic webhooks (`AFW_ALERT_WEBHOOK_SECRET`).
    pub webhook_secret: Option<Arc<String>>,
    /// Bounded delivery of alerts to the channels.
    pub dispatch: channels::Dispatcher,
    /// Maximum lifetime of a `GET /logs/stream` connection (the client reconnects, which
    /// re-checks its token).
    pub stream_max: std::time::Duration,
}

impl std::fmt::Debug for LogsHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogsHandle")
            .field("store", &self.store.as_ref().map(|s| s.kind()))
            .field("cipher", &self.cipher.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for LogsHandle {
    fn default() -> Self {
        Self {
            store: None,
            cipher: None,
            events: broadcast::channel(STREAM_CAPACITY).0,
            policy: Arc::new(|_| Box::pin(async { Ok(None) })),
            webhook_secret: None,
            dispatch: channels::Dispatcher::default(),
            stream_max: std::time::Duration::from_secs(15 * 60),
        }
    }
}

impl LogsHandle {
    /// Builds the handle from the configuration. An invalid `AFW_DATA_KEY` is reported by
    /// [`validate_config`]; here it disables content storage (never stores in clear).
    pub fn new(config: &Config, pool: Option<PgPool>) -> Self {
        let cipher = config
            .data_key
            .as_deref()
            .and_then(|k| crypto::DataCipher::from_base64(k).ok())
            .map(Arc::new);
        let store = pool.as_ref().map(|pool| {
            Arc::new(match config.log_store.as_deref() {
                Some("clickhouse") => AnyLogStore::ClickHouse(clickhouse::ClickHouseLogStore::new(
                    config
                        .clickhouse_url
                        .as_deref()
                        .unwrap_or("http://localhost:8123"),
                    config.clickhouse_user.clone(),
                    config.clickhouse_password.clone(),
                    config.clickhouse_database.clone(),
                )),
                _ => AnyLogStore::Postgres(postgres::PgLogStore::new(pool.clone())),
            })
        });
        let policy: PolicyLoader = match pool {
            Some(pool) => Arc::new(move |rev| {
                let pool = pool.clone();
                Box::pin(async move { Ok(load_revision_document(&pool, rev).await) })
            }),
            None => LogsHandle::default().policy,
        };
        Self {
            store,
            cipher,
            policy,
            webhook_secret: config.alert_webhook_secret.clone().map(Arc::new),
            ..Self::default()
        }
    }

    pub fn store(&self) -> Result<&AnyLogStore, ApiError> {
        self.store
            .as_deref()
            .ok_or_else(|| ApiError::Internal("no log store configured".into()))
    }

    pub async fn load_policy(&self, revision: Option<u64>) -> Option<PolicyDocument> {
        match (self.policy)(revision).await {
            Ok(doc) => doc,
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "cannot load the policy");
                None
            }
        }
    }
}

/// Best-effort read of a published document from the `revisions` table of the policy module
/// (lot L7a). Any error (table absent, other schema) gives `None`.
async fn load_revision_document(pool: &PgPool, revision: Option<u64>) -> Option<PolicyDocument> {
    let row: Result<Option<(sqlx::types::Json<PolicyDocument>,)>, _> = match revision {
        Some(n) => {
            sqlx::query_as("SELECT document FROM revisions WHERE number = $1")
                .bind(i64::try_from(n).ok()?)
                .fetch_optional(pool)
                .await
        }
        None => {
            sqlx::query_as("SELECT document FROM revisions ORDER BY number DESC LIMIT 1")
                .fetch_optional(pool)
                .await
        }
    };
    match row {
        Ok(r) => r.map(|r| r.0.0),
        Err(e) => {
            tracing::debug!(error = %e, "policy revisions unavailable");
            None
        }
    }
}

/// Checks the logs settings at startup (fail fast on an invalid data key or store).
pub fn validate_config(config: &Config) -> anyhow::Result<()> {
    if let Some(k) = &config.data_key {
        crypto::DataCipher::from_base64(k).map_err(|e| anyhow::anyhow!("AFW_DATA_KEY: {e}"))?;
    } else {
        tracing::warn!("AFW_DATA_KEY not set: HTTP contents and captures will not be stored");
    }
    match config.log_store.as_deref() {
        None | Some("postgres") => Ok(()),
        Some("clickhouse") if config.clickhouse_url.is_some() => Ok(()),
        Some("clickhouse") => anyhow::bail!("AFW_LOG_STORE=clickhouse requires AFW_CLICKHOUSE_URL"),
        Some(other) => anyhow::bail!("AFW_LOG_STORE: unknown store {other:?}"),
    }
}

/// Initializes the store and starts the periodic tasks (retention). Called by the binary.
pub async fn start(state: &AppState) -> anyhow::Result<()> {
    if let Some(store) = &state.logs.store {
        store.init().await?;
        retention::spawn(state.clone());
    }
    Ok(())
}

/// Routes of this module, nested by [`crate::router`].
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/logs/flows", get(routes::list_flows))
        .route("/logs/flows/stats", get(routes::flow_stats))
        .route("/logs/flows/{id}", get(routes::get_flow_detail))
        .route("/logs/dns", get(routes::list_dns))
        .route("/logs/stream", get(stream::stream))
        .route("/ingest/tool-calls", post(routes::ingest_tool_calls))
        .route("/alerts", get(alerts::list))
        .route("/alerts/{id}/ack", post(alerts::ack))
        .route(
            "/alert-channels",
            get(channels::list).post(channels::create),
        )
        .route(
            "/alert-channels/{id}",
            get(channels::get_one)
                .put(channels::update)
                .delete(channels::delete),
        )
        .route("/captures", get(captures::list).post(captures::create))
        .route("/captures/{id}", get(captures::get_one))
        .route("/captures/{id}/download", get(captures::download))
        .route("/internal-map", get(views::internal_map))
        .route("/agents/{id}/overview", get(views::agent_overview))
}
