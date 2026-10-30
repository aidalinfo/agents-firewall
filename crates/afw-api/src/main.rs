//! `afw-api` binary: control-plane REST API.

use afw_api::{AppState, Config, auth::principal::upsert_bootstrap_token, migrate, router};
use anyhow::Context;
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Config::from_env();
    let pool = match &config.database_url {
        Some(url) => {
            let pool = PgPoolOptions::new()
                .max_connections(10)
                .connect(url)
                .await
                .context("connecting to PostgreSQL")?;
            migrate(&pool).await.context("running migrations")?;
            if let Some(token) = &config.bootstrap_admin_token {
                upsert_bootstrap_token(&pool, token)
                    .await
                    .map_err(|e| anyhow::anyhow!("bootstrap token: {e}"))?;
            }
            Some(pool)
        }
        None => {
            tracing::warn!("no database configured: only /healthz is functional");
            None
        }
    };
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    tracing::info!(listen = %config.listen, "afw-api listening");
    axum::serve(listener, router(AppState::new(config, pool))).await?;
    Ok(())
}
