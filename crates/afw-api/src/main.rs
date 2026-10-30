//! `afw-api` binary: control-plane REST API, plus the mutual-TLS gateway listener.

use std::sync::Arc;

use afw_api::audit::export::AuditExportConfig;
use afw_api::auth::oidc::{OidcSettings, OidcVerifier};
use afw_api::gateways::GatewaySettings;
use afw_api::{AppState, Config, auth::principal::upsert_bootstrap_token, migrate, router};
use anyhow::Context;
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Config::from_env();
    afw_api::logs::validate_config(&config)?;
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
    let gw = GatewaySettings::from_env(config.public_url.as_deref())?;
    let mut state = AppState::new(config.clone(), pool.clone());
    if let Some(settings) = OidcSettings::from_env()? {
        tracing::info!(issuer = %settings.issuer, "OIDC enabled");
        state.oidc = Some(Arc::new(OidcVerifier::new(settings)));
    }
    state.audit_export = Arc::new(AuditExportConfig::from_env()?);
    state.gateways.offline_after = gw.offline_after;
    state.gateways.cert_days = gw.cert_days;
    state.gateways.max_connections = gw.max_connections;
    state.gateways.header_read_timeout = gw.header_read_timeout;

    if pool.is_some() {
        let pki = Arc::new(
            afw_tls::ConsolePki::load_or_create(&gw.pki_dir)
                .with_context(|| format!("console PKI in {}", gw.pki_dir.display()))?,
        );
        state.gateways.pki = Some(pki.clone());
        let tls = pki
            .server_config(&gw.server_names)
            .context("gateway listener TLS configuration")?;
        let listener = tokio::net::TcpListener::bind(&gw.listen)
            .await
            .with_context(|| format!("binding {}", gw.listen))?;
        tracing::info!(listen = %gw.listen, names = ?gw.server_names, "gateway mTLS listener");
        tokio::spawn(afw_api::gateways::tls::serve(listener, state.clone(), tls));
        afw_api::audit::export::spawn_periodic(state.clone());
    }

    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    tracing::info!(listen = %config.listen, "afw-api listening");
    afw_api::logs::start(&state)
        .await
        .context("starting the log store")?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}
