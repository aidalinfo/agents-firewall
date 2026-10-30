//! Mutual-TLS listener of the gateway protocol and the [`AuthenticatedGateway`] extractor.
//!
//! The client certificate is verified by rustls against the console CA during the handshake
//! ([`afw_tls::ConsolePki::server_config`]: optional, so that registration works without one).
//! The verified leaf is attached to every request of the connection as a typed extension,
//! which a client cannot forge: headers are never consulted.

use std::sync::Arc;
use std::time::Duration;

use afw_core::sha256_hex;
use axum::Extension;
use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::Request;
use axum::http::request::Parts;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use uuid::Uuid;

use crate::AppState;
use crate::error::ApiError;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Verified client certificate of the TLS connection.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerCertificate {
    /// `gw:<id>` common name ([`afw_tls::peer_gateway_id`]).
    pub gateway_id: Option<String>,
    /// SHA-256 (hex) of the leaf DER.
    pub cert_sha256: String,
}

/// Extension set by [`serve`] on every request: `None` when no certificate was presented.
#[derive(Clone, Debug)]
pub struct PeerIdentity(pub Option<PeerCertificate>);

/// Serves the gateway protocol on `listener` with mutual TLS until the task is dropped.
pub async fn serve(listener: TcpListener, state: AppState, config: Arc<rustls::ServerConfig>) {
    let acceptor = TlsAcceptor::from(config);
    let app = super::gw_router(state);
    loop {
        let (tcp, remote) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "gateway listener accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => {
                    tracing::info!(%remote, error = %e, "gateway TLS handshake refused");
                    return;
                }
                Err(_) => return,
            };
            let peer = tls
                .get_ref()
                .1
                .peer_certificates()
                .filter(|c| !c.is_empty())
                .map(|certs| PeerCertificate {
                    gateway_id: afw_tls::peer_gateway_id(certs),
                    cert_sha256: sha256_hex(certs[0].as_ref()),
                });
            let app = app.layer(Extension(PeerIdentity(peer)));
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                app.clone().oneshot(req.map(Body::new))
            });
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await
            {
                tracing::debug!(%remote, error = %e, "gateway connection closed");
            }
        });
    }
}

/// A gateway authenticated by its pinned client certificate. Rejection: `401`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedGateway(pub Uuid);

impl FromRequestParts<AppState> for AuthenticatedGateway {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let peer = parts
            .extensions
            .get::<PeerIdentity>()
            .and_then(|p| p.0.clone())
            .ok_or(ApiError::Unauthorized)?;
        let id = peer
            .gateway_id
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or(ApiError::Unauthorized)?;
        let pool = state.pool.as_ref().ok_or(ApiError::Unauthorized)?;
        let known: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM gateways WHERE id = $1 AND deleted_at IS NULL AND cert_sha256 = $2",
        )
        .bind(id)
        .bind(&peer.cert_sha256)
        .fetch_optional(pool)
        .await?;
        known.map(Self).ok_or(ApiError::Unauthorized)
    }
}
