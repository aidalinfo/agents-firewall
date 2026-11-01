//! Health and metrics (`:9090`): `/healthz`, `/metrics` (Prometheus text), `/ca.crt`
//! (public inspection CA certificate).

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::http_pipeline::{GwBody, full};
use crate::state::GatewayState;

pub async fn serve(state: Arc<GatewayState>, listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| route(state.clone(), req));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}

async fn route(
    state: Arc<GatewayState>,
    req: Request<Incoming>,
) -> Result<Response<GwBody>, Infallible> {
    let (status, ctype, body) = match req.uri().path() {
        "/healthz" => {
            let rev = state.store.revision();
            let body = serde_json::json!({
                "status": "ok",
                "policy_revision": rev,
                "enforcing": if rev.is_some() { "policy" } else { "deny-all" },
                "gateway_id": state.gateway_id,
            });
            (StatusCode::OK, "application/json", body.to_string())
        }
        "/metrics" => (
            StatusCode::OK,
            "text/plain; version=0.0.4",
            state.metrics.render(
                state.store.revision(),
                state.events.queued(),
                state.events.dropped.load(Ordering::Relaxed),
            ),
        ),
        "/ca.crt" => (
            StatusCode::OK,
            "application/x-pem-file",
            state.ca.ca_cert_pem(),
        ),
        _ => (StatusCode::NOT_FOUND, "text/plain", "not found\n".into()),
    };
    Ok(Response::builder()
        .status(status)
        .header("content-type", ctype)
        .body(full(body))
        .expect("static response"))
}
