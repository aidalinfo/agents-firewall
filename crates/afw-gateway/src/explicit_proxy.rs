//! Explicit proxy (`:3128`): `CONNECT host:port` (then the same pipeline as transparent
//! flows inside the tunnel) and absolute-form HTTP requests.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use afw_core::events::Verdict;
use afw_core::policy::AppProto;
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::flow::{Flow, Target, resolve};
use crate::http_pipeline::{GwBody, HttpFlow, deny_response, full, handle_request};
use crate::sniff::host_only;
use crate::state::GatewayState;

pub async fn serve(state: Arc<GatewayState>, listener: TcpListener) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            let svc = hyper::service::service_fn(move |req| proxy_request(state.clone(), peer, req));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .with_upgrades()
                .await;
        });
    }
}

fn split_authority(a: &str, default_port: u16) -> Option<(String, u16)> {
    let uri: http::uri::Authority = a.parse().ok()?;
    Some((host_only(uri.host()), uri.port_u16().unwrap_or(default_port)))
}

async fn proxy_request(state: Arc<GatewayState>, peer: SocketAddr, mut req: Request<Incoming>) -> Result<Response<GwBody>, Infallible> {
    if req.method() == Method::CONNECT {
        let Some((host, port)) = req.uri().authority().and_then(|a| split_authority(a.as_str(), 443)) else {
            return Ok(simple(StatusCode::BAD_REQUEST, "invalid CONNECT target"));
        };
        // Early refusal with the EF-21 message when no application-level rule could allow it.
        let flow = Flow::new(state.clone(), peer, Target::Name(host.clone(), port), Some(host.clone()), None);
        let dst = resolve(&state, &host, port).await;
        if let Some(d) = dst {
            flow.set_dst(d);
        }
        let mut best = None;
        for app in [None, Some(AppProto::Https), Some(AppProto::Http)] {
            let (d, _) = state.decide(&flow.ctx(app, dst.map(|a| a.ip()), true));
            if d.verdict == Verdict::Allow || d.needs_l7 {
                best = Some(d);
                break;
            }
            best.get_or_insert(d);
        }
        let d = best.expect("at least one decision");
        let meta = state.metadata_blocked(&d, dst.map(|a| a.ip()), Some(&host));
        if meta {
            state.alerts.cloud_metadata(d.agent_id, &host);
        }
        if (d.verdict == Verdict::Deny && !d.needs_l7) || meta {
            let mut d = d;
            d.verdict = Verdict::Deny;
            flow.emit_deny(&d);
            return Ok(deny_response(d.deny_message(&host)));
        }
        drop(flow);
        let on = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            if let Ok(up) = on.await {
                crate::flow::handle(state, TokioIo::new(up), peer, Target::Name(host, port)).await;
            }
        });
        return Ok(Response::builder().status(StatusCode::OK).body(full("")).expect("static response"));
    }
    // Absolute-form request: one flow per request (a proxy connection may change hosts).
    let Some(authority) = req.uri().authority().map(|a| a.as_str().to_string()) else {
        return Ok(simple(StatusCode::BAD_REQUEST, "this is agents-firewall's proxy: absolute URI expected"));
    };
    if req.uri().scheme_str() != Some("http") {
        return Ok(simple(StatusCode::BAD_REQUEST, "only http:// URIs are proxied; use CONNECT for https"));
    }
    let Some((host, port)) = split_authority(&authority, 80) else {
        return Ok(simple(StatusCode::BAD_REQUEST, "invalid request target"));
    };
    let flow = Flow::new(state.clone(), peer, Target::Name(host.clone(), port), Some(host.clone()), None);
    flow.set_app(AppProto::Http);
    let dst = resolve(&state, &host, port).await;
    if let Some(d) = dst {
        flow.set_dst(d);
    }
    let hf = HttpFlow::new(flow, false, dst);
    handle_request(hf, req).await
}

fn simple(status: StatusCode, text: &str) -> Response<GwBody> {
    Response::builder()
        .status(status)
        .header("x-agents-firewall", "error")
        .body(full(format!("agents-firewall: {text}\n")))
        .expect("static response")
}
