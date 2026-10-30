//! TLS flows: connection-level decision, then either TLS inspection (termination with a leaf
//! from the gateway's CA, per-request pipeline, upstream TLS verified on the same name) or an
//! opaque tunnel (bypass rule; metadata and byte counts only).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use afw_core::events::Verdict;
use afw_core::policy::AppProto;

use crate::flow::{AgentStream, Flow, resolve};
use crate::http_pipeline::{HttpFlow, serve_conn};
use crate::io::{Prefixed, Tap};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn handle<S: AgentStream>(
    flow: Arc<Flow>,
    stream: Prefixed<S>,
    connect_sni_mismatch: bool,
) {
    let state = flow.state.clone();
    // The name (SNI or CONNECT host) is resolved by the gateway; the agent's address is only
    // used for nameless flows.
    let upstream = match (&flow.name, flow.target.addr()) {
        (Some(name), _) => resolve(&state, name, flow.port()).await,
        (None, orig) => orig,
    };
    if let Some(a) = upstream {
        flow.set_dst(a);
    }
    let (d0, _) = state.decide(&flow.ctx(Some(AppProto::Https), upstream.map(|a| a.ip()), true));
    if let Some(a) = upstream {
        state.alerts.on_connection(d0.agent_id, a, d0.internal);
    }
    let meta = state.metadata_blocked(&d0, upstream.map(|a| a.ip()), flow.name.as_deref());
    if meta {
        state
            .alerts
            .cloud_metadata(d0.agent_id, flow.name.as_deref().unwrap_or_default());
    }
    if connect_sni_mismatch {
        let mut d = d0;
        d.verdict = Verdict::Deny;
        flow.emit_deny(&d);
        stream.reset();
        return;
    }
    let allowed = d0.verdict == Verdict::Allow && !meta;

    // Opaque tunnel: explicit bypass rule, no request-level condition to evaluate.
    if allowed && !d0.inspect_tls && !d0.needs_l7 {
        let Some(dst) = upstream else {
            stream.reset();
            return;
        };
        let Ok(mut up) = crate::upstream::connect(dst).await else {
            stream.reset();
            return;
        };
        flow.mark_allowed(&d0);
        let capture = state
            .captures
            .for_agent(d0.agent_id)
            .map(|c| (c, flow.src, dst));
        let mut agent = Tap::new(stream, flow.counters.clone(), capture);
        let _ = crate::io::splice(&mut agent, &mut up).await;
        return;
    }

    // Inspection (also used to deliver the explicit EF-21 denial over TLS).
    let leaf_name = match (&flow.name, upstream.or(flow.target.addr())) {
        (Some(n), _) => n.clone(),
        (None, Some(a)) => a.ip().to_string(),
        (None, None) => {
            stream.reset();
            return;
        }
    };
    if !state
        .alerts
        .allow_sni(flow.src.ip(), d0.agent_id, &leaf_name)
    {
        let mut d = d0;
        d.verdict = Verdict::Deny;
        flow.emit_deny(&d);
        stream.reset();
        return;
    }
    let cfg = state
        .ca
        .server_config_for_target(&leaf_name, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(t)) => t,
        _ => {
            // No way to show a message: still log the denial when the flow was refused.
            if !allowed {
                let mut d = d0;
                d.verdict = Verdict::Deny;
                flow.emit_deny(&d);
            }
            return;
        }
    };
    flow.tls_inspected.store(true, Ordering::Relaxed);
    flow.set_app(AppProto::Https);
    let capture = state
        .captures
        .for_agent(d0.agent_id)
        .map(|c| (c, flow.src, upstream.unwrap_or(flow.src)));
    let io = Tap::new(tls, flow.counters.clone(), capture);
    serve_conn(HttpFlow::new(flow, true, upstream), io).await;
}
