//! L4 flows (TCP that is neither TLS nor HTTP): decision on address/port (+ name from the
//! CONNECT target or the DNS cache), then a counted bidirectional splice.

use std::sync::Arc;

use afw_core::events::Verdict;

use crate::flow::{AgentStream, Flow, resolve};
use crate::io::Tap;

pub async fn handle<S: AgentStream>(flow: Arc<Flow>, stream: S) {
    let state = flow.state.clone();
    let app = *flow.app.lock().unwrap_or_else(|e| e.into_inner());
    // CONNECT target name: resolved by the gateway. Transparent: the original destination is
    // the real destination (any name only comes from the DNS cache, for attribution).
    let dst = match (flow.target.addr(), &flow.name) {
        (Some(orig), _) => Some(orig),
        (None, Some(name)) => resolve(&state, name, flow.port()).await,
        (None, None) => None,
    };
    if let Some(d) = dst {
        flow.set_dst(d);
    }
    let (d, _) = state.decide(&flow.ctx(app, dst.map(|a| a.ip()), true));
    if let Some(dst) = dst {
        state.alerts.on_connection(d.agent_id, dst, d.internal);
    }
    let meta = state.metadata_blocked(&d, dst.map(|a| a.ip()), flow.name.as_deref());
    if meta {
        state
            .alerts
            .cloud_metadata(d.agent_id, &dst.map(|a| a.to_string()).unwrap_or_default());
    }
    let Some(dst) = dst.filter(|_| d.verdict == Verdict::Allow && !meta) else {
        let mut d = d;
        d.verdict = Verdict::Deny;
        flow.emit_deny(&d);
        stream.reset();
        return;
    };
    let mut upstream = match crate::upstream::connect(dst).await {
        Ok(u) => u,
        Err(e) => {
            tracing::debug!(%dst, error = %e, "upstream connect failed");
            flow.mark_allowed(&d);
            stream.reset();
            return;
        }
    };
    flow.mark_allowed(&d);
    let capture = state
        .captures
        .for_agent(d.agent_id)
        .map(|c| (c, flow.src, dst));
    let mut agent = Tap::new(stream, flow.counters.clone(), capture);
    let _ = crate::io::splice(&mut agent, &mut upstream).await;
}
