//! L4 flows (TCP that is neither TLS nor HTTP): decision on address/port (+ name from the
//! CONNECT target or the DNS cache), then a counted bidirectional splice.

use std::sync::Arc;

use afw_core::events::Verdict;

use crate::flow::{AgentStream, Flow, decide_and_resolve};
use crate::io::Tap;

pub async fn handle<S: AgentStream>(flow: Arc<Flow>, stream: S) {
    let state = flow.state.clone();
    let started = std::time::Instant::now();
    let app = *flow.app.lock().unwrap_or_else(|e| e.into_inner());
    // CONNECT target name: resolved by the gateway. Transparent: the original destination is
    // the real destination (any name only comes from the DNS cache, for attribution).
    let (mut d, dst) = match flow.target.addr() {
        Some(orig) => (
            state.decide(&flow.ctx(app, Some(orig.ip()), true)).0,
            Some(orig),
        ),
        None => decide_and_resolve(&flow, app).await,
    };
    // Raw TCP content is never analysed (ADR 0017 §7). Relayed when the destination is
    // internal (monitored by default, [Killian]) or when the deciding rule explicitly accepts
    // a non-HTTP service; otherwise refused if a deny-by-content rule could apply.
    if d.verdict == afw_core::events::Verdict::Allow
        && !d.internal
        && !d.explicit_non_http
        && d.content_rules_apply
    {
        d.verdict = afw_core::events::Verdict::Deny;
        d.rule_id = None;
        d.rule_number = None;
        d.implicit = None;
        d.rule_name = "content-not-inspectable".into();
    }
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
        flow.emit_deny(&d, afw_core::events::DenyMode::TcpReset);
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
    state
        .metrics
        .added_latency(started.elapsed().as_micros() as u64);
    let capture = state
        .captures
        .for_agent(d.agent_id)
        .map(|c| (c, flow.src, dst));
    let mut agent = Tap::new(stream, flow.counters.clone(), capture);
    let _ = crate::io::splice(&mut agent, &mut upstream).await;
}
