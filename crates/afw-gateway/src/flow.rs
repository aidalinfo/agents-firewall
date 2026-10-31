//! Flow model, flow events and the common dispatcher used by the transparent listener and by
//! CONNECT tunnels of the explicit proxy: sniff the first bytes, then TLS, HTTP or L4.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use afw_core::events::{FlowEvent, GatewayEvent, Verdict};
use afw_core::policy::{AppProto, L4Proto, Track};
use chrono::{DateTime, Utc};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::engine::{Decision, FlowContext};
use crate::io::{Counters, Prefixed};
use crate::sniff::{Sniff, host_only, read_initial};
use crate::state::GatewayState;

/// Agent-side stream that can be refused abruptly.
pub trait AgentStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// Refuses the connection: TCP reset when possible, else plain close.
    fn reset(self);
}

impl AgentStream for TcpStream {
    fn reset(self) {
        crate::io::reset(self);
    }
}

impl AgentStream for TokioIo<Upgraded> {
    fn reset(self) {
        drop(self);
    }
}

impl<S: AgentStream> AgentStream for Prefixed<S> {
    fn reset(self) {
        self.into_inner().reset();
    }
}

/// Where the agent wanted to go.
#[derive(Debug, Clone)]
pub enum Target {
    /// Original destination of a transparently intercepted connection (agent-chosen IP).
    Addr(SocketAddr),
    /// Host and port of an explicit proxy CONNECT.
    Name(String, u16),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Target::Addr(a) => a.port(),
            Target::Name(_, p) => *p,
        }
    }
    pub fn addr(&self) -> Option<SocketAddr> {
        match self {
            Target::Addr(a) => Some(*a),
            Target::Name(..) => None,
        }
    }
}

/// One agent connection. The flow event of an allowed flow is emitted when the last
/// reference is dropped (end of the connection and of every response body).
pub struct Flow {
    pub id: Uuid,
    pub state: Arc<GatewayState>,
    pub src: SocketAddr,
    pub target: Target,
    /// Destination actually used (resolved by the gateway when a name is present).
    pub dst: Mutex<Option<SocketAddr>>,
    pub name: Option<String>,
    pub sni: Option<String>,
    pub app: Mutex<Option<AppProto>>,
    pub started_at: DateTime<Utc>,
    pub counters: Arc<Counters>,
    pub tls_inspected: AtomicBool,
    /// Decision of the forwarded traffic; `Some` = emit a flow event on drop.
    pub allowed: Mutex<Option<Decision>>,
    pub data_classes: Mutex<BTreeSet<String>>,
}

impl Flow {
    pub fn new(
        state: Arc<GatewayState>,
        src: SocketAddr,
        target: Target,
        name: Option<String>,
        sni: Option<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            id: Uuid::now_v7(),
            state,
            src,
            dst: Mutex::new(target.addr()),
            target,
            name,
            sni,
            app: Mutex::new(None),
            started_at: Utc::now(),
            counters: Arc::new(Counters::default()),
            tls_inspected: AtomicBool::new(false),
            allowed: Mutex::new(None),
            data_classes: Mutex::new(BTreeSet::new()),
        })
    }

    pub fn port(&self) -> u16 {
        self.target.port()
    }

    pub fn set_dst(&self, a: SocketAddr) {
        *self.dst.lock().unwrap_or_else(|e| e.into_inner()) = Some(a);
    }

    pub fn dst(&self) -> Option<SocketAddr> {
        *self.dst.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_app(&self, a: AppProto) {
        *self.app.lock().unwrap_or_else(|e| e.into_inner()) = Some(a);
    }

    /// Marks the flow as (at least partly) forwarded under `d`.
    pub fn mark_allowed(&self, d: &Decision) {
        let mut a = self.allowed.lock().unwrap_or_else(|e| e.into_inner());
        if a.is_none() {
            *a = Some(d.clone());
        }
    }

    pub fn add_classes(&self, names: impl IntoIterator<Item = String>) {
        self.data_classes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(names);
    }

    /// Context for the policy engine. `dst_ip` is trusted unless it is the agent's choice.
    pub fn ctx(&self, app: Option<AppProto>, dst_ip: Option<IpAddr>, trusted: bool) -> FlowContext {
        FlowContext {
            agent_ip: self.src.ip(),
            dst_ip,
            dst_ip_trusted: trusted,
            dst_port: self.port(),
            l4: L4Proto::Tcp,
            app,
            host: self.name.clone(),
            method: None,
            path: None,
            data_classes: vec![],
            now: Utc::now(),
        }
    }

    fn event(&self, id: Uuid, d: &Decision, ended: bool) -> FlowEvent {
        let dst = self.dst().unwrap_or_else(|| {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), self.port())
        });
        FlowEvent {
            id,
            gateway_id: self.state.gateway_id,
            agent_id: d.agent_id,
            zone_id: d.zone_id,
            src: self.src,
            dst,
            protocol: L4Proto::Tcp,
            app: *self.app.lock().unwrap_or_else(|e| e.into_inner()),
            domain: self.name.clone(),
            sni: self.sni.clone(),
            bytes_out: self.counters.out(),
            bytes_in: self.counters.inn(),
            started_at: self.started_at,
            ended_at: ended.then(Utc::now),
            verdict: d.verdict,
            decision: d.to_ref(),
            internal: d.internal,
            llm_provider: d.llm_provider,
            tls_inspected: self.tls_inspected.load(Ordering::Relaxed),
            data_classes: self
                .data_classes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .cloned()
                .collect(),
            observed: d.observed,
        }
    }

    /// Emits a denial for this flow now (connection or single request). Returns its id.
    pub fn emit_deny(&self, d: &Decision) -> Uuid {
        let id = if self
            .allowed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            Uuid::now_v7()
        } else {
            self.id
        };
        let mut ev = self.event(id, d, true);
        ev.verdict = Verdict::Deny;
        emit_flow(&self.state, ev, Track::Detailed);
        id
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        let d = self
            .allowed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(d) = d {
            let ev = self.event(self.id, &d, true);
            emit_flow(&self.state, ev, d.track);
        }
    }
}

fn emit_flow(state: &GatewayState, ev: FlowEvent, track: Track) {
    use std::sync::atomic::Ordering::Relaxed;
    state.metrics.flows_total.fetch_add(1, Relaxed);
    state.metrics.bytes_in.fetch_add(ev.bytes_in, Relaxed);
    state.metrics.bytes_out.fetch_add(ev.bytes_out, Relaxed);
    if ev.verdict == Verdict::Deny {
        state.metrics.denied_total.fetch_add(1, Relaxed);
        state.alerts.on_deny(ev.agent_id);
    }
    if ev.verdict == Verdict::Allow && track == Track::None && !ev.observed {
        return;
    }
    state.events.emit(GatewayEvent::Flow(ev));
}

/// Resolves the name of a flow with the gateway's resolver. Returns the address to connect
/// to (first IPv4, else first address), never the agent's choice when a name is present.
pub async fn resolve(state: &GatewayState, name: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    let ips = state.resolver.lookup(name).await.ok()?;
    let ip = ips.iter().find(|i| i.is_ipv4()).or(ips.first()).copied()?;
    Some(SocketAddr::new(ip, port))
}

/// Connection-level decision and upstream address (ADR 0018): a name that the policy denies
/// by name is never resolved upstream (no exfiltration through resolution). Otherwise the name
/// is resolved by the gateway and the decision is taken again with that trusted address.
/// Nameless flows are judged on their original destination.
pub async fn decide_and_resolve(
    flow: &Flow,
    app: Option<AppProto>,
) -> (Decision, Option<SocketAddr>) {
    let state = &flow.state;
    let Some(name) = &flow.name else {
        let dst = flow.target.addr();
        let (d, _) = state.decide(&flow.ctx(app, dst.map(|a| a.ip()), true));
        return (d, dst);
    };
    let (pre, _) = state.decide(&flow.ctx(app, None, false));
    if pre.verdict == Verdict::Deny && !pre.needs_l7 {
        return (pre, None);
    }
    match resolve(state, name, flow.port()).await {
        Some(a) => {
            flow.set_dst(a);
            let (d, _) = state.decide(&flow.ctx(app, Some(a.ip()), true));
            (d, Some(a))
        }
        None => (pre, None),
    }
}

/// Entry point for a new agent connection (transparent or CONNECT tunnel).
pub async fn handle<S: AgentStream>(
    state: Arc<GatewayState>,
    mut stream: S,
    src: SocketAddr,
    target: Target,
) {
    let _active = state.metrics.active();
    let (initial, kind) = match read_initial(&mut stream, state.sniff_timeout).await {
        Ok(x) => x,
        Err(_) => return,
    };
    let connect_name = match &target {
        Target::Name(h, _) => Some(host_only(h)),
        Target::Addr(_) => None,
    };
    let stream = Prefixed::new(initial, stream);
    match kind {
        Sniff::Tls { sni } => {
            let mismatch = matches!((&connect_name, &sni), (Some(c), Some(s)) if c != s);
            let name = sni.clone().or(connect_name);
            let flow = Flow::new(state.clone(), src, target, name, sni);
            flow.set_app(AppProto::Tls);
            crate::tls_mitm::handle(flow, stream, mismatch).await;
        }
        Sniff::Http { host } => {
            let host_name = host.as_deref().map(host_only).filter(|h| !h.is_empty());
            let name = connect_name.or(host_name);
            let flow = Flow::new(state.clone(), src, target, name, None);
            flow.set_app(AppProto::Http);
            crate::http_pipeline::serve_plain(flow, stream).await;
        }
        Sniff::Ssh | Sniff::Other => {
            let app = (kind == Sniff::Ssh).then_some(AppProto::Ssh);
            let name = connect_name.or_else(|| {
                target
                    .addr()
                    .and_then(|a| state.dns_cache.name_for(src.ip(), a.ip()))
            });
            let flow = Flow::new(state.clone(), src, target, name, None);
            if let Some(a) = app {
                flow.set_app(a);
            }
            crate::l4::handle(flow, stream).await;
        }
        Sniff::Suspect => {
            // Looks like TLS/HTTP but cannot be classified (slow, truncated or malformed): never
            // relayed raw (it would escape inspection).
            let flow = Flow::new(state.clone(), src, target, connect_name, None);
            let (mut d, _) =
                state.decide(&flow.ctx(None, flow.target.addr().map(|a| a.ip()), true));
            d.verdict = Verdict::Deny;
            d.rule_id = None;
            d.rule_number = None;
            d.rule_name = "unclassified-protocol".into();
            flow.emit_deny(&d);
            stream.reset();
        }
        Sniff::NeedMore => unreachable!("read_initial never returns NeedMore"),
    }
}
