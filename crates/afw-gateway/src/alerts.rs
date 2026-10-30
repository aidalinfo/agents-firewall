//! Local alerts (EF-36, EF-82): cloud metadata, deny burst, port/host scan, sensitive port,
//! new internal host, internal burst, secret detected, unusual admin action, SNI flood.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use afw_core::events::{AdminAction, AlertEvent, AlertKind, GatewayEvent, Severity};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::events::EventSink;

pub const WINDOW: Duration = Duration::from_secs(60);
pub const DENY_BURST: usize = 10;
pub const SCAN_PORTS: usize = 10;
pub const SCAN_HOSTS: usize = 10;
pub const INTERNAL_BURST: usize = 100;
/// New leaf names (SNI) per agent and minute before refusing (leaf cache exhaustion).
pub const SNI_PER_MINUTE: usize = 20;
pub const SENSITIVE_PORTS: &[u16] = &[22, 2375, 2376, 3306, 5432, 6379, 6443, 8006, 9200, 10250, 27017];
const COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Default)]
struct AgentWindows {
    denies: VecDeque<Instant>,
    /// (time, host, port) of connections.
    conns: VecDeque<(Instant, IpAddr, u16)>,
    internal: VecDeque<Instant>,
    internal_hosts: HashSet<IpAddr>,
    sni: VecDeque<(Instant, String)>,
}

#[derive(Default)]
struct State {
    agents: HashMap<Option<Uuid>, AgentWindows>,
    last: HashMap<(AlertKind, Option<Uuid>, String), Instant>,
}

pub struct Alerts {
    sink: Arc<EventSink>,
    state: Mutex<State>,
}

fn prune<T>(q: &mut VecDeque<T>, now: Instant, at: impl Fn(&T) -> Instant) {
    while q.front().is_some_and(|x| now.duration_since(at(x)) > WINDOW) {
        q.pop_front();
    }
}

impl Alerts {
    pub fn new(sink: Arc<EventSink>) -> Self {
        Self {
            sink,
            state: Mutex::new(State::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn raise(&self, st: &mut State, kind: AlertKind, severity: Severity, agent: Option<Uuid>, key: String, summary: String, details: serde_json::Value) {
        let now = Instant::now();
        let k = (kind, agent, key);
        if st.last.get(&k).is_some_and(|t| now.duration_since(*t) < COOLDOWN) {
            return;
        }
        st.last.insert(k, now);
        if st.last.len() > 50_000 {
            st.last.retain(|_, t| now.duration_since(*t) < COOLDOWN);
        }
        self.sink.emit(GatewayEvent::Alert(AlertEvent {
            id: Uuid::now_v7(),
            at: Utc::now(),
            kind,
            severity,
            agent_id: agent,
            summary,
            details,
        }));
    }

    /// Every decided connection attempt (allowed or not).
    pub fn on_connection(&self, agent: Option<Uuid>, dst: SocketAddr, internal: bool) {
        let now = Instant::now();
        let mut st = self.lock();
        let w = st.agents.entry(agent).or_default();
        w.conns.push_back((now, dst.ip(), dst.port()));
        prune(&mut w.conns, now, |x| x.0);
        let ports: HashSet<u16> = w.conns.iter().filter(|c| c.1 == dst.ip()).map(|c| c.2).collect();
        let internal_hosts: HashSet<IpAddr> = if internal {
            w.internal.push_back(now);
            w.conns.iter().map(|c| c.1).collect()
        } else {
            HashSet::new()
        };
        prune(&mut w.internal, now, |x| *x);
        let burst = w.internal.len();
        let new_host = internal && w.internal_hosts.insert(dst.ip());
        if w.internal_hosts.len() > 10_000 {
            w.internal_hosts.clear();
        }
        if ports.len() >= SCAN_PORTS {
            self.raise(&mut st, AlertKind::PortScan, Severity::Warning, agent, dst.ip().to_string(),
                format!("{} ports of {} contacted in 60 s", ports.len(), dst.ip()), json!({"host": dst.ip(), "ports": ports.len()}));
        }
        if internal_hosts.len() >= SCAN_HOSTS {
            self.raise(&mut st, AlertKind::PortScan, Severity::Warning, agent, "hosts".into(),
                format!("{} hosts contacted in 60 s", internal_hosts.len()), json!({"hosts": internal_hosts.len()}));
        }
        if burst >= INTERNAL_BURST {
            self.raise(&mut st, AlertKind::InternalBurst, Severity::Warning, agent, String::new(),
                format!("{burst} internal connections in 60 s"), json!({"connections": burst}));
        }
        if new_host {
            self.raise(&mut st, AlertKind::NewInternalHost, Severity::Info, agent, dst.ip().to_string(),
                format!("first connection to internal host {}", dst.ip()), json!({"host": dst.ip(), "port": dst.port()}));
        }
        if SENSITIVE_PORTS.contains(&dst.port()) {
            self.raise(&mut st, AlertKind::SensitivePort, Severity::Warning, agent, dst.to_string(),
                format!("connection to sensitive port {dst}"), json!({"destination": dst.to_string()}));
        }
    }

    pub fn on_deny(&self, agent: Option<Uuid>) {
        let now = Instant::now();
        let mut st = self.lock();
        let w = st.agents.entry(agent).or_default();
        w.denies.push_back(now);
        prune(&mut w.denies, now, |x| *x);
        let n = w.denies.len();
        if n >= DENY_BURST {
            self.raise(&mut st, AlertKind::DenyBurst, Severity::Warning, agent, String::new(),
                format!("{n} denied connections in 60 s"), json!({"denied": n}));
        }
    }

    pub fn cloud_metadata(&self, agent: Option<Uuid>, destination: &str) {
        let mut st = self.lock();
        self.raise(&mut st, AlertKind::CloudMetadata, Severity::Critical, agent, destination.to_string(),
            format!("attempt to reach cloud metadata ({destination})"), json!({"destination": destination}));
    }

    pub fn secret(&self, agent: Option<Uuid>, destination: &str, kinds: &[String], blocked: bool) {
        let mut st = self.lock();
        self.raise(&mut st, AlertKind::SecretDetected, if blocked { Severity::Critical } else { Severity::Warning }, agent,
            format!("{destination}:{}", kinds.join(",")),
            format!("secret detected towards {destination} ({})", if blocked { "blocked" } else { "allowed" }),
            json!({"destination": destination, "kinds": kinds, "blocked": blocked}));
    }

    pub fn admin_action(&self, agent: Option<Uuid>, a: &AdminAction) {
        if !matches!(a.action.as_str(), "exec" | "delete" | "attach") {
            return;
        }
        let mut st = self.lock();
        self.raise(&mut st, AlertKind::UnusualAdminAction, Severity::Warning, agent, format!("{}:{}", a.action, a.resource),
            format!("{:?} {} on {}", a.system, a.action, a.resource).to_lowercase(), json!({"system": a.system, "action": a.action, "resource": a.resource}));
    }

    /// Counts a new TLS server name for an agent; `false` when over [`SNI_PER_MINUTE`].
    pub fn allow_sni(&self, agent_ip: IpAddr, agent: Option<Uuid>, name: &str) -> bool {
        let now = Instant::now();
        let mut st = self.lock();
        let w = st.agents.entry(agent).or_default();
        prune(&mut w.sni, now, |x| x.0);
        if w.sni.iter().any(|(_, n)| n == name) {
            return true;
        }
        if w.sni.len() >= SNI_PER_MINUTE {
            self.raise(&mut st, AlertKind::NewDestination, Severity::Warning, agent, "sni-flood".into(),
                format!("more than {SNI_PER_MINUTE} new TLS names per minute from {agent_ip}: refused"), json!({"source": agent_ip}));
            return false;
        }
        w.sni.push_back((now, name.to_string()));
        true
    }
}
