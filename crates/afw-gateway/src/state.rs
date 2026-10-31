//! Shared gateway state, options and start-up.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use afw_core::events::Verdict;
use afw_tls::GatewayCa;
use anyhow::Context;
use rustls::ClientConfig;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::alerts::Alerts;
use crate::capture::Captures;
use crate::engine::{Decision, DecisionLayer, FlowContext};
use crate::events::EventSink;
use crate::metrics::Metrics;
use crate::policy_store::{ActivePolicy, PolicyStore};
use crate::upstream::{Resolver, SystemResolver, is_cloud_metadata};

/// How the original destination of a transparently intercepted connection is found.
pub trait OrigDst: Send + Sync {
    fn original_dst(&self, stream: &TcpStream) -> io::Result<SocketAddr>;
}

/// `getsockopt(SO_ORIGINAL_DST)` after an nftables `redirect` (Linux).
pub struct SoOriginalDst;

impl OrigDst for SoOriginalDst {
    #[cfg(target_os = "linux")]
    fn original_dst(&self, stream: &TcpStream) -> io::Result<SocketAddr> {
        use std::os::fd::AsRawFd;
        const SO_ORIGINAL_DST: libc::c_int = 80;
        let fd = stream.as_raw_fd();
        let local = stream.local_addr()?;
        // SAFETY: getsockopt writes at most `len` bytes into a properly sized sockaddr.
        unsafe {
            if local.is_ipv4() {
                let mut addr: libc::sockaddr_in = std::mem::zeroed();
                let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                if libc::getsockopt(
                    fd,
                    libc::SOL_IP,
                    SO_ORIGINAL_DST,
                    &mut addr as *mut _ as *mut libc::c_void,
                    &mut len,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                Ok(SocketAddr::new(IpAddr::V4(ip), u16::from_be(addr.sin_port)))
            } else {
                let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
                let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
                if libc::getsockopt(
                    fd,
                    libc::SOL_IPV6,
                    SO_ORIGINAL_DST,
                    &mut addr as *mut _ as *mut libc::c_void,
                    &mut len,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
                Ok(SocketAddr::new(
                    IpAddr::V6(ip),
                    u16::from_be(addr.sin6_port),
                ))
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn original_dst(&self, _stream: &TcpStream) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SO_ORIGINAL_DST requires Linux",
        ))
    }
}

/// Test double: original destination registered per client address.
#[derive(Default)]
pub struct MapOrigDst(Mutex<HashMap<SocketAddr, SocketAddr>>);

impl MapOrigDst {
    pub fn insert(&self, client: SocketAddr, dst: SocketAddr) {
        self.0.lock().unwrap().insert(client, dst);
    }
}

impl OrigDst for MapOrigDst {
    fn original_dst(&self, stream: &TcpStream) -> io::Result<SocketAddr> {
        let peer = stream.peer_addr()?;
        self.0
            .lock()
            .unwrap()
            .get(&peer)
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no original destination"))
    }
}

pub struct GatewayOptions {
    pub state_dir: PathBuf,
    /// Overrides the identity's gateway id (tests, standalone).
    pub gateway_id: Option<Uuid>,
    pub transparent: Option<SocketAddr>,
    pub proxy: Option<SocketAddr>,
    pub dns: Option<SocketAddr>,
    pub health: Option<SocketAddr>,
    pub resolver: Arc<dyn Resolver>,
    pub orig_dst: Arc<dyn OrigDst>,
    /// Extra trusted roots (PEM) for upstream TLS.
    pub extra_roots: Vec<String>,
    pub console_url: Option<String>,
    pub ca_export: Option<PathBuf>,
    pub standalone_policy: Option<PathBuf>,
    /// Delay to wait for the first bytes of a transparent connection before treating it as
    /// a raw (server-first) TCP flow.
    pub sniff_timeout: Duration,
    /// Addresses of the gateway itself (never a valid transparent destination: loop guard).
    pub own_addresses: Vec<IpAddr>,
}

impl GatewayOptions {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            gateway_id: None,
            transparent: Some("0.0.0.0:15001".parse().unwrap()),
            proxy: Some("0.0.0.0:3128".parse().unwrap()),
            dns: Some("0.0.0.0:53".parse().unwrap()),
            health: Some("0.0.0.0:9090".parse().unwrap()),
            resolver: Arc::new(SystemResolver),
            orig_dst: Arc::new(SoOriginalDst),
            extra_roots: vec![],
            console_url: None,
            ca_export: None,
            standalone_policy: None,
            sniff_timeout: Duration::from_millis(800),
            own_addresses: vec![],
        }
    }

    /// Every listener on an ephemeral loopback port.
    pub fn for_tests(state_dir: PathBuf) -> Self {
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        Self {
            gateway_id: Some(Uuid::nil()),
            transparent: Some(any),
            proxy: Some(any),
            dns: Some(any),
            health: Some(any),
            sniff_timeout: Duration::from_millis(300),
            ..Self::new(state_dir)
        }
    }
}

/// Name attributed to an address returned by the gateway's DNS, per agent (ADR 0018).
#[derive(Default)]
pub struct DnsCache(Mutex<HashMap<(IpAddr, IpAddr), (String, Instant)>>);

pub const DNS_CACHE_TTL: Duration = Duration::from_secs(600);

impl DnsCache {
    pub fn insert(&self, agent: IpAddr, ip: IpAddr, name: &str) {
        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() > 100_000 {
            let now = Instant::now();
            m.retain(|_, v| v.1 > now);
        }
        m.insert(
            (agent, ip),
            (name.to_string(), Instant::now() + DNS_CACHE_TTL),
        );
    }

    pub fn name_for(&self, agent: IpAddr, ip: IpAddr) -> Option<String> {
        let m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        m.get(&(agent, ip))
            .filter(|v| v.1 > Instant::now())
            .map(|v| v.0.clone())
    }
}

pub struct GatewayState {
    pub gateway_id: Uuid,
    pub store: Arc<PolicyStore>,
    pub ca: GatewayCa,
    /// Upstream TLS, ALPN h2 + http/1.1.
    pub upstream_tls: Arc<ClientConfig>,
    /// Upstream TLS, ALPN http/1.1 only (WebSocket upgrades).
    pub upstream_tls_h1: Arc<ClientConfig>,
    pub resolver: Arc<dyn Resolver>,
    pub events: Arc<EventSink>,
    pub alerts: Alerts,
    pub dns_cache: DnsCache,
    pub metrics: Metrics,
    pub captures: Captures,
    pub orig_dst: Arc<dyn OrigDst>,
    pub sniff_timeout: Duration,
    pub own_addresses: Vec<IpAddr>,
    pub state_dir: PathBuf,
}

impl GatewayState {
    /// Evaluates a flow against the active policy. Never fails open: the engine always
    /// returns a decision (deny-all without a valid policy).
    pub fn decide(&self, ctx: &FlowContext) -> (Decision, Arc<ActivePolicy>) {
        let active = self.store.current();
        let t = Instant::now();
        let d = active.engine.evaluate(ctx);
        self.metrics
            .decision_latency(t.elapsed().as_micros() as u64);
        if let (Some(rule), Some(rev)) = (d.rule_id, active.revision()) {
            self.events.rule_hit(rule, rev);
        }
        (d, active)
    }

    /// Cloud metadata may only be reached through an explicit baseline accept rule.
    pub fn metadata_blocked(&self, d: &Decision, ip: Option<IpAddr>, name: Option<&str>) -> bool {
        let literal = name.and_then(|n| n.trim_matches(['[', ']']).parse::<IpAddr>().ok());
        let meta = ip.or(literal).is_some_and(is_cloud_metadata)
            || name.is_some_and(crate::upstream::is_cloud_metadata_name);
        meta && !(d.verdict == Verdict::Allow
            && d.layer == DecisionLayer::Baseline
            && d.rule_id.is_some()
            && !d.observed)
    }
}

#[derive(Debug, Clone, Default)]
pub struct BoundAddrs {
    pub transparent: Option<SocketAddr>,
    pub proxy: Option<SocketAddr>,
    pub dns: Option<SocketAddr>,
    pub health: Option<SocketAddr>,
}

pub struct RunningGateway {
    pub state: Arc<GatewayState>,
    pub addrs: BoundAddrs,
    tasks: Vec<JoinHandle<()>>,
}

impl RunningGateway {
    /// Waits until a listener task ends (normally never).
    pub async fn wait(mut self) {
        if let Some(t) = self.tasks.pop() {
            let _ = t.await;
        }
    }
}

impl Drop for RunningGateway {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

pub struct Gateway;

/// Reads the gateway id assigned at registration (`<state>/identity/gateway_id`).
pub fn stored_gateway_id(state_dir: &std::path::Path) -> Option<Uuid> {
    std::fs::read_to_string(state_dir.join("identity").join("gateway_id"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

impl Gateway {
    pub async fn start(opts: GatewayOptions) -> anyhow::Result<RunningGateway> {
        std::fs::create_dir_all(&opts.state_dir)
            .with_context(|| format!("state dir {}", opts.state_dir.display()))?;
        let ca =
            GatewayCa::load_or_create(&opts.state_dir.join("ca"), "agents-firewall inspection CA")
                .context("inspection CA")?;
        if let Some(path) = &opts.ca_export {
            crate::policy_store::write_atomic(path, ca.ca_cert_pem().as_bytes())
                .with_context(|| format!("export inspection CA to {}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
            }
        }
        let store = Arc::new(PolicyStore::load(opts.state_dir.join("policy.json")));
        if let Some(p) = &opts.standalone_policy {
            match std::fs::read(p)
                .map_err(|e| e.to_string())
                .and_then(|b| store.install_bytes(&b).map_err(|e| e.to_string()))
            {
                Ok(rev) => tracing::info!(revision = rev, "standalone policy installed"),
                Err(e) => {
                    tracing::error!(error = %e, file = %p.display(), "standalone policy rejected: keeping the last valid policy")
                }
            }
        }
        let alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let upstream_tls =
            afw_tls::upstream_client_config(&opts.extra_roots, alpn).context("upstream TLS")?;
        let upstream_tls_h1 =
            afw_tls::upstream_client_config(&opts.extra_roots, vec![b"http/1.1".to_vec()])?;
        let events = Arc::new(EventSink::new(Some(
            opts.state_dir.join("events.spool.jsonl"),
        )));
        events.start();
        let gateway_id = opts
            .gateway_id
            .or_else(|| stored_gateway_id(&opts.state_dir))
            .unwrap_or_else(Uuid::nil);
        let state = Arc::new(GatewayState {
            gateway_id,
            store,
            ca,
            upstream_tls,
            upstream_tls_h1,
            resolver: opts.resolver.clone(),
            alerts: Alerts::new(events.clone()),
            events,
            dns_cache: DnsCache::default(),
            metrics: Metrics::new(),
            captures: Captures::default(),
            orig_dst: opts.orig_dst.clone(),
            sniff_timeout: opts.sniff_timeout,
            own_addresses: opts.own_addresses.clone(),
            state_dir: opts.state_dir.clone(),
        });

        let mut addrs = BoundAddrs::default();
        let mut tasks = Vec::new();
        if let Some(a) = opts.transparent {
            let l = TcpListener::bind(a)
                .await
                .with_context(|| format!("bind transparent {a}"))?;
            addrs.transparent = Some(l.local_addr()?);
            tasks.push(tokio::spawn(crate::transparent::serve(state.clone(), l)));
        }
        if let Some(a) = opts.proxy {
            let l = TcpListener::bind(a)
                .await
                .with_context(|| format!("bind proxy {a}"))?;
            addrs.proxy = Some(l.local_addr()?);
            tasks.push(tokio::spawn(crate::explicit_proxy::serve(state.clone(), l)));
        }
        if let Some(a) = opts.dns {
            let (udp, tcp) = bind_dns(a).await?;
            addrs.dns = Some(udp.local_addr()?);
            tasks.push(tokio::spawn(crate::dns::serve_udp(
                state.clone(),
                Arc::new(udp),
            )));
            tasks.push(tokio::spawn(crate::dns::serve_tcp(state.clone(), tcp)));
        }
        if let Some(a) = opts.health {
            let l = TcpListener::bind(a)
                .await
                .with_context(|| format!("bind health {a}"))?;
            addrs.health = Some(l.local_addr()?);
            tasks.push(tokio::spawn(crate::health::serve(state.clone(), l)));
        }
        match &opts.console_url {
            Some(url) => tasks.push(tokio::spawn(crate::console_client::run(
                state.clone(),
                url.clone(),
            ))),
            None => tasks.push(tokio::spawn(crate::console_client::write_local(
                state.clone(),
            ))),
        }
        Ok(RunningGateway {
            state,
            addrs,
            tasks,
        })
    }
}

/// Binds UDP and TCP on the same DNS port (an ephemeral port is retried until both bind).
async fn bind_dns(a: SocketAddr) -> anyhow::Result<(UdpSocket, TcpListener)> {
    for _ in 0..20 {
        let udp = UdpSocket::bind(a)
            .await
            .with_context(|| format!("bind DNS/udp {a}"))?;
        let port = udp.local_addr()?.port();
        match TcpListener::bind(SocketAddr::new(a.ip(), port)).await {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(e) if a.port() != 0 => return Err(e).with_context(|| format!("bind DNS/tcp {a}")),
            Err(_) => continue,
        }
    }
    anyhow::bail!("cannot bind DNS on {a}")
}
