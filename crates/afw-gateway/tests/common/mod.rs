//! Test harness: an in-process gateway with a standalone policy, local TLS upstreams (trusted
//! through an extra CA, like `AFW_UPSTREAM_CA_FILE`) and a static resolver.
#![allow(dead_code)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use afw_core::InstalledPolicy;
use afw_core::events::GatewayEvent;
use afw_core::policy::*;
use afw_gateway::upstream::StaticResolver;
use afw_gateway::{Gateway, GatewayOptions, MapOrigDst, RunningGateway};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::broadcast;
use uuid::Uuid;

pub const AGENT_IP: &str = "127.0.0.1";
pub const UNKNOWN_IP: &str = "127.0.0.2";
pub const EVIL_IP: &str = "127.0.0.3";
pub const INTERNAL_IP: &str = "127.0.0.4";
/// Address of the "public" test upstreams (distinct from the agent's address, which the
/// engine treats as internal).
pub const UPSTREAM_IP: &str = "127.0.0.5";
pub const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

pub fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

pub const ZONE: u128 = 0x100;
pub const AGENT: u128 = 0x200;
pub const OBJ_ALLOWED: u128 = 0x301;
pub const OBJ_LLM: u128 = 0x302;
pub const OBJ_META: u128 = 0x303;
pub const OBJ_K8S: u128 = 0x304;
pub const OBJ_IP: u128 = 0x305;
pub const OBJ_PATH: u128 = 0x306;
pub const SVC_ADMIN: u128 = 0x601;
pub const SVC_V1: u128 = 0x602;
pub const CLASS_SECRETS: u128 = 0x401;
pub const RULE_NO_ADMIN: u128 = 0x506;
pub const RULE_IP: u128 = 0x507;
pub const RULE_PATH: u128 = 0x508;
/// An address accepted by an IP object (never a name).
pub const TRUSTED_IP: &str = "127.0.0.6";
pub const RULE_META: u128 = 0x501;
pub const RULE_SECRETS: u128 = 0x502;
pub const RULE_LLM: u128 = 0x503;
pub const RULE_ALLOWED: u128 = 0x504;
pub const RULE_K8S: u128 = 0x505;

fn obj(n: u128, name: &str, category: Option<DestCategory>, spec: NetObjectSpec) -> NetObject {
    NetObject {
        id: id(n),
        name: name.into(),
        comment: String::new(),
        category,
        spec,
    }
}

fn rule(n: u128, name: &str, layer: Layer, position: u32, dst: &[u128], classes: &[u128], action: Action) -> Rule {
    Rule {
        id: id(n),
        name: name.into(),
        layer,
        section: None,
        position,
        sources: match layer {
            Layer::Baseline => vec![],
            Layer::Zone { zone_id } => vec![zone_id],
        },
        destinations: dst.iter().map(|d| id(*d)).collect(),
        services: vec![],
        data_classes: classes.iter().map(|d| id(*d)).collect(),
        action,
        track: Track::Detailed,
        expires_at: None,
        comment: String::new(),
        enabled: true,
    }
}

fn rule_svc(n: u128, name: &str, layer: Layer, position: u32, dst: &[u128], svc: u128, action: Action) -> Rule {
    Rule {
        services: vec![id(svc)],
        ..rule(n, name, layer, position, dst, &[], action)
    }
}

fn path_service(n: u128, name: &str, prefix: &str) -> Service {
    Service {
        id: id(n),
        name: name.into(),
        comment: String::new(),
        protocol: L4Proto::Tcp,
        ports: vec![],
        app: Some(AppMatch {
            proto: AppProto::Https,
            methods: vec![],
            path_prefixes: vec![prefix.into()],
        }),
    }
}

/// Test policy: baseline denies cloud metadata and secrets, accepts the LLM provider; the
/// zone accepts `allowed.test` and `k8s.test`. Everything else falls to the cleanup rule.
pub fn document(mode: ZoneMode) -> PolicyDocument {
    let zone = Layer::Zone { zone_id: id(ZONE) };
    let mut settings = PolicySettings::default();
    settings.internal_networks.push(format!("{INTERNAL_IP}/32").parse().unwrap());
    settings.max_buffered_body = 64 * 1024;
    PolicyDocument {
        objects: vec![
            obj(OBJ_ALLOWED, "allowed.test", None, NetObjectSpec::Domain { pattern: "allowed.test".into() }),
            obj(OBJ_LLM, "llm.test", Some(DestCategory::LlmProvider), NetObjectSpec::Domain { pattern: "llm.test".into() }),
            obj(OBJ_META, "metadata", Some(DestCategory::CloudMetadata), NetObjectSpec::Host { ip: "169.254.169.254".parse().unwrap() }),
            obj(OBJ_K8S, "k8s.test", None, NetObjectSpec::Domain { pattern: "k8s.test".into() }),
            obj(OBJ_IP, "trusted ip", None, NetObjectSpec::Host { ip: TRUSTED_IP.parse().unwrap() }),
            obj(OBJ_PATH, "path.test", None, NetObjectSpec::Domain { pattern: "path.test".into() }),
        ],
        services: vec![path_service(SVC_ADMIN, "admin paths", "/admin"), path_service(SVC_V1, "v1 api", "/v1/")],
        data_classes: vec![DataClass {
            id: id(CLASS_SECRETS),
            name: "secrets".into(),
            comment: String::new(),
            category: DataCategory::Secret,
            detectors: vec![Detector::Builtin { id: "aws_access_key".into() }],
        }],
        zones: vec![Zone {
            id: id(ZONE),
            name: "bots".into(),
            comment: String::new(),
            mode,
            delegated_to_mcp: false,
        }],
        agents: vec![Agent {
            id: id(AGENT),
            name: "daniel-bot".into(),
            zone_id: id(ZONE),
            kind: AgentKind::DockerCompose,
            gateway_id: None,
            addresses: vec![AGENT_IP.parse().unwrap()],
            labels: Default::default(),
            hermes: false,
            mcp_admin: false,
        }],
        rules: vec![
            rule(RULE_META, "cloud metadata", Layer::Baseline, 1, &[OBJ_META], &[], Action::Deny),
            rule(RULE_SECRETS, "outbound secrets", Layer::Baseline, 2, &[], &[CLASS_SECRETS], Action::Deny),
            rule(RULE_LLM, "llm providers", Layer::Baseline, 3, &[OBJ_LLM], &[], Action::Accept),
            rule_svc(RULE_NO_ADMIN, "no admin paths", zone, 0, &[OBJ_ALLOWED], SVC_ADMIN, Action::Deny),
            rule(RULE_ALLOWED, "allowed api", zone, 1, &[OBJ_ALLOWED], &[], Action::Accept),
            rule(RULE_K8S, "kubernetes", zone, 2, &[OBJ_K8S], &[], Action::Accept),
            rule(RULE_IP, "trusted ip", zone, 3, &[OBJ_IP], &[], Action::Accept),
            rule_svc(RULE_PATH, "v1 only", zone, 4, &[OBJ_PATH], SVC_V1, Action::Accept),
        ],
        inspection_rules: vec![],
        settings,
    }
}

pub fn installed(rev: u64, mode: ZoneMode) -> InstalledPolicy {
    InstalledPolicy::new(rev, "test", document(mode))
}

/// What an upstream test server received.
#[derive(Debug, Clone)]
pub struct Seen {
    pub host: String,
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
    pub ws_messages: Vec<Vec<u8>>,
}

#[derive(Clone, Default)]
pub struct Log(pub Arc<Mutex<Vec<Seen>>>);

impl Log {
    pub fn all(&self) -> Vec<Seen> {
        self.0.lock().unwrap().clone()
    }
    pub fn contains_bytes(&self, needle: &[u8]) -> bool {
        self.all().iter().any(|s| {
            s.body.windows(needle.len()).any(|w| w == needle)
                || s.ws_messages.iter().any(|m| m.windows(needle.len()).any(|w| w == needle))
        })
    }
}

pub struct Harness {
    pub gw: RunningGateway,
    pub events: broadcast::Receiver<GatewayEvent>,
    /// Events received but not matched yet (a later wait may look for them).
    pub seen: Vec<GatewayEvent>,
    pub upstream_addr: SocketAddr,
    pub plain_addr: SocketAddr,
    pub internal_addr: SocketAddr,
    pub log: Log,
    pub orig: Arc<MapOrigDst>,
    pub _dir: tempfile::TempDir,
    pub _up_dir: tempfile::TempDir,
}

pub async fn harness(policy: Option<InstalledPolicy>) -> Harness {
    harness_with(policy, |_| {}).await
}

pub async fn harness_with(policy: Option<InstalledPolicy>, tweak: impl FnOnce(&mut GatewayOptions)) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let up_dir = tempfile::tempdir().unwrap();
    let up_ca = afw_tls::GatewayCa::load_or_create(&up_dir.path().join("ca"), "upstream test CA").unwrap();
    let log = Log::default();
    let upstream_addr = spawn_upstream(format!("{UPSTREAM_IP}:0").parse().unwrap(), Some(up_ca.clone()), log.clone()).await;
    let plain_addr = spawn_upstream(format!("{UPSTREAM_IP}:0").parse().unwrap(), None, log.clone()).await;
    let internal_addr = spawn_echo(format!("{INTERNAL_IP}:0").parse().unwrap()).await;

    if let Some(p) = &policy {
        std::fs::write(dir.path().join("policy.json"), serde_json::to_vec(p).unwrap()).unwrap();
    }
    let mut hosts: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for h in ["allowed.test", "llm.test", "denied.test", "k8s.test", "other.test", "path.test"] {
        hosts.insert(h.into(), vec![UPSTREAM_IP.parse().unwrap()]);
    }
    hosts.insert("metadata.test".into(), vec!["169.254.169.254".parse().unwrap()]);
    let orig = Arc::new(MapOrigDst::default());
    let mut opts = GatewayOptions::for_tests(dir.path().to_path_buf());
    opts.resolver = Arc::new(StaticResolver::new(hosts));
    opts.orig_dst = orig.clone();
    opts.extra_roots = vec![up_ca.ca_cert_pem()];
    tweak(&mut opts);
    let gw = Gateway::start(opts).await.unwrap();
    let events = gw.state.events.subscribe();
    Harness {
        gw,
        events,
        seen: Vec::new(),
        upstream_addr,
        plain_addr,
        internal_addr,
        log,
        orig,
        _dir: dir,
        _up_dir: up_dir,
    }
}

impl Harness {
    pub fn proxy(&self) -> SocketAddr {
        self.gw.addrs.proxy.unwrap()
    }

    pub fn dns(&self) -> SocketAddr {
        self.gw.addrs.dns.unwrap()
    }

    /// Opens a "transparent" connection from `src_ip` whose original destination is `dst`.
    pub async fn transparent(&self, src_ip: &str, dst: SocketAddr) -> TcpStream {
        let sock = TcpSocket::new_v4().unwrap();
        sock.bind(format!("{src_ip}:0").parse().unwrap()).unwrap();
        let local = sock.local_addr().unwrap();
        self.orig.insert(local, dst);
        sock.connect(self.gw.addrs.transparent.unwrap()).await.unwrap()
    }

    pub fn inspection_ca(&self) -> String {
        self.gw.state.ca.ca_cert_pem()
    }

    /// TLS client to the gateway trusting only its inspection CA.
    pub async fn tls<S: AsyncRead + AsyncWrite + Unpin>(&self, tcp: S, sni: &str) -> std::io::Result<tokio_rustls::client::TlsStream<S>> {
        tls_with(tcp, sni, &self.inspection_ca(), vec![b"http/1.1".to_vec()]).await
    }

    /// Waits for the first event matching `pred` (including events already received).
    pub async fn wait_event(&mut self, pred: impl Fn(&GatewayEvent) -> bool) -> GatewayEvent {
        if let Some(i) = self.seen.iter().position(&pred) {
            return self.seen.remove(i);
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match tokio::time::timeout_at(deadline, self.events.recv()).await {
                Ok(Ok(ev)) if pred(&ev) => return ev,
                Ok(Ok(ev)) => {
                    if std::env::var("AFW_TEST_DEBUG").is_ok() {
                        eprintln!("event: {}", serde_json::to_string(&ev).unwrap());
                    }
                    self.seen.push(ev);
                }
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(e)) => panic!("event channel closed: {e}"),
                Err(_) => panic!("timed out waiting for event; seen: {:?}", self.seen),
            }
        }
    }
}

pub async fn tls_with<S: AsyncRead + AsyncWrite + Unpin>(
    tcp: S,
    sni: &str,
    ca_pem: &str,
    alpn: Vec<Vec<u8>>,
) -> std::io::Result<tokio_rustls::client::TlsStream<S>> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    connector
        .connect(ServerName::try_from(sni.to_string()).unwrap(), tcp)
        .await
}

/// Sends a raw HTTP/1.1 request and reads the whole response (connection closed by `Connection: close`).
pub async fn http_raw<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, req: &[u8]) -> String {
    s.write_all(req).await.unwrap();
    s.flush().await.unwrap();
    read_all(s).await
}

pub async fn read_all<S: AsyncRead + Unpin>(s: &mut S) -> String {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = [0u8; 8192];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    String::from_utf8_lossy(&out).into_owned()
}

pub fn get(host: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").into_bytes()
}

pub fn post(host: &str, path: &str, body: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Upstream HTTP(S) server recording what it receives; answers `ok:<path>`; echoes WebSocket
/// messages.
pub async fn spawn_upstream(addr: SocketAddr, ca: Option<afw_tls::GatewayCa>, log: Log) -> SocketAddr {
    let listener = TcpListener::bind(addr).await.unwrap();
    let local = listener.local_addr().unwrap();
    let acceptor = ca.map(|ca| tokio_rustls::TlsAcceptor::from(ca.server_config_for_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let acceptor = acceptor.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| upstream_handler(req, log.clone()));
                let builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                match acceptor {
                    Some(a) => {
                        if let Ok(tls) = a.accept(tcp).await {
                            let _ = builder.serve_connection_with_upgrades(TokioIo::new(tls), svc).await;
                        }
                    }
                    None => {
                        let _ = builder.serve_connection_with_upgrades(TokioIo::new(tcp), svc).await;
                    }
                }
            });
        }
    });
    local
}

async fn upstream_handler(mut req: Request<Incoming>, log: Log) -> Result<Response<Full<Bytes>>, Infallible> {
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.to_string()))
        .unwrap_or_default();
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    if req.headers().get("upgrade").is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket")) {
        let key = req.headers().get("sec-websocket-key").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
        let idx = {
            let mut l = log.0.lock().unwrap();
            l.push(Seen { host, method, path, body: vec![], ws_messages: vec![] });
            l.len() - 1
        };
        let on = hyper::upgrade::on(&mut req);
        let log2 = log.clone();
        tokio::spawn(async move {
            if let Ok(up) = on.await {
                let mut io = TokioIo::new(up);
                while let Some((op, payload)) = read_frame(&mut io).await {
                    if op == 0x8 {
                        break;
                    }
                    log2.0.lock().unwrap()[idx].ws_messages.push(payload.clone());
                    let _ = io.write_all(&ws_frame(op, &payload, false)).await;
                }
            }
        });
        return Ok(Response::builder()
            .status(101)
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header("sec-websocket-accept", ws_accept(&key))
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    let body = req.into_body().collect().await.map(|b| b.to_bytes().to_vec()).unwrap_or_default();
    log.0.lock().unwrap().push(Seen { host, method, path: path.clone(), body, ws_messages: vec![] });
    Ok(Response::new(Full::new(Bytes::from(format!("ok:{path}")))))
}

pub async fn spawn_echo(addr: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind(addr).await.unwrap();
    let local = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let (mut r, mut w) = tcp.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    local
}

/// The gateway relays the upstream's handshake headers untouched; tests do not validate it.
pub fn ws_accept(key: &str) -> String {
    format!("test-accept-{}", key.len())
}

/// Builds one WebSocket frame (FIN set). Client frames must be masked.
pub fn ws_frame(op: u8, payload: &[u8], masked: bool) -> Vec<u8> {
    let mut f = vec![0x80 | op];
    let mask_bit = if masked { 0x80 } else { 0 };
    let len = payload.len();
    if len < 126 {
        f.push(mask_bit | len as u8);
    } else if len < 65536 {
        f.push(mask_bit | 126);
        f.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        f.push(mask_bit | 127);
        f.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if masked {
        let key = [0x12, 0x34, 0x56, 0x78];
        f.extend_from_slice(&key);
        f.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    } else {
        f.extend_from_slice(payload);
    }
    f
}

/// Reads one frame; returns (opcode, unmasked payload).
pub async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> Option<(u8, Vec<u8>)> {
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await.ok()?;
    let op = h[0] & 0x0f;
    let masked = h[1] & 0x80 != 0;
    let mut len = (h[1] & 0x7f) as u64;
    if len == 126 {
        let mut b = [0u8; 2];
        s.read_exact(&mut b).await.ok()?;
        len = u16::from_be_bytes(b) as u64;
    } else if len == 127 {
        let mut b = [0u8; 8];
        s.read_exact(&mut b).await.ok()?;
        len = u64::from_be_bytes(b);
    }
    let mut key = [0u8; 4];
    if masked {
        s.read_exact(&mut key).await.ok()?;
    }
    let mut p = vec![0u8; len as usize];
    s.read_exact(&mut p).await.ok()?;
    if masked {
        for (i, b) in p.iter_mut().enumerate() {
            *b ^= key[i % 4];
        }
    }
    Some((op, p))
}
