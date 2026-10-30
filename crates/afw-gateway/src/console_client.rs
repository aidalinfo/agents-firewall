//! Console client (`/gw/v1`, mutual TLS, ADR 0004): registration, policy long-poll + ack,
//! batched events, heartbeat and commands (capture, reinstall, self-test). The console being
//! unreachable never changes enforcement: the last valid policy stays active (EF-23).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use afw_core::InstalledPolicy;
use afw_core::protocol::{
    EventBatch, GatewayCommand, GatewayStats, Heartbeat, HeartbeatResponse, POLICY_LONG_POLL_SECS, PolicyAck,
    RegisterRequest, RegisterResponse,
};
use afw_tls::GatewayIdentity;
use anyhow::{Context, anyhow, bail};
use bytes::Bytes;
use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use uuid::Uuid;

use crate::events::BATCH_MAX;
use crate::state::GatewayState;

pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(15);
pub const EVENTS_EVERY: Duration = Duration::from_secs(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

pub fn identity_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("identity")
}

pub fn is_registered(state_dir: &Path) -> bool {
    let d = identity_dir(state_dir);
    d.join("gateway.crt").exists() && d.join("gateway_id").exists()
}

/// Minimal HTTPS client (one connection per request).
pub struct ConsoleHttp {
    host: String,
    port: u16,
    tls: Arc<ClientConfig>,
}

impl ConsoleHttp {
    pub fn new(url: &str, tls: Arc<ClientConfig>) -> anyhow::Result<Self> {
        let uri: Uri = url.parse().context("console URL")?;
        if uri.scheme_str() != Some("https") {
            bail!("console URL must be https://");
        }
        let host = uri.host().ok_or_else(|| anyhow!("console URL without host"))?.trim_matches(['[', ']']).to_string();
        Ok(Self {
            port: uri.port_u16().unwrap_or(443),
            host,
            tls,
        })
    }

    pub async fn request(&self, method: Method, path: &str, body: Option<Vec<u8>>, content_type: &str, timeout: Duration) -> anyhow::Result<(u16, Bytes)> {
        let fut = async {
            let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port)).await?;
            let name = ServerName::try_from(self.host.clone())?;
            let tls = tokio_rustls::TlsConnector::from(self.tls.clone()).connect(name, tcp).await?;
            let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
            tokio::spawn(conn);
            let authority = if self.host.contains(':') { format!("[{}]:{}", self.host, self.port) } else { format!("{}:{}", self.host, self.port) };
            let req = Request::builder()
                .method(method)
                .uri(path)
                .header("host", authority)
                .header("content-type", content_type)
                .header("user-agent", concat!("afw-gateway/", env!("CARGO_PKG_VERSION")))
                .body(Full::new(Bytes::from(body.unwrap_or_default())))?;
            let resp = send.send_request(req).await?;
            let status = resp.status().as_u16();
            let bytes = resp.into_body().collect().await?.to_bytes();
            Ok::<_, anyhow::Error>((status, bytes))
        };
        tokio::time::timeout(timeout, fut).await.map_err(|_| anyhow!("console request timed out"))?
    }

    async fn json<T: serde::Serialize>(&self, path: &str, body: &T) -> anyhow::Result<(u16, Bytes)> {
        self.request(Method::POST, path, Some(serde_json::to_vec(body)?), "application/json", REQUEST_TIMEOUT).await
    }
}

/// Registers the gateway (one-time token): generates the key + CSR, stores the certificate,
/// the console CA and the gateway id under `<state>/identity`.
pub async fn register(console_url: &str, token: &str, name: &str, console_ca_pem: Option<String>, state_dir: &Path) -> anyhow::Result<Uuid> {
    let dir = identity_dir(state_dir);
    let csr_pem = GatewayIdentity::generate(&dir).context("generate gateway key")?;
    let roots: Vec<String> = console_ca_pem.into_iter().collect();
    let tls = afw_tls::upstream_client_config(&roots, vec![b"http/1.1".to_vec()])?;
    let http = ConsoleHttp::new(console_url, tls)?;
    let hostname = std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()).unwrap_or_default();
    let req = RegisterRequest {
        token: token.to_string(),
        name: name.to_string(),
        hostname,
        csr_pem,
    };
    let (status, body) = http.json("/gw/v1/register", &req).await?;
    if status != 200 && status != 201 {
        bail!("registration refused ({status}): {}", String::from_utf8_lossy(&body));
    }
    let resp: RegisterResponse = serde_json::from_slice(&body).context("registration response")?;
    GatewayIdentity::store_cert(&dir, &resp.cert_pem, &resp.ca_pem)?;
    crate::policy_store::write_atomic(&dir.join("gateway_id"), resp.gateway_id.to_string().as_bytes())?;
    Ok(resp.gateway_id)
}

/// Main loop with the console: never returns.
pub async fn run(state: Arc<GatewayState>, url: String) {
    let http = loop {
        match GatewayIdentity::client_config(&identity_dir(&state.state_dir))
            .map_err(anyhow::Error::from)
            .and_then(|tls| ConsoleHttp::new(&url, tls))
        {
            Ok(h) => break Arc::new(h),
            Err(e) => {
                tracing::error!(error = %e, "gateway not registered with the console (run `afw-gateway register`); enforcing the local policy");
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    };
    let force = Arc::new(AtomicBool::new(false));
    let p = tokio::spawn(policy_loop(state.clone(), http.clone(), force.clone()));
    let e = tokio::spawn(events_loop(state.clone(), http.clone()));
    heartbeat_loop(state, http, force).await;
    p.abort();
    e.abort();
}

async fn policy_loop(state: Arc<GatewayState>, http: Arc<ConsoleHttp>, force: Arc<AtomicBool>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let have = if force.swap(false, Ordering::Relaxed) { None } else { state.store.revision() };
        let path = match have {
            Some(r) => format!("/gw/v1/policy?have={r}"),
            None => "/gw/v1/policy".to_string(),
        };
        let res = http
            .request(Method::GET, &path, None, "application/json", Duration::from_secs(POLICY_LONG_POLL_SECS + 10))
            .await;
        match res {
            Ok((200, body)) => {
                backoff = Duration::from_secs(1);
                let (revision, outcome) = match serde_json::from_slice::<InstalledPolicy>(&body) {
                    Ok(p) => {
                        let rev = p.revision;
                        (rev, state.store.install(p).map(|_| ()).map_err(|e| e.to_string()))
                    }
                    Err(e) => (0, Err(format!("invalid policy document: {e}"))),
                };
                match &outcome {
                    Ok(()) => tracing::info!(revision, "policy installed"),
                    Err(e) => tracing::error!(revision, error = %e, "policy rejected: keeping the last valid policy"),
                }
                let ack = PolicyAck {
                    revision,
                    ok: outcome.is_ok(),
                    error: outcome.err(),
                };
                if let Err(e) = http.json("/gw/v1/policy/ack", &ack).await {
                    tracing::warn!(error = %e, "policy ack failed");
                }
                if !ack.ok {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
            Ok((204, _)) | Ok((304, _)) => backoff = Duration::from_secs(1),
            Ok((status, body)) => {
                tracing::warn!(status, body = %String::from_utf8_lossy(&body), "policy poll refused");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
            Err(e) => {
                tracing::warn!(error = %e, "console unreachable: enforcing the last valid policy");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
}

async fn events_loop(state: Arc<GatewayState>, http: Arc<ConsoleHttp>) {
    let mut backoff = EVENTS_EVERY;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = state.events.notify.notified() => {}
        }
        loop {
            let batch = state.events.take_batch(BATCH_MAX);
            if batch.is_empty() {
                break;
            }
            let full = batch.len() >= BATCH_MAX;
            let body = EventBatch {
                batch_id: Uuid::now_v7(),
                events: batch,
            };
            match http.json("/gw/v1/events", &body).await {
                Ok((s, _)) if (200..300).contains(&s) => {
                    backoff = EVENTS_EVERY;
                    if !full {
                        break;
                    }
                }
                other => {
                    if let Err(e) = &other {
                        tracing::debug!(error = %e, "events not delivered");
                    }
                    state.events.requeue(body.events);
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    break;
                }
            }
        }
    }
}

async fn heartbeat_loop(state: Arc<GatewayState>, http: Arc<ConsoleHttp>, force: Arc<AtomicBool>) {
    loop {
        let m = &state.metrics;
        let hb = Heartbeat {
            version: env!("CARGO_PKG_VERSION").to_string(),
            revision: state.store.revision(),
            stats: GatewayStats {
                uptime_secs: m.uptime_secs(),
                active_flows: m.active_flows.load(Ordering::Relaxed),
                flows_total: m.flows_total.load(Ordering::Relaxed),
                denied_total: m.denied_total.load(Ordering::Relaxed),
                bytes_in: m.bytes_in.load(Ordering::Relaxed),
                bytes_out: m.bytes_out.load(Ordering::Relaxed),
                events_queued: state.events.queued(),
                events_dropped: state.events.dropped.load(Ordering::Relaxed),
            },
            ca_fingerprint: state.ca.fingerprint_sha256(),
        };
        match http.json("/gw/v1/heartbeat", &hb).await {
            Ok((200, body)) => {
                if let Ok(r) = serde_json::from_slice::<HeartbeatResponse>(&body) {
                    for c in r.commands {
                        command(&state, &http, &force, c);
                    }
                }
            }
            Ok((s, _)) => tracing::warn!(status = s, "heartbeat refused"),
            Err(e) => tracing::debug!(error = %e, "heartbeat failed"),
        }
        tokio::time::sleep(HEARTBEAT_EVERY).await;
    }
}

fn command(state: &Arc<GatewayState>, http: &Arc<ConsoleHttp>, force: &AtomicBool, c: GatewayCommand) {
    match c {
        GatewayCommand::StartCapture { capture_id, agent_id, duration_secs } => {
            let session = state.captures.start(capture_id, agent_id, duration_secs);
            let (state, http) = (state.clone(), http.clone());
            tokio::spawn(async move {
                tokio::time::sleep(session.until.saturating_duration_since(std::time::Instant::now())).await;
                state.captures.finish(&session);
                let data = session.bytes();
                let path = format!("/gw/v1/captures/{capture_id}");
                for _ in 0..5 {
                    match http.request(Method::POST, &path, Some(data.clone()), "application/vnd.tcpdump.pcap", Duration::from_secs(120)).await {
                        Ok((s, _)) if (200..300).contains(&s) => return,
                        _ => tokio::time::sleep(Duration::from_secs(10)).await,
                    }
                }
                let _ = save_capture(&state.state_dir, capture_id, &data);
            });
        }
        GatewayCommand::Reinstall => force.store(true, Ordering::Relaxed),
        GatewayCommand::SelfTest => {
            let ok = state.ca.leaf_for("self-test.agents-firewall.invalid").is_ok();
            tracing::info!(ok, revision = ?state.store.revision(), "self-test");
        }
    }
}

fn save_capture(dir: &Path, id: Uuid, data: &[u8]) -> std::io::Result<()> {
    crate::policy_store::write_atomic(&dir.join("captures").join(format!("{id}.pcap")), data)
}

/// Without a console: events appended to `<state>/events.jsonl` (rotated at 64 MiB).
pub async fn write_local(state: Arc<GatewayState>) {
    use std::io::Write;
    let path = state.state_dir.join("events.jsonl");
    loop {
        tokio::select! {
            _ = tokio::time::sleep(EVENTS_EVERY) => {}
            _ = state.events.notify.notified() => {}
        }
        let batch = state.events.take_batch(BATCH_MAX * 10);
        if batch.is_empty() {
            continue;
        }
        if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > 64 * 1024 * 1024 {
            let _ = std::fs::rename(&path, path.with_extension("jsonl.1"));
        }
        let res = std::fs::OpenOptions::new().create(true).append(true).open(&path).and_then(|mut f| {
            let mut buf = Vec::new();
            for e in &batch {
                serde_json::to_writer(&mut buf, e)?;
                buf.push(b'\n');
            }
            f.write_all(&buf)
        });
        if let Err(e) = res {
            tracing::warn!(error = %e, "cannot write local events");
        }
    }
}
