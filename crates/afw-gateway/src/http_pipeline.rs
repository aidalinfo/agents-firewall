//! Per-request HTTP pipeline (plain HTTP, inspected HTTPS, explicit proxy requests):
//! Host check against the flow's name, decision with method and path, content analysis with
//! re-decision on detected data classes, EF-21 denials, streaming analysis with cut-off beyond
//! the buffer, response logging, HTTP events with masked contents.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, ready};

use afw_core::events::{Body, BodyEncoding, GatewayEvent, HttpEvent, Verdict};
use afw_core::policy::{AppProto, Track};
use base64::Engine;
use bytes::{Bytes, BytesMut};
use chrono::Utc;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Request, Response, StatusCode, Uri, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::dlp::{DlpFinding, Scanner, decode_content, is_secret, mask_bytes, to_event};
use crate::engine::{Decision, FlowContext};
use crate::flow::{AgentStream, Flow, resolve};
use crate::io::Tap;
use crate::sniff::host_only;
use crate::state::GatewayState;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type GwBody = BoxBody<Bytes, BoxError>;

/// Headers whose value is always redacted in logs.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
];
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

pub fn full(b: impl Into<Bytes>) -> GwBody {
    Full::new(b.into()).map_err(|never| match never {}).boxed()
}

/// EF-21 denial response.
pub fn deny_response(text: String) -> Response<GwBody> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("x-agents-firewall", "denied")
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(full(text))
        .expect("static response")
}

fn error_response(status: StatusCode, text: &str) -> Response<GwBody> {
    Response::builder()
        .status(status)
        .header("x-agents-firewall", "error")
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(format!("agents-firewall: {text}")))
        .expect("static response")
}

/// HTTP view of a flow: who the agent may talk to and how to reach the upstream.
pub struct HttpFlow {
    pub flow: Arc<Flow>,
    /// Upstream scheme is HTTPS (inspected TLS).
    pub tls: bool,
    /// Address the gateway connects to (resolved from the name); `None` if resolution failed.
    pub upstream: Option<SocketAddr>,
    /// The agent negotiated HTTP/2: offer h2 upstream too (otherwise HTTP/1.1 only, which
    /// avoids a protocol translation and the h2 setup cost on each new connection).
    pub agent_h2: bool,
    client: OnceLock<Client<Connector, GwBody>>,
}

impl HttpFlow {
    pub fn new(flow: Arc<Flow>, tls: bool, upstream: Option<SocketAddr>) -> Arc<Self> {
        Self::with_alpn(flow, tls, upstream, false)
    }

    pub fn with_alpn(
        flow: Arc<Flow>,
        tls: bool,
        upstream: Option<SocketAddr>,
        agent_h2: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            flow,
            tls,
            upstream,
            agent_h2,
            client: OnceLock::new(),
        })
    }

    fn app(&self) -> AppProto {
        if self.tls {
            AppProto::Https
        } else {
            AppProto::Http
        }
    }

    /// Name every request of this flow must carry in `Host` (or the IP for nameless flows).
    fn expected_host(&self) -> Option<String> {
        self.flow
            .name
            .clone()
            .or_else(|| self.upstream.map(|a| a.ip().to_string()))
    }

    fn authority(&self) -> String {
        let host = self.expected_host().unwrap_or_default();
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        format!("{host}:{}", self.flow.port())
    }

    fn client(&self, addr: SocketAddr) -> &Client<Connector, GwBody> {
        self.client.get_or_init(|| {
            let st = &self.flow.state;
            let tls = self.tls.then(|| {
                (
                    self.expected_host().unwrap_or_default(),
                    st.upstream_tls.clone(),
                )
            });
            Client::builder(TokioExecutor::new())
                .pool_max_idle_per_host(8)
                .set_host(false)
                .build(Connector { addr, tls })
        })
    }

    pub fn state(&self) -> &Arc<GatewayState> {
        &self.flow.state
    }
}

/// Serves plain HTTP from a transparent connection or a CONNECT tunnel.
pub async fn serve_plain<S: AgentStream>(flow: Arc<Flow>, stream: S) {
    let state = flow.state.clone();
    let upstream = match (&flow.name, flow.target.addr()) {
        (Some(name), _) => resolve(&state, name, flow.port()).await,
        (None, orig) => orig,
    };
    if let Some(a) = upstream {
        flow.set_dst(a);
    }
    let (d0, _) = state.decide(&flow.ctx(Some(AppProto::Http), upstream.map(|a| a.ip()), true));
    if let Some(a) = upstream {
        state.alerts.on_connection(d0.agent_id, a, d0.internal);
    }
    let capture = state
        .captures
        .for_agent(d0.agent_id)
        .map(|c| (c, flow.src, upstream.unwrap_or(flow.src)));
    let io = Tap::new(stream, flow.counters.clone(), capture);
    serve_conn(HttpFlow::new(flow, false, upstream), io).await;
}

/// Serves HTTP/1.1 and HTTP/2 on an agent connection (with upgrades).
pub async fn serve_conn<IO>(hf: Arc<HttpFlow>, io: IO)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |req| handle_request(hf.clone(), req));
    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    let _ = builder
        .serve_connection_with_upgrades(TokioIo::new(io), svc)
        .await;
}

fn header_pairs(h: &HeaderMap) -> Vec<(String, String)> {
    h.iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}

fn masked_headers(
    scanner: &Scanner,
    h: &HeaderMap,
    location: &str,
) -> (Vec<(String, String)>, Vec<DlpFinding>) {
    let pairs = header_pairs(h);
    let mut found = scanner.scan_headers(&pairs);
    let mut out = Vec::with_capacity(pairs.len());
    for (name, value) in pairs {
        let lname = name.to_ascii_lowercase();
        let loc = format!("header:{lname}");
        let mine: Vec<DlpFinding> = found
            .iter()
            .filter(|f| f.location == loc)
            .cloned()
            .collect();
        let shown = if SENSITIVE_HEADERS.contains(&lname.as_str()) {
            format!(
                "[REDACTED:{}]",
                &hex::encode(Sha256::digest(value.as_bytes()))[..12]
            )
        } else {
            String::from_utf8_lossy(&mask_bytes(value.as_bytes(), &mine)).into_owned()
        };
        let shown_name = if found
            .iter()
            .any(|f| f.location == format!("header_name:{lname}"))
        {
            "[MASKED-HEADER-NAME]".to_string()
        } else {
            name
        };
        out.push((shown_name, shown));
    }
    for f in &mut found {
        f.location = format!("{location}{}", f.location.trim_start_matches("header"));
    }
    (out, found)
}

/// Stored body: masked, truncated to `max_stored` (never cutting through a finding), hash of
/// the full original content.
pub fn stored_body(
    data: &[u8],
    total: u64,
    findings: &[DlpFinding],
    max_stored: usize,
    sha256: String,
) -> Body {
    let mut cut = data.len().min(max_stored);
    for f in findings {
        if f.start < cut && f.end > cut {
            cut = f.start;
        }
    }
    let local: Vec<DlpFinding> = findings.iter().filter(|f| f.end <= cut).cloned().collect();
    let masked = mask_bytes(&data[..cut], &local);
    let truncated = (cut as u64) < total;
    let (encoding, data) = match String::from_utf8(masked) {
        Ok(s) => (BodyEncoding::Utf8, s),
        Err(e) => (
            BodyEncoding::Base64,
            base64::engine::general_purpose::STANDARD.encode(e.into_bytes()),
        ),
    };
    Body {
        encoding,
        data,
        size: total,
        truncated,
        sha256,
    }
}

fn class_ids(findings: &[DlpFinding]) -> Vec<Uuid> {
    let set: BTreeSet<Uuid> = findings
        .iter()
        .filter_map(|f| f.class_id.parse().ok())
        .collect();
    set.into_iter().collect()
}

/// Evaluates detected data classes; returns the decision when it denies.
#[derive(Clone)]
pub struct ContentJudge {
    pub state: Arc<GatewayState>,
    pub ctx: FlowContext,
    pub destination: String,
}

impl ContentJudge {
    pub fn judge(&self, findings: &[DlpFinding]) -> (Decision, bool) {
        let mut ctx = self.ctx.clone();
        ctx.data_classes = class_ids(findings);
        let (d, _) = self.state.decide(&ctx);
        let blocked = d.verdict == Verdict::Deny;
        let secrets: Vec<String> = findings
            .iter()
            .filter(|f| is_secret(f))
            .map(|f| f.kind.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if !secrets.is_empty() {
            self.state
                .alerts
                .secret(d.agent_id, &self.destination, &secrets, blocked);
        }
        if blocked {
            self.state
                .metrics
                .content_blocks
                .fetch_add(1, Ordering::Relaxed);
        }
        (d, blocked)
    }
}

/// Everything needed to emit the HTTP event once the exchange is over.
pub struct HttpLog {
    pub state: Arc<GatewayState>,
    pub flow: Arc<Flow>,
    pub ev: HttpEvent,
    pub track: Track,
    pub max_stored: usize,
    pub req: Arc<Mutex<ReqCapture>>,
}

#[derive(Default)]
pub struct ReqCapture {
    pub data: Vec<u8>,
    pub total: u64,
    pub findings: Vec<DlpFinding>,
    pub sha256: Option<String>,
    pub present: bool,
}

impl HttpLog {
    /// Emits the event (response body optional).
    pub fn emit(mut self, response: Option<Body>, response_findings: Vec<DlpFinding>) {
        if self.track == Track::None {
            return;
        }
        let req = std::mem::take(&mut *self.req.lock().unwrap_or_else(|e| e.into_inner()));
        let mut all = req.findings.clone();
        all.extend(response_findings);
        if self.track != Track::Log {
            if req.present {
                let sha = req.sha256.clone().unwrap_or_default();
                self.ev.request_body = Some(stored_body(
                    &req.data,
                    req.total,
                    &req.findings,
                    self.max_stored,
                    sha,
                ));
            }
            self.ev.response_body = response;
        }
        let names: BTreeSet<String> = all.iter().map(|f| f.class_name.clone()).collect();
        self.flow.add_classes(names);
        let mut seen = BTreeSet::new();
        self.ev.findings.extend(
            all.iter()
                .filter(|f| seen.insert((f.fingerprint.clone(), f.location.clone())))
                .map(to_event),
        );
        self.state.events.emit(GatewayEvent::Http(self.ev));
    }
}

fn hop_by_hop_strip(h: &mut HeaderMap) {
    if let Some(list) = h
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    {
        for name in list.split(',') {
            if let Ok(n) = HeaderName::from_bytes(name.trim().as_bytes()) {
                h.remove(n);
            }
        }
    }
    for n in HOP_BY_HOP {
        h.remove(*n);
    }
}

pub fn is_websocket(req: &Request<Incoming>) -> bool {
    req.version() == Version::HTTP_11
        && req
            .headers()
            .get(header::UPGRADE)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
}

/// Handles one request of an agent.
pub async fn handle_request(
    hf: Arc<HttpFlow>,
    req: Request<Incoming>,
) -> Result<Response<GwBody>, Infallible> {
    Ok(handle(hf, req).await)
}

async fn handle(hf: Arc<HttpFlow>, req: Request<Incoming>) -> Response<GwBody> {
    let started = std::time::Instant::now();
    let state = hf.state().clone();
    let flow = hf.flow.clone();
    state.metrics.http_requests.fetch_add(1, Ordering::Relaxed);
    let active = state.store.current();
    let scanner = active.scanner.clone();
    let settings = active.settings();
    let max_buf = settings.max_buffered_body as usize;
    let max_stored = settings.max_stored_body as usize;

    let method = req.method().as_str().to_string();
    let req_host = req
        .uri()
        .host()
        .map(str::to_string)
        .or_else(|| {
            req.headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .map(|h| host_only(&h));
    let path_q = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let path = req.uri().path().to_string();
    let upstream_ip = hf.upstream.map(|a| a.ip());

    let base_ctx = || {
        let mut c = flow.ctx(Some(hf.app()), upstream_ip, true);
        c.method = Some(method.clone());
        c.path = Some(path.clone());
        c
    };
    let scheme = if hf.tls { "https" } else { "http" };
    let mut ev = HttpEvent {
        id: Uuid::now_v7(),
        flow_id: flow.id,
        gateway_id: state.gateway_id,
        agent_id: None,
        at: Utc::now(),
        method: method.clone(),
        url: String::new(),
        host: req_host.clone().unwrap_or_default(),
        request_headers: vec![],
        request_body: None,
        status: None,
        response_headers: vec![],
        response_body: None,
        findings: vec![],
        admin_action: crate::admin::recognize(&method, &path),
        websocket: false,
    };
    let url_findings = scanner.scan_url(&path_q);
    ev.url = format!(
        "{scheme}://{}{}",
        hf.authority(),
        String::from_utf8_lossy(&mask_bytes(path_q.as_bytes(), &url_findings))
    );
    let (masked_req_headers, header_findings) =
        masked_headers(&scanner, req.headers(), "request.header");
    ev.request_headers = masked_req_headers;

    // 1. Host must match the flow's name (domain fronting, SNI/Host or CONNECT/Host mismatch).
    let expected = hf.expected_host();
    let host = match (&req_host, &expected) {
        (Some(h), Some(e)) if h == e => e.clone(),
        (None, Some(e)) => e.clone(),
        _ => {
            let (mut d, _) = state.decide(&base_ctx());
            d.verdict = Verdict::Deny;
            ev.agent_id = d.agent_id;
            flow.emit_deny(&d);
            emit_denied_http(&state, ev);
            let agent = d
                .agent_name
                .clone()
                .unwrap_or_else(|| "unknown-agent".into());
            let shown = req_host.unwrap_or_else(|| "<no host>".into());
            return deny_response(format!(
                "blocked by agents-firewall: {shown} not allowed for {agent} (rule host-mismatch)"
            ));
        }
    };

    // 2. Decision with method and path.
    let (d1, _) = state.decide(&base_ctx());
    ev.agent_id = d1.agent_id;
    let meta = state.metadata_blocked(&d1, upstream_ip, Some(&host));
    if meta {
        state.alerts.cloud_metadata(d1.agent_id, &host);
    }
    if d1.verdict == Verdict::Deny || meta {
        let mut d = d1.clone();
        d.verdict = Verdict::Deny;
        flow.emit_deny(&d);
        emit_denied_http(&state, ev);
        return deny_response(d1.deny_message(&host));
    }
    if let Some(a) = &ev.admin_action {
        state.alerts.admin_action(d1.agent_id, a);
    }
    let judge = ContentJudge {
        state: state.clone(),
        ctx: base_ctx(),
        destination: host.clone(),
    };

    // 3. URL and header contents.
    let mut findings: Vec<DlpFinding> = url_findings;
    findings.extend(header_findings);
    let mut decision = d1.clone();
    if !findings.is_empty() {
        let (d2, blocked) = judge.judge(&findings);
        if blocked {
            flow.emit_deny(&d2);
            emit_denied_http_findings(&state, ev, &findings);
            return deny_response(d2.deny_message(&host));
        }
        decision = d2;
    }

    let Some(upstream) = hf.upstream else {
        return error_response(StatusCode::BAD_GATEWAY, &format!("cannot resolve {host}"));
    };

    if is_websocket(&req) {
        ev.websocket = true;
        let log = HttpLog {
            state: state.clone(),
            flow: flow.clone(),
            ev,
            track: decision.track,
            max_stored,
            req: Arc::new(Mutex::new(ReqCapture {
                findings,
                ..Default::default()
            })),
        };
        return crate::websocket::handle(hf.clone(), req, upstream, decision, judge, log).await;
    }

    // 4. Body: buffered up to max_buffered_body, then streamed analysis.
    let (mut parts, mut body) = req.into_parts();
    let encoding = parts
        .headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty() && s != "identity");
    let mut buf = BytesMut::new();
    let mut ended = false;
    while buf.len() <= max_buf {
        match body.frame().await {
            None => {
                ended = true;
                break;
            }
            Some(Ok(f)) => {
                if let Ok(data) = f.into_data() {
                    buf.extend_from_slice(&data);
                }
            }
            Some(Err(_)) => return error_response(StatusCode::BAD_REQUEST, "request body error"),
        }
    }
    let capture = Arc::new(Mutex::new(ReqCapture {
        present: !buf.is_empty() || !ended,
        ..Default::default()
    }));
    let blocked_by: Arc<Mutex<Option<Decision>>> = Arc::new(Mutex::new(None));
    let content_denied = |d: Decision, findings: &[DlpFinding], ev: HttpEvent| {
        flow.emit_deny(&d);
        emit_denied_http_findings(&state, ev, findings);
        deny_response(d.deny_message(&host))
    };
    let upstream_body: GwBody = if ended {
        let raw = buf.freeze();
        let analysed = match &encoding {
            Some(enc) => match decode_content(enc, &raw, max_buf.saturating_mul(8).max(1)) {
                Ok(d) => Bytes::from(d),
                Err(e) => {
                    tracing::info!(error = %e, "undecodable request body: denied");
                    let mut d = decision.clone();
                    d.verdict = Verdict::Deny;
                    flow.emit_deny(&d);
                    emit_denied_http(&state, ev);
                    return deny_response(content_failure_message(&d, &host));
                }
            },
            None => raw.clone(),
        };
        let body_findings = scanner.scan(&analysed, "request.body");
        {
            let mut c = capture.lock().unwrap_or_else(|e| e.into_inner());
            c.total = analysed.len() as u64;
            c.sha256 = Some(hex::encode(Sha256::digest(&raw)));
            c.data = analysed[..analysed.len().min(max_stored + 4096)].to_vec();
            c.findings = body_findings.clone();
        }
        if !body_findings.is_empty() {
            findings.extend(body_findings);
            let (d2, blocked) = judge.judge(&findings);
            if blocked {
                return content_denied(d2, &findings, ev);
            }
            decision = d2;
        }
        full(raw)
    } else {
        if encoding.is_some() {
            // A compressed stream cannot be analysed incrementally: fail closed.
            let mut d = decision.clone();
            d.verdict = Verdict::Deny;
            flow.emit_deny(&d);
            emit_denied_http(&state, ev);
            return deny_response(content_failure_message(&d, &host));
        }
        // Early, stateless check of what is already buffered.
        let first = scanner.scan(&buf, "request.body");
        if !first.is_empty() {
            let (d2, blocked) = judge.judge(&first);
            if blocked {
                return content_denied(d2, &first, ev);
            }
        }
        scanning_body(
            body,
            buf.freeze(),
            scanner.clone(),
            judge.clone(),
            blocked_by.clone(),
            capture.clone(),
            max_stored + 4096,
        )
    };
    {
        let mut c = capture.lock().unwrap_or_else(|e| e.into_inner());
        let mut f = std::mem::take(&mut c.findings);
        f.extend(
            findings
                .iter()
                .filter(|x| x.location != "request.body")
                .cloned(),
        );
        c.findings = f;
    }

    // 5. Forward.
    flow.mark_allowed(&decision);
    hop_by_hop_strip(&mut parts.headers);
    parts.version = Version::HTTP_11;
    parts.uri = match format!("{scheme}://{}{path_q}", hf.authority()).parse::<Uri>() {
        Ok(u) => u,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid request target"),
    };
    if !parts.headers.contains_key(header::HOST)
        && let Ok(v) = HeaderValue::from_str(&host)
    {
        parts.headers.insert(header::HOST, v);
    }
    let up_req = Request::from_parts(parts, upstream_body);
    state.metrics.added_latency(started.elapsed().as_micros() as u64);
    let resp = hf.client(upstream).request(up_req).await;
    let log = HttpLog {
        state: state.clone(),
        flow: flow.clone(),
        ev,
        track: decision.track,
        max_stored,
        req: capture,
    };
    match resp {
        Ok(resp) => {
            let (mut parts, body) = resp.into_parts();
            let mut log = log;
            log.ev.status = Some(parts.status.as_u16());
            log.ev.response_headers = masked_headers(&scanner, &parts.headers, "response.header").0;
            hop_by_hop_strip(&mut parts.headers);
            parts.version = Version::HTTP_11;
            let tap = RespTap::new(body, log, scanner.clone(), max_buf, max_stored);
            Response::from_parts(parts, tap.boxed())
        }
        Err(e) => {
            let blocked = blocked_by.lock().unwrap_or_else(|e| e.into_inner()).take();
            match blocked {
                Some(d) => {
                    let f = log
                        .req
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .findings
                        .clone();
                    flow.emit_deny(&d);
                    emit_denied_http_findings(&state, log.ev, &f);
                    deny_response(d.deny_message(&host))
                }
                None => {
                    tracing::debug!(error = %e, %upstream, "upstream request failed");
                    log.emit(None, vec![]);
                    error_response(StatusCode::BAD_GATEWAY, "upstream unreachable")
                }
            }
        }
    }
}

fn content_failure_message(d: &Decision, host: &str) -> String {
    let agent = d
        .agent_name
        .clone()
        .unwrap_or_else(|| "unknown-agent".into());
    format!("blocked by agents-firewall: {host} not allowed for {agent} (rule content-inspection)")
}

fn emit_denied_http(state: &GatewayState, ev: HttpEvent) {
    state.events.emit(GatewayEvent::Http(ev));
}

fn emit_denied_http_findings(state: &GatewayState, mut ev: HttpEvent, findings: &[DlpFinding]) {
    ev.findings = findings.iter().map(to_event).collect();
    state.events.emit(GatewayEvent::Http(ev));
}

/// Request body streamed upstream with incremental analysis (`afw_dlp::StreamScanner`):
/// never relays more than `safe_len()`, and the held-back rest only once `finish()` found
/// nothing the policy denies. A denied detection ends the body with an error (the upstream
/// request is aborted) and records the decision. The scanner borrows the shared `Scanner`,
/// so the analysis runs in its own task fed by the agent's body.
fn scanning_body(
    mut body: Incoming,
    prefix: Bytes,
    scanner: Arc<Scanner>,
    judge: ContentJudge,
    blocked: Arc<Mutex<Option<Decision>>>,
    capture: Arc<Mutex<ReqCapture>>,
    capture_max: usize,
) -> GwBody {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, BoxError>>(4);
    tokio::spawn(async move {
        let mut ss = scanner.stream("request.body");
        let mut pending = BytesMut::new();
        let mut released: u64 = 0;
        let mut hasher = Sha256::new();
        let mut all: Vec<DlpFinding> = Vec::new();
        // Returns false when the body must be cut.
        let check = |found: Vec<DlpFinding>, all: &mut Vec<DlpFinding>| -> bool {
            if found.is_empty() {
                return true;
            }
            all.extend(found);
            capture.lock().unwrap_or_else(|e| e.into_inner()).findings = all.clone();
            let (d, deny) = judge.judge(all);
            if deny {
                *blocked.lock().unwrap_or_else(|e| e.into_inner()) = Some(d);
                return false;
            }
            true
        };
        let mut next: Option<Bytes> = Some(prefix);
        loop {
            let data = match next.take() {
                Some(d) => d,
                None => match body.frame().await {
                    None => break,
                    Some(Err(e)) => {
                        let _ = tx.send(Err(Box::new(e))).await;
                        return;
                    }
                    Some(Ok(f)) => match f.into_data() {
                        Ok(d) => d,
                        Err(_) => continue,
                    },
                },
            };
            hasher.update(&data);
            {
                let mut c = capture.lock().unwrap_or_else(|e| e.into_inner());
                c.total += data.len() as u64;
                let room = capture_max.saturating_sub(c.data.len());
                c.data.extend_from_slice(&data[..data.len().min(room)]);
            }
            let found = ss.feed(&data);
            pending.extend_from_slice(&data);
            if !check(found, &mut all) {
                let _ = tx.send(Err(Box::new(ContentBlocked))).await;
                return;
            }
            let n = (ss.safe_len().saturating_sub(released) as usize).min(pending.len());
            if n > 0 {
                released += n as u64;
                if tx.send(Ok(pending.split_to(n).freeze())).await.is_err() {
                    return;
                }
            }
        }
        capture.lock().unwrap_or_else(|e| e.into_inner()).sha256 =
            Some(hex::encode(hasher.finalize()));
        let found = ss.finish();
        if !check(found, &mut all) {
            let _ = tx.send(Err(Box::new(ContentBlocked))).await;
            return;
        }
        if !pending.is_empty() {
            let _ = tx.send(Ok(pending.freeze())).await;
        }
    });
    ChannelBody { rx }.boxed()
}

struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, BoxError>>,
}

impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.rx.poll_recv(cx).map(|o| o.map(|r| r.map(Frame::data)))
    }
}

#[derive(Debug)]
struct ContentBlocked;

impl std::fmt::Display for ContentBlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request body blocked by agents-firewall content policy")
    }
}

impl std::error::Error for ContentBlocked {}

/// Response body relayed to the agent while being hashed, captured (bounded), analysed for
/// the log; emits the HTTP event at the end (or when dropped).
struct RespTap {
    inner: Incoming,
    log: Option<HttpLog>,
    scanner: Arc<Scanner>,
    scan_max: usize,
    captured: Vec<u8>,
    capture_max: usize,
    total: u64,
    hasher: Sha256,
}

impl RespTap {
    fn new(
        inner: Incoming,
        log: HttpLog,
        scanner: Arc<Scanner>,
        max_buf: usize,
        max_stored: usize,
    ) -> Self {
        Self {
            inner,
            log: Some(log),
            scanner,
            scan_max: max_buf,
            captured: vec![],
            capture_max: max_buf.max(max_stored + 4096),
            total: 0,
            hasher: Sha256::new(),
        }
    }

    fn finish(&mut self) {
        let Some(log) = self.log.take() else { return };
        // Logging only: the response is analysed (first `max_buffered_body` bytes) to mask it.
        let n = self.captured.len().min(self.scan_max);
        let findings = self.scanner.scan(&self.captured[..n], "response.body");
        let sha = hex::encode(self.hasher.clone().finalize());
        let body = (self.total > 0)
            .then(|| stored_body(&self.captured, self.total, &findings, log.max_stored, sha));
        log.emit(body, findings);
    }
}

impl Drop for RespTap {
    fn drop(&mut self) {
        self.finish();
    }
}

impl hyper::body::Body for RespTap {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let r = ready!(Pin::new(&mut self.inner).poll_frame(cx));
        match r {
            None => {
                self.finish();
                Poll::Ready(None)
            }
            Some(Err(e)) => Poll::Ready(Some(Err(Box::new(e)))),
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    let data = data.clone();
                    self.hasher.update(&data);
                    self.total += data.len() as u64;
                    let room = self.capture_max.saturating_sub(self.captured.len());
                    self.captured
                        .extend_from_slice(&data[..data.len().min(room)]);
                }
                Poll::Ready(Some(Ok(frame)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

/// Upstream connector pinned to the address resolved by the gateway; TLS verified against
/// the flow's name (the SNI the agent presented).
#[derive(Clone)]
pub struct Connector {
    addr: SocketAddr,
    tls: Option<(String, Arc<rustls::ClientConfig>)>,
}

pub enum UpStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

pub struct UpConn {
    io: TokioIo<UpStream>,
    h2: bool,
}

impl AsyncRead for UpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            UpStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            UpStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            UpStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpStream::Plain(s) => Pin::new(s).poll_flush(cx),
            UpStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            UpStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

impl hyper::rt::Read for UpConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for UpConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl Connection for UpConn {
    fn connected(&self) -> Connected {
        let c = Connected::new();
        if self.h2 { c.negotiated_h2() } else { c }
    }
}

/// Opens an upstream connection (TLS when `tls` is set, verified on `name`).
pub async fn open_upstream(
    addr: SocketAddr,
    tls: Option<(String, Arc<rustls::ClientConfig>)>,
) -> std::io::Result<(UpStream, bool)> {
    let tcp = crate::upstream::connect(addr).await?;
    match tls {
        None => Ok((UpStream::Plain(tcp), false)),
        Some((name, cfg)) => {
            let server = ServerName::try_from(name)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let s = tokio::time::timeout(
                crate::upstream::CONNECT_TIMEOUT,
                tokio_rustls::TlsConnector::from(cfg).connect(server, tcp),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream TLS timeout")
            })??;
            let h2 = s.get_ref().1.alpn_protocol() == Some(b"h2");
            Ok((UpStream::Tls(Box::new(s)), h2))
        }
    }
}

impl tower::Service<Uri> for Connector {
    type Response = UpConn;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<UpConn, std::io::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let (addr, tls) = (self.addr, self.tls.clone());
        Box::pin(async move {
            let (s, h2) = open_upstream(addr, tls).await?;
            Ok(UpConn {
                io: TokioIo::new(s),
                h2,
            })
        })
    }
}

/// Collects a request header list (for tests and logs).
pub fn headers_of(req: &Request<Incoming>) -> Vec<(String, String)> {
    header_pairs(req.headers())
}

/// Marks a response as coming from a denied decision (for callers outside the pipeline).
pub fn denied(d: &Decision, destination: &str) -> Response<GwBody> {
    deny_response(d.deny_message(destination))
}
