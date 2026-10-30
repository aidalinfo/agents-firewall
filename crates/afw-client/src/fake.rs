//! In-process fake of the control-plane API ("home-made wiremock"), for tests only.
//!
//! Routes are registered as `(method, path)` → canned response; every request received is
//! recorded (method, path, query, headers, body) so tests can assert what the client sent.
//! Responses should be built from the `afw-core` DTOs so they match the OpenAPI contract,
//! whose schemas are generated from those very types.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use serde::Serialize;

/// A canned response.
#[derive(Clone, Debug)]
pub struct Reply {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Reply {
    /// JSON response.
    pub fn json(status: u16, value: &impl Serialize) -> Self {
        Self {
            status,
            content_type: "application/json".into(),
            body: serde_json::to_vec(value).expect("serializable"),
        }
    }

    /// `application/problem+json` response (RFC 7807).
    pub fn problem(status: u16, title: &str, detail: &str) -> Self {
        let body = serde_json::json!({
            "type": "about:blank",
            "title": title,
            "status": status,
            "detail": detail,
        });
        Self {
            status,
            content_type: "application/problem+json".into(),
            body: serde_json::to_vec(&body).expect("serializable"),
        }
    }

    /// Raw response.
    pub fn raw(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: content_type.into(),
            body: body.into(),
        }
    }

    /// Empty response (e.g. `204 No Content`).
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: String::new(),
            body: Vec::new(),
        }
    }
}

/// A request received by the fake server.
#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    /// Decoded query string pairs, in order.
    pub query: Vec<(String, String)>,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Recorded {
    /// Header value (lower-case name).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// First value of a query parameter.
    pub fn query_param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Body parsed as JSON (`Null` when empty).
    pub fn json(&self) -> serde_json::Value {
        if self.body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&self.body).expect("request body is JSON")
        }
    }
}

#[derive(Default)]
struct Inner {
    /// Queued replies per `METHOD path`; the last one is repeated once the queue is drained.
    routes: BTreeMap<String, VecDeque<Reply>>,
    requests: Vec<Recorded>,
}

/// Handle on a running fake API server.
#[derive(Clone)]
pub struct FakeApi {
    addr: SocketAddr,
    inner: Arc<Mutex<Inner>>,
}

impl FakeApi {
    /// Starts the server on an ephemeral loopback port.
    pub async fn start() -> Self {
        let inner = Arc::new(Mutex::new(Inner::default()));
        let app = axum::Router::new()
            .fallback(handle)
            .with_state(inner.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake API");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { addr, inner }
    }

    /// Base URL of the server (without `/api/v1`).
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Registers a reply for `method` + `path` (path under `/api/v1`, e.g. `/zones`). Several
    /// registrations of the same route are served in order, the last one being repeated.
    pub fn on(&self, method: &str, path: &str, reply: Reply) -> &Self {
        let key = format!("{} /api/v1{}", method.to_ascii_uppercase(), path);
        self.inner
            .lock()
            .expect("fake lock")
            .routes
            .entry(key)
            .or_default()
            .push_back(reply);
        self
    }

    /// Shortcut for a JSON reply.
    pub fn on_json(&self, method: &str, path: &str, status: u16, value: &impl Serialize) -> &Self {
        self.on(method, path, Reply::json(status, value))
    }

    /// Every request received so far.
    pub fn requests(&self) -> Vec<Recorded> {
        self.inner.lock().expect("fake lock").requests.clone()
    }

    /// Requests received for `method` + `path` (path under `/api/v1`).
    pub fn requests_to(&self, method: &str, path: &str) -> Vec<Recorded> {
        let full = format!("/api/v1{path}");
        self.requests()
            .into_iter()
            .filter(|r| r.method.eq_ignore_ascii_case(method) && r.path == full)
            .collect()
    }
}

async fn handle(State(inner): State<Arc<Mutex<Inner>>>, req: Request) -> Response {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| {
            url_decode_pairs(q)
                .into_iter()
                .collect::<Vec<(String, String)>>()
        })
        .unwrap_or_default();
    let headers = headers_map(req.headers());
    let body = to_bytes(req.into_body(), 16 * 1024 * 1024)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();
    let key = format!("{method} {path}");
    let reply = {
        let mut g = inner.lock().expect("fake lock");
        g.requests.push(Recorded {
            method,
            path: path.clone(),
            query,
            headers,
            body,
        });
        match g.routes.get_mut(&key) {
            Some(q) if q.len() > 1 => q.pop_front(),
            Some(q) => q.front().cloned(),
            None => None,
        }
    };
    let reply = reply.unwrap_or_else(|| {
        Reply::problem(404, "Not Found", &format!("fake API: no route for {key}"))
    });
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    if !reply.content_type.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, reply.content_type);
    }
    builder
        .body(Body::from(reply.body))
        .expect("valid fake response")
}

fn headers_map(h: &HeaderMap) -> BTreeMap<String, String> {
    h.iter()
        .map(|(k, v)| {
            (
                k.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn url_decode_pairs(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
