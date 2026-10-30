//! Bypass tests of gateway registration and of the mTLS gateway protocol `/gw/v1` (lot L7c).
//! Skipped when `AFW_TEST_DATABASE_URL` is not set.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use afw_api::AppState;
use afw_api::auth::Principal;
use afw_api::gateways::ports::{LogsPort, PolicyPort, PortFuture, Ports};
use afw_core::InstalledPolicy;
use afw_core::api::EnrollmentRequest;
use afw_core::events::GatewayEvent;
use afw_core::policy::{Agent, PolicyDocument};
use afw_core::protocol::{GatewayCommand, PolicyAck};
use afw_tls::{ConsolePki, GatewayIdentity};
use axum::http::StatusCode;
use serde_json::json;
use support::*;
use uuid::Uuid;

#[derive(Default)]
struct FakePolicy {
    installed: Mutex<Option<InstalledPolicy>>,
    acks: Mutex<Vec<(Uuid, PolicyAck)>>,
}

impl PolicyPort for FakePolicy {
    fn installed_policy_for<'a>(
        &'a self,
        _: &'a AppState,
        _: Uuid,
    ) -> PortFuture<'a, Option<InstalledPolicy>> {
        Box::pin(async move { Ok(self.installed.lock().unwrap().clone()) })
    }
    fn record_install_ack<'a>(
        &'a self,
        _: &'a AppState,
        gateway_id: Uuid,
        ack: PolicyAck,
    ) -> PortFuture<'a, ()> {
        Box::pin(async move {
            self.acks.lock().unwrap().push((gateway_id, ack));
            Ok(())
        })
    }
    fn current_policy<'a>(&'a self, _: &'a AppState) -> PortFuture<'a, Option<PolicyDocument>> {
        Box::pin(async { Ok(None) })
    }
    fn create_agent<'a>(
        &'a self,
        _: &'a AppState,
        _: &'a Principal,
        _: Option<Uuid>,
        _: &'a EnrollmentRequest,
    ) -> PortFuture<'a, (Agent, Uuid)> {
        Box::pin(async { Err(afw_api::ApiError::NotFound) })
    }
}

#[derive(Default)]
struct FakeLogs {
    events: Mutex<Vec<(Uuid, Vec<GatewayEvent>)>>,
    captures: Mutex<Vec<(Uuid, Uuid, Vec<u8>)>>,
    pending: Mutex<Vec<GatewayCommand>>,
    /// Number of next ingestion calls that fail.
    fail: Mutex<u32>,
    /// Delay of each ingestion.
    slow: Mutex<Option<Duration>>,
}

impl LogsPort for FakeLogs {
    fn ingest_gateway_events<'a>(
        &'a self,
        _: &'a AppState,
        gateway_id: Uuid,
        events: Vec<GatewayEvent>,
    ) -> PortFuture<'a, ()> {
        Box::pin(async move {
            let delay = *self.slow.lock().unwrap();
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }
            {
                let mut fail = self.fail.lock().unwrap();
                if *fail > 0 {
                    *fail -= 1;
                    return Err(afw_api::ApiError::Internal("store down".into()));
                }
            }
            self.events.lock().unwrap().push((gateway_id, events));
            Ok(())
        })
    }
    fn pending_commands<'a>(
        &'a self,
        _: &'a AppState,
        _: Uuid,
    ) -> PortFuture<'a, Vec<GatewayCommand>> {
        Box::pin(async move { Ok(std::mem::take(&mut *self.pending.lock().unwrap())) })
    }
    fn store_capture<'a>(
        &'a self,
        _: &'a AppState,
        gateway_id: Uuid,
        capture_id: Uuid,
        data: bytes::Bytes,
    ) -> PortFuture<'a, ()> {
        Box::pin(async move {
            self.captures
                .lock()
                .unwrap()
                .push((gateway_id, capture_id, data.to_vec()));
            Ok(())
        })
    }
}

struct Env {
    pool: sqlx::PgPool,
    app: axum::Router,
    base: String,
    pki: Arc<ConsolePki>,
    policy: Arc<FakePolicy>,
    logs: Arc<FakeLogs>,
    admin: String,
    _dir: tempfile::TempDir,
}

async fn env(pool: sqlx::PgPool) -> Env {
    env_with(pool, |_| {}).await
}

async fn env_with(pool: sqlx::PgPool, tune: impl FnOnce(&mut AppState)) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let pki = Arc::new(ConsolePki::load_or_create(&dir.path().join("pki")).unwrap());
    let policy = Arc::new(FakePolicy::default());
    let logs = Arc::new(FakeLogs::default());
    let mut state = state(&pool);
    state.gateways.pki = Some(pki.clone());
    state.gateways.long_poll = Duration::from_millis(600);
    state.gateways.poll_interval = Duration::from_millis(100);
    tune(&mut state);
    state.ports = Ports {
        policy: policy.clone(),
        logs: logs.clone(),
    };
    let server = pki
        .server_config(&["localhost".to_owned(), "127.0.0.1".to_owned()])
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    tokio::spawn(afw_api::gateways::tls::serve(
        listener,
        state.clone(),
        server,
    ));
    let admin = token(&pool, "admin", None).await;
    Env {
        app: afw_api::router(state),
        pool,
        base,
        pki,
        policy,
        logs,
        admin,
        _dir: dir,
    }
}

/// HTTPS client trusting the console CA, without a client certificate.
fn anonymous_client(ca_pem: &str) -> reqwest::Client {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let cfg = rustls::ClientConfig::builder_with_provider(afw_tls::crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(cfg)
        .build()
        .unwrap()
}

fn gateway_client(dir: &std::path::Path) -> reqwest::Client {
    let cfg = GatewayIdentity::client_config(dir).unwrap();
    reqwest::Client::builder()
        .use_preconfigured_tls((*cfg).clone())
        .build()
        .unwrap()
}

async fn registration_token(e: &Env) -> String {
    registration_token_named(e, "gw-a").await
}

async fn registration_token_named(e: &Env, name: &str) -> String {
    let res = call(
        &e.app,
        "POST",
        "/api/v1/gateways/registration-tokens",
        Some(&e.admin),
        Some(json!({"name": name})),
    )
    .await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
    let body = res.json();
    let expires: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(body["expires_at"].clone()).unwrap();
    let ttl = expires - chrono::Utc::now();
    assert!(ttl <= chrono::Duration::minutes(15) && ttl > chrono::Duration::minutes(14));
    body["token"].as_str().unwrap().to_owned()
}

async fn register(e: &Env, token: &str, csr: &str, name: &str) -> reqwest::Response {
    anonymous_client(&e.pki.ca_cert_pem())
        .post(format!("{}/gw/v1/register", e.base))
        .json(&json!({"token": token, "name": name, "hostname": "host-a", "csr_pem": csr}))
        .send()
        .await
        .unwrap()
}

/// Registers a gateway and returns (id, identity dir).
async fn registered(e: &Env, name: &str) -> (Uuid, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let csr = GatewayIdentity::generate(dir.path()).unwrap();
    let token = registration_token_named(e, name).await;
    let res = register(e, &token, &csr, name).await;
    assert_eq!(res.status().as_u16(), 201);
    let body: serde_json::Value = res.json().await.unwrap();
    GatewayIdentity::store_cert(
        dir.path(),
        body["cert_pem"].as_str().unwrap(),
        body["ca_pem"].as_str().unwrap(),
    )
    .unwrap();
    (body["gateway_id"].as_str().unwrap().parse().unwrap(), dir)
}

fn heartbeat() -> serde_json::Value {
    json!({"version": "0.1.0", "revision": 3, "ca_fingerprint": "ab12",
        "stats": {"uptime_secs": 5, "active_flows": 1, "flows_total": 2, "denied_total": 1,
                  "bytes_in": 10, "bytes_out": 20, "events_queued": 0, "events_dropped": 0}})
}

#[tokio::test]
async fn registration_token_is_single_use_and_expires() {
    let pool = pool_or_skip!();
    let e = env(pool).await;
    let dir = tempfile::tempdir().unwrap();
    let csr = GatewayIdentity::generate(dir.path()).unwrap();
    let token = registration_token(&e).await;

    // An invalid CSR does not consume the token.
    let res = register(&e, &token, "not a csr", "gw-a").await;
    assert_eq!(res.status().as_u16(), 400);
    let res = register(&e, &token, &csr, "gw-a").await;
    assert_eq!(res.status().as_u16(), 201);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body["cert_pem"].as_str().unwrap().contains("CERTIFICATE"));
    assert_eq!(body["ca_pem"].as_str().unwrap(), e.pki.ca_cert_pem());
    // Reused.
    let res = register(&e, &token, &csr, "gw-b").await;
    assert_eq!(res.status().as_u16(), 401, "reused token");
    // Unknown.
    let res = register(&e, "afw_rt_unknown", &csr, "gw-c").await;
    assert_eq!(res.status().as_u16(), 401, "unknown token");
    // Expired.
    let expired = registration_token(&e).await;
    sqlx::query(
        "UPDATE gateway_registration_tokens SET expires_at = now() - interval '1 second' \
         WHERE token_sha256 = $1",
    )
    .bind(afw_core::sha256_hex(expired.as_bytes()))
    .execute(&e.pool)
    .await
    .unwrap();
    let res = register(&e, &expired, &csr, "gw-d").await;
    assert_eq!(res.status().as_u16(), 401, "expired token");
    // Only the hash is stored.
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM gateway_registration_tokens WHERE token_sha256 = $1",
    )
    .bind(&token)
    .fetch_one(&e.pool)
    .await
    .unwrap();
    assert_eq!(leaked, 0);
    // Registration is audited.
    let audit = afw_api::audit::load(&e.pool, 1, 100).await.unwrap();
    assert!(audit.iter().any(|a| a.action == "gateway.register"));
    assert!(
        audit
            .iter()
            .any(|a| a.action == "gateway.registration_token.create")
    );
}

#[tokio::test]
async fn gw_routes_require_a_valid_client_certificate() {
    let pool = pool_or_skip!();
    let e = env(pool).await;
    let (gw, dir) = registered(&e, "gw-a").await;

    // No certificate (even with spoofed identity headers): refused.
    let anon = anonymous_client(&e.pki.ca_cert_pem());
    for (method, path) in [
        ("GET", "/gw/v1/policy"),
        ("POST", "/gw/v1/heartbeat"),
        ("POST", "/gw/v1/policy/ack"),
        ("POST", "/gw/v1/events"),
    ] {
        let res = anon
            .request(method.parse().unwrap(), format!("{}{path}", e.base))
            .header("x-afw-gateway-id", gw.to_string())
            .header("x-client-cert", "gw:whatever")
            .json(&heartbeat())
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 401, "{method} {path} without cert");
    }

    // A certificate from another CA: the handshake fails.
    let rogue_dir = tempfile::tempdir().unwrap();
    let rogue = ConsolePki::load_or_create(rogue_dir.path()).unwrap();
    let other = tempfile::tempdir().unwrap();
    let csr = GatewayIdentity::generate(other.path()).unwrap();
    let cert = rogue.sign_gateway_csr(&csr, &gw.to_string(), 30).unwrap();
    GatewayIdentity::store_cert(other.path(), &cert, &e.pki.ca_cert_pem()).unwrap();
    let res = gateway_client(other.path())
        .post(format!("{}/gw/v1/heartbeat", e.base))
        .json(&heartbeat())
        .send()
        .await;
    assert!(
        res.is_err() || res.unwrap().status().as_u16() == 401,
        "rogue CA accepted"
    );

    // A certificate of the console CA for the same id but another key (not the one issued at
    // registration): refused by the pinned fingerprint.
    let twin = tempfile::tempdir().unwrap();
    let csr = GatewayIdentity::generate(twin.path()).unwrap();
    let cert = e.pki.sign_gateway_csr(&csr, &gw.to_string(), 30).unwrap();
    GatewayIdentity::store_cert(twin.path(), &cert, &e.pki.ca_cert_pem()).unwrap();
    let res = gateway_client(twin.path())
        .post(format!("{}/gw/v1/heartbeat", e.base))
        .json(&heartbeat())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401, "unpinned certificate");

    // The legitimate gateway passes.
    let client = gateway_client(dir.path());
    let res = client
        .post(format!("{}/gw/v1/heartbeat", e.base))
        .json(&heartbeat())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);

    // The public listener does not serve the gateway protocol at all.
    for path in ["/gw/v1/policy", "/gw/v1/register"] {
        let res = call(&e.app, "GET", path, None, None).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{path} on public router");
    }

    // A removed gateway is refused, certificate still valid or not.
    let res = call(
        &e.app,
        "DELETE",
        &format!("/api/v1/gateways/{gw}"),
        Some(&e.admin),
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    let res = client
        .post(format!("{}/gw/v1/heartbeat", e.base))
        .json(&heartbeat())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401, "deleted gateway");
}

#[tokio::test]
async fn heartbeat_status_and_commands() {
    let pool = pool_or_skip!();
    let e = env(pool).await;
    let (gw, dir) = registered(&e, "gw-a").await;
    let client = gateway_client(dir.path());

    let list = call(&e.app, "GET", "/api/v1/gateways", Some(&e.admin), None).await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(list.json()[0]["status"], "pending");

    // Commands: queued by an admin (viewer refused), delivered once.
    let viewer = token(&e.pool, "viewer", None).await;
    let cmd = json!({"type": "self_test"});
    let uri = format!("/api/v1/gateways/{gw}/commands");
    let res = call(&e.app, "POST", &uri, Some(&viewer), Some(cmd.clone())).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    let res = call(&e.app, "POST", &uri, Some(&e.admin), Some(cmd)).await;
    assert_eq!(res.status, StatusCode::ACCEPTED, "{}", res.text());
    let res = call(
        &e.app,
        "POST",
        &format!("/api/v1/gateways/{}/commands", Uuid::new_v4()),
        Some(&e.admin),
        Some(json!({"type": "reinstall"})),
    )
    .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    let capture = Uuid::new_v4();
    e.logs
        .pending
        .lock()
        .unwrap()
        .push(GatewayCommand::StartCapture {
            capture_id: capture,
            agent_id: Uuid::new_v4(),
            duration_secs: 10,
        });

    let hb = |c: &reqwest::Client| {
        c.post(format!("{}/gw/v1/heartbeat", e.base))
            .json(&heartbeat())
            .send()
    };
    let first: serde_json::Value = hb(&client).await.unwrap().json().await.unwrap();
    let commands = first["commands"].as_array().unwrap();
    assert_eq!(commands.len(), 2, "{first}");
    assert!(commands.iter().any(|c| c["type"] == "self_test"));
    assert!(commands.iter().any(|c| c["type"] == "start_capture"));
    let second: serde_json::Value = hb(&client).await.unwrap().json().await.unwrap();
    assert_eq!(second["commands"], json!([]));

    let one = call(
        &e.app,
        "GET",
        &format!("/api/v1/gateways/{gw}"),
        Some(&viewer),
        None,
    )
    .await;
    assert_eq!(one.status, StatusCode::OK);
    let g = one.json();
    assert_eq!(g["status"], "online");
    assert_eq!(g["version"], "0.1.0");
    assert_eq!(g["active_revision"], 3);
    assert_eq!(g["ca_fingerprint"], "ab12");
    assert_eq!(g["stats"]["bytes_out"], 20);
    assert_eq!(g["name"], "gw-a");

    // Seen too long ago: offline.
    sqlx::query("UPDATE gateways SET last_seen_at = now() - interval '1 hour'")
        .execute(&e.pool)
        .await
        .unwrap();
    let one = call(
        &e.app,
        "GET",
        &format!("/api/v1/gateways/{gw}"),
        Some(&viewer),
        None,
    )
    .await;
    assert_eq!(one.json()["status"], "offline");
}

#[tokio::test]
async fn policy_long_poll_ack_events_and_captures() {
    let pool = pool_or_skip!();
    let e = env(pool).await;
    let (gw, dir) = registered(&e, "gw-a").await;
    let client = gateway_client(dir.path());

    // Nothing installed: 204 after the long poll.
    let started = std::time::Instant::now();
    let res = client
        .get(format!("{}/gw/v1/policy", e.base))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 204);
    assert!(started.elapsed() >= Duration::from_millis(500));

    *e.policy.installed.lock().unwrap() =
        Some(InstalledPolicy::new(3, "admin", PolicyDocument::default()));
    let res = client
        .get(format!("{}/gw/v1/policy?have=2", e.base))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let installed: InstalledPolicy = res.json().await.unwrap();
    assert_eq!(installed.revision, 3);
    installed.verify().unwrap();
    let res = client
        .get(format!("{}/gw/v1/policy?have=3", e.base))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 204);
    // Installed while waiting: answered before the end of the long poll.
    let policy = e.policy.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        *policy.installed.lock().unwrap() =
            Some(InstalledPolicy::new(4, "admin", PolicyDocument::default()));
    });
    let res = client
        .get(format!("{}/gw/v1/policy?have=3", e.base))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);

    let res = client
        .post(format!("{}/gw/v1/policy/ack", e.base))
        .json(&json!({"revision": 4, "ok": true, "error": null}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 204);
    assert_eq!(e.policy.acks.lock().unwrap()[0].0, gw);

    // Events: idempotent per batch_id.
    let batch = json!({"batch_id": Uuid::new_v4(), "events": [
        {"type": "rule_hits", "hits": []}
    ]});
    for _ in 0..2 {
        let res = client
            .post(format!("{}/gw/v1/events", e.base))
            .json(&batch)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 202);
    }
    assert_eq!(e.logs.events.lock().unwrap().len(), 1);
    assert_eq!(e.logs.events.lock().unwrap()[0].0, gw);

    // Capture upload.
    let capture = Uuid::new_v4();
    let res = client
        .post(format!("{}/gw/v1/captures/{capture}", e.base))
        .header("content-type", "application/vnd.tcpdump.pcap")
        .body(vec![0xd4u8, 0xc3, 0xb2, 0xa1, 1, 2, 3])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 204);
    let captures = e.logs.captures.lock().unwrap();
    assert_eq!(
        captures[0],
        (gw, capture, vec![0xd4, 0xc3, 0xb2, 0xa1, 1, 2, 3])
    );
}

#[tokio::test]
async fn gateway_name_is_imposed_by_the_registration_token() {
    let pool = pool_or_skip!();
    let e = env(pool).await;
    let dir = tempfile::tempdir().unwrap();
    let csr = GatewayIdentity::generate(dir.path()).unwrap();
    let token = registration_token_named(&e, "gw-expected").await;
    let res = register(&e, &token, &csr, "gw-chosen-by-the-gateway").await;
    assert_eq!(res.status().as_u16(), 201);
    let body: serde_json::Value = res.json().await.unwrap();
    let id = body["gateway_id"].as_str().unwrap();
    let g = call(&e.app, "GET", &format!("/api/v1/gateways/{id}"), Some(&e.admin), None).await;
    assert_eq!(g.json()["name"], "gw-expected");
}

#[tokio::test]
async fn event_batches_are_reserved_atomically() {
    let pool = pool_or_skip!();
    let e = env(pool).await;
    let (gw_a, dir_a) = registered(&e, "gw-a").await;
    let (gw_b, dir_b) = registered(&e, "gw-b").await;
    let (a, b) = (gateway_client(dir_a.path()), gateway_client(dir_b.path()));
    let url = format!("{}/gw/v1/events", e.base);
    let batch = json!({"batch_id": Uuid::new_v4(), "events": [{"type": "rule_hits", "hits": []}]});

    // A failed ingestion releases the reservation: the retry is ingested.
    *e.logs.fail.lock().unwrap() = 1;
    let res = a.post(&url).json(&batch).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 500);
    assert_eq!(e.logs.events.lock().unwrap().len(), 0);
    let res = a.post(&url).json(&batch).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 202);
    assert_eq!(e.logs.events.lock().unwrap().len(), 1);

    // Concurrent duplicates: ingested once.
    *e.logs.slow.lock().unwrap() = Some(Duration::from_millis(300));
    let dup = json!({"batch_id": Uuid::new_v4(), "events": []});
    let (r1, r2) = tokio::join!(
        a.post(&url).json(&dup).send(),
        a.post(&url).json(&dup).send()
    );
    assert_eq!(r1.unwrap().status().as_u16(), 202);
    assert_eq!(r2.unwrap().status().as_u16(), 202);
    assert_eq!(e.logs.events.lock().unwrap().len(), 2);

    // The key is (gateway, batch): another gateway's batch with the same id is ingested.
    let res = b.post(&url).json(&dup).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 202);
    let events = e.logs.events.lock().unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[2].0, gw_b);
    assert_ne!(gw_a, gw_b);
}

#[tokio::test]
async fn listener_limits_connections() {
    let pool = pool_or_skip!();
    let e = env_with(pool, |s| s.gateways.max_connections = 1).await;
    let (_, dir) = registered(&e, "gw-a").await;
    // registered() used the only slot, then released it. Hold it with a silent TCP connection.
    let addr = e.base.trim_start_matches("https://").to_owned();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let hold = tokio::net::TcpStream::connect(&addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let res = gateway_client(dir.path())
        .post(format!("{}/gw/v1/heartbeat", e.base))
        .json(&heartbeat())
        .send()
        .await;
    assert!(res.is_err(), "a connection beyond the limit must be refused");
    drop(hold);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let res = gateway_client(dir.path())
        .post(format!("{}/gw/v1/heartbeat", e.base))
        .json(&heartbeat())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
}

#[tokio::test]
async fn listener_closes_connections_that_send_no_headers() {
    use tokio::io::AsyncReadExt;
    let pool = pool_or_skip!();
    let e = env_with(pool, |s| {
        s.gateways.header_read_timeout = Duration::from_millis(300)
    })
    .await;
    let (_, dir) = registered(&e, "gw-a").await;
    let mut cfg = (*GatewayIdentity::client_config(dir.path()).unwrap()).clone();
    cfg.alpn_protocols.clear();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let addr = e.base.trim_start_matches("https://").to_owned();
    let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let mut tls = connector
        .connect("127.0.0.1".try_into().unwrap(), tcp)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await;
    assert!(read.is_ok(), "the server kept a silent connection open");
    assert!(started.elapsed() < Duration::from_secs(3));
}
