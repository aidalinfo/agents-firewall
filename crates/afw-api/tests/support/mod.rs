//! Shared helpers of the L7c integration tests: one fresh PostgreSQL database per test, HTTP calls
//! through the router, and a fake OIDC provider.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use afw_api::{AppState, Config, migrate};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, PgPool};
use tower::ServiceExt;
use uuid::Uuid;

/// A brand new database (own audit chain, own tables) for one test, or `None` (test skipped) when
/// `AFW_TEST_DATABASE_URL` is not set.
pub async fn fresh_pool() -> Option<PgPool> {
    let url = std::env::var("AFW_TEST_DATABASE_URL").ok()?;
    let admin = PgConnectOptions::from_str(&url).expect("database url");
    let name = format!("afw_l7c_{}", Uuid::new_v4().simple());
    let mut conn = admin.connect().await.expect("connect test server");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut conn)
        .await
        .expect("create test database");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(admin.database(&name))
        .await
        .expect("connect test database");
    migrate(&pool).await.expect("migrations");
    Some(pool)
}

#[macro_export]
macro_rules! pool_or_skip {
    () => {
        match support::fresh_pool().await {
            Some(p) => p,
            None => {
                eprintln!("AFW_TEST_DATABASE_URL not set: skipped");
                return;
            }
        }
    };
}

pub fn state(pool: &PgPool) -> AppState {
    AppState::new(Config::default(), Some(pool.clone()))
}

/// Inserts an API token directly and returns its secret.
pub async fn token(pool: &PgPool, role: &str, agent_id: Option<Uuid>) -> String {
    let secret = format!("test-{role}-{}", Uuid::new_v4());
    let kind = if matches!(role, "mcp_agent" | "agent_plugin") {
        "agent"
    } else {
        "human"
    };
    sqlx::query(
        "INSERT INTO api_tokens (name, token_sha256, role, actor_kind, actor_name, agent_id, \
         created_by) VALUES ($1, $2, $3, $4, $1, $5, '{\"kind\":\"system\",\"id\":\"t\",\"name\":\"t\"}')",
    )
    .bind(format!("{role}-token"))
    .bind(afw_core::sha256_hex(secret.as_bytes()))
    .bind(role)
    .bind(kind)
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("insert token");
    secret
}

pub struct Resp {
    pub status: StatusCode,
    pub headers: axum::http::HeaderMap,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Calls `app` with an optional bearer token and JSON body.
pub async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> Resp {
    call_with(app, method, uri, bearer, body, &[]).await
}

pub async fn call_with(
    app: &Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> Resp {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&b).unwrap())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = http_body_util::BodyExt::collect(res.into_body())
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    Resp {
        status,
        headers,
        body,
    }
}

// ---------------------------------------------------------------------------------------------
// Fake OIDC provider

pub const KID_1: &str = "key-1";
pub const KID_2: &str = "key-2";

pub fn rsa_pem(n: u8) -> &'static [u8] {
    match n {
        1 => include_bytes!("../fixtures/oidc-rsa-1.pem"),
        _ => include_bytes!("../fixtures/oidc-rsa-2.pem"),
    }
}

pub fn rsa_jwk(n: u8, kid: &str) -> Value {
    let modulus = match n {
        1 => include_str!("../fixtures/oidc-rsa-1.n"),
        _ => include_str!("../fixtures/oidc-rsa-2.n"),
    };
    serde_json::json!({"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
        "n": modulus.trim(), "e": "AQAB"})
}

/// Minimal OIDC provider: discovery document and a JWKS that the test can replace.
pub struct FakeOidc {
    pub issuer: String,
    pub jwks: Arc<Mutex<Value>>,
    pub jwks_hits: Arc<Mutex<u32>>,
}

impl FakeOidc {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");
        let jwks = Arc::new(Mutex::new(serde_json::json!({"keys": [rsa_jwk(1, KID_1)]})));
        let jwks_hits = Arc::new(Mutex::new(0u32));
        let discovery = serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "end_session_endpoint": format!("{issuer}/logout"),
        });
        let (j, h) = (jwks.clone(), jwks_hits.clone());
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let d = discovery.clone();
                    async move { axum::Json(d) }
                }),
            )
            .route(
                "/jwks",
                get(move || {
                    let (j, h) = (j.clone(), h.clone());
                    async move {
                        *h.lock().unwrap() += 1;
                        axum::Json(j.lock().unwrap().clone())
                    }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            issuer,
            jwks,
            jwks_hits,
        }
    }

    pub fn settings(&self) -> afw_api::auth::oidc::OidcSettings {
        afw_api::auth::oidc::OidcSettings {
            issuer: self.issuer.clone(),
            client_id: "afw-console".into(),
            audiences: vec!["afw-console".into()],
            scopes: "openid profile email".into(),
            role_claim: "groups".into(),
            admin_groups: vec!["afw-admins".into()],
            auditor_groups: vec!["afw-auditors".into()],
            viewer_groups: vec!["afw-viewers".into()],
            default_role: None,
        }
    }

    /// Standard claims, valid for one hour, for the `afw-console` audience.
    pub fn claims(&self, groups: &[&str]) -> Value {
        let now = chrono::Utc::now().timestamp();
        serde_json::json!({
            "iss": self.issuer, "aud": "afw-console", "sub": "user-42",
            "email": "alice@example.org", "name": "Alice",
            "groups": groups, "iat": now, "exp": now + 3600,
        })
    }

    pub fn sign(&self, claims: &Value, key: u8, kid: &str) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(kid.to_owned());
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(rsa_pem(key)).unwrap();
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }
}

// ---------------------------------------------------------------------------------------------
// Policy port returning a fixed published policy

pub struct StaticPolicy(pub afw_core::policy::PolicyDocument);

impl afw_api::gateways::ports::PolicyPort for StaticPolicy {
    fn installed_policy_for<'a>(
        &'a self,
        _: &'a AppState,
        _: Uuid,
    ) -> afw_api::gateways::ports::PortFuture<'a, Option<afw_core::InstalledPolicy>> {
        Box::pin(async { Ok(None) })
    }
    fn record_install_ack<'a>(
        &'a self,
        _: &'a AppState,
        _: Uuid,
        _: afw_core::protocol::PolicyAck,
    ) -> afw_api::gateways::ports::PortFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn current_policy<'a>(
        &'a self,
        _: &'a AppState,
    ) -> afw_api::gateways::ports::PortFuture<'a, Option<afw_core::policy::PolicyDocument>> {
        Box::pin(async move { Ok(Some(self.0.clone())) })
    }
    fn create_agent<'a>(
        &'a self,
        _: &'a AppState,
        _: &'a afw_api::auth::Principal,
        _: Option<Uuid>,
        _: &'a afw_core::api::EnrollmentRequest,
    ) -> afw_api::gateways::ports::PortFuture<'a, (afw_core::policy::Agent, Uuid)> {
        Box::pin(async { Err(afw_api::ApiError::NotFound) })
    }
}

/// A published policy with one zone and the given agents (all in that zone).
pub fn policy_with_agents(agents: &[Uuid]) -> afw_core::policy::PolicyDocument {
    let zone = Uuid::from_u128(500);
    afw_core::policy::PolicyDocument {
        zones: vec![afw_core::policy::Zone {
            id: zone,
            name: "z".into(),
            comment: String::new(),
            mode: afw_core::policy::ZoneMode::Enforce,
            delegated_to_mcp: false,
        }],
        agents: agents
            .iter()
            .map(|id| afw_core::policy::Agent {
                id: *id,
                name: id.to_string(),
                zone_id: zone,
                kind: afw_core::policy::AgentKind::Container,
                gateway_id: None,
                addresses: vec![],
                labels: Default::default(),
                hermes: true,
                mcp_admin: true,
            })
            .collect(),
        ..Default::default()
    }
}

/// State whose policy port publishes `agents`.
pub fn state_with_agents(pool: &PgPool, agents: &[Uuid]) -> AppState {
    let mut s = state(pool);
    s.ports.policy = Arc::new(StaticPolicy(policy_with_agents(agents)));
    s
}
