//! Shared helpers of the policy tests: a dedicated PostgreSQL database per test, tokens per role,
//! HTTP calls through the full router.
#![allow(dead_code)]

use std::sync::Arc;

use afw_api::policy::FlowLookup;
use afw_api::{AppState, Config, migrate, router};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection, PgPool};
use tower::ServiceExt;
use uuid::Uuid;

pub struct Env {
    pub pool: PgPool,
    pub state: AppState,
    pub admin: String,
    pub admin2: String,
    pub auditor: String,
    pub viewer: String,
    pub plugin: String,
}

/// Creates a fresh database (migrated) and the usual tokens. `None` when
/// `AFW_TEST_DATABASE_URL` is not set (test skipped).
pub async fn env() -> Option<Env> {
    env_with(None).await
}

pub async fn env_with(flows: Option<Arc<dyn FlowLookup>>) -> Option<Env> {
    let url = std::env::var("AFW_TEST_DATABASE_URL").ok()?;
    let name = format!("t_{}", Uuid::new_v4().simple());
    let mut admin_conn = PgConnection::connect(&url).await.expect("connect");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin_conn)
        .await
        .expect("create database");
    let (base, _) = url.rsplit_once('/').expect("database url with a path");
    let pool = PgPool::connect(&format!("{base}/{name}"))
        .await
        .expect("connect test database");
    migrate(&pool).await.expect("migrations");
    let mut state = AppState::new(Config::default(), Some(pool.clone()));
    state.flow_lookup = flows;
    let env = Env {
        admin: String::new(),
        admin2: String::new(),
        auditor: String::new(),
        viewer: String::new(),
        plugin: String::new(),
        pool,
        state,
    };
    let admin = env.token("admin", "alice", None).await;
    let admin2 = env.token("admin", "bob", None).await;
    let auditor = env.token("auditor", "carol", None).await;
    let viewer = env.token("viewer", "dave", None).await;
    let plugin = env
        .token("agent_plugin", "plugin", Some(Uuid::new_v4()))
        .await;
    Some(Env {
        admin,
        admin2,
        auditor,
        viewer,
        plugin,
        ..env
    })
}

impl Env {
    pub fn app(&self) -> Router {
        router(self.state.clone())
    }

    /// Inserts a token and returns its secret.
    pub async fn token(&self, role: &str, name: &str, agent: Option<Uuid>) -> String {
        let secret = format!("{name}-{}", Uuid::new_v4());
        let kind = if agent.is_some() { "agent" } else { "human" };
        sqlx::query(
            "INSERT INTO api_tokens (name, token_sha256, role, actor_kind, actor_name, agent_id, \
             created_by) VALUES ($1, $2, $3, $4, $1, $5, '{}')",
        )
        .bind(name)
        .bind(afw_core::sha256_hex(secret.as_bytes()))
        .bind(role)
        .bind(kind)
        .bind(agent)
        .execute(&self.pool)
        .await
        .expect("insert token");
        secret
    }

    /// Calls the API (`/api/v1` prefix added) and returns the status and JSON body.
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        token: &str,
        session: Option<Uuid>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.call_iface(method, path, token, session, body, None)
            .await
    }

    pub async fn call_iface(
        &self,
        method: &str,
        path: &str,
        token: &str,
        session: Option<Uuid>,
        body: Option<Value>,
        iface: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(format!("/api/v1{path}"))
            .header("authorization", format!("Bearer {token}"));
        if let Some(s) = session {
            req = req.header("x-afw-session", s.to_string());
        }
        if let Some(i) = iface {
            req = req.header("x-afw-interface", i);
        }
        let req = match body {
            Some(b) => req
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&b).unwrap()))
                .unwrap(),
            None => req.body(Body::empty()).unwrap(),
        };
        let res = self.app().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = http_body_util::BodyExt::collect(res.into_body())
            .await
            .unwrap()
            .to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        (status, value)
    }

    /// Opens a session for `token` and returns its id.
    pub async fn open(&self, token: &str) -> Uuid {
        let (st, body) = self.call("POST", "/sessions", token, None, None).await;
        assert_eq!(st, StatusCode::CREATED, "open session: {body}");
        body["id"].as_str().unwrap().parse().unwrap()
    }

    /// Creates a resource in a session and asserts 201.
    pub async fn create(&self, token: &str, s: Uuid, collection: &str, body: Value) -> Value {
        let (st, out) = self
            .call(
                "POST",
                &format!("/{collection}"),
                token,
                Some(s),
                Some(body),
            )
            .await;
        assert_eq!(st, StatusCode::CREATED, "create {collection}: {out}");
        out
    }

    /// Publishes and asserts 201; returns the revision number.
    pub async fn publish(&self, token: &str, s: Uuid) -> u64 {
        let (st, out) = self
            .call(
                "POST",
                &format!("/sessions/{s}/publish"),
                token,
                None,
                Some(json!({"comment": "test"})),
            )
            .await;
        assert_eq!(st, StatusCode::CREATED, "publish: {out}");
        out["number"].as_u64().unwrap()
    }
}

// ---- Resource builders ------------------------------------------------------------------------

pub fn zone(id: Uuid, name: &str, delegated: bool) -> Value {
    json!({"id": id, "name": name, "mode": "enforce", "delegated_to_mcp": delegated})
}

pub fn domain(id: Uuid, name: &str, pattern: &str) -> Value {
    json!({"id": id, "name": name, "spec": {"type": "domain", "pattern": pattern}})
}

pub fn any_object(id: Uuid, name: &str) -> Value {
    json!({"id": id, "name": name, "spec": {"type": "any"}})
}

pub fn group(id: Uuid, name: &str, members: &[Uuid]) -> Value {
    json!({"id": id, "name": name, "spec": {"type": "group", "members": members}})
}

pub fn tcp_service(id: Uuid, name: &str, port: u16) -> Value {
    json!({"id": id, "name": name, "protocol": "tcp", "ports": [{"start": port, "end": port}]})
}

pub fn secret_class(id: Uuid, name: &str) -> Value {
    json!({"id": id, "name": name, "category": "secret",
           "detectors": [{"type": "builtin", "id": "aws_access_key"}]})
}

pub fn agent(id: Uuid, name: &str, zone: Uuid, mcp_admin: bool) -> Value {
    json!({"id": id, "name": name, "zone_id": zone, "kind": "docker_compose",
           "mcp_admin": mcp_admin})
}

pub fn zone_rule(id: Uuid, name: &str, zone: Uuid, position: u32, dests: &[Uuid]) -> Value {
    json!({"id": id, "name": name, "layer": {"type": "zone", "zone_id": zone},
           "position": position, "sources": [zone], "destinations": dests,
           "action": "accept", "enabled": true})
}

pub fn baseline_rule(id: Uuid, name: &str, position: u32, dests: &[Uuid]) -> Value {
    json!({"id": id, "name": name, "layer": {"type": "baseline"}, "position": position,
           "destinations": dests, "action": "deny", "enabled": true})
}
