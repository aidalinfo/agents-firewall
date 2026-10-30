//! `POST /enrollments` (lot L7c): agent creation is delegated to the policy module (port), the
//! plugin token is minted here. Skipped when `AFW_TEST_DATABASE_URL` is not set.

mod support;

use std::sync::{Arc, Mutex};

use afw_api::AppState;
use afw_api::auth::Principal;
use afw_api::gateways::ports::{PolicyPort, PortFuture, Ports, Unwired};
use afw_core::InstalledPolicy;
use afw_core::api::EnrollmentRequest;
use afw_core::policy::{Agent, PolicyDocument, Zone, ZoneMode};
use afw_core::protocol::PolicyAck;
use axum::http::StatusCode;
use serde_json::json;
use support::*;
use uuid::Uuid;

const OWN: Uuid = Uuid::from_u128(1);
const DELEGATED: Uuid = Uuid::from_u128(2);
const MCP_AGENT: Uuid = Uuid::from_u128(10);

struct FakePolicy {
    created: Mutex<Vec<(Option<Uuid>, EnrollmentRequest)>>,
}

fn doc() -> PolicyDocument {
    let zone = |id| Zone {
        id,
        name: id.to_string(),
        comment: String::new(),
        mode: ZoneMode::Enforce,
        delegated_to_mcp: true,
    };
    PolicyDocument {
        zones: vec![zone(OWN), zone(DELEGATED)],
        agents: vec![agent(MCP_AGENT, OWN, "ops-bot")],
        ..Default::default()
    }
}

fn agent(id: Uuid, zone_id: Uuid, name: &str) -> Agent {
    Agent {
        id,
        name: name.into(),
        zone_id,
        kind: afw_core::policy::AgentKind::Container,
        gateway_id: None,
        addresses: vec![],
        labels: Default::default(),
        hermes: true,
        mcp_admin: false,
    }
}

impl PolicyPort for FakePolicy {
    fn installed_policy_for<'a>(
        &'a self,
        _: &'a AppState,
        _: Uuid,
    ) -> PortFuture<'a, Option<InstalledPolicy>> {
        Box::pin(async { Ok(None) })
    }
    fn record_install_ack<'a>(
        &'a self,
        _: &'a AppState,
        _: Uuid,
        _: PolicyAck,
    ) -> PortFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn current_policy<'a>(&'a self, _: &'a AppState) -> PortFuture<'a, Option<PolicyDocument>> {
        Box::pin(async { Ok(Some(doc())) })
    }
    fn create_agent<'a>(
        &'a self,
        _: &'a AppState,
        _: &'a Principal,
        session_id: Option<Uuid>,
        request: &'a EnrollmentRequest,
    ) -> PortFuture<'a, (Agent, Uuid)> {
        Box::pin(async move {
            self.created
                .lock()
                .unwrap()
                .push((session_id, request.clone()));
            Ok((
                agent(Uuid::new_v4(), request.zone_id, &request.name),
                session_id.unwrap_or(Uuid::from_u128(99)),
            ))
        })
    }
}

fn body(zone: Uuid, hermes: bool) -> serde_json::Value {
    json!({"name": "bot-1", "zone_id": zone, "kind": "container",
           "gateway_id": Uuid::new_v4(), "hermes": hermes})
}

#[tokio::test]
async fn enrollment_creates_agent_and_plugin_token() {
    let pool = pool_or_skip!();
    let policy = Arc::new(FakePolicy {
        created: Mutex::new(vec![]),
    });
    let mut state = state(&pool);
    state.ports = Ports {
        policy: policy.clone(),
        logs: Arc::new(Unwired),
    };
    let app = afw_api::router(state);
    let admin = token(&pool, "admin", None).await;
    let session = Uuid::new_v4();
    let session_s = session.to_string();

    let res = call_with(
        &app,
        "POST",
        "/api/v1/enrollments",
        Some(&admin),
        Some(body(DELEGATED, true)),
        &[("x-afw-session", session_s.as_str())],
    )
    .await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
    let out = res.json();
    assert_eq!(out["session_id"], session_s.as_str());
    let plugin = out["plugin_token"].as_str().unwrap().to_owned();
    assert!(plugin.starts_with("afw_at_"), "{plugin}");
    let agent_id: Uuid = out["agent"]["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(policy.created.lock().unwrap()[0].0, Some(session));

    // The plugin token is bound to the agent and limited to the plugin role.
    let (role, bound): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT role, agent_id FROM api_tokens WHERE token_sha256 = $1 AND revoked_at IS NULL",
    )
    .bind(afw_core::sha256_hex(plugin.as_bytes()))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(role, "agent_plugin");
    assert_eq!(bound, Some(agent_id));
    let me = call(&app, "GET", "/api/v1/me", Some(&plugin), None).await;
    assert_eq!(me.status, StatusCode::FORBIDDEN);
    let audit = afw_api::audit::load(&pool, 1, 100).await.unwrap();
    let entry = audit
        .iter()
        .find(|e| e.action == "token.create")
        .expect("plugin token audited");
    assert_eq!(entry.session_id, Some(session));
    assert!(!serde_json::to_string(&audit).unwrap().contains(&plugin));

    // Not a Hermes agent: no token.
    let res = call(
        &app,
        "POST",
        "/api/v1/enrollments",
        Some(&admin),
        Some(body(DELEGATED, false)),
    )
    .await;
    assert_eq!(res.status, StatusCode::CREATED);
    assert_eq!(res.json()["plugin_token"], serde_json::Value::Null);
}

#[tokio::test]
async fn enrollment_rights() {
    let pool = pool_or_skip!();
    let policy = Arc::new(FakePolicy {
        created: Mutex::new(vec![]),
    });
    let mut state = state(&pool);
    state.ports = Ports {
        policy: policy.clone(),
        logs: Arc::new(Unwired),
    };
    let app = afw_api::router(state);
    for role in ["viewer", "auditor"] {
        let t = token(&pool, role, None).await;
        let res = call(&app, "POST", "/api/v1/enrollments", Some(&t), Some(body(DELEGATED, true))).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{role}");
    }
    let plugin = token(&pool, "agent_plugin", Some(Uuid::new_v4())).await;
    let res = call(&app, "POST", "/api/v1/enrollments", Some(&plugin), Some(body(DELEGATED, true))).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);

    // The MCP agent may enroll into a delegated zone, never into its own zone.
    let mcp = token(&pool, "mcp_agent", Some(MCP_AGENT)).await;
    let res = call(&app, "POST", "/api/v1/enrollments", Some(&mcp), Some(body(OWN, true))).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "own zone");
    let res = call(&app, "POST", "/api/v1/enrollments", Some(&mcp), Some(body(Uuid::new_v4(), true))).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "unknown zone");
    assert!(policy.created.lock().unwrap().is_empty());
    let res = call(&app, "POST", "/api/v1/enrollments", Some(&mcp), Some(body(DELEGATED, true))).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
    // /me of the MCP agent lists its writable zones: delegated, minus its own.
    let me = call(&app, "GET", "/api/v1/me", Some(&mcp), None).await;
    assert_eq!(me.json()["writable_zones"], json!([DELEGATED]));
    assert_eq!(me.json()["agent_id"], MCP_AGENT.to_string());
}
