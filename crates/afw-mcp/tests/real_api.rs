//! afw-mcp against the REAL afw-api (PostgreSQL from `AFW_TEST_DATABASE_URL`; skipped without
//! it): changes made through MCP are audited with interface `mcp`, and the approved agent gets a
//! readable 403 on its own zone.

#[path = "common/real_api.rs"]
mod real_api;

use afw_client::{AfwClient, PolicyKind, PublishOutcome};
use afw_core::api::{CreateApiToken, Role};
use afw_core::events::Interface;
use afw_mcp::AfwMcp;
use rmcp::model::{CallToolResult, RawContent};
use serde_json::{Value, json};
use uuid::Uuid;

fn text(r: &CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| match &c.raw {
            RawContent::Text(t) => Some(t.text.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn mcp_changes_are_audited_and_own_zone_is_refused() {
    let Some(api) = real_api::start().await else {
        eprintln!("AFW_TEST_DATABASE_URL not set: skipped");
        return;
    };
    // Admin: zones `ops` (the agent's own, delegated) and `clients` (delegated), agent ops-bot.
    let admin = AfwClient::new(&api.url, api.admin_token.clone(), Interface::Cli).unwrap();
    admin.open_session(None).await.unwrap();
    let ops = Uuid::new_v4();
    let clients = Uuid::new_v4();
    for (id, name) in [(ops, "ops"), (clients, "clients")] {
        admin
            .create_raw(
                PolicyKind::Zones,
                &json!({"id": id, "name": name, "comment": "", "mode": "enforce", "delegated_to_mcp": true}),
            )
            .await
            .unwrap();
    }
    let agent = Uuid::new_v4();
    admin
        .create_raw(
            PolicyKind::Agents,
            &json!({"id": agent, "name": "ops-bot", "zone_id": ops, "kind": "container",
                    "addresses": ["10.77.0.20"], "labels": {}, "hermes": false, "mcp_admin": true}),
        )
        .await
        .unwrap();
    let sid = admin.session().unwrap();
    match admin.publish_session(sid, "setup").await.unwrap() {
        PublishOutcome::Published { .. } => {}
        other => panic!("{other:?}"),
    }
    let token = admin
        .create_token(&CreateApiToken {
            name: "ops-bot".into(),
            role: Role::McpAgent,
            agent_id: Some(agent),
            expires_at: None,
        })
        .await
        .unwrap();

    let mcp = AfwMcp::new(AfwClient::new(&api.url, token.secret, Interface::Mcp).unwrap());
    let me = mcp.call("whoami", json!({}).as_object().cloned()).await;
    assert_eq!(me.is_error, Some(false), "{}", text(&me));
    assert!(text(&me).contains("mcp_agent"));

    // Allowed: an object for the delegated zone `clients`.
    let r = mcp
        .call(
            "create_resource",
            json!({"kind": "objects", "resource": {"name": "pypi", "spec": {"type": "domain", "pattern": "pypi.org"}}})
                .as_object()
                .cloned(),
        )
        .await;
    assert_eq!(r.is_error, Some(false), "{}", text(&r));

    // Refused by the API: its own zone.
    let r = mcp
        .call(
            "update_resource",
            json!({"kind": "zones", "id": "ops", "fields": {"mode": "observe"}})
                .as_object()
                .cloned(),
        )
        .await;
    assert_eq!(r.is_error, Some(true), "{}", text(&r));
    assert!(text(&r).contains("403"), "{}", text(&r));

    // Audit: the MCP change carries interface `mcp`.
    let audit = admin
        .list_audit(&afw_client::AuditQuery {
            interface: Some(Interface::Mcp),
            limit: Some(1000),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!audit.items.is_empty(), "no audit entry with interface mcp");
    assert!(audit.items.iter().all(|e| e.interface == Interface::Mcp));
    let all: Value = serde_json::to_value(&audit.items).unwrap();
    assert!(
        all.to_string().contains("pypi") || all.to_string().contains("object"),
        "{all}"
    );
}

/// Sets up a delegated zone `clients` and the agent `ops-bot` (zone `ops`), returns an MCP
/// server acting with ops-bot's `mcp_agent` token, and the admin client.
async fn mcp_agent(api: &real_api::RealApi) -> (AfwMcp, AfwClient) {
    let admin = AfwClient::new(&api.url, api.admin_token.clone(), Interface::Cli).unwrap();
    admin.open_session(None).await.unwrap();
    let ops = Uuid::new_v4();
    for (id, name) in [(ops, "ops"), (Uuid::new_v4(), "clients")] {
        admin
            .create_raw(
                PolicyKind::Zones,
                &json!({"id": id, "name": name, "comment": "", "mode": "enforce", "delegated_to_mcp": true}),
            )
            .await
            .unwrap();
    }
    let agent = Uuid::new_v4();
    admin
        .create_raw(
            PolicyKind::Agents,
            &json!({"id": agent, "name": "ops-bot", "zone_id": ops, "kind": "container",
                    "addresses": ["10.77.0.20"], "labels": {}, "hermes": false, "mcp_admin": true}),
        )
        .await
        .unwrap();
    let sid = admin.session().unwrap();
    match admin.publish_session(sid, "setup").await.unwrap() {
        PublishOutcome::Published { .. } => {}
        other => panic!("{other:?}"),
    }
    let token = admin
        .create_token(&CreateApiToken {
            name: "ops-bot".into(),
            role: Role::McpAgent,
            agent_id: Some(agent),
            expires_at: None,
        })
        .await
        .unwrap();
    (
        AfwMcp::new(AfwClient::new(&api.url, token.secret, Interface::Mcp).unwrap()),
        admin,
    )
}

fn create_pypi() -> Option<serde_json::Map<String, Value>> {
    json!({"kind": "objects", "resource": {"name": "pypi", "spec": {"type": "domain", "pattern": "pypi.org"}}})
        .as_object()
        .cloned()
}

#[tokio::test]
async fn discard_session_really_abandons_the_session() {
    let Some(api) = real_api::start().await else {
        eprintln!("AFW_TEST_DATABASE_URL not set: skipped");
        return;
    };
    let (mcp, admin) = mcp_agent(&api).await;
    let r = mcp.call("create_resource", create_pypi()).await;
    assert_eq!(r.is_error, Some(false), "{}", text(&r));
    let cur = mcp.call("current_session", None).await;
    let sid: Uuid = serde_json::from_str::<Value>(&text(&cur)).unwrap()["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let r = mcp.call("discard_session", None).await;
    assert_eq!(r.is_error, Some(false), "{}", text(&r));
    // The API holds the session as discarded, its change is gone, its locks released.
    let s = admin.get_session(sid).await.unwrap();
    assert_eq!(s.state, afw_core::api::SessionState::Discarded);
    let r = mcp.call("current_session", None).await;
    assert!(text(&r).contains("No open session"), "{}", text(&r));
    // A new change goes to a NEW session, without the discarded change.
    let r = mcp.call("create_resource", create_pypi()).await;
    assert_eq!(r.is_error, Some(false), "{}", text(&r));
    let cur = mcp.call("current_session", None).await;
    let v: Value = serde_json::from_str(&text(&cur)).unwrap();
    assert_ne!(v["id"].as_str().unwrap(), sid.to_string());
    // Audited with interface mcp.
    let audit = admin
        .list_audit(&afw_client::AuditQuery {
            action: Some("session.discard".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(audit.items.len(), 1);
    assert_eq!(audit.items[0].interface, Interface::Mcp);
}

#[tokio::test]
async fn discard_session_ignores_a_session_closed_elsewhere() {
    let Some(api) = real_api::start().await else {
        eprintln!("AFW_TEST_DATABASE_URL not set: skipped");
        return;
    };
    let (mcp, admin) = mcp_agent(&api).await;
    // The agent's session S1, closed by a human administrator (abandoned session).
    let r = mcp.call("open_session", None).await;
    assert_eq!(r.is_error, Some(false), "{}", text(&r));
    let s1: Uuid = serde_json::from_str::<Value>(&text(&r)).unwrap()["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    admin.discard_session(s1).await.unwrap();
    // Nothing left to discard: a readable answer, not a stale 409 on S1.
    let r = mcp.call("discard_session", None).await;
    assert!(text(&r).contains("No open session"), "{}", text(&r));
    // A new change opens a new session instead of writing into the closed S1.
    let r = mcp.call("create_resource", create_pypi()).await;
    assert_eq!(r.is_error, Some(false), "{}", text(&r));
    let cur = mcp.call("current_session", None).await;
    let v: Value = serde_json::from_str(&text(&cur)).unwrap();
    assert_ne!(v["id"].as_str().unwrap(), s1.to_string());
    assert_eq!(v["state"], "open");
    // And discarding it works.
    let r = mcp.call("discard_session", None).await;
    assert_eq!(r.is_error, Some(false), "{}", text(&r));
    let r = mcp.call("current_session", None).await;
    assert!(text(&r).contains("No open session"), "{}", text(&r));
}
