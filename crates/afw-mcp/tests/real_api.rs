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
