//! afw-mcp against the fake API.

use afw_client::AfwClient;
use afw_client::fake::{FakeApi, Reply};
use afw_core::api::{Approval, ApprovalStatus, Session, SessionState};
use afw_core::events::{Actor, ActorKind, Interface};
use afw_core::policy::{Zone, ZoneMode};
use afw_mcp::AfwMcp;
use chrono::Utc;
use rmcp::model::{CallToolResult, RawContent};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

fn server(fake: &FakeApi) -> AfwMcp {
    AfwMcp::new(AfwClient::new(&fake.url(), "mcp-token", Interface::Mcp).unwrap())
}

fn text(r: &CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| match &c.raw {
            RawContent::Text(t) => Some(t.text.clone()),
            _ => None,
        })
        .collect()
}

fn args(v: Value) -> Option<Map<String, Value>> {
    v.as_object().cloned()
}

fn actor() -> Actor {
    Actor {
        kind: ActorKind::Agent,
        id: "ops-bot".into(),
        name: "ops-bot".into(),
    }
}

fn session(id: Uuid) -> Session {
    Session {
        id,
        owner: actor(),
        interface: Interface::Mcp,
        state: SessionState::Open,
        opened_at: Utc::now(),
        closed_at: None,
        locks: vec![],
        changes: 1,
        approval_id: None,
        name: None,
        pending_install: None,
        base_revision: None,
        next_revision: None,
    }
}

#[test]
fn tool_list_covers_the_cli_operations() {
    let tools = AfwMcp::tool_list();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    for expected in [
        "whoami", "list_resources", "get_resource", "create_resource", "update_resource",
        "delete_resource", "where_used", "move_rule", "get_rulebase", "open_session",
        "current_session", "discard_session", "publish_session", "allow_from_log",
        "verify_policy", "list_revisions", "diff_revision", "install_revision", "list_installs",
        "list_gateways", "policy_status", "search_flows", "get_flow", "search_dns",
        "agent_overview", "internal_map", "list_alerts", "ack_alert", "list_audit",
        "verify_audit", "list_approvals",
    ] {
        assert!(names.contains(&expected), "missing tool {expected}");
    }
    // No tool to decide approvals nor to manage tokens: those stay human.
    assert!(!names.iter().any(|n| n.contains("decide") || n.contains("token")));
    for t in &tools {
        assert_eq!(t.input_schema.get("type"), Some(&json!("object")), "{}", t.name);
        let write = t.annotations.as_ref().and_then(|a| a.read_only_hint) == Some(false);
        let desc = t.description.as_deref().unwrap_or_default();
        if write && t.name != "open_session" && t.name != "discard_session" && t.name != "ack_alert" {
            assert!(desc.contains("NEVER modify your own zone"), "{}: {desc}", t.name);
        }
    }
}

#[tokio::test]
async fn tool_call_reaches_the_api_with_mcp_interface() {
    let fake = FakeApi::start().await;
    let z = Zone {
        id: Uuid::new_v4(),
        name: "clients".into(),
        comment: String::new(),
        mode: ZoneMode::Enforce,
        delegated_to_mcp: true,
    };
    fake.on(
        "GET",
        "/sessions/current",
        Reply::problem(404, "Not Found", "none"),
    );
    fake.on_json("GET", "/zones", 200, &vec![z.clone()]);
    let s = server(&fake);
    let r = s.call("list_resources", args(json!({"kind": "zones"}))).await;
    assert_eq!(r.is_error, Some(false), "{}", text(&r));
    assert!(text(&r).contains("clients"));
    let req = &fake.requests_to("GET", "/zones")[0];
    assert_eq!(req.header("x-afw-interface"), Some("mcp"));
    assert_eq!(req.header("authorization"), Some("Bearer mcp-token"));
}

#[tokio::test]
async fn forbidden_is_a_readable_tool_error() {
    let fake = FakeApi::start().await;
    let sid = Uuid::new_v4();
    let own = Uuid::new_v4();
    fake.on_json("GET", "/sessions/current", 200, &session(sid));
    fake.on(
        "GET",
        &format!("/zones/{own}"),
        Reply::json(200, &json!({"id": own, "name": "ops", "comment": "", "mode": "enforce", "delegated_to_mcp": true})),
    );
    fake.on(
        "PUT",
        &format!("/zones/{own}"),
        Reply::problem(403, "Forbidden", "the MCP agent cannot modify its own zone"),
    );
    let s = server(&fake);
    let r = s
        .call(
            "update_resource",
            args(json!({"kind": "zones", "id": own.to_string(), "fields": {"mode": "observe"}})),
        )
        .await;
    assert_eq!(r.is_error, Some(true));
    let t = text(&r);
    assert!(t.contains("403") && t.contains("cannot modify its own zone"), "{t}");
    assert!(t.contains("Do not retry"), "{t}");
    let put = &fake.requests_to("PUT", &format!("/zones/{own}"))[0];
    assert_eq!(put.header("x-afw-session"), Some(sid.to_string().as_str()));
    assert_eq!(put.json()["mode"], "observe");
}

#[tokio::test]
async fn publish_202_reports_pending_human_approval() {
    let fake = FakeApi::start().await;
    let sid = Uuid::new_v4();
    fake.on_json("GET", "/sessions/current", 200, &session(sid));
    let approval = Approval {
        id: Uuid::new_v4(),
        session_id: sid,
        requested_by: actor(),
        requested_at: Utc::now(),
        summary: "rule to *.com".into(),
        reason: "wildcard on the Internet".into(),
        status: ApprovalStatus::Pending,
        decided_by: None,
        decided_at: None,
        comment: None,
    };
    fake.on(
        "POST",
        &format!("/sessions/{sid}/publish"),
        Reply::json(202, &approval),
    );
    let s = server(&fake);
    let r = s
        .call("publish_session", args(json!({"comment": "open *.com"})))
        .await;
    assert_eq!(r.is_error, Some(false));
    let t = text(&r);
    assert!(t.contains("PENDING HUMAN APPROVAL") && t.contains(&approval.id.to_string()), "{t}");
}

#[tokio::test]
async fn invalid_arguments_are_reported_without_calling_the_api() {
    let fake = FakeApi::start().await;
    let s = server(&fake);
    let r = s.call("get_flow", args(json!({"flow_id": "nope"}))).await;
    assert_eq!(r.is_error, Some(true));
    assert!(text(&r).contains("UUID"));
    let r = s.call("list_resources", args(json!({"kind": "secrets"}))).await;
    assert_eq!(r.is_error, Some(true));
    assert!(fake.requests().is_empty());
}

/// Full JSON-RPC exchange over an in-memory transport (what stdio carries).
#[tokio::test]
async fn json_rpc_session_over_a_byte_stream() {
    use rmcp::ServiceExt;
    let fake = FakeApi::start().await;
    fake.on_json("GET", "/gateways", 200, &json!([]));
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let srv = server(&fake);
    tokio::spawn(async move {
        if let Ok(running) = srv.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let (rd, mut wr) = tokio::io::split(client_io);
    let mut lines = BufReader::new(rd).lines();
    let mut send = async |v: Value| {
        wr.write_all(format!("{v}\n").as_bytes()).await.unwrap();
    };
    send(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"}}}))
    .await;
    let init: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(init["result"]["serverInfo"]["name"], "afw-mcp");
    assert!(init["result"]["instructions"].as_str().unwrap().contains("own zone"));
    send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await;
    send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).await;
    let list: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert!(list["result"]["tools"].as_array().unwrap().len() >= 30);
    send(json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "list_gateways", "arguments": {}}}))
    .await;
    let call: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(call["result"]["isError"], false, "{call}");
    assert_eq!(fake.requests_to("GET", "/gateways").len(), 1);
}

#[tokio::test]
async fn http_transport_requires_the_listen_token() {
    let fake = FakeApi::start().await;
    let app = afw_mcp::http_router(server(&fake), "listen-secret-0123456789".into());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"}}});
    let http = reqwest::Client::new();
    let url = format!("http://{addr}/mcp");
    let post = |token: Option<&str>| {
        let mut rb = http
            .post(&url)
            .header("accept", "application/json, text/event-stream")
            .json(&body);
        if let Some(t) = token {
            rb = rb.bearer_auth(t);
        }
        rb.send()
    };
    assert_eq!(post(None).await.unwrap().status(), 401);
    assert_eq!(post(Some("wrong")).await.unwrap().status(), 401);
    let ok = post(Some("listen-secret-0123456789")).await.unwrap();
    assert_eq!(ok.status(), 200);
    assert!(ok.text().await.unwrap().contains("afw-mcp"));
}
