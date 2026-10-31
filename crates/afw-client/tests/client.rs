//! afw-client against the fake API (responses built from afw-core DTOs, i.e. contract-shaped).

use afw_client::fake::{FakeApi, Reply};
use afw_client::{
    AfwClient, AllowFromLog, ClientError, ClientOptions, PolicyKind, PublishOutcome, StreamQuery,
};
use afw_core::api::{Approval, ApprovalStatus, FlowQuery, Page, Revision, Session, SessionState};
use afw_core::events::{Actor, ActorKind, Interface, Verdict};
use afw_core::policy::{Action, Layer, NetObject, NetObjectSpec, Rule, Track, Zone, ZoneMode};
use chrono::{TimeZone, Utc};
use futures::StreamExt;
use serde_json::json;
use uuid::Uuid;

fn actor() -> Actor {
    Actor {
        kind: ActorKind::Human,
        id: "u1".into(),
        name: "Alice".into(),
    }
}

fn session(id: Uuid) -> Session {
    Session {
        id,
        owner: actor(),
        interface: Interface::Cli,
        state: SessionState::Open,
        opened_at: Utc.with_ymd_and_hms(2026, 10, 30, 10, 0, 0).unwrap(),
        closed_at: None,
        locks: vec![],
        changes: 0,
        approval_id: None,
        name: None,
        pending_install: None,
        base_revision: None,
        next_revision: None,
    }
}

fn rule(zone: Uuid) -> Rule {
    Rule {
        id: Uuid::new_v4(),
        name: "github".into(),
        layer: Layer::Zone { zone_id: zone },
        section: None,
        position: 1,
        sources: vec![zone],
        destinations: vec![],
        services: vec![],
        data_classes: vec![],
        action: Action::Accept,
        track: Track::Detailed,
        expires_at: None,
        comment: String::new(),
        enabled: true,
    }
}

async fn client(fake: &FakeApi, iface: Interface) -> AfwClient {
    AfwClient::new(&fake.url(), "s3cr3t-token", iface).unwrap()
}

#[tokio::test]
async fn sends_bearer_interface_and_session_headers() {
    let fake = FakeApi::start().await;
    let zone = Zone {
        id: Uuid::new_v4(),
        name: "clients".into(),
        comment: String::new(),
        mode: ZoneMode::Enforce,
        delegated_to_mcp: true,
    };
    fake.on_json("GET", "/zones", 200, &vec![zone.clone()]);
    let c = client(&fake, Interface::Mcp).await;
    assert_eq!(c.list_zones().await.unwrap(), vec![zone.clone()]);
    let sid = Uuid::new_v4();
    c.set_session(Some(sid));
    c.list_zones().await.unwrap();

    let reqs = fake.requests_to("GET", "/zones");
    assert_eq!(reqs[0].header("authorization"), Some("Bearer s3cr3t-token"));
    assert_eq!(reqs[0].header("x-afw-interface"), Some("mcp"));
    assert_eq!(reqs[0].header("x-afw-session"), None);
    assert_eq!(
        reqs[1].header("x-afw-session"),
        Some(sid.to_string().as_str())
    );
}

#[tokio::test]
async fn base_url_accepts_console_or_api_root_and_debug_hides_token() {
    let c = AfwClient::new("https://afw.example.org/", "tok-xyz", Interface::Cli).unwrap();
    assert_eq!(c.api_url(), "https://afw.example.org/api/v1");
    let c = AfwClient::new("https://afw.example.org/api/v1", "tok-xyz", Interface::Cli).unwrap();
    assert_eq!(c.api_url(), "https://afw.example.org/api/v1");
    assert!(!format!("{c:?}").contains("tok-xyz"));
    assert!(matches!(
        AfwClient::new("afw.example.org", "t", Interface::Cli),
        Err(ClientError::Config(_))
    ));
    assert!(matches!(
        AfwClient::new("https://x", " ", Interface::Cli),
        Err(ClientError::Config(_))
    ));
}

#[tokio::test]
async fn invalid_ca_certificate_is_refused() {
    let opts = ClientOptions {
        ca_cert_pem: Some(b"not a certificate".to_vec()),
        timeout: None,
    };
    let err = AfwClient::with_options("https://x", "t", Interface::Cli, opts).unwrap_err();
    assert!(matches!(err, ClientError::Config(_)), "{err}");
}

#[tokio::test]
async fn problem_json_becomes_typed_api_error() {
    let fake = FakeApi::start().await;
    fake.on(
        "DELETE",
        &format!("/zones/{}", Uuid::nil()),
        Reply::problem(403, "Forbidden", "the MCP agent cannot modify its own zone"),
    );
    let c = client(&fake, Interface::Mcp).await;
    c.set_session(Some(Uuid::new_v4()));
    let err = c.delete_zone(Uuid::nil()).await.unwrap_err();
    match &err {
        ClientError::Api { status, problem } => {
            assert_eq!(*status, 403);
            assert_eq!(problem.title, "Forbidden");
            assert_eq!(
                problem.detail.as_deref(),
                Some("the MCP agent cannot modify its own zone")
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(err.status(), Some(403));
    assert!(err.to_string().contains("own zone"));
}

#[tokio::test]
async fn non_problem_error_body_is_still_an_api_error() {
    let fake = FakeApi::start().await;
    fake.on("GET", "/me", Reply::raw(502, "text/plain", "bad gateway"));
    let c = client(&fake, Interface::Cli).await;
    let err = c.me().await.unwrap_err();
    assert_eq!(err.status(), Some(502));
    assert_eq!(
        err.problem().unwrap().detail.as_deref(),
        Some("bad gateway")
    );
}

#[tokio::test]
async fn mutations_require_a_session() {
    let fake = FakeApi::start().await;
    let c = client(&fake, Interface::Cli).await;
    let err = c
        .create_raw(PolicyKind::Objects, &json!({"name": "x"}))
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::NoSession));
    assert!(fake.requests().is_empty());
}

#[tokio::test]
async fn ensure_session_uses_current_then_opens() {
    let fake = FakeApi::start().await;
    let sid = Uuid::new_v4();
    fake.on(
        "GET",
        "/sessions/current",
        Reply::problem(404, "Not Found", "no open session"),
    );
    fake.on_json("POST", "/sessions", 201, &session(sid));
    let c = client(&fake, Interface::Cli).await;
    assert!(matches!(
        c.ensure_session(false).await,
        Err(ClientError::NoSession)
    ));
    assert_eq!(c.ensure_session(true).await.unwrap(), sid);
    assert_eq!(c.session(), Some(sid));
    // Open session without a name: no body is sent (the contract has no request body).
    assert!(fake.requests_to("POST", "/sessions")[0].body.is_empty());
}

#[tokio::test]
async fn flow_filters_are_sent_as_query_parameters() {
    let fake = FakeApi::start().await;
    let page: Page<afw_core::events::FlowEvent> = Page {
        items: vec![],
        next_cursor: None,
    };
    fake.on_json("GET", "/logs/flows", 200, &page);
    let c = client(&fake, Interface::Cli).await;
    let agent = Uuid::new_v4();
    let q = FlowQuery {
        agent: Some(agent),
        verdict: Some(Verdict::Deny),
        destination: Some("*.github.com".into()),
        from: Some(Utc.with_ymd_and_hms(2026, 10, 30, 8, 0, 0).unwrap()),
        q: Some("token leak".into()),
        limit: Some(50),
        ..Default::default()
    };
    c.list_flows(&q).await.unwrap();
    let r = &fake.requests_to("GET", "/logs/flows")[0];
    assert_eq!(r.query_param("agent"), Some(agent.to_string().as_str()));
    assert_eq!(r.query_param("verdict"), Some("deny"));
    assert_eq!(r.query_param("destination"), Some("*.github.com"));
    assert_eq!(r.query_param("from"), Some("2026-10-30T08:00:00Z"));
    assert_eq!(r.query_param("q"), Some("token leak"));
    assert_eq!(r.query_param("limit"), Some("50"));
    assert_eq!(r.query_param("zone"), None);
}

#[tokio::test]
async fn publish_distinguishes_revision_and_pending_approval() {
    let fake = FakeApi::start().await;
    let sid = Uuid::new_v4();
    let rev = Revision {
        number: 7,
        published_at: Utc::now(),
        published_by: actor(),
        interface: Interface::Cli,
        session_id: Some(sid),
        comment: "open github".into(),
        sha256: "ab".repeat(32),
    };
    let approval = Approval {
        id: Uuid::new_v4(),
        session_id: sid,
        requested_by: actor(),
        requested_at: Utc::now(),
        summary: "*.com".into(),
        reason: "wide wildcard on the Internet".into(),
        status: ApprovalStatus::Pending,
        decided_by: None,
        decided_at: None,
        comment: None,
    };
    let path = format!("/sessions/{sid}/publish");
    fake.on("POST", &path, Reply::json(202, &approval));
    fake.on("POST", &path, Reply::json(201, &rev));
    let c = client(&fake, Interface::Mcp).await;
    c.set_session(Some(sid));
    match c.publish_session(sid, "open github").await.unwrap() {
        PublishOutcome::PendingApproval { approval: a } => assert_eq!(a, approval),
        other => panic!("{other:?}"),
    }
    assert_eq!(c.session(), Some(sid), "pending: session stays active");
    match c.publish_session(sid, "open github").await.unwrap() {
        PublishOutcome::Published { revision } => assert_eq!(revision.number, 7),
        other => panic!("{other:?}"),
    }
    assert_eq!(c.session(), None, "published: session closed");
    assert_eq!(
        fake.requests_to("POST", &path)[0].json(),
        json!({"comment": "open github"})
    );
}

#[tokio::test]
async fn rules_decode_plain_rules_and_rule_views() {
    let fake = FakeApi::start().await;
    let zone = Uuid::new_v4();
    let plain = rule(zone);
    let mut view = serde_json::to_value(rule(zone)).unwrap();
    view["number"] = json!(4);
    view["hits"] = json!(12);
    view["locked_by"] = json!(null);
    view["pending_change"] = json!("update");
    fake.on_json(
        "GET",
        "/rules",
        200,
        &vec![serde_json::to_value(&plain).unwrap(), view.clone()],
    );
    let c = client(&fake, Interface::Cli).await;
    let rules = c.list_rules().await.unwrap();
    assert_eq!(rules[0].rule, plain);
    assert_eq!(rules[0].number, None);
    assert_eq!(rules[1].number, Some(4));
    assert_eq!(rules[1].hits, Some(12));
    assert_eq!(serde_json::to_value(&rules[1]).unwrap(), view);
}

#[tokio::test]
async fn allow_from_log_posts_flow_and_decodes_rule() {
    let fake = FakeApi::start().await;
    let sid = Uuid::new_v4();
    let zone = Uuid::new_v4();
    let obj = NetObject {
        id: Uuid::new_v4(),
        name: "api.github.com".into(),
        comment: String::new(),
        category: None,
        spec: NetObjectSpec::Domain {
            pattern: "api.github.com".into(),
        },
    };
    let r = rule(zone);
    let resp = afw_core::api::AllowFromLogResponse {
        rule: afw_core::api::RuleView {
            rule: r.clone(),
            number: 3,
            hits: 0,
            last_hit_at: None,
            expired: false,
            locked_by: None,
            pending_change: Some(afw_core::api::ChangeOp::Create),
        },
        created_object: Some(obj.clone()),
        changes: vec![],
    };
    fake.on_json(
        "POST",
        &format!("/sessions/{sid}/allow-from-log"),
        201,
        &resp,
    );
    let c = client(&fake, Interface::Cli).await;
    let flow = Uuid::new_v4();
    let out = c
        .allow_from_log(
            sid,
            &AllowFromLog {
                flow_id: flow,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(out.rule.rule, r);
    assert_eq!(out.rule.number, Some(3));
    assert_eq!(out.created_object, Some(obj));
    assert_eq!(
        fake.requests()[0].json(),
        json!({ "flow_id": flow.to_string() })
    );
}

#[tokio::test]
async fn resolve_by_name_or_id() {
    let fake = FakeApi::start().await;
    let a = Uuid::new_v4();
    fake.on_json(
        "GET",
        "/zones",
        200,
        &json!([
            {"id": a, "name": "clients", "comment": "", "mode": "enforce", "delegated_to_mcp": false},
            {"id": Uuid::new_v4(), "name": "dup", "comment": "", "mode": "enforce", "delegated_to_mcp": false},
            {"id": Uuid::new_v4(), "name": "dup", "comment": "", "mode": "observe", "delegated_to_mcp": false}
        ]),
    );
    let c = client(&fake, Interface::Cli).await;
    assert_eq!(c.resolve(PolicyKind::Zones, "clients").await.unwrap(), a);
    assert_eq!(
        c.resolve(PolicyKind::Zones, &a.to_string()).await.unwrap(),
        a
    );
    assert!(matches!(
        c.resolve(PolicyKind::Zones, "nope").await,
        Err(ClientError::NotFound { .. })
    ));
    assert!(matches!(
        c.resolve(PolicyKind::Zones, "dup").await,
        Err(ClientError::Ambiguous { count: 2, .. })
    ));
}

#[tokio::test]
async fn live_stream_yields_gateway_events() {
    let fake = FakeApi::start().await;
    let alert = afw_core::events::GatewayEvent::Alert(afw_core::events::AlertEvent {
        id: Uuid::new_v4(),
        at: Utc::now(),
        kind: afw_core::events::AlertKind::DenyBurst,
        severity: afw_core::events::Severity::Warning,
        agent_id: None,
        summary: "burst".into(),
        details: json!({}),
    });
    let body = format!(
        ": hello\n\nevent: alert\ndata: {}\n\nevent: alert\ndata: not-json\n\n",
        serde_json::to_string(&alert).unwrap()
    );
    fake.on(
        "GET",
        "/logs/stream",
        Reply::raw(200, "text/event-stream", body),
    );
    let c = client(&fake, Interface::Cli).await;
    let q = StreamQuery {
        verdict: Some(Verdict::Deny),
        ..Default::default()
    };
    let items: Vec<_> = c.stream_logs(&q).await.unwrap().collect().await;
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].as_ref().unwrap(), &alert);
    assert!(matches!(items[1], Err(ClientError::Decode { .. })));
    let r = &fake.requests_to("GET", "/logs/stream")[0];
    assert_eq!(r.query_param("verdict"), Some("deny"));
    assert_eq!(r.header("accept"), Some("text/event-stream"));
}

#[tokio::test]
async fn binary_and_ndjson_downloads() {
    let fake = FakeApi::start().await;
    let id = Uuid::new_v4();
    fake.on(
        "GET",
        &format!("/captures/{id}/download"),
        Reply::raw(
            200,
            "application/vnd.tcpdump.pcap",
            vec![0xd4, 0xc3, 0xb2, 0xa1],
        ),
    );
    fake.on(
        "GET",
        "/audit/export",
        Reply::raw(200, "application/x-ndjson", "{}\n{}\n"),
    );
    let c = client(&fake, Interface::Cli).await;
    assert_eq!(
        c.download_capture(id).await.unwrap().as_ref(),
        &[0xd4, 0xc3, 0xb2, 0xa1]
    );
    assert_eq!(
        c.export_audit(Some(10)).await.unwrap().as_ref(),
        b"{}\n{}\n"
    );
    assert_eq!(
        fake.requests_to("GET", "/audit/export")[0].query_param("from_seq"),
        Some("10")
    );
}
