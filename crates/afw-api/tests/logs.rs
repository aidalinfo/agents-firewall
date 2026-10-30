//! Logs module (lot L7b) against a real PostgreSQL, skipped when `AFW_TEST_DATABASE_URL` is not
//! set. Each test runs in its own database.

use std::sync::Arc;

use afw_api::gateways::ports::LogsPort;
use afw_api::logs::{self, captures, retention, views};
use afw_api::{AppState, Config, migrate, router};
use afw_core::api::{
    AgentOverview, Alert, AlertChannel, AlertChannelKind, Capture, Confidence, FlowDetail,
    FlowListItem, FlowStats, InternalMap, Page,
};
use afw_core::events::*;
use afw_core::policy::{
    Agent, AgentKind, AppProto, L4Proto, PolicyDocument, Retention, Zone, ZoneMode,
};
use afw_core::protocol::{EventBatch, GatewayCommand};
use axum::body::Body as AxBody;
use axum::http::{Request, StatusCode};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const AGENT: Uuid = Uuid::from_u128(0xa1);
const AGENT2: Uuid = Uuid::from_u128(0xa2);
const ZONE: Uuid = Uuid::from_u128(0x21);
const ZONE2: Uuid = Uuid::from_u128(0x22);
const GW: Uuid = Uuid::from_u128(0x61);
const RULE: Uuid = Uuid::from_u128(0x71);
const SECRET_BODY: &str = "very-secret-request-body-4242";

struct Env {
    state: AppState,
    pool: PgPool,
    tokens: std::collections::HashMap<&'static str, String>,
}

fn policy() -> PolicyDocument {
    let zone = |id, name: &str| Zone {
        id,
        name: name.into(),
        comment: String::new(),
        mode: ZoneMode::Enforce,
        delegated_to_mcp: false,
    };
    let agent = |id, name: &str, zone_id, ip: &str| Agent {
        id,
        name: name.into(),
        zone_id,
        kind: AgentKind::Container,
        gateway_id: Some(GW),
        addresses: vec![ip.parse().unwrap()],
        labels: Default::default(),
        hermes: true,
        mcp_admin: false,
    };
    PolicyDocument {
        zones: vec![zone(ZONE, "bots"), zone(ZONE2, "infra")],
        agents: vec![
            agent(AGENT, "daniel-bot", ZONE, "10.0.0.5"),
            agent(AGENT2, "ops-bot", ZONE2, "10.0.0.6"),
        ],
        ..Default::default()
    }
}

async fn env_with(webhook_secret: Option<&str>) -> Option<Env> {
    let url = std::env::var("AFW_TEST_DATABASE_URL").ok()?;
    let admin = PgPool::connect(&url).await.expect("connect");
    let db = format!("logs_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {db}"))
        .execute(&admin)
        .await
        .unwrap();
    let base = url.rsplit_once('/').unwrap().0;
    let pool = PgPool::connect(&format!("{base}/{db}")).await.unwrap();
    migrate(&pool).await.unwrap();
    let config = Config {
        data_key: Some(base64::engine::general_purpose::STANDARD.encode([9u8; 32])),
        alert_webhook_secret: webhook_secret.map(str::to_owned),
        alert_allowed_hosts: Some("127.0.0.1".to_owned()),
        ..Config::default()
    };
    let mut state = AppState::new(config, Some(pool.clone()));
    let doc = policy();
    state.logs.policy = Arc::new(move |_| {
        let doc = doc.clone();
        Box::pin(async move { Ok(Some(doc)) })
    });
    let mut tokens = std::collections::HashMap::new();
    for (role, agent) in [
        ("admin", None),
        ("auditor", None),
        ("viewer", None),
        ("mcp_agent", Some(AGENT2)),
        ("agent_plugin", Some(AGENT)),
    ] {
        let secret = format!("{role}-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO api_tokens (name, token_sha256, role, actor_kind, actor_name, agent_id, \
             created_by) VALUES ($1, $2, $3, 'human', $1, $4, '{}')",
        )
        .bind(role)
        .bind(afw_core::sha256_hex(secret.as_bytes()))
        .bind(role)
        .bind(agent)
        .execute(&pool)
        .await
        .unwrap();
        tokens.insert(role, secret);
    }
    Some(Env {
        state,
        pool,
        tokens,
    })
}

async fn env() -> Option<Env> {
    env_with(None).await
}

macro_rules! env_or_skip {
    ($e:expr) => {
        match $e.await {
            Some(e) => e,
            None => {
                eprintln!("AFW_TEST_DATABASE_URL not set: skipped");
                return;
            }
        }
    };
}

impl Env {
    async fn call(
        &self,
        role: &str,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Vec<u8>) {
        let mut req = Request::builder()
            .method(method)
            .uri(format!("/api/v1{uri}"))
            .header("authorization", format!("Bearer {}", self.tokens[role]));
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                AxBody::from(b.to_string())
            }
            None => AxBody::empty(),
        };
        let res = router(self.state.clone())
            .oneshot(req.body(body).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, bytes)
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, role: &str, uri: &str) -> T {
        let (s, b) = self.call(role, "GET", uri, None).await;
        assert_eq!(s, StatusCode::OK, "{uri}: {}", String::from_utf8_lossy(&b));
        serde_json::from_slice(&b).unwrap()
    }

    async fn audit_actions(&self) -> Vec<String> {
        sqlx::query_scalar("SELECT action FROM audit_log ORDER BY seq")
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }
}

fn t(secs_ago: i64) -> DateTime<Utc> {
    let now = Utc::now() - Duration::seconds(secs_ago);
    DateTime::from_timestamp_micros(now.timestamp_micros()).unwrap()
}

fn flow(
    n: u128,
    agent: Uuid,
    zone: Uuid,
    domain: Option<&str>,
    dst: &str,
    verdict: Verdict,
    at: DateTime<Utc>,
) -> FlowEvent {
    FlowEvent {
        id: Uuid::from_u128(n),
        gateway_id: Uuid::nil(),
        agent_id: Some(agent),
        zone_id: Some(zone),
        src: "10.0.0.5:40000".parse().unwrap(),
        dst: dst.parse().unwrap(),
        protocol: L4Proto::Tcp,
        app: Some(AppProto::Https),
        domain: domain.map(str::to_owned),
        sni: domain.map(str::to_owned),
        bytes_out: 100,
        bytes_in: 200,
        started_at: at,
        ended_at: Some(at + Duration::seconds(1)),
        verdict,
        decision: DecisionRef {
            rule_id: Some(RULE),
            rule_number: Some(12),
            rule_name: "web".into(),
            revision: Some(1),
            layer: "zone".into(),
            reason: "matched".into(),
        },
        internal: false,
        llm_provider: false,
        tls_inspected: true,
        data_classes: vec![],
        observed: false,
    }
}

fn http(n: u128, flow_id: u128, at: DateTime<Utc>) -> HttpEvent {
    HttpEvent {
        id: Uuid::from_u128(n),
        flow_id: Uuid::from_u128(flow_id),
        gateway_id: Uuid::nil(),
        agent_id: Some(AGENT),
        at,
        method: "POST".into(),
        url: "https://api.exemple.com/v1/upload".into(),
        host: "api.exemple.com".into(),
        request_headers: vec![("authorization".into(), "[SECRET:bearer:abc]".into())],
        request_body: Some(Body {
            encoding: BodyEncoding::Utf8,
            data: SECRET_BODY.into(),
            size: SECRET_BODY.len() as u64,
            truncated: false,
            sha256: "00".into(),
        }),
        status: Some(403),
        response_headers: vec![],
        response_body: None,
        findings: vec![],
        admin_action: None,
        websocket: false,
    }
}

fn call(n: u128, start: DateTime<Utc>, end: Option<DateTime<Utc>>, status: Option<&str>) -> Value {
    json!({
        "id": Uuid::from_u128(n), "agent": "daniel-bot", "conversation_id": format!("conv-{n}"),
        "tool": "terminal", "args_summary": "curl api", "started_at": start,
        "ended_at": end, "status": status,
    })
}

async fn ingest(e: &Env, events: Vec<GatewayEvent>) -> logs::IngestReport {
    logs::ingest_gateway_events(&e.state, GW, events)
        .await
        .unwrap()
}

#[tokio::test]
async fn ingested_flows_are_searchable_filtered_paginated_and_enriched() {
    let e = env_or_skip!(env());
    let mut events = vec![
        GatewayEvent::Flow(flow(
            1,
            AGENT,
            ZONE,
            Some("api.exemple.com"),
            "93.184.216.34:443",
            Verdict::Deny,
            t(50),
        )),
        GatewayEvent::Flow(flow(
            2,
            AGENT,
            ZONE,
            Some("www.autre.org"),
            "198.51.100.7:443",
            Verdict::Allow,
            t(40),
        )),
        GatewayEvent::Flow(flow(
            3,
            AGENT2,
            ZONE2,
            None,
            "10.1.2.3:5432",
            Verdict::Allow,
            t(30),
        )),
        GatewayEvent::Http(http(100, 1, t(50))),
    ];
    let r = ingest(&e, events.clone()).await;
    assert_eq!((r.flows, r.http), (3, 1));
    // The gateway id is the authenticated one.
    let stored: Uuid = sqlx::query_scalar("SELECT gateway_id FROM flows WHERE id = $1")
        .bind(Uuid::from_u128(1))
        .fetch_one(&e.pool)
        .await
        .unwrap();
    assert_eq!(stored, GW);
    // Idempotent per event id, and per batch id.
    assert_eq!(ingest(&e, events.clone()).await.flows, 0);
    let batch = EventBatch {
        batch_id: Uuid::new_v4(),
        events: events.split_off(3),
    };
    assert!(
        !logs::ingest_gateway_batch(&e.state, GW, batch.clone())
            .await
            .unwrap()
            .duplicate
    );
    assert!(
        logs::ingest_gateway_batch(&e.state, GW, batch)
            .await
            .unwrap()
            .duplicate
    );

    let ids = |p: Page<FlowListItem>| {
        p.items
            .iter()
            .map(|i| i.flow.id.as_u128())
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(e.get("viewer", "/logs/flows").await), vec![3, 2, 1]);
    assert_eq!(
        ids(e.get("viewer", &format!("/logs/flows?agent={AGENT}")).await),
        vec![2, 1]
    );
    assert_eq!(
        ids(e.get("viewer", &format!("/logs/flows?zone={ZONE2}")).await),
        vec![3]
    );
    assert_eq!(
        ids(e.get("viewer", "/logs/flows?verdict=deny").await),
        vec![1]
    );
    assert_eq!(
        ids(e.get("viewer", &format!("/logs/flows?rule={RULE}")).await).len(),
        3
    );
    assert_eq!(
        ids(e.get("viewer", "/logs/flows?destination=exemple.com").await),
        vec![1]
    );
    assert_eq!(
        ids(e.get("viewer", "/logs/flows?destination=10.0.0.0/8").await),
        vec![3]
    );
    assert_eq!(
        ids(e
            .get("viewer", "/logs/flows?destination=198.51.100.7")
            .await),
        vec![2]
    );
    assert_eq!(ids(e.get("viewer", "/logs/flows?q=AUTRE").await), vec![2]);
    assert_eq!(
        ids(e.get("viewer", "/logs/flows?q=v1%2Fupload").await),
        vec![1],
        "q searches URLs"
    );
    assert_eq!(
        ids(e.get("viewer", "/logs/flows?q=100%25").await),
        Vec::<u128>::new(),
        "wildcards escaped"
    );
    let from = (t(45)).to_rfc3339().replace('+', "%2B");
    assert_eq!(
        ids(e.get("viewer", &format!("/logs/flows?from={from}")).await),
        vec![3, 2]
    );

    // Cursor pagination covers everything once.
    let p1: Page<FlowListItem> = e.get("viewer", "/logs/flows?limit=2").await;
    assert_eq!(ids(p1.clone()), vec![3, 2]);
    let c = p1.next_cursor.expect("next page");
    let p2: Page<FlowListItem> = e
        .get("viewer", &format!("/logs/flows?limit=2&cursor={c}"))
        .await;
    assert_eq!(ids(p2.clone()), vec![1]);
    assert!(p2.next_cursor.is_none());

    // Display fields computed by the API.
    let p: Page<FlowListItem> = e.get("viewer", "/logs/flows?verdict=deny").await;
    assert_eq!(p.items[0].agent_name.as_deref(), Some("daniel-bot"));
    assert_eq!(p.items[0].zone_name.as_deref(), Some("bots"));
    assert_eq!(p.items[0].rule_label, "12 · web");

    for bad in [
        "/logs/flows?limit=0",
        "/logs/flows?cursor=zz",
        "/logs/flows?verdict=maybe",
        "/logs/flows?nope=1",
    ] {
        let (s, b) = e.call("viewer", "GET", bad, None).await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "{bad}: {}",
            String::from_utf8_lossy(&b)
        );
    }
    // Plugin tokens cannot read logs.
    assert_eq!(
        e.call("agent_plugin", "GET", "/logs/flows", None).await.0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn dns_queries_are_searchable() {
    let e = env_or_skip!(env());
    let dns = |n: u128, q: &str, ans: &str, v| {
        GatewayEvent::Dns(DnsEvent {
            id: Uuid::from_u128(n),
            gateway_id: GW,
            agent_id: Some(AGENT),
            zone_id: Some(ZONE),
            at: t(10 - n as i64),
            qname: q.into(),
            qtype: "A".into(),
            answers: vec![ans.into()],
            verdict: v,
            decision: flow(0, AGENT, ZONE, None, "1.1.1.1:53", v, t(0)).decision,
        })
    };
    ingest(
        &e,
        vec![
            dns(1, "api.exemple.com.", "93.184.216.34", Verdict::Allow),
            dns(2, "evil.test", "203.0.113.9", Verdict::Deny),
        ],
    )
    .await;
    let ids = |p: Page<DnsEvent>| p.items.iter().map(|i| i.id.as_u128()).collect::<Vec<_>>();
    assert_eq!(ids(e.get("viewer", "/logs/dns").await), vec![2, 1]);
    assert_eq!(
        ids(e.get("viewer", "/logs/dns?destination=exemple.com").await),
        vec![1]
    );
    assert_eq!(
        ids(e
            .get("viewer", "/logs/dns?destination=203.0.113.0/24")
            .await),
        vec![2]
    );
    assert_eq!(
        ids(e.get("viewer", "/logs/dns?verdict=deny&q=evil").await),
        vec![2]
    );
    let p: Page<DnsEvent> = e.get("viewer", "/logs/dns?limit=1").await;
    assert!(p.next_cursor.is_some());
}

#[tokio::test]
async fn contents_are_encrypted_hidden_from_viewers_and_audited_for_auditors() {
    let e = env_or_skip!(env());
    ingest(
        &e,
        vec![
            GatewayEvent::Flow(flow(
                1,
                AGENT,
                ZONE,
                Some("api.exemple.com"),
                "93.184.216.34:443",
                Verdict::Deny,
                t(5),
            )),
            GatewayEvent::Http(http(100, 1, t(5))),
        ],
    )
    .await;
    // The database never holds the body in clear.
    let dump: String = sqlx::query_scalar(
        "SELECT event::text || encode(COALESCE(content, ''::bytea), 'escape') FROM http_events",
    )
    .fetch_one(&e.pool)
    .await
    .unwrap();
    assert!(!dump.contains(SECRET_BODY));
    assert!(!dump.contains("[SECRET:bearer:abc]"));

    for role in ["viewer", "mcp_agent"] {
        let d: FlowDetail = e
            .get(role, &format!("/logs/flows/{}", Uuid::from_u128(1)))
            .await;
        assert_eq!(d.http.len(), 1);
        assert!(
            d.http[0].request_body.is_none(),
            "{role} must not see bodies"
        );
        assert!(d.http[0].request_headers.is_empty());
        assert_eq!(d.http[0].url, "https://api.exemple.com/v1/upload");
    }
    assert!(
        !e.audit_actions()
            .await
            .contains(&"flow.content_access".to_owned())
    );

    let d: FlowDetail = e
        .get("auditor", &format!("/logs/flows/{}", Uuid::from_u128(1)))
        .await;
    assert_eq!(d.http[0].request_body.as_ref().unwrap().data, SECRET_BODY);
    assert_eq!(d.http[0].request_headers[0].1, "[SECRET:bearer:abc]");
    let (target,): (String,) =
        sqlx::query_as("SELECT target FROM audit_log WHERE action = 'flow.content_access'")
            .fetch_one(&e.pool)
            .await
            .unwrap();
    assert_eq!(target, format!("flow:{}", Uuid::from_u128(1)));
    // Views of the detail.
    assert_eq!(
        d.agent_message.as_deref(),
        Some("blocked by agents-firewall: api.exemple.com not allowed for daniel-bot (rule 12)")
    );
    let prop = d.allow_proposal.expect("proposal for a denied flow");
    assert_eq!(prop.zone_id, ZONE);
    assert_eq!(prop.destinations[0].label, "api.exemple.com");
    // Trace recomputed by the engine on the flow's revision: no rule, default deny.
    let last = d.trace.last().expect("trace");
    assert_eq!(last.rule_label, "default-deny");
    assert_eq!(last.layer, "implicit");

    let (s, _) = e
        .call(
            "viewer",
            "GET",
            &format!("/logs/flows/{}", Uuid::new_v4()),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn contents_are_dropped_without_data_key() {
    let mut e = env_or_skip!(env());
    e.state.logs.cipher = None;
    ingest(&e, vec![GatewayEvent::Http(http(100, 1, t(5)))]).await;
    let (content, event): (Option<Vec<u8>>, String) =
        sqlx::query_as("SELECT content, event::text FROM http_events")
            .fetch_one(&e.pool)
            .await
            .unwrap();
    assert!(content.is_none());
    assert!(!event.contains(SECRET_BODY));
}

#[tokio::test]
async fn tool_calls_upsert_ownership_and_correlation() {
    let e = env_or_skip!(env());
    let base = t(600);
    let at = |s: i64| base + Duration::seconds(s);
    // Only the plugin token may report tool calls.
    for role in ["admin", "viewer", "mcp_agent"] {
        let (s, _) = e
            .call(
                role,
                "POST",
                "/ingest/tool-calls",
                Some(json!({"events": []})),
            )
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{role}");
    }
    // Flows first: the calls arrive later (re-correlation on ingestion).
    ingest(
        &e,
        vec![
            GatewayEvent::Flow(flow(
                1,
                AGENT,
                ZONE,
                Some("a.exemple.com"),
                "93.184.216.34:443",
                Verdict::Allow,
                at(5),
            )),
            GatewayEvent::Flow(flow(
                2,
                AGENT,
                ZONE,
                Some("b.exemple.com"),
                "93.184.216.34:443",
                Verdict::Allow,
                at(25),
            )),
            GatewayEvent::Flow(flow(
                3,
                AGENT,
                ZONE,
                Some("c.exemple.com"),
                "93.184.216.34:443",
                Verdict::Allow,
                at(43),
            )),
            GatewayEvent::Flow(flow(
                4,
                AGENT,
                ZONE,
                Some("d.exemple.com"),
                "93.184.216.34:443",
                Verdict::Allow,
                at(100),
            )),
        ],
    )
    .await;
    // End before start (any order), then the start again: never reset to null.
    let post = |events: Vec<Value>| {
        e.call(
            "agent_plugin",
            "POST",
            "/ingest/tool-calls",
            Some(json!({"events": events})),
        )
    };
    assert_eq!(
        post(vec![call(10, at(0), Some(at(10)), Some("ok"))])
            .await
            .0,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        post(vec![call(10, at(0), None, None)]).await.0,
        StatusCode::ACCEPTED
    );
    let row: (Option<DateTime<Utc>>, Option<String>, Uuid) =
        sqlx::query_as("SELECT ended_at, status, agent_id FROM tool_calls WHERE id = $1")
            .bind(Uuid::from_u128(10))
            .fetch_one(&e.pool)
            .await
            .unwrap();
    assert_eq!(
        (row.0, row.1.as_deref(), row.2),
        (Some(at(10)), Some("ok"), AGENT)
    );
    // Two overlapping calls → probable; one ended < 5 s before → uncertain; a gated call is ignored.
    post(vec![
        call(11, at(20), Some(at(40)), Some("ok")),
        call(12, at(22), Some(at(30)), Some("ok")),
        call(13, at(41), Some(at(50)), Some("gated")),
    ])
    .await;

    let p: Page<FlowListItem> = e.get("viewer", "/logs/flows").await;
    let by_id = |n: u128| p.items.iter().find(|i| i.flow.id.as_u128() == n).unwrap();
    assert_eq!(by_id(1).correlation_confidence, Some(Confidence::Certain));
    assert_eq!(by_id(1).tool.as_deref(), Some("terminal"));
    assert_eq!(by_id(1).conversation_id.as_deref(), Some("conv-10"));
    assert_eq!(by_id(2).correlation_confidence, Some(Confidence::Probable));
    assert_eq!(by_id(2).conversation_id.as_deref(), Some("conv-12"));
    assert_eq!(by_id(3).correlation_confidence, Some(Confidence::Uncertain));
    assert_eq!(by_id(3).conversation_id.as_deref(), Some("conv-11"));
    assert_eq!(by_id(4).correlation_confidence, None);

    let d: FlowDetail = e
        .get("viewer", &format!("/logs/flows/{}", Uuid::from_u128(2)))
        .await;
    let c = d.correlation.unwrap();
    assert_eq!(
        (c.tool_call_id, c.confidence),
        (Uuid::from_u128(12), Confidence::Probable)
    );
    assert_eq!(d.tool_call.unwrap().id, Uuid::from_u128(12));

    // Another agent's plugin cannot overwrite a call it does not own.
    let other = format!("plugin2-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO api_tokens (name, token_sha256, role, actor_kind, actor_name, agent_id, created_by) \
         VALUES ('p2', $1, 'agent_plugin', 'agent', 'p2', $2, '{}')",
    )
    .bind(afw_core::sha256_hex(other.as_bytes()))
    .bind(AGENT2)
    .execute(&e.pool)
    .await
    .unwrap();
    let mut e2 = e.tokens.clone();
    e2.insert("agent_plugin", other);
    let env2 = Env {
        state: e.state.clone(),
        pool: e.pool.clone(),
        tokens: e2,
    };
    let mut forged = call(10, at(0), Some(at(99)), Some("forged"));
    forged["conversation_id"] = json!("hijack");
    env2.call(
        "agent_plugin",
        "POST",
        "/ingest/tool-calls",
        Some(json!({"events": [forged]})),
    )
    .await;
    let row: (Option<String>, String) =
        sqlx::query_as("SELECT status, conversation_id FROM tool_calls WHERE id = $1")
            .bind(Uuid::from_u128(10))
            .fetch_one(&e.pool)
            .await
            .unwrap();
    assert_eq!(row, (Some("ok".to_owned()), "conv-10".to_owned()));

    // Validation.
    let (s, _) = post(vec![call(14, at(10), Some(at(0)), Some("ok"))]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sse_stream_receives_ingested_flows_filtered() {
    let e = env_or_skip!(env());
    let req = Request::get(format!("/api/v1/logs/stream?agent={AGENT}&verdict=deny"))
        .header("authorization", format!("Bearer {}", e.tokens["viewer"]))
        .body(AxBody::empty())
        .unwrap();
    let res = router(e.state.clone()).oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/event-stream");
    let mut body = res.into_body();
    ingest(
        &e,
        vec![
            GatewayEvent::Flow(flow(
                1,
                AGENT,
                ZONE,
                Some("ok.test"),
                "1.1.1.1:443",
                Verdict::Allow,
                t(1),
            )),
            GatewayEvent::Flow(flow(
                2,
                AGENT2,
                ZONE2,
                Some("x.test"),
                "1.1.1.1:443",
                Verdict::Deny,
                t(1),
            )),
            GatewayEvent::Flow(flow(
                3,
                AGENT,
                ZONE,
                Some("no.test"),
                "1.1.1.1:443",
                Verdict::Deny,
                t(1),
            )),
        ],
    )
    .await;
    let mut text = String::new();
    while !text.contains("\n\n") {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), body.frame())
            .await
            .expect("an event within 5 s")
            .unwrap()
            .unwrap();
        if let Ok(d) = frame.into_data() {
            text.push_str(&String::from_utf8_lossy(&d));
        }
    }
    assert!(text.starts_with("event: flow\n"), "{text}");
    assert!(text.contains(&Uuid::from_u128(3).to_string()), "{text}");
    assert!(!text.contains(&Uuid::from_u128(1).to_string()));
    assert!(!text.contains(&Uuid::from_u128(2).to_string()));
}

async fn webhook_server() -> (
    String,
    tokio::sync::mpsc::UnboundedReceiver<(axum::http::HeaderMap, String)>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let app = axum::Router::new()
        .route(
            "/hook/secret-token",
            axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send((headers, body));
                    StatusCode::OK
                }
            }),
        )
        .route(
            "/redirect",
            axum::routing::post(|| async {
                axum::response::Redirect::temporary("/hook/secret-token")
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/hook/secret-token"), rx)
}

#[tokio::test]
async fn new_destination_alert_is_sent_to_a_signed_webhook_and_acknowledged() {
    let e = env_or_skip!(env_with(Some("hook-key")));
    let (url, mut rx) = webhook_server().await;
    let ch = json!({"id": Uuid::nil(), "name": "soc", "kind": "webhook", "url": url,
                    "min_severity": "warning", "enabled": true});
    // Only admins configure channels.
    for role in ["viewer", "auditor", "mcp_agent"] {
        assert_eq!(
            e.call(role, "POST", "/alert-channels", Some(ch.clone()))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    let (s, b) = e.call("admin", "POST", "/alert-channels", Some(ch)).await;
    assert_eq!(s, StatusCode::CREATED, "{}", String::from_utf8_lossy(&b));
    let created: AlertChannel = serde_json::from_slice(&b).unwrap();
    assert!(
        created.url.ends_with("/***"),
        "secret part masked: {}",
        created.url
    );
    let listed: Vec<AlertChannel> = e.get("viewer", "/alert-channels").await;
    assert_eq!(listed[0].url, created.url);
    // PUT with the masked URL keeps the stored one.
    let mut upd = serde_json::to_value(&created).unwrap();
    upd["name"] = json!("soc-2");
    let (s, _) = e
        .call(
            "admin",
            "PUT",
            &format!("/alert-channels/{}", created.id),
            Some(upd),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let stored: String = sqlx::query_scalar("SELECT url FROM alert_channels")
        .fetch_one(&e.pool)
        .await
        .unwrap();
    assert_eq!(stored, url);

    // Two days of history, then a destination never seen.
    ingest(
        &e,
        vec![GatewayEvent::Flow(flow(
            1,
            AGENT,
            ZONE,
            Some("old.test"),
            "1.1.1.1:443",
            Verdict::Allow,
            t(2 * 86400),
        ))],
    )
    .await;
    ingest(
        &e,
        vec![GatewayEvent::Flow(flow(
            2,
            AGENT,
            ZONE,
            Some("old.test"),
            "1.1.1.1:443",
            Verdict::Allow,
            t(10),
        ))],
    )
    .await;
    let r = ingest(
        &e,
        vec![GatewayEvent::Flow(flow(
            3,
            AGENT,
            ZONE,
            Some("exfil.test"),
            "203.0.113.5:443",
            Verdict::Allow,
            t(5),
        ))],
    )
    .await;
    assert_eq!(r.alerts, 1);

    let (headers, body) = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("webhook called")
        .unwrap();
    let ts: i64 = headers["x-afw-timestamp"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        headers["x-afw-signature"].to_str().unwrap(),
        logs::channels::sign(b"hook-key", ts, body.as_bytes())
    );
    let payload: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(payload["alert"]["event"]["kind"], "new_destination");

    let alerts: Page<Alert> = e.get("viewer", "/alerts?acknowledged=false").await;
    assert_eq!(alerts.items.len(), 1);
    let id = alerts.items[0].event.id;
    assert_eq!(
        e.call("viewer", "POST", &format!("/alerts/{id}/ack"), None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (s, b) = e
        .call("auditor", "POST", &format!("/alerts/{id}/ack"), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let acked: Alert = serde_json::from_slice(&b).unwrap();
    assert!(acked.acknowledged);
    assert!(
        e.get::<Page<Alert>>("viewer", "/alerts?acknowledged=false")
            .await
            .items
            .is_empty()
    );
    let (s, _) = e
        .call(
            "admin",
            "DELETE",
            &format!("/alert-channels/{}", created.id),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let actions = e.audit_actions().await;
    for a in [
        "alert_channel.create",
        "alert_channel.update",
        "alert.ack",
        "alert_channel.delete",
    ] {
        assert!(actions.contains(&a.to_owned()), "{a} audited: {actions:?}");
    }
}

#[tokio::test]
async fn webhook_channel_requires_a_signing_key_and_teams_payload() {
    let e = env_or_skip!(env());
    let ch = json!({"id": Uuid::nil(), "name": "x", "kind": "webhook", "url": "https://h/x",
                    "min_severity": "info", "enabled": true});
    assert_eq!(
        e.call("admin", "POST", "/alert-channels", Some(ch)).await.0,
        StatusCode::BAD_REQUEST
    );
    let bad = json!({"id": Uuid::nil(), "name": "x", "kind": "teams", "url": "file:///etc/passwd",
                     "min_severity": "info", "enabled": true});
    assert_eq!(
        e.call("admin", "POST", "/alert-channels", Some(bad))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let alert = Alert {
        event: AlertEvent {
            id: Uuid::nil(),
            at: t(0),
            kind: AlertKind::SecretDetected,
            severity: Severity::Critical,
            agent_id: Some(AGENT),
            summary: "secret".into(),
            details: Value::Null,
        },
        gateway_id: None,
        acknowledged: false,
        acknowledged_by: None,
    };
    let teams = logs::channels::payload(AlertChannelKind::Teams, &alert, None);
    assert_eq!(teams["@type"], "MessageCard");
    let chat = logs::channels::payload(AlertChannelKind::PulseChat, &alert, None);
    assert!(chat["text"].as_str().unwrap().contains("secret"));
}

#[tokio::test]
async fn deny_burst_and_volume_spike_alerts() {
    let e = env_or_skip!(env());
    let mut events: Vec<GatewayEvent> = (0..20)
        .map(|i| {
            GatewayEvent::Flow(flow(
                100 + i,
                AGENT,
                ZONE,
                Some("x.test"),
                "1.1.1.1:443",
                Verdict::Deny,
                t(5),
            ))
        })
        .collect();
    let mut big = flow(
        1,
        AGENT2,
        ZONE2,
        Some("y.test"),
        "1.1.1.1:443",
        Verdict::Allow,
        t(5),
    );
    big.bytes_out = 20 * 1024 * 1024;
    events.push(GatewayEvent::Flow(big));
    ingest(&e, events).await;
    let kinds: Vec<String> = sqlx::query_scalar("SELECT kind FROM alerts ORDER BY kind")
        .fetch_all(&e.pool)
        .await
        .unwrap();
    assert_eq!(kinds, vec!["deny_burst", "volume_spike"]);
    // Deduplicated.
    ingest(
        &e,
        (0..20)
            .map(|i| {
                GatewayEvent::Flow(flow(
                    200 + i,
                    AGENT,
                    ZONE,
                    Some("x.test"),
                    "1.1.1.1:443",
                    Verdict::Deny,
                    t(3),
                ))
            })
            .collect(),
    )
    .await;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM alerts")
        .fetch_one(&e.pool)
        .await
        .unwrap();
    assert_eq!(n, 2);
    // Gateway alerts are stored once.
    let ga = AlertEvent {
        id: Uuid::from_u128(77),
        at: t(1),
        kind: AlertKind::CloudMetadata,
        severity: Severity::Critical,
        agent_id: Some(AGENT),
        summary: "169.254.169.254".into(),
        details: Value::Null,
    };
    assert_eq!(
        ingest(&e, vec![GatewayEvent::Alert(ga.clone())])
            .await
            .alerts,
        1
    );
    assert_eq!(ingest(&e, vec![GatewayEvent::Alert(ga)]).await.alerts, 0);
}

#[tokio::test]
async fn captures_flow_from_request_to_audited_download() {
    let e = env_or_skip!(env());
    let req = json!({"agent_id": AGENT, "duration_secs": 30});
    // Unknown agent (never seen by a gateway).
    assert_eq!(
        e.call("admin", "POST", "/captures", Some(req.clone()))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    ingest(
        &e,
        vec![GatewayEvent::Flow(flow(
            1,
            AGENT,
            ZONE,
            Some("a.test"),
            "1.1.1.1:443",
            Verdict::Allow,
            t(5),
        ))],
    )
    .await;
    assert_eq!(
        e.call("viewer", "POST", "/captures", Some(req.clone()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        e.call(
            "admin",
            "POST",
            "/captures",
            Some(json!({"agent_id": AGENT, "duration_secs": 0}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (s, b) = e.call("admin", "POST", "/captures", Some(req)).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let cap: Capture = serde_json::from_slice(&b).unwrap();
    assert_eq!(cap.gateway_id, GW);

    let cmds = captures::pending_commands(&e.pool, GW).await.unwrap();
    assert_eq!(
        cmds,
        vec![GatewayCommand::StartCapture {
            capture_id: cap.id,
            agent_id: AGENT,
            duration_secs: 30
        }]
    );
    assert!(
        captures::pending_commands(&e.pool, GW)
            .await
            .unwrap()
            .is_empty(),
        "handed over once"
    );
    assert_eq!(
        e.call(
            "auditor",
            "GET",
            &format!("/captures/{}/download", cap.id),
            None
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    let pcap = b"\xd4\xc3\xb2\xa1pcap-secret-payload";
    // Another gateway cannot upload it.
    assert!(
        captures::store_capture(&e.state, Uuid::new_v4(), cap.id, pcap)
            .await
            .is_err()
    );
    let done = captures::store_capture(&e.state, GW, cap.id, pcap)
        .await
        .unwrap();
    assert_eq!(done.size, Some(pcap.len() as u64));
    let raw: Vec<u8> = sqlx::query_scalar("SELECT data FROM captures")
        .fetch_one(&e.pool)
        .await
        .unwrap();
    assert!(!raw.windows(14).any(|w| w == b"secret-payload"));

    assert_eq!(
        e.call(
            "viewer",
            "GET",
            &format!("/captures/{}/download", cap.id),
            None
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (s, b) = e
        .call(
            "auditor",
            "GET",
            &format!("/captures/{}/download", cap.id),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b, pcap);
    let got: Capture = e.get("viewer", &format!("/captures/{}", cap.id)).await;
    assert_eq!(got.state, afw_core::api::CaptureState::Done);
    let list: Page<Capture> = e.get("viewer", "/captures").await;
    assert_eq!(list.items.len(), 1);
    let actions = e.audit_actions().await;
    assert!(actions.contains(&"capture.request".to_owned()));
    assert!(actions.contains(&"capture.download".to_owned()));
    // State guard: a finished capture cannot be uploaded again.
    assert!(
        captures::store_capture(&e.state, GW, cap.id, b"other")
            .await
            .is_err()
    );
    let (s, b) = e
        .call(
            "auditor",
            "GET",
            &format!("/captures/{}/download", cap.id),
            None,
        )
        .await;
    assert_eq!((s, b.as_slice()), (StatusCode::OK, &pcap[..]));
}

#[tokio::test]
async fn agent_overview_internal_map_stats_and_rule_counters() {
    let e = env_or_skip!(env());
    let mut internal = flow(1, AGENT, ZONE, None, "10.0.0.6:22", Verdict::Allow, t(60));
    internal.internal = true;
    internal.app = Some(AppProto::Ssh);
    let mut db = flow(2, AGENT, ZONE, None, "10.9.9.9:5432", Verdict::Allow, t(50));
    db.internal = true;
    let mut old_db = flow(
        3,
        AGENT,
        ZONE,
        None,
        "10.9.9.9:5432",
        Verdict::Allow,
        t(3 * 86400),
    );
    old_db.internal = true;
    let mut observed = flow(
        5,
        AGENT,
        ZONE,
        Some("obs.test"),
        "1.1.1.1:443",
        Verdict::Allow,
        t(30),
    );
    observed.observed = true;
    ingest(
        &e,
        vec![
            GatewayEvent::Flow(internal),
            GatewayEvent::Flow(db),
            GatewayEvent::Flow(old_db),
            GatewayEvent::Flow(flow(
                4,
                AGENT,
                ZONE,
                Some("api.exemple.com"),
                "93.184.216.34:443",
                Verdict::Deny,
                t(40),
            )),
            GatewayEvent::Flow(observed),
            GatewayEvent::RuleHits {
                hits: vec![RuleHit {
                    rule_id: RULE,
                    revision: 1,
                    hits: 5,
                    last_hit_at: t(1),
                }],
            },
        ],
    )
    .await;
    ingest(
        &e,
        vec![GatewayEvent::RuleHits {
            hits: vec![RuleHit {
                rule_id: RULE,
                revision: 2,
                hits: 2,
                last_hit_at: t(0),
            }],
        }],
    )
    .await;

    let o: AgentOverview = e.get("viewer", &format!("/agents/{AGENT}/overview")).await;
    assert_eq!(o.agent.name, "daniel-bot");
    assert_eq!(o.zone.name, "bots");
    assert_eq!((o.flows_24h, o.denied_24h), (4, 1));
    assert_eq!(o.recent_denied.len(), 1);
    assert!(
        o.top_destinations
            .iter()
            .any(|d| d.destination == "api.exemple.com")
    );
    assert_eq!(
        e.call(
            "viewer",
            "GET",
            &format!("/agents/{}/overview", Uuid::new_v4()),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    let m: InternalMap = e.get("viewer", "/internal-map").await;
    assert_eq!(m.edges.len(), 2);
    let ssh = m.edges.iter().find(|x| x.port == 22).unwrap();
    assert_eq!(
        (ssh.source.as_str(), ssh.target.clone()),
        (AGENT.to_string().as_str(), AGENT2.to_string()),
        "agent-to-agent edge"
    );
    assert!(ssh.new);
    let pg = m.edges.iter().find(|x| x.port == 5432).unwrap();
    assert_eq!(pg.target, "10.9.9.9");
    assert!(!pg.new, "seen 3 days ago");
    assert_eq!(pg.flows, 1);
    assert!(m.nodes.iter().any(|n| n.label == "ops-bot"));
    let m: InternalMap = e.get("viewer", "/internal-map?period=7d").await;
    assert_eq!(m.edges.iter().find(|x| x.port == 5432).unwrap().flows, 2);
    assert_eq!(
        e.call("viewer", "GET", "/internal-map?period=2y", None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );

    let s: FlowStats = e.get("viewer", "/logs/flows/stats?bucket=1m").await;
    assert_eq!(
        s.points.len(),
        60 + 1 - usize::from(s.from.timestamp() % 60 == 0)
    );
    assert_eq!((s.allow, s.deny, s.observed), (2, 1, 1));
    assert_eq!(s.total, 4);
    let s: FlowStats = e
        .get(
            "viewer",
            &format!("/logs/flows/stats?bucket=1h&agent={AGENT}&verdict=deny"),
        )
        .await;
    assert_eq!(s.total, 1);
    assert_eq!(
        e.call(
            "viewer",
            "GET",
            "/logs/flows/stats?bucket=1m&from=2020-01-01T00:00:00Z",
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );

    let stats = views::rule_stats(&e.pool).await.unwrap();
    assert_eq!(stats[&RULE].0, 7);
    assert!(stats[&RULE].1.is_some());
}

#[tokio::test]
async fn retention_purges_by_level() {
    let e = env_or_skip!(env());
    ingest(
        &e,
        vec![
            GatewayEvent::Flow(flow(
                1,
                AGENT,
                ZONE,
                Some("a.test"),
                "1.1.1.1:443",
                Verdict::Allow,
                t(10 * 86400),
            )),
            GatewayEvent::Http(http(100, 1, t(10 * 86400))),
            GatewayEvent::Flow(flow(
                2,
                AGENT,
                ZONE,
                Some("a.test"),
                "1.1.1.1:443",
                Verdict::Allow,
                t(3 * 86400),
            )),
            GatewayEvent::Http(http(101, 2, t(3 * 86400))),
            GatewayEvent::Flow(flow(
                3,
                AGENT,
                ZONE,
                Some("a.test"),
                "1.1.1.1:443",
                Verdict::Allow,
                t(60),
            )),
        ],
    )
    .await;
    retention::purge_once(
        &e.state,
        Retention {
            flows: 5,
            http: 2,
            captures: 1,
        },
    )
    .await
    .unwrap();
    let flows: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM flows ORDER BY id")
        .fetch_all(&e.pool)
        .await
        .unwrap();
    assert_eq!(flows, vec![Uuid::from_u128(2), Uuid::from_u128(3)]);
    let http: i64 = sqlx::query_scalar("SELECT count(*) FROM http_events")
        .fetch_one(&e.pool)
        .await
        .unwrap();
    assert_eq!(http, 0);
}

#[tokio::test]
async fn logs_port_adapter_ingests_and_handles_captures() {
    let e = env_or_skip!(env());
    let port = logs::port::LogsPortImpl;
    port.ingest_gateway_events(
        &e.state,
        GW,
        vec![GatewayEvent::Flow(flow(
            1,
            AGENT,
            ZONE,
            Some("a.test"),
            "1.1.1.1:443",
            Verdict::Allow,
            t(5),
        ))],
    )
    .await
    .unwrap();
    let (s, b) = e
        .call(
            "admin",
            "POST",
            "/captures",
            Some(json!({"agent_id": AGENT, "duration_secs": 5})),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let cap: Capture = serde_json::from_slice(&b).unwrap();
    assert_eq!(port.pending_commands(&e.state, GW).await.unwrap().len(), 1);
    port.store_capture(&e.state, GW, cap.id, bytes::Bytes::from_static(b"pcap"))
        .await
        .unwrap();
    let got: Capture = e.get("viewer", &format!("/captures/{}", cap.id)).await;
    assert_eq!(got.size, Some(4));
}

#[tokio::test]
async fn a_gateway_cannot_overwrite_or_extend_another_gateways_events() {
    let e = env_or_skip!(env());
    ingest(
        &e,
        vec![GatewayEvent::Flow(flow(
            1,
            AGENT,
            ZONE,
            Some("a.test"),
            "1.1.1.1:443",
            Verdict::Deny,
            t(5),
        ))],
    )
    .await;
    // Another gateway reuses the same ids.
    let other = Uuid::from_u128(0x62);
    let mut forged = flow(
        1,
        AGENT2,
        ZONE2,
        Some("forged.test"),
        "2.2.2.2:443",
        Verdict::Allow,
        t(5),
    );
    forged.bytes_out = 1;
    let r = logs::ingest_gateway_events(
        &e.state,
        other,
        vec![
            GatewayEvent::Flow(forged),
            GatewayEvent::Http(http(100, 1, t(5))),
        ],
    )
    .await
    .unwrap();
    assert_eq!(r.flows, 0);
    let d: FlowDetail = e
        .get("auditor", &format!("/logs/flows/{}", Uuid::from_u128(1)))
        .await;
    assert_eq!(d.flow.gateway_id, GW);
    assert_eq!(d.flow.domain.as_deref(), Some("a.test"));
    assert_eq!(d.flow.verdict, Verdict::Deny);
    assert!(
        d.http.is_empty(),
        "an exchange from another gateway is not attached to the flow"
    );
    // And a later event from that gateway with an already used id is ignored, not merged.
    let (gw, dom): (Uuid, String) =
        sqlx::query_as("SELECT gateway_id, dest FROM flows WHERE id = $1")
            .bind(Uuid::from_u128(1))
            .fetch_one(&e.pool)
            .await
            .unwrap();
    assert_eq!((gw, dom.as_str()), (GW, "a.test"));
}

async fn alert_count(e: &Env) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM alerts")
        .fetch_one(&e.pool)
        .await
        .unwrap()
}

fn gw_alert(kind: AlertKind) -> AlertEvent {
    AlertEvent {
        id: Uuid::new_v4(),
        at: t(1),
        kind,
        severity: Severity::Warning,
        agent_id: Some(AGENT),
        summary: "x".into(),
        details: json!({"dst_ip": "10.9.9.9"}),
    }
}

#[tokio::test]
async fn webhook_urls_cannot_target_internal_addresses() {
    let e = env_or_skip!(env_with(Some("k")));
    for url in [
        "http://203.0.113.10/hook",
        "https://10.0.0.1/hook",
        "https://127.0.0.2/hook",
        "https://[::1]/hook",
        "https://169.254.169.254/latest/meta-data",
        "https://[fd00:ec2::254]/x",
        "https://[::ffff:10.0.0.1]/x",
        "https://localhost/hook",
        "https://0.0.0.0/hook",
    ] {
        for kind in ["webhook", "teams", "pulse_chat"] {
            let ch = json!({"id": Uuid::nil(), "name": "x", "kind": kind, "url": url,
                            "min_severity": "info", "enabled": true});
            let (s, b) = e.call("admin", "POST", "/alert-channels", Some(ch)).await;
            assert_eq!(
                s,
                StatusCode::BAD_REQUEST,
                "{kind} {url}: {}",
                String::from_utf8_lossy(&b)
            );
        }
    }
}

#[tokio::test]
async fn webhook_send_time_check_and_no_redirects() {
    let e = env_or_skip!(env_with(Some("k")));
    let (url, mut rx) = webhook_server().await;
    // A channel stored before the allowlist changed (direct insert): checked again at send time.
    let mut strict = e.state.clone();
    let mut cfg = (*strict.config).clone();
    cfg.alert_allowed_hosts = None;
    strict.config = Arc::new(cfg);
    sqlx::query(
        "INSERT INTO alert_channels (id, name, kind, url, min_severity, enabled) \
         VALUES ($1, 'loop', 'webhook', $2, 'info', true)",
    )
    .bind(Uuid::new_v4())
    .bind(&url)
    .execute(&e.pool)
    .await
    .unwrap();
    logs::ingest_gateway_events(
        &strict,
        GW,
        vec![GatewayEvent::Alert(gw_alert(AlertKind::PortScan))],
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(1500), rx.recv())
            .await
            .is_err(),
        "loopback refused at send time without allowlist"
    );
    // Redirects are never followed.
    sqlx::query("UPDATE alert_channels SET url = $1")
        .bind(url.replace("/hook/secret-token", "/redirect"))
        .execute(&e.pool)
        .await
        .unwrap();
    ingest(&e, vec![GatewayEvent::Alert(gw_alert(AlertKind::PortScan))]).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(1500), rx.recv())
            .await
            .is_err(),
        "redirect must not be followed"
    );
    // Control: the allowlisted direct URL is delivered.
    sqlx::query("UPDATE alert_channels SET url = $1")
        .bind(&url)
        .execute(&e.pool)
        .await
        .unwrap();
    ingest(&e, vec![GatewayEvent::Alert(gw_alert(AlertKind::PortScan))]).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn alerts_are_capped_per_agent_and_kind_with_a_summary() {
    let e = env_or_skip!(env());
    let events: Vec<GatewayEvent> = (0..30)
        .map(|_| GatewayEvent::Alert(gw_alert(AlertKind::PortScan)))
        .collect();
    let r = ingest(&e, events).await;
    assert_eq!(r.alerts, 21, "20 alerts then one summary");
    assert_eq!(alert_count(&e).await, 21);
    let capped: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM alerts WHERE event->'details'->>'capped' = 'true'",
    )
    .fetch_one(&e.pool)
    .await
    .unwrap();
    assert_eq!(capped, 1);
    // Another kind is not affected.
    assert_eq!(
        ingest(
            &e,
            vec![GatewayEvent::Alert(gw_alert(AlertKind::SensitivePort))]
        )
        .await
        .alerts,
        1
    );
}

#[tokio::test]
async fn alert_delivery_queue_is_bounded() {
    let e = env_or_skip!(env_with(Some("k")));
    let (url, mut rx) = webhook_server().await;
    let ch = json!({"id": Uuid::nil(), "name": "soc", "kind": "webhook", "url": url,
                    "min_severity": "info", "enabled": true});
    assert_eq!(
        e.call("admin", "POST", "/alert-channels", Some(ch)).await.0,
        StatusCode::CREATED
    );
    let mut full = e.state.clone();
    full.logs.dispatch = logs::channels::Dispatcher::new(4, 0);
    logs::ingest_gateway_events(
        &full,
        GW,
        vec![GatewayEvent::Alert(gw_alert(AlertKind::PortScan))],
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(1500), rx.recv())
            .await
            .is_err(),
        "a full queue drops deliveries"
    );
}

#[tokio::test]
async fn channel_audit_records_the_url_fingerprint() {
    let e = env_or_skip!(env_with(Some("k")));
    let url = "http://127.0.0.1:9/hook/secret-token";
    let ch = json!({"id": Uuid::nil(), "name": "soc", "kind": "webhook", "url": url,
                    "min_severity": "info", "enabled": true});
    assert_eq!(
        e.call("admin", "POST", "/alert-channels", Some(ch)).await.0,
        StatusCode::CREATED
    );
    let diff: Value =
        sqlx::query_scalar("SELECT diff FROM audit_log WHERE action = 'alert_channel.create'")
            .fetch_one(&e.pool)
            .await
            .unwrap();
    assert_eq!(
        diff["after"]["url_sha256"],
        afw_core::sha256_hex(url.as_bytes())
    );
    assert!(!diff.to_string().contains("secret-token"));
}

#[tokio::test]
async fn deny_burst_uses_flow_time() {
    let e = env_or_skip!(env());
    let events: Vec<GatewayEvent> = (0..20)
        .map(|i| {
            GatewayEvent::Flow(flow(
                300 + i,
                AGENT,
                ZONE,
                Some("x.test"),
                "1.1.1.1:443",
                Verdict::Deny,
                t(7200 + i as i64),
            ))
        })
        .collect();
    ingest(&e, events).await;
    let kinds: Vec<String> = sqlx::query_scalar("SELECT kind FROM alerts")
        .fetch_all(&e.pool)
        .await
        .unwrap();
    assert_eq!(
        kinds,
        vec!["deny_burst"],
        "a delayed batch is still a burst"
    );
}

#[tokio::test]
async fn sse_stream_has_a_max_lifetime_and_reports_lag() {
    let mut e = env_or_skip!(env());
    e.state.logs.events = tokio::sync::broadcast::channel(1).0;
    e.state.logs.stream_max = std::time::Duration::from_secs(2);
    let req = Request::get("/api/v1/logs/stream")
        .header("authorization", format!("Bearer {}", e.tokens["viewer"]))
        .body(AxBody::empty())
        .unwrap();
    let res = router(e.state.clone()).oneshot(req).await.unwrap();
    let mut body = res.into_body();
    for i in 0..3 {
        let _ = e.state.logs.events.send(GatewayEvent::Flow(flow(
            i,
            AGENT,
            ZONE,
            None,
            "1.1.1.1:443",
            Verdict::Allow,
            t(1),
        )));
    }
    let mut text = String::new();
    let done = tokio::time::timeout(std::time::Duration::from_secs(6), async {
        while let Some(f) = body.frame().await {
            if let Ok(d) = f.unwrap().into_data() {
                text.push_str(&String::from_utf8_lossy(&d));
            }
        }
    })
    .await;
    assert!(done.is_ok(), "stream must end after its max lifetime");
    assert!(text.contains("event: lagged"), "{text}");
}

#[tokio::test]
async fn retention_purges_known_destinations() {
    let e = env_or_skip!(env());
    ingest(
        &e,
        vec![GatewayEvent::Flow(flow(
            1,
            AGENT,
            ZONE,
            Some("old.test"),
            "1.1.1.1:443",
            Verdict::Allow,
            t(10 * 86400),
        ))],
    )
    .await;
    ingest(
        &e,
        vec![GatewayEvent::Flow(flow(
            2,
            AGENT,
            ZONE,
            Some("new.test"),
            "1.1.1.1:443",
            Verdict::Allow,
            t(60),
        ))],
    )
    .await;
    retention::purge_once(
        &e.state,
        Retention {
            flows: 5,
            http: 2,
            captures: 1,
        },
    )
    .await
    .unwrap();
    let dests: Vec<String> = sqlx::query_scalar("SELECT destination FROM agent_destinations")
        .fetch_all(&e.pool)
        .await
        .unwrap();
    assert_eq!(dests, vec!["new.test"]);
}
