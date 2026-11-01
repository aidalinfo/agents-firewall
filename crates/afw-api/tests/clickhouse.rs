//! ClickHouse `LogStore`, skipped when `AFW_TEST_CLICKHOUSE_URL` is not set (each run uses its
//! own database).

use afw_api::logs::clickhouse::ClickHouseLogStore;
use afw_api::logs::store::{Cursor, Destination, LogFilter, LogStore, StoredHttp};
use afw_api::logs::{AnyLogStore, correlation::correlate};
use afw_core::api::Confidence;
use afw_core::events::*;
use afw_core::policy::{AppProto, L4Proto};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

const AGENT: Uuid = Uuid::from_u128(0xa1);
const AGENT2: Uuid = Uuid::from_u128(0xa2);
const ZONE: Uuid = Uuid::from_u128(0x21);

fn t(secs_ago: i64) -> DateTime<Utc> {
    let now = Utc::now() - Duration::seconds(secs_ago);
    DateTime::from_timestamp_micros(now.timestamp_micros()).unwrap()
}

fn flow(
    n: u128,
    agent: Uuid,
    domain: Option<&str>,
    dst: &str,
    verdict: Verdict,
    at: DateTime<Utc>,
) -> FlowEvent {
    FlowEvent {
        id: Uuid::from_u128(n),
        gateway_id: Uuid::from_u128(0x61),
        agent_id: Some(agent),
        zone_id: Some(ZONE),
        src: "10.0.0.5:40000".parse().unwrap(),
        dst: dst.parse().unwrap(),
        protocol: L4Proto::Tcp,
        app: Some(AppProto::Https),
        domain: domain.map(str::to_owned),
        sni: None,
        bytes_out: 100,
        bytes_in: 50,
        started_at: at,
        ended_at: None,
        verdict,
        decision: DecisionRef {
            rule_id: None,
            rule_number: None,
            rule_name: "default-deny".into(),
            revision: Some(1),
            layer: "implicit".into(),
            reason: String::new(),
        },
        internal: false,
        llm_provider: false,
        tls_inspected: true,
        data_classes: vec![],
        observed: false,
        content_inspected: true,
        deny_mode: None,
    }
}

fn call(
    n: u128,
    start: DateTime<Utc>,
    end: Option<DateTime<Utc>>,
    status: Option<&str>,
) -> ToolCallEvent {
    ToolCallEvent {
        id: Uuid::from_u128(n),
        agent: "bot".into(),
        conversation_id: format!("conv-{n}"),
        tool: "terminal".into(),
        args_summary: "x".into(),
        started_at: start,
        ended_at: end,
        status: status.map(str::to_owned),
    }
}

async fn store() -> Option<AnyLogStore> {
    let url = std::env::var("AFW_TEST_CLICKHOUSE_URL").ok()?;
    let db = format!("afw_{}", Uuid::new_v4().simple());
    let res = reqwest::Client::new()
        .post(&url)
        .body(format!("CREATE DATABASE {db}"))
        .send()
        .await
        .expect("ClickHouse reachable");
    assert!(res.status().is_success(), "{}", res.text().await.unwrap());
    let s = AnyLogStore::ClickHouse(ClickHouseLogStore::new(&url, None, None, Some(db)));
    s.init().await.unwrap();
    s.init().await.unwrap();
    Some(s)
}

#[tokio::test]
async fn clickhouse_store_round_trip() {
    let Some(s) = store().await else {
        eprintln!("AFW_TEST_CLICKHOUSE_URL not set: skipped");
        return;
    };
    let flows = vec![
        flow(
            1,
            AGENT,
            Some("api.exemple.com"),
            "93.184.216.34:443",
            Verdict::Deny,
            t(50),
        ),
        flow(
            2,
            AGENT,
            Some("www.autre.org"),
            "198.51.100.7:443",
            Verdict::Allow,
            t(40),
        ),
        flow(3, AGENT2, None, "10.1.2.3:5432", Verdict::Allow, t(30)),
    ];
    assert_eq!(s.insert_flows(&flows).await.unwrap().len(), 3);
    assert!(
        s.insert_flows(&flows).await.unwrap().is_empty(),
        "idempotent"
    );

    let ids = |v: Vec<afw_api::logs::store::StoredFlow>| {
        v.iter().map(|f| f.flow.id.as_u128()).collect::<Vec<_>>()
    };
    let all = LogFilter::default();
    assert_eq!(
        ids(s.search_flows(&all, None, 10).await.unwrap()),
        vec![3, 2, 1]
    );
    let f = LogFilter {
        agent: Some(AGENT),
        verdict: Some(Verdict::Deny),
        ..Default::default()
    };
    assert_eq!(ids(s.search_flows(&f, None, 10).await.unwrap()), vec![1]);
    let f = LogFilter {
        destination: Destination::parse("exemple.com"),
        ..Default::default()
    };
    assert_eq!(ids(s.search_flows(&f, None, 10).await.unwrap()), vec![1]);
    let f = LogFilter {
        destination: Destination::parse("10.0.0.0/8"),
        ..Default::default()
    };
    assert_eq!(ids(s.search_flows(&f, None, 10).await.unwrap()), vec![3]);
    let f = LogFilter {
        q: Some("AUTRE".into()),
        ..Default::default()
    };
    assert_eq!(ids(s.search_flows(&f, None, 10).await.unwrap()), vec![2]);
    let page = s.search_flows(&all, None, 2).await.unwrap();
    let last = &page[1].flow;
    let c = Cursor {
        at: last.started_at,
        id: last.id,
    };
    assert_eq!(
        ids(s.search_flows(&all, Some(c), 10).await.unwrap()),
        vec![1]
    );

    // HTTP exchanges and URL search.
    let h = HttpEvent {
        id: Uuid::from_u128(100),
        flow_id: Uuid::from_u128(1),
        gateway_id: Uuid::nil(),
        agent_id: Some(AGENT),
        at: t(50),
        method: "GET".into(),
        url: "https://api.exemple.com/v1/upload".into(),
        host: "api.exemple.com".into(),
        request_headers: vec![],
        request_body: None,
        status: Some(403),
        response_headers: vec![],
        response_body: None,
        findings: vec![],
        admin_action: None,
        websocket: false,
    };
    let stored = StoredHttp {
        event: h,
        content: Some(vec![1, 2, 3]),
    };
    s.insert_http(std::slice::from_ref(&stored)).await.unwrap();
    s.insert_http(std::slice::from_ref(&stored)).await.unwrap();
    assert_eq!(
        s.http_for_flow(Uuid::from_u128(1)).await.unwrap(),
        vec![stored]
    );
    let f = LogFilter {
        q: Some("v1/upload".into()),
        ..Default::default()
    };
    assert_eq!(ids(s.search_flows(&f, None, 10).await.unwrap()), vec![1]);

    // DNS.
    let dns = DnsEvent {
        id: Uuid::from_u128(200),
        gateway_id: Uuid::nil(),
        agent_id: Some(AGENT),
        zone_id: Some(ZONE),
        at: t(20),
        qname: "evil.test.".into(),
        qtype: "A".into(),
        answers: vec!["203.0.113.9".into()],
        verdict: Verdict::Deny,
        decision: flows[0].decision.clone(),
    };
    s.insert_dns(std::slice::from_ref(&dns)).await.unwrap();
    s.insert_dns(std::slice::from_ref(&dns)).await.unwrap();
    let f = LogFilter {
        destination: Destination::parse("203.0.113.0/24"),
        ..Default::default()
    };
    assert_eq!(s.search_dns(&f, None, 10).await.unwrap(), vec![dns]);

    // Tool calls: end then start (merged, never reset to null), ownership.
    let base = t(50) - Duration::seconds(5);
    s.upsert_tool_calls(
        AGENT,
        &[call(
            10,
            base,
            Some(base + Duration::seconds(30)),
            Some("ok"),
        )],
    )
    .await
    .unwrap();
    s.upsert_tool_calls(AGENT, &[call(10, base, None, None)])
        .await
        .unwrap();
    s.upsert_tool_calls(AGENT2, &[call(10, base, Some(base), Some("forged"))])
        .await
        .unwrap();
    let calls = s
        .tool_calls_between(AGENT, base - Duration::hours(1), t(0))
        .await
        .unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].status.as_deref(), Some("ok"));
    assert_eq!(calls[0].ended_at, Some(base + Duration::seconds(30)));
    assert!(
        s.tool_calls_between(AGENT2, base - Duration::hours(1), t(0))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        s.get_tool_call(Uuid::from_u128(10))
            .await
            .unwrap()
            .unwrap()
            .status
            .as_deref(),
        Some("ok")
    );
    let (c, k) = correlate(flows[0].started_at, &calls).unwrap();
    assert_eq!(
        (c.id, k.confidence),
        (Uuid::from_u128(10), Confidence::Certain)
    );
    s.set_correlation(Uuid::from_u128(1), Some((c.id, k.confidence)))
        .await
        .unwrap();
    assert_eq!(
        s.get_flow(Uuid::from_u128(1))
            .await
            .unwrap()
            .unwrap()
            .correlation,
        Some((Uuid::from_u128(10), Confidence::Certain))
    );
    assert_eq!(s.recent_tool_calls(AGENT, 5).await.unwrap().len(), 1);

    // Aggregates.
    let a = s.agent_activity(AGENT, t(3600)).await.unwrap();
    assert_eq!((a.flows, a.denied, a.bytes_out), (2, 1, 200));
    assert_eq!(
        s.top_destinations(AGENT, t(3600), 5).await.unwrap().len(),
        2
    );
    assert_eq!(
        s.recent_flows(AGENT, Some(Verdict::Deny), 5)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        s.bytes_out(AGENT, t(3600), t(0) + Duration::seconds(1))
            .await
            .unwrap(),
        200
    );
    assert_eq!(
        s.count_flows(
            AGENT,
            Some(Verdict::Allow),
            t(3600),
            t(0) + Duration::seconds(1)
        )
        .await
        .unwrap(),
        1
    );
    assert!(s.last_gateway_of_agent(AGENT).await.unwrap().is_some());
    let h = s
        .flow_histogram(&all, t(3600), t(0) + Duration::seconds(1), 3600)
        .await
        .unwrap();
    let total: u64 = h.iter().map(|r| r.1 + r.2 + r.3).sum();
    assert_eq!(total, 3);

    let mut internal = flow(4, AGENT, None, "10.9.9.9:5432", Verdict::Allow, t(10));
    internal.internal = true;
    let mut old = flow(
        5,
        AGENT,
        None,
        "10.9.9.9:5432",
        Verdict::Allow,
        t(3 * 86400),
    );
    old.internal = true;
    s.insert_flows(&[internal, old]).await.unwrap();
    let edges = s
        .internal_edges(t(86400), t(0) + Duration::seconds(1), None)
        .await
        .unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(
        (edges[0].flows, edges[0].port, edges[0].agent_id),
        (1, 5432, Some(AGENT))
    );
    assert!(edges[0].first_seen_at < t(86400));

    s.purge(t(86400), t(86400)).await.unwrap();
    let left = ids(s.search_flows(&all, None, 10).await.unwrap());
    assert!(!left.contains(&5), "{left:?}");
    assert!(left.contains(&4));
}
