//! End to end with the real control plane (`afw-api`): registration with a one-time token,
//! publication and installation of a revision through the REST API, the gateway fetches it
//! over mutual TLS (`/gw/v1/policy`), acknowledges and enforces it, and a denied flow shows up
//! in `GET /api/v1/logs/flows`. Needs PostgreSQL: skipped when `AFW_TEST_DATABASE_URL` is not
//! set, e.g.
//!   AFW_DOCKER_ARGS="--network afw-test-net -e AFW_TEST_DATABASE_URL=postgres://postgres:postgres@afw-pg-l6/postgres" \
//!     scripts/cargo.sh test -p afw-gateway --test console_e2e

mod common;
#[path = "../../afw-api/tests/policy_support/mod.rs"]
mod policy_support;

use std::sync::Arc;
use std::time::Duration;

use afw_tls::ConsolePki;
use axum::http::StatusCode;
use common::*;
use policy_support::*;
use serde_json::json;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[tokio::test]
async fn registered_gateway_enforces_installed_revision_and_reports_flows() {
    let Some(mut env) = env().await else {
        eprintln!("AFW_TEST_DATABASE_URL not set: skipped");
        return;
    };
    let pki_dir = tempfile::tempdir().unwrap();
    let pki = Arc::new(ConsolePki::load_or_create(&pki_dir.path().join("pki")).unwrap());
    env.state.gateways.pki = Some(pki.clone());
    env.state.gateways.long_poll = Duration::from_millis(500);
    env.state.gateways.poll_interval = Duration::from_millis(50);
    let server = pki.server_config(&["127.0.0.1".to_owned()]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    tokio::spawn(afw_api::gateways::tls::serve(
        listener,
        env.state.clone(),
        server,
    ));
    let admin = env.admin.clone();

    // 1. Registration with a one-time token (the gateway's own client).
    let (st, tok) = env
        .call(
            "POST",
            "/gateways/registration-tokens",
            &admin,
            None,
            Some(json!({"name": "gw-e2e"})),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{tok}");
    let state_dir = tempfile::tempdir().unwrap();
    let gw = afw_gateway::console_client::register(
        &base,
        tok["token"].as_str().unwrap(),
        "gw-e2e",
        Some(pki.ca_cert_pem()),
        state_dir.path(),
    )
    .await
    .expect("registration");
    // The token is single use.
    let again = afw_gateway::console_client::register(
        &base,
        tok["token"].as_str().unwrap(),
        "gw-e2e",
        Some(pki.ca_cert_pem()),
        tempfile::tempdir().unwrap().path(),
    )
    .await;
    assert!(again.is_err());

    // 2. The gateway starts without policy (deny all) and polls the console.
    let mut h = harness_in(state_dir, None, |o| {
        o.gateway_id = None;
        o.console_url = Some(base.clone());
    })
    .await;
    assert_eq!(h.gw.state.gateway_id, gw);
    assert_eq!(h.gw.state.store.revision(), None);

    // 3. Publish and install a revision through the REST API.
    let s = env.open(&admin).await;
    let (z, a, o, r) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    // Agents' addresses must be in the internal networks (here: the loopback agent address).
    let settings = json!({
        "internal_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", format!("{AGENT_IP}/32")],
        "max_buffered_body": 1048576, "max_stored_body": 262144,
        "retention_days": {"flows": 30, "http": 14, "captures": 7}
    });
    let (st, out) = env
        .call("PUT", "/settings", &admin, Some(s), Some(settings))
        .await;
    assert_eq!(st, StatusCode::OK, "{out}");
    env.create(&admin, s, "zones", zone(z, "bots", false)).await;
    env.create(&admin, s, "objects", domain(o, "allowed", "allowed.test"))
        .await;
    env.create(
        &admin,
        s,
        "agents",
        json!({"id": a, "name": "daniel-bot", "zone_id": z, "kind": "docker_compose", "addresses": [AGENT_IP]}),
    )
    .await;
    env.create(&admin, s, "rules", zone_rule(r, "allowed api", z, 1, &[o]))
        .await;
    let rev = env.publish(&admin, s).await;
    let (st, res) = env
        .call(
            "POST",
            "/installs",
            &admin,
            None,
            Some(json!({"revision": rev, "gateways": [gw]})),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED, "{res}");

    // 4. Fetched, verified, enforced and acknowledged.
    let mut ok = false;
    for _ in 0..100 {
        if h.gw.state.store.revision() == Some(rev) {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ok, "installed revision not applied by the gateway");
    let mut installed = false;
    for _ in 0..50 {
        let (_, list) = env
            .call(
                "GET",
                &format!("/installs?gateway={gw}"),
                &admin,
                None,
                None,
            )
            .await;
        if list["items"][0]["state"] == "installed" {
            installed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(installed, "install not acknowledged");

    // 5. Allowed and denied traffic under the installed revision.
    let s1 = h.transparent(AGENT_IP, h.upstream_addr).await;
    let mut tls = h.tls(s1, "allowed.test").await.unwrap();
    let resp = http_raw(&mut tls, &get("allowed.test", "/ok")).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    let mut t = h
        .transparent(AGENT_IP, "198.51.100.9:4444".parse().unwrap())
        .await;
    let _ = t.write_all(b"\x00raw").await;
    h.wait_event(|e| matches!(e, afw_core::events::GatewayEvent::Flow(f) if f.verdict == afw_core::events::Verdict::Deny))
        .await;

    // 6. The denied flow is in the console's logs (events are sent every second).
    let auditor = env.auditor.clone();
    let mut found = None;
    for _ in 0..100 {
        let (st, body) = env
            .call("GET", "/logs/flows?verdict=deny", &auditor, None, None)
            .await;
        assert_eq!(st, StatusCode::OK, "{body}");
        if let Some(item) = body["items"]
            .as_array()
            .and_then(|a| a.iter().find(|i| i["dst"] == "198.51.100.9:4444"))
        {
            found = Some(item.clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let item = found.expect("denied flow not found in /logs/flows");
    assert_eq!(item["gateway_id"], json!(gw));
    assert_eq!(item["agent_id"], json!(a));
}
