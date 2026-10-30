//! End to end: events posted by a registered gateway on the mTLS route `/gw/v1/events` are
//! ingested by the logs module (wired `LogsPort`) and found by `GET /logs/flows`; capture
//! commands and uploads go through the same port. Skipped without `AFW_TEST_DATABASE_URL`.

mod support;

use std::sync::Arc;

use afw_api::Config;
use afw_tls::{ConsolePki, GatewayIdentity};
use axum::http::StatusCode;
use base64::Engine;
use serde_json::json;
use support::*;
use uuid::Uuid;

fn anonymous_client(ca_pem: &str) -> reqwest::Client {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let cfg = rustls::ClientConfig::builder_with_provider(afw_tls::crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(cfg)
        .build()
        .unwrap()
}

#[tokio::test]
async fn gateway_events_reach_the_logs_api() {
    let pool = pool_or_skip!();
    let dir = tempfile::tempdir().unwrap();
    let pki = Arc::new(ConsolePki::load_or_create(&dir.path().join("pki")).unwrap());
    let config = Config {
        data_key: Some(base64::engine::general_purpose::STANDARD.encode([3u8; 32])),
        ..Config::default()
    };
    let mut state = afw_api::AppState::new(config, Some(pool.clone()));
    state.gateways.pki = Some(pki.clone());
    let server = pki.server_config(&["127.0.0.1".to_owned()]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    tokio::spawn(afw_api::gateways::tls::serve(
        listener,
        state.clone(),
        server,
    ));
    let app = afw_api::router(state);
    let admin = token(&pool, "admin", None).await;
    let auditor = token(&pool, "auditor", None).await;

    // Register a gateway.
    let res = call(
        &app,
        "POST",
        "/api/v1/gateways/registration-tokens",
        Some(&admin),
        Some(json!({"name": "gw-a"})),
    )
    .await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
    let reg_token = res.json()["token"].as_str().unwrap().to_owned();
    let id_dir = tempfile::tempdir().unwrap();
    let csr = GatewayIdentity::generate(id_dir.path()).unwrap();
    let res = anonymous_client(&pki.ca_cert_pem())
        .post(format!("{base}/gw/v1/register"))
        .json(&json!({"token": reg_token, "name": "gw-a", "hostname": "h", "csr_pem": csr}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 201);
    let body: serde_json::Value = res.json().await.unwrap();
    GatewayIdentity::store_cert(
        id_dir.path(),
        body["cert_pem"].as_str().unwrap(),
        body["ca_pem"].as_str().unwrap(),
    )
    .unwrap();
    let gw: Uuid = body["gateway_id"].as_str().unwrap().parse().unwrap();
    let client = reqwest::Client::builder()
        .use_preconfigured_tls((*GatewayIdentity::client_config(id_dir.path()).unwrap()).clone())
        .build()
        .unwrap();

    // A batch with a flow (the gateway id inside the event is not trusted).
    let flow_id = Uuid::new_v4();
    let agent = Uuid::new_v4();
    let now = chrono::Utc::now();
    let batch = json!({"batch_id": Uuid::new_v4(), "events": [{
        "type": "flow", "id": flow_id, "gateway_id": Uuid::nil(), "agent_id": agent,
        "zone_id": null, "src": "10.0.0.5:40000", "dst": "93.184.216.34:443", "protocol": "tcp",
        "app": "https", "domain": "api.exemple.com", "sni": "api.exemple.com",
        "bytes_out": 10, "bytes_in": 20, "started_at": now, "ended_at": null,
        "verdict": "deny", "decision": {"rule_id": null, "rule_number": null,
          "rule_name": "default-deny", "revision": null, "layer": "implicit", "reason": "x"},
        "internal": false, "llm_provider": false, "tls_inspected": true,
        "data_classes": [], "observed": false
    }]});
    let res = client
        .post(format!("{base}/gw/v1/events"))
        .json(&batch)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 202);

    let res = call(
        &app,
        "GET",
        "/api/v1/logs/flows?verdict=deny",
        Some(&auditor),
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let items = res.json()["items"].clone();
    assert_eq!(items.as_array().unwrap().len(), 1);
    assert_eq!(items[0]["id"], json!(flow_id));
    assert_eq!(items[0]["gateway_id"], json!(gw));
    assert_eq!(items[0]["rule_label"], "default-deny");

    // Capture: requested through the API, commanded in the heartbeat, uploaded over mTLS.
    let res = call(
        &app,
        "POST",
        "/api/v1/captures",
        Some(&admin),
        Some(json!({"agent_id": agent, "duration_secs": 5})),
    )
    .await;
    assert_eq!(res.status, StatusCode::ACCEPTED, "{}", res.text());
    let capture = res.json()["id"].as_str().unwrap().to_owned();
    let hb = json!({"version": "0.1.0", "revision": null, "ca_fingerprint": "ab",
        "stats": {"uptime_secs": 1, "active_flows": 0, "flows_total": 1, "denied_total": 1,
                  "bytes_in": 0, "bytes_out": 0, "events_queued": 0, "events_dropped": 0}});
    let res = client
        .post(format!("{base}/gw/v1/heartbeat"))
        .json(&hb)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let cmds: serde_json::Value = res.json().await.unwrap();
    assert_eq!(cmds["commands"][0]["capture_id"], json!(capture));
    let res = client
        .post(format!("{base}/gw/v1/captures/{capture}"))
        .header("content-type", "application/vnd.tcpdump.pcap")
        .body(b"pcap-bytes".to_vec())
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success(), "{}", res.status());
    let res = call(
        &app,
        "GET",
        &format!("/api/v1/captures/{capture}/download"),
        Some(&auditor),
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.body, b"pcap-bytes");
}
