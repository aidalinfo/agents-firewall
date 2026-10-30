//! End to end: install a published revision → the gateway fetches it on `/gw/v1/policy` (mutual
//! TLS) → acknowledges it → the install is `installed` and the revision active. Uses the real
//! policy port wired by `AppState::new`. Skipped when `AFW_TEST_DATABASE_URL` is not set.

mod policy_support;

use std::sync::Arc;
use std::time::Duration;

use afw_core::InstalledPolicy;
use afw_tls::{ConsolePki, GatewayIdentity};
use axum::http::StatusCode;
use policy_support::*;
use serde_json::json;
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

fn gateway_client(dir: &std::path::Path) -> reqwest::Client {
    let cfg = GatewayIdentity::client_config(dir).unwrap();
    reqwest::Client::builder()
        .use_preconfigured_tls((*cfg).clone())
        .build()
        .unwrap()
}

#[tokio::test]
async fn install_is_served_to_the_gateway_and_acknowledged() {
    let Some(mut env) = env().await else {
        eprintln!("AFW_TEST_DATABASE_URL not set: skipped");
        return;
    };
    let pki_dir = tempfile::tempdir().unwrap();
    let pki = Arc::new(ConsolePki::load_or_create(&pki_dir.path().join("pki")).unwrap());
    env.state.gateways.pki = Some(pki.clone());
    env.state.gateways.long_poll = Duration::from_millis(400);
    env.state.gateways.poll_interval = Duration::from_millis(50);
    let server = pki
        .server_config(&["localhost".to_owned(), "127.0.0.1".to_owned()])
        .unwrap();
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

    // Register a gateway (one-time token + CSR).
    let a = env.admin.clone();
    let (st, tok) = env
        .call(
            "POST",
            "/gateways/registration-tokens",
            &a,
            None,
            Some(json!({"name": "gw-e2e"})),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{tok}");
    let dir = tempfile::tempdir().unwrap();
    let csr = GatewayIdentity::generate(dir.path()).unwrap();
    let res = anonymous_client(&pki.ca_cert_pem())
        .post(format!("{base}/gw/v1/register"))
        .json(&json!({"token": tok["token"], "name": "gw-e2e", "hostname": "h", "csr_pem": csr}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 201);
    let reg: serde_json::Value = res.json().await.unwrap();
    GatewayIdentity::store_cert(
        dir.path(),
        reg["cert_pem"].as_str().unwrap(),
        reg["ca_pem"].as_str().unwrap(),
    )
    .unwrap();
    let gw: Uuid = reg["gateway_id"].as_str().unwrap().parse().unwrap();
    let client = gateway_client(dir.path());

    // Nothing installed yet: 204 at the end of the long poll.
    let res = client
        .get(format!("{base}/gw/v1/policy"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 204);

    // Publish and install.
    let s = env.open(&a).await;
    let z = Uuid::new_v4();
    env.create(&a, s, "zones", zone(z, "prod", false)).await;
    assert_eq!(env.publish(&a, s).await, 1);
    let (st, res) = env
        .call(
            "POST",
            "/installs",
            &a,
            None,
            Some(json!({"revision": 1, "gateways": [gw]})),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED, "{res}");

    let res = client
        .get(format!("{base}/gw/v1/policy"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let installed: InstalledPolicy = res.json().await.unwrap();
    installed.verify().unwrap();
    assert_eq!(installed.revision, 1);
    assert!(!installed.rollback);
    assert_eq!(installed.document.zones[0].id, z);
    let res = client
        .get(format!("{base}/gw/v1/policy?have=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 204);

    let res = client
        .post(format!("{base}/gw/v1/policy/ack"))
        .json(&json!({"revision": 1, "ok": true, "error": null}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 204);
    let (_, list) = env
        .call("GET", &format!("/installs?gateway={gw}"), &a, None, None)
        .await;
    assert_eq!(list["items"][0]["state"], "installed", "{list}");
    let state = afw_api::policy::install::gateway_policy_state(&env.pool, gw)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.active_revision, Some(1));
    let (desired, active): (Option<i64>, Option<i64>) =
        sqlx::query_as("SELECT desired_revision, active_revision FROM gateways WHERE id = $1")
            .bind(gw)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!((desired, active), (Some(1), Some(1)));
}
