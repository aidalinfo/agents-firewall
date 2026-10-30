//! Audit API (lot L7c): listing, verification (tampering detection), NDJSON export and anchoring
//! of the chain head in immutable storage. Skipped when `AFW_TEST_DATABASE_URL` is not set.

mod support;

use std::sync::{Arc, Mutex};

use afw_api::audit::export::{AuditExportConfig, S3Config};
use afw_api::auth::Principal;
use afw_core::api::Role;
use afw_core::events::{AuditEntry, Interface};
use axum::http::StatusCode;
use serde_json::json;
use support::*;

async fn seed(pool: &sqlx::PgPool, n: usize) {
    for i in 0..n {
        let mut p = Principal::for_tests(Role::Admin);
        if i % 2 == 1 {
            p.interface = Interface::Cli;
            p.actor.name = "bob".into();
        }
        let mut tx = pool.begin().await.unwrap();
        afw_api::audit::record(
            &mut tx,
            &p,
            None,
            if i % 3 == 0 { "rule.create" } else { "zone.update" },
            &format!("x:{i}"),
            json!({"i": i}),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
}

async fn tamper(pool: &sqlx::PgPool, sql: &str) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(sql).execute(&mut *tx).await.unwrap();
    sqlx::query("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update_delete")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn list_filters_and_paginates() {
    let pool = pool_or_skip!();
    seed(&pool, 7).await;
    let app = afw_api::router(state(&pool));
    let viewer = token(&pool, "viewer", None).await;

    let page = call(&app, "GET", "/api/v1/audit?limit=3", Some(&viewer), None).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let body = page.json();
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["seq"], 1);
    let cursor = body["next_cursor"].as_str().unwrap().to_owned();
    let next = call(
        &app,
        "GET",
        &format!("/api/v1/audit?limit=3&cursor={cursor}"),
        Some(&viewer),
        None,
    )
    .await
    .json();
    assert_eq!(next["items"][0]["seq"], 4);

    let all = |q: &str| {
        let app = app.clone();
        let viewer = viewer.clone();
        let q = q.to_owned();
        async move {
            let r = call(&app, "GET", &format!("/api/v1/audit?{q}"), Some(&viewer), None).await;
            assert_eq!(r.status, StatusCode::OK, "{q}: {}", r.text());
            r.json()["items"].as_array().unwrap().clone()
        }
    };
    assert_eq!(all("action=rule.create").await.len(), 3);
    assert_eq!(all("action=zone.*").await.len(), 4);
    assert_eq!(all("interface=cli").await.len(), 3);
    assert_eq!(all("actor=bob").await.len(), 3);
    assert_eq!(all("from_seq=6").await.len(), 2);
    let future = (chrono::Utc::now() + chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    assert_eq!(all(&format!("from={future}")).await.len(), 0);
    assert_eq!(all(&format!("to={future}")).await.len(), 7);
    let bad = call(&app, "GET", "/api/v1/audit?interface=telnet", Some(&viewer), None).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn verify_detects_a_modified_row() {
    let pool = pool_or_skip!();
    seed(&pool, 5).await;
    let app = afw_api::router(state(&pool));
    let viewer = token(&pool, "viewer", None).await;
    let ok = call(&app, "GET", "/api/v1/audit/verify", Some(&viewer), None).await;
    assert_eq!(ok.status, StatusCode::OK);
    let body = ok.json();
    assert_eq!(body["ok"], true, "{body}");
    assert_eq!(body["checked"], 5);
    assert_eq!(body["head_seq"], 5);
    assert_eq!(body["broken_at"], serde_json::Value::Null);

    tamper(&pool, "UPDATE audit_log SET target = 'rule:innocent' WHERE seq = 3").await;
    let res = call(&app, "GET", "/api/v1/audit/verify", Some(&viewer), None)
        .await
        .json();
    assert_eq!(res["ok"], false);
    assert_eq!(res["broken_at"], 3);
}

#[tokio::test]
async fn verify_detects_a_deleted_row_and_a_rewritten_genesis() {
    let pool = pool_or_skip!();
    seed(&pool, 5).await;
    let app = afw_api::router(state(&pool));
    let viewer = token(&pool, "viewer", None).await;
    tamper(&pool, "DELETE FROM audit_log WHERE seq = 4").await;
    let res = call(&app, "GET", "/api/v1/audit/verify", Some(&viewer), None)
        .await
        .json();
    assert_eq!(res["ok"], false);
    assert_eq!(res["broken_at"], 5);

    let pool2 = pool_or_skip!();
    seed(&pool2, 3).await;
    tamper(&pool2, "DELETE FROM audit_log WHERE seq = 1").await;
    let app2 = afw_api::router(state(&pool2));
    let viewer2 = token(&pool2, "viewer", None).await;
    let res = call(&app2, "GET", "/api/v1/audit/verify", Some(&viewer2), None)
        .await
        .json();
    assert_eq!(res["ok"], false, "truncated head of chain");
    assert_eq!(res["broken_at"], 2);
}

#[tokio::test]
async fn export_is_ndjson_and_restricted() {
    let pool = pool_or_skip!();
    seed(&pool, 4).await;
    let app = afw_api::router(state(&pool));
    let viewer = token(&pool, "viewer", None).await;
    let auditor = token(&pool, "auditor", None).await;
    let res = call(&app, "GET", "/api/v1/audit/export", Some(&viewer), None).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    let res = call(&app, "GET", "/api/v1/audit/export?from_seq=2", Some(&auditor), None).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.headers["content-type"], "application/x-ndjson");
    let entries: Vec<AuditEntry> = res
        .text()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].seq, 2);
    afw_core::audit::verify_chain(&entries).unwrap();
}

#[tokio::test]
async fn anchor_is_appended_to_file_and_checked_by_verify() {
    let pool = pool_or_skip!();
    seed(&pool, 3).await;
    let dir = tempfile::tempdir().unwrap();
    let mut state = state(&pool);
    state.audit_export = Arc::new(AuditExportConfig {
        dir: Some(dir.path().to_path_buf()),
        ..Default::default()
    });
    let app = afw_api::router(state.clone());
    let admin = token(&pool, "admin", None).await;
    let auditor = token(&pool, "auditor", None).await;

    let res = call(&app, "POST", "/api/v1/audit/export", Some(&auditor), None).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    let res = call(&app, "POST", "/api/v1/audit/export", Some(&admin), None).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let anchor = res.json();
    assert_eq!(anchor["seq"], 3);
    let file = dir.path().join("audit-anchors.jsonl");
    let content = std::fs::read_to_string(&file).unwrap();
    assert_eq!(content.lines().count(), 1);
    let line: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(line["seq"], 3);
    assert_eq!(line["hash"], anchor["hash"]);
    assert!(line["at"].is_string());

    // The periodic task does not write a new line while the head did not move.
    afw_api::audit::export::anchor_if_moved(&state).await.unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap().lines().count(), 1);
    seed(&pool, 1).await;
    afw_api::audit::export::anchor_if_moved(&state).await.unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap().lines().count(), 2);

    let verify = call(&app, "GET", "/api/v1/audit/verify", Some(&auditor), None)
        .await
        .json();
    assert_eq!(verify["ok"], true, "{verify}");

    // A complete rewrite of the chain is consistent in itself but contradicts the anchor.
    let mut forged = afw_api::audit::load(&pool, 1, 100).await.unwrap();
    forged[0].target = "x:forged".into();
    let mut prev = afw_core::audit::GENESIS_HASH.to_owned();
    for e in forged.iter_mut() {
        e.prev_hash = prev.clone();
        e.hash = afw_core::audit::audit_hash(&prev, e);
        prev = e.hash.clone();
    }
    afw_core::audit::verify_chain(&forged).unwrap();
    for e in &forged {
        tamper(
            &pool,
            &format!(
                "UPDATE audit_log SET target = '{}', prev_hash = '{}', hash = '{}' WHERE seq = {}",
                e.target, e.prev_hash, e.hash, e.seq
            ),
        )
        .await;
    }
    let verify = call(&app, "GET", "/api/v1/audit/verify", Some(&auditor), None)
        .await
        .json();
    assert_eq!(verify["ok"], false, "{verify}");
    // The earliest contradicted anchor.
    assert_eq!(verify["broken_at"], 3);
}

#[tokio::test]
async fn anchor_is_put_to_s3_with_object_lock() {
    let pool = pool_or_skip!();
    seed(&pool, 2).await;
    // Fake S3 endpoint recording the request.
    let seen: Arc<Mutex<Vec<(String, axum::http::HeaderMap, Vec<u8>)>>> = Default::default();
    let s = seen.clone();
    let s3 = axum::Router::new().fallback(
        move |req: axum::extract::Request| {
            let s = s.clone();
            async move {
                let (parts, body) = req.into_parts();
                let body = axum::body::to_bytes(body, 1 << 20).await.unwrap();
                s.lock()
                    .unwrap()
                    .push((format!("{} {}", parts.method, parts.uri), parts.headers, body.to_vec()));
                StatusCode::OK
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, s3).await.unwrap() });

    let mut state = state(&pool);
    state.audit_export = Arc::new(AuditExportConfig {
        dir: None,
        s3: Some(S3Config {
            endpoint,
            bucket: "afw-audit".into(),
            region: "eu-west-3".into(),
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "secret".into(),
            prefix: "anchors/".into(),
            retention_days: 30,
        }),
        ..Default::default()
    });
    let anchor = afw_api::audit::export::anchor_now(&state).await.unwrap();
    assert_eq!(anchor.seq, 2);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let (line, headers, body) = &seen[0];
    assert!(line.starts_with("PUT /afw-audit/anchors/"), "{line}");
    assert_eq!(headers["x-amz-object-lock-mode"], "COMPLIANCE");
    let until = headers["x-amz-object-lock-retain-until-date"]
        .to_str()
        .unwrap();
    let until: chrono::DateTime<chrono::Utc> = until.parse().unwrap();
    assert!(until > chrono::Utc::now() + chrono::Duration::days(29));
    assert!(headers.contains_key("x-amz-checksum-sha256"));
    let auth = headers["authorization"].to_str().unwrap();
    assert!(
        auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"),
        "{auth}"
    );
    assert!(auth.contains("/eu-west-3/s3/aws4_request"));
    assert!(auth.contains("x-amz-object-lock-mode"));
    let doc: serde_json::Value = serde_json::from_slice(body).unwrap();
    assert_eq!(doc["seq"], 2);
    assert_eq!(doc["hash"], anchor.hash.as_str());
}
