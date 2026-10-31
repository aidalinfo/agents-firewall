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
            if i % 3 == 0 {
                "rule.create"
            } else {
                "zone.update"
            },
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

    let seqs = |v: &serde_json::Value| -> Vec<i64> {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["seq"].as_i64().unwrap())
            .collect()
    };
    // Default: most recent first.
    let page = call(&app, "GET", "/api/v1/audit?limit=3", Some(&viewer), None).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let body = page.json();
    assert_eq!(seqs(&body), vec![7, 6, 5]);
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
    assert_eq!(seqs(&next), vec![4, 3, 2]);
    let last = call(
        &app,
        "GET",
        &format!(
            "/api/v1/audit?limit=3&cursor={}",
            next["next_cursor"].as_str().unwrap()
        ),
        Some(&viewer),
        None,
    )
    .await
    .json();
    assert_eq!(seqs(&last), vec![1]);
    assert!(last["next_cursor"].is_null());

    // order=asc: oldest first, the cursor continues forward.
    let page = call(
        &app,
        "GET",
        "/api/v1/audit?limit=3&order=asc",
        Some(&viewer),
        None,
    )
    .await
    .json();
    assert_eq!(seqs(&page), vec![1, 2, 3]);
    let cursor = page["next_cursor"].as_str().unwrap().to_owned();
    let next = call(
        &app,
        "GET",
        &format!("/api/v1/audit?limit=3&order=asc&cursor={cursor}"),
        Some(&viewer),
        None,
    )
    .await
    .json();
    assert_eq!(seqs(&next), vec![4, 5, 6]);
    let desc = call(
        &app,
        "GET",
        "/api/v1/audit?limit=2&order=desc&from_seq=4",
        Some(&viewer),
        None,
    )
    .await
    .json();
    assert_eq!(seqs(&desc), vec![7, 6]);
    let bad = call(&app, "GET", "/api/v1/audit?order=up", Some(&viewer), None).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    let all = |q: &str| {
        let app = app.clone();
        let viewer = viewer.clone();
        let q = q.to_owned();
        async move {
            let r = call(
                &app,
                "GET",
                &format!("/api/v1/audit?{q}"),
                Some(&viewer),
                None,
            )
            .await;
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
    let bad = call(
        &app,
        "GET",
        "/api/v1/audit?interface=telnet",
        Some(&viewer),
        None,
    )
    .await;
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

    tamper(
        &pool,
        "UPDATE audit_log SET target = 'rule:innocent' WHERE seq = 3",
    )
    .await;
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
    let res = call(
        &app,
        "GET",
        "/api/v1/audit/export?from_seq=2",
        Some(&auditor),
        None,
    )
    .await;
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
    afw_api::audit::export::anchor_if_moved(&state)
        .await
        .unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap().lines().count(), 1);
    seed(&pool, 1).await;
    afw_api::audit::export::anchor_if_moved(&state)
        .await
        .unwrap();
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

/// Fake S3 (path-style, mounted under `/s3base`) that checks every SigV4 signature, stores
/// PUT objects, and serves ListObjectsV2 and GET.
struct FakeS3 {
    endpoint: String,
    objects: Arc<Mutex<std::collections::BTreeMap<String, Vec<u8>>>>,
    requests: Arc<Mutex<Vec<(String, axum::http::HeaderMap)>>>,
}

fn check_signature(method: &str, uri: &axum::http::Uri, headers: &axum::http::HeaderMap) -> bool {
    use afw_api::audit::sigv4;
    let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let field = |name: &str| {
        auth.split([',', ' '])
            .find_map(|p| p.trim().strip_prefix(name))
            .unwrap_or("")
            .to_owned()
    };
    let credential = field("Credential=");
    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 {
        return false;
    }
    let signed: Vec<String> = field("SignedHeaders=")
        .split(';')
        .map(str::to_owned)
        .collect();
    let hv: Vec<(String, String)> = signed
        .iter()
        .map(|h| {
            (
                h.clone(),
                headers
                    .get(h.as_str())
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned(),
            )
        })
        .collect();
    let date = headers["x-amz-date"].to_str().unwrap();
    let at = chrono::NaiveDateTime::parse_from_str(date, "%Y%m%dT%H%M%SZ")
        .unwrap()
        .and_utc();
    let mut query: Vec<&str> = uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|q| !q.is_empty())
        .collect();
    query.sort();
    let expected = sigv4::authorization(
        &sigv4::SigningParams {
            access_key_id: parts[0],
            secret_access_key: "secret",
            region: parts[2],
            service: "s3",
            at,
        },
        method,
        uri.path(),
        &query.join("&"),
        &hv,
        headers["x-amz-content-sha256"].to_str().unwrap(),
    );
    expected == auth
}

impl FakeS3 {
    async fn start() -> Self {
        let objects: Arc<Mutex<std::collections::BTreeMap<String, Vec<u8>>>> = Default::default();
        let requests: Arc<Mutex<Vec<(String, axum::http::HeaderMap)>>> = Default::default();
        let (o, r) = (objects.clone(), requests.clone());
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let (o, r) = (o.clone(), r.clone());
            async move {
                use axum::response::IntoResponse;
                let (parts, body) = req.into_parts();
                let body = axum::body::to_bytes(body, 1 << 20).await.unwrap();
                r.lock().unwrap().push((
                    format!("{} {}", parts.method, parts.uri),
                    parts.headers.clone(),
                ));
                if !check_signature(parts.method.as_str(), &parts.uri, &parts.headers) {
                    return (StatusCode::FORBIDDEN, "SignatureDoesNotMatch").into_response();
                }
                let Some(rest) = parts.uri.path().strip_prefix("/s3base/afw-audit") else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                let key = rest.trim_start_matches('/').to_owned();
                match parts.method.as_str() {
                    "PUT" => {
                        o.lock().unwrap().insert(key, body.to_vec());
                        StatusCode::OK.into_response()
                    }
                    "GET" if key.is_empty() => {
                        let q = parts.uri.query().unwrap_or("");
                        assert!(q.contains("list-type=2"), "{q}");
                        let prefix = q
                            .split('&')
                            .find_map(|p| p.strip_prefix("prefix="))
                            .unwrap_or("")
                            .replace("%2F", "/");
                        let keys: String = o
                            .lock()
                            .unwrap()
                            .keys()
                            .filter(|k| k.starts_with(&prefix))
                            .map(|k| format!("<Contents><Key>{k}</Key></Contents>"))
                            .collect();
                        format!(
                            "<?xml version=\"1.0\"?><ListBucketResult>{keys}\
                             <IsTruncated>false</IsTruncated></ListBucketResult>"
                        )
                        .into_response()
                    }
                    "GET" => match o.lock().unwrap().get(&key) {
                        Some(b) => b.clone().into_response(),
                        None => StatusCode::NOT_FOUND.into_response(),
                    },
                    _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/s3base", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            endpoint,
            objects,
            requests,
        }
    }

    fn config(&self) -> S3Config {
        S3Config {
            endpoint: self.endpoint.clone(),
            bucket: "afw-audit".into(),
            region: "eu-west-3".into(),
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "secret".into(),
            prefix: "anchors/".into(),
            retention_days: 30,
        }
    }
}

async fn forge_complete_rewrite(pool: &sqlx::PgPool) {
    let mut forged = afw_api::audit::load(pool, 1, 100).await.unwrap();
    forged[0].target = "x:forged".into();
    let mut prev = afw_core::audit::GENESIS_HASH.to_owned();
    for e in forged.iter_mut() {
        e.prev_hash = prev.clone();
        e.hash = afw_core::audit::audit_hash(&prev, e);
        prev = e.hash.clone();
    }
    for e in &forged {
        tamper(
            pool,
            &format!(
                "UPDATE audit_log SET target = '{}', prev_hash = '{}', hash = '{}' WHERE seq = {}",
                e.target, e.prev_hash, e.hash, e.seq
            ),
        )
        .await;
    }
}

#[tokio::test]
async fn anchor_is_put_to_s3_with_object_lock() {
    let pool = pool_or_skip!();
    seed(&pool, 2).await;
    let s3 = FakeS3::start().await;
    let mut state = state(&pool);
    state.audit_export = Arc::new(AuditExportConfig {
        dir: None,
        s3: Some(s3.config()),
        ..Default::default()
    });
    // The endpoint has a path (`/s3base`): the signature covers it.
    let anchor = afw_api::audit::export::anchor_now(&state).await.unwrap();
    assert_eq!(anchor.seq, 2);
    {
        let reqs = s3.requests.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let (line, headers) = &reqs[0];
        assert!(line.starts_with("PUT /s3base/afw-audit/anchors/"), "{line}");
        assert_eq!(headers["x-amz-object-lock-mode"], "COMPLIANCE");
        let until: chrono::DateTime<chrono::Utc> = headers["x-amz-object-lock-retain-until-date"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(until > chrono::Utc::now() + chrono::Duration::days(29));
        assert!(headers.contains_key("x-amz-checksum-sha256"));
    }
    let objects = s3.objects.lock().unwrap().clone();
    assert_eq!(objects.len(), 1, "signature refused by the fake S3");
    let doc: serde_json::Value = serde_json::from_slice(objects.values().next().unwrap()).unwrap();
    assert_eq!(doc["seq"], 2);
    assert_eq!(doc["hash"], anchor.hash.as_str());

    let app = afw_api::router(state);
    let viewer = token(&pool, "viewer", None).await;
    let verify = call(&app, "GET", "/api/v1/audit/verify", Some(&viewer), None)
        .await
        .json();
    assert_eq!(verify["ok"], true, "{verify}");
    assert_eq!(verify["anchor_sources"], json!(["db", "s3"]));

    // Complete rewrite AND removal of the database anchors: the S3 anchor still catches it.
    forge_complete_rewrite(&pool).await;
    sqlx::query("DELETE FROM audit_anchors")
        .execute(&pool)
        .await
        .unwrap();
    let verify = call(&app, "GET", "/api/v1/audit/verify", Some(&viewer), None)
        .await
        .json();
    assert_eq!(verify["ok"], false, "{verify}");
    assert_eq!(verify["broken_at"], 2);
    let reqs = s3.requests.lock().unwrap();
    assert!(
        reqs.iter()
            .any(|(l, _)| l.starts_with("GET /s3base/afw-audit?"))
    );
}

#[tokio::test]
async fn verify_reports_its_anchor_sources() {
    let pool = pool_or_skip!();
    seed(&pool, 1).await;
    let dir = tempfile::tempdir().unwrap();
    let mut st = state(&pool);
    let app = afw_api::router(st.clone());
    let viewer = token(&pool, "viewer", None).await;
    let v = call(&app, "GET", "/api/v1/audit/verify", Some(&viewer), None)
        .await
        .json();
    assert_eq!(v["anchor_sources"], json!(["db"]));
    st.audit_export = Arc::new(AuditExportConfig {
        dir: Some(dir.path().to_path_buf()),
        ..Default::default()
    });
    let app = afw_api::router(st);
    let v = call(&app, "GET", "/api/v1/audit/verify", Some(&viewer), None)
        .await
        .json();
    assert_eq!(v["anchor_sources"], json!(["db", "file"]));
}
