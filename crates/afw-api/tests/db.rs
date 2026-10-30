//! Tests against a real PostgreSQL, skipped when `AFW_TEST_DATABASE_URL` is not set.

use afw_api::auth::Principal;
use afw_api::auth::principal::upsert_bootstrap_token;
use afw_api::{AppState, Config, audit, migrate};
use afw_core::api::Role;
use afw_core::audit::{GENESIS_HASH, verify_chain};
use afw_core::events::Interface;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use sqlx::PgPool;
use tower::ServiceExt;

/// One pool per test: each `#[tokio::test]` has its own runtime.
async fn pool() -> Option<PgPool> {
    let url = std::env::var("AFW_TEST_DATABASE_URL").ok()?;
    let pool = PgPool::connect(&url).await.expect("connect test database");
    migrate(&pool).await.expect("migrations");
    Some(pool)
}

#[tokio::test]
async fn audit_record_builds_a_verifiable_chain() {
    let Some(pool) = pool().await else {
        eprintln!("AFW_TEST_DATABASE_URL not set: skipped");
        return;
    };
    let principal = Principal::for_tests(Role::Admin);
    for i in 0..3 {
        let mut tx = pool.begin().await.unwrap();
        audit::record(
            &mut tx,
            &principal,
            None,
            "rule.create",
            &format!("rule:{i}"),
            serde_json::json!({"after": {"name": format!("r{i}"), "position": i, "ratio": 0.5}}),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    // A rolled-back change leaves no hole in the chain.
    let mut tx = pool.begin().await.unwrap();
    audit::record(&mut tx, &principal, None, "x", "y", serde_json::Value::Null)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    audit::record_content_access(&pool, &principal, uuid::Uuid::nil())
        .await
        .unwrap();

    let entries = audit::load(&pool, 1, 100_000).await.unwrap();
    assert!(entries.len() >= 4);
    assert_eq!(entries[0].prev_hash, GENESIS_HASH);
    assert_eq!(verify_chain(&entries), Ok(()));

    // Append-only at the database level.
    assert!(
        sqlx::query("UPDATE audit_log SET action = 'tampered'")
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM audit_log")
            .execute(&pool)
            .await
            .is_err()
    );
}

async fn whoami(p: Principal) -> String {
    format!("{:?}/{:?}", p.role, p.interface)
}

#[tokio::test]
async fn bearer_token_authenticates_principal() {
    let Some(pool) = pool().await else {
        eprintln!("AFW_TEST_DATABASE_URL not set: skipped");
        return;
    };
    upsert_bootstrap_token(&pool, "first-secret").await.unwrap();
    upsert_bootstrap_token(&pool, "boot-secret").await.unwrap();
    let app: Router = Router::new()
        .route("/whoami", get(whoami))
        .with_state(AppState::new(Config::default(), Some(pool)));
    let call = |auth: Option<&str>, iface: Option<&str>| {
        let mut req = Request::get("/whoami");
        if let Some(a) = auth {
            req = req.header("authorization", a);
        }
        if let Some(i) = iface {
            req = req.header("x-afw-interface", i);
        }
        app.clone().oneshot(req.body(Body::empty()).unwrap())
    };
    let ok = call(Some("Bearer boot-secret"), Some("cli")).await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(ok.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(
        &body[..],
        format!("{:?}/{:?}", Role::Admin, Interface::Cli).as_bytes()
    );

    for auth in [
        None,
        Some("Bearer wrong"),
        Some("Bearer first-secret"),
        Some("Basic boot-secret"),
    ] {
        let res = call(auth, None).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{auth:?}");
        assert_eq!(res.headers()["content-type"], "application/problem+json");
    }
}

#[test]
fn roles_are_ordered() {
    let viewer = Principal::for_tests(Role::Viewer);
    assert!(viewer.require(Role::Viewer).is_ok());
    assert!(viewer.require(Role::Auditor).is_err());
    assert!(!viewer.can_see_content());
    let auditor = Principal::for_tests(Role::Auditor);
    assert!(auditor.require(Role::Auditor).is_ok());
    assert!(auditor.require(Role::Admin).is_err());
    assert!(auditor.can_see_content());
    let mcp = Principal::for_tests(Role::McpAgent);
    assert!(mcp.require(Role::Admin).is_ok());
    assert_eq!(mcp.interface, Interface::Mcp);
    assert!(!mcp.can_see_content());
}
