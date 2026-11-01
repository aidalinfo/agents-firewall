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
    // Unique secrets: the database is shared by concurrent tests and successive runs.
    let n = uuid::Uuid::new_v4();
    let (admin, expired, until, revoked) = (
        format!("admin-{n}"),
        format!("expired-{n}"),
        format!("until-{n}"),
        format!("revoked-{n}"),
    );
    insert_token(&pool, &admin, "admin", None, "NULL").await;
    insert_token(
        &pool,
        &expired,
        "admin",
        None,
        "now() - interval '1 second'",
    )
    .await;
    insert_token(&pool, &until, "viewer", None, "now() + interval '1 hour'").await;
    insert_token(&pool, &revoked, "admin", None, "NULL").await;
    sqlx::query("UPDATE api_tokens SET revoked_at = now() WHERE name = $1")
        .bind(&revoked)
        .execute(&pool)
        .await
        .unwrap();
    let app: Router = Router::new()
        .route("/whoami", get(whoami))
        .with_state(AppState::new(Config::default(), Some(pool)));
    let call = |auth: Option<String>, iface: Option<&str>| {
        let mut req = Request::get("/whoami");
        if let Some(a) = auth {
            req = req.header("authorization", a);
        }
        if let Some(i) = iface {
            req = req.header("x-afw-interface", i);
        }
        app.clone().oneshot(req.body(Body::empty()).unwrap())
    };
    let ok = call(Some(format!("Bearer {admin}")), Some("cli"))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(ok.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(
        &body[..],
        format!("{:?}/{:?}", Role::Admin, Interface::Cli).as_bytes()
    );
    let lower = call(Some(format!("bearer {admin}")), None).await.unwrap();
    assert_eq!(lower.status(), StatusCode::OK, "scheme is case-insensitive");
    let res = call(Some(format!("Bearer {until}")), None).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    for auth in [
        None,
        Some("Bearer wrong".to_owned()),
        Some(format!("Bearer {revoked}")),
        Some(format!("Basic {admin}")),
        Some(format!("Bearer {expired}")),
        Some("Bearer".to_owned()),
    ] {
        let res = call(auth.clone(), None).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{auth:?}");
        assert_eq!(res.headers()["content-type"], "application/problem+json");
    }
}

async fn insert_token(
    pool: &PgPool,
    secret: &str,
    role: &str,
    agent: Option<uuid::Uuid>,
    expires: &str,
) {
    sqlx::query(&format!(
        "INSERT INTO api_tokens (name, token_sha256, role, actor_kind, actor_name, agent_id, \
         created_by, expires_at) VALUES ($1, $2, $3, 'human', $1, $4, '{{}}', {expires})"
    ))
    .bind(secret)
    .bind(afw_core::sha256_hex(secret.as_bytes()))
    .bind(role)
    .bind(agent)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn revoked_bootstrap_token_is_not_reactivated() {
    let Some(pool) = pool().await else {
        eprintln!("AFW_TEST_DATABASE_URL not set: skipped");
        return;
    };
    // A new bootstrap token revokes the previous one.
    upsert_bootstrap_token(&pool, "previous-boot")
        .await
        .unwrap();
    upsert_bootstrap_token(&pool, "revoked-boot").await.unwrap();
    let previous_revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM api_tokens WHERE token_sha256 = $1")
            .bind(afw_core::sha256_hex(b"previous-boot"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(previous_revoked);
    sqlx::query("UPDATE api_tokens SET revoked_at = now() WHERE token_sha256 = $1")
        .bind(afw_core::sha256_hex(b"revoked-boot"))
        .execute(&pool)
        .await
        .unwrap();
    upsert_bootstrap_token(&pool, "revoked-boot").await.unwrap();
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM api_tokens WHERE token_sha256 = $1")
            .bind(afw_core::sha256_hex(b"revoked-boot"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(revoked);
}

#[tokio::test]
async fn only_one_active_mcp_agent_token() {
    let Some(pool) = pool().await else {
        eprintln!("AFW_TEST_DATABASE_URL not set: skipped");
        return;
    };
    sqlx::query("UPDATE api_tokens SET revoked_at = now() WHERE role = 'mcp_agent'")
        .execute(&pool)
        .await
        .unwrap();
    let agent = Some(uuid::Uuid::new_v4());
    insert_token(
        &pool,
        &format!("mcp-{}", uuid::Uuid::new_v4()),
        "mcp_agent",
        agent,
        "NULL",
    )
    .await;
    let second = sqlx::query(
        "INSERT INTO api_tokens (name, token_sha256, role, actor_kind, actor_name, created_by) \
         VALUES ('mcp2', $1, 'mcp_agent', 'agent', 'mcp2', '{}')",
    )
    .bind(afw_core::sha256_hex(uuid::Uuid::new_v4().as_bytes()))
    .execute(&pool)
    .await;
    assert!(
        second.is_err(),
        "a second active mcp_agent token must be refused"
    );
}
