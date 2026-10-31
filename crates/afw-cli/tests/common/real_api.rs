//! The real control-plane API (afw-api) on an ephemeral port, on a fresh PostgreSQL database
//! (`AFW_TEST_DATABASE_URL`), with an admin token. Tests are skipped without the variable.

use std::str::FromStr;

use afw_api::{AppState, Config, migrate};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, PgPool};
use uuid::Uuid;

#[allow(dead_code)]
pub struct RealApi {
    pub url: String,
    pub admin_token: String,
    pub pool: PgPool,
}

pub async fn start() -> Option<RealApi> {
    let url = std::env::var("AFW_TEST_DATABASE_URL").ok()?;
    let admin = PgConnectOptions::from_str(&url).expect("database url");
    let name = format!("afw_l8_{}", Uuid::new_v4().simple());
    let mut conn = admin.connect().await.expect("connect test server");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut conn)
        .await
        .expect("create test database");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(admin.database(&name))
        .await
        .expect("connect test database");
    migrate(&pool).await.expect("migrations");
    let admin_token = format!("admin-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO api_tokens (name, token_sha256, role, actor_kind, actor_name, created_by) \
         VALUES ('admin', $1, 'admin', 'human', 'Alice', '{\"kind\":\"system\",\"id\":\"t\",\"name\":\"t\"}')",
    )
    .bind(afw_core::sha256_hex(admin_token.as_bytes()))
    .execute(&pool)
    .await
    .expect("insert admin token");
    let app = afw_api::router(AppState::new(Config::default(), Some(pool.clone())));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Some(RealApi {
        url: format!("http://{addr}"),
        admin_token,
        pool,
    })
}
