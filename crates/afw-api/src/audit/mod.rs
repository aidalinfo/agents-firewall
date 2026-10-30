//! Hash-chained audit log: recording (shared by every lot), listing, verification, export
//! (routes: lot L7c).

use afw_core::audit::{GENESIS_HASH, audit_hash};
use afw_core::events::{Actor, AuditEntry, Interface};
use axum::Router;
use chrono::{DateTime, Utc};
use sqlx::types::Json;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::AppState;
use crate::auth::Principal;
use crate::error::ApiError;

/// Advisory lock key serializing appends to the audit chain.
const AUDIT_LOCK_KEY: i64 = 0x0061_6677_6175_6474; // "afwaudt"

/// Routes of this module, nested by [`crate::router`].
pub fn routes() -> Router<AppState> {
    Router::new()
}

fn interface_str(i: Interface) -> &'static str {
    match i {
        Interface::Ui => "ui",
        Interface::Cli => "cli",
        Interface::Mcp => "mcp",
        Interface::Api => "api",
        Interface::System => "system",
    }
}

/// Appends an entry to the audit chain. Call it inside the same transaction as the change it
/// records (`&mut *tx`): the transaction-scoped advisory lock serializes the chain, and a
/// rollback removes the entry together with the change, so `seq` stays contiguous.
pub async fn record(
    conn: &mut PgConnection,
    principal: &Principal,
    session_id: Option<Uuid>,
    action: &str,
    target: &str,
    diff: serde_json::Value,
) -> Result<AuditEntry, ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AUDIT_LOCK_KEY)
        .execute(&mut *conn)
        .await?;
    let last: Option<(i64, String)> =
        sqlx::query_as("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut *conn)
            .await?;
    let (seq, prev_hash) = match last {
        Some((seq, hash)) => (seq + 1, hash),
        None => (1, GENESIS_HASH.to_owned()),
    };
    // PostgreSQL stores microseconds: truncate so the stored entry hashes identically.
    let now = Utc::now();
    let at = DateTime::from_timestamp_micros(now.timestamp_micros()).unwrap_or(now);
    let mut entry = AuditEntry {
        seq,
        at,
        actor: principal.actor.clone(),
        interface: principal.interface,
        session_id,
        action: action.to_owned(),
        target: target.to_owned(),
        diff,
        prev_hash,
        hash: String::new(),
    };
    entry.hash = audit_hash(&entry.prev_hash, &entry);
    sqlx::query(
        "INSERT INTO audit_log (seq, at, actor, interface, session_id, action, target, diff, \
         prev_hash, hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(entry.seq)
    .bind(entry.at)
    .bind(Json(&entry.actor))
    .bind(interface_str(entry.interface))
    .bind(entry.session_id)
    .bind(&entry.action)
    .bind(&entry.target)
    .bind(Json(&entry.diff))
    .bind(&entry.prev_hash)
    .bind(&entry.hash)
    .execute(&mut *conn)
    .await?;
    Ok(entry)
}

/// Records that `principal` read the captured contents of a flow (EF-54).
pub async fn record_content_access(
    pool: &PgPool,
    principal: &Principal,
    flow_id: Uuid,
) -> Result<AuditEntry, ApiError> {
    let mut tx = pool.begin().await?;
    let entry = record(
        &mut tx,
        principal,
        None,
        "flow.content_access",
        &format!("flow:{flow_id}"),
        serde_json::Value::Null,
    )
    .await?;
    tx.commit().await?;
    Ok(entry)
}

type AuditRow = (
    i64,
    DateTime<Utc>,
    Json<Actor>,
    String,
    Option<Uuid>,
    String,
    String,
    Json<serde_json::Value>,
    String,
    String,
);

/// Reads entries with `seq >= from_seq`, in order (at most `limit`).
pub async fn load(pool: &PgPool, from_seq: i64, limit: i64) -> Result<Vec<AuditEntry>, ApiError> {
    let rows: Vec<AuditRow> = sqlx::query_as(
        "SELECT seq, at, actor, interface, session_id, action, target, diff, prev_hash, hash \
         FROM audit_log WHERE seq >= $1 ORDER BY seq LIMIT $2",
    )
    .bind(from_seq)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            let interface = serde_json::from_value(serde_json::Value::String(r.3.clone()))
                .map_err(|_| ApiError::Internal(format!("invalid interface {:?}", r.3)))?;
            Ok(AuditEntry {
                seq: r.0,
                at: r.1,
                actor: r.2.0,
                interface,
                session_id: r.4,
                action: r.5,
                target: r.6,
                diff: r.7.0,
                prev_hash: r.8,
                hash: r.9,
            })
        })
        .collect()
}
