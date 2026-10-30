//! Periodic purge according to `settings.retention_days` of the latest published policy
//! (defaults of `Retention` when no policy is available).

use std::time::Duration as StdDuration;

use afw_core::policy::Retention;
use chrono::{Duration, Utc};

use super::captures;
use super::ingest::pool;
use super::store::LogStore;
use crate::AppState;
use crate::error::ApiError;

pub const INTERVAL: StdDuration = StdDuration::from_secs(3600);

/// One purge pass. Returns the number of deleted rows (approximate with ClickHouse).
pub async fn purge_once(state: &AppState, retention: Retention) -> Result<u64, ApiError> {
    let now = Utc::now();
    let days = |d: u32| now - Duration::days(i64::from(d.max(1)));
    let pool = pool(state)?;
    let mut n = state
        .logs
        .store()?
        .purge(days(retention.flows), days(retention.http))
        .await?;
    n += captures::purge(pool, days(retention.captures)).await?;
    n += sqlx::query("DELETE FROM alerts WHERE at < $1")
        .bind(days(retention.flows))
        .execute(pool)
        .await?
        .rows_affected();
    n += sqlx::query("DELETE FROM agent_destinations WHERE last_seen_at < $1")
        .bind(days(retention.flows))
        .execute(pool)
        .await?
        .rows_affected();
    n += sqlx::query("DELETE FROM ingested_batches WHERE ingested_at < $1")
        .bind(now - Duration::days(7))
        .execute(pool)
        .await?
        .rows_affected();
    captures::expire_stale(pool).await?;
    Ok(n)
}

/// Current retention settings.
pub async fn current(state: &AppState) -> Retention {
    state
        .logs
        .load_policy(None)
        .await
        .map(|d| d.settings.retention_days)
        .unwrap_or_default()
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(INTERVAL);
        loop {
            tick.tick().await;
            let retention = current(&state).await;
            match purge_once(&state, retention).await {
                Ok(n) => tracing::info!(deleted = n, "log retention pass"),
                Err(e) => tracing::warn!(error = %e, "log retention pass failed"),
            }
        }
    });
}
