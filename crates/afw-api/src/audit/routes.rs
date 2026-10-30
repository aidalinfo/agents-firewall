//! `GET /audit`, `GET /audit/verify`, `GET /audit/export` (NDJSON), `POST /audit/export`
//! (immediate anchor).

use std::collections::BTreeMap;

use afw_core::api::{AuditVerifyResult, Page, Role};
use afw_core::audit::{GENESIS_HASH, audit_hash};
use afw_core::events::{AuditEntry, Interface};
use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, QueryBuilder};

use super::export::{self, Anchor, AuditExportConfig};
use super::{AUDIT_COLUMNS, AuditRow, interface_str, load, row_to_entry};
use crate::AppState;
use crate::auth::Principal;
use crate::auth::tokens::pool;
use crate::error::ApiError;

const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 1000;
const BATCH: i64 = 1000;

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    pub from_seq: Option<i64>,
    /// Actor id or name.
    pub actor: Option<String>,
    /// Exact action, or a prefix ending with `*` (`rule.*`).
    pub action: Option<String>,
    pub interface: Option<Interface>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// `GET /audit` (viewer): ascending `seq`, cursor = last returned `seq`.
pub async fn list(
    State(state): State<AppState>,
    principal: Principal,
    q: Result<Query<AuditQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Page<AuditEntry>>, ApiError> {
    principal.require(Role::Viewer)?;
    let Query(q) = q.map_err(|e| ApiError::BadRequest(e.body_text()))?;
    let limit = i64::from(q.limit.unwrap_or(DEFAULT_LIMIT as u32)).clamp(1, MAX_LIMIT);
    let after: i64 = match &q.cursor {
        None => 0,
        Some(c) => c
            .parse()
            .map_err(|_| ApiError::BadRequest("invalid cursor".into()))?,
    };
    let mut b: QueryBuilder<Postgres> = QueryBuilder::new(format!(
        "SELECT {AUDIT_COLUMNS} FROM audit_log WHERE seq > "
    ));
    b.push_bind(after);
    if let Some(from_seq) = q.from_seq {
        b.push(" AND seq >= ").push_bind(from_seq);
    }
    if let Some(actor) = &q.actor {
        b.push(" AND (actor->>'id' = ")
            .push_bind(actor.clone())
            .push(" OR actor->>'name' = ")
            .push_bind(actor.clone())
            .push(")");
    }
    if let Some(action) = &q.action {
        match action.strip_suffix('*') {
            Some(prefix) => {
                b.push(" AND action LIKE ")
                    .push_bind(format!("{}%", like_escape(prefix)))
                    .push(" ESCAPE '\\'");
            }
            None => {
                b.push(" AND action = ").push_bind(action.clone());
            }
        }
    }
    if let Some(i) = q.interface {
        b.push(" AND interface = ").push_bind(interface_str(i));
    }
    if let Some(from) = q.from {
        b.push(" AND at >= ").push_bind(from);
    }
    if let Some(to) = q.to {
        b.push(" AND at < ").push_bind(to);
    }
    b.push(" ORDER BY seq LIMIT ").push_bind(limit);
    let rows: Vec<AuditRow> = b.build_query_as().fetch_all(pool(&state)?).await?;
    let items = rows
        .into_iter()
        .map(row_to_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = (items.len() as i64 == limit)
        .then(|| items.last().map(|e| e.seq.to_string()))
        .flatten();
    Ok(Json(Page { items, next_cursor }))
}

/// `GET /audit/verify` response: [`AuditVerifyResult`] plus the anchor sources compared.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct AuditVerifyReport {
    #[serde(flatten)]
    pub result: AuditVerifyResult,
    /// Sources of the anchors the chain was compared with, in order: `db` (anchors table),
    /// `file` (`AFW_AUDIT_EXPORT_DIR`), `s3` (`AFW_AUDIT_S3_*`).
    pub anchor_sources: Vec<&'static str>,
}

/// Anchors from every source: the anchors table, the export file and the S3 bucket when
/// configured. A configured source that cannot be read is an error (never skipped).
async fn anchors(
    pool: &PgPool,
    cfg: &AuditExportConfig,
) -> Result<(Vec<Anchor>, Vec<&'static str>), ApiError> {
    let rows: Vec<(i64, String, DateTime<Utc>)> =
        sqlx::query_as("SELECT seq, hash, at FROM audit_anchors ORDER BY id")
            .fetch_all(pool)
            .await?;
    let mut out: Vec<Anchor> = rows
        .into_iter()
        .map(|(seq, hash, at)| Anchor { seq, hash, at })
        .collect();
    let mut sources = vec!["db"];
    if let Some(dir) = &cfg.dir {
        let dir = dir.clone();
        out.extend(
            tokio::task::spawn_blocking(move || export::read_file_anchors(&dir))
                .await
                .map_err(|e| ApiError::Internal(e.to_string()))??,
        );
        sources.push("file");
    }
    if let Some(s3) = &cfg.s3 {
        out.extend(export::read_s3_anchors(s3).await?);
        sources.push("s3");
    }
    Ok((out, sources))
}

/// Verifies the whole chain from the genesis: contiguous `seq` from 1, chaining, recomputed
/// hashes, and agreement with every exported anchor. `broken_at` is the first broken `seq`.
pub async fn verify(pool: &PgPool, cfg: &AuditExportConfig) -> Result<AuditVerifyReport, ApiError> {
    // seq -> expected hashes (several anchors may name the same seq).
    let mut expected: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    let (all, anchor_sources) = anchors(pool, cfg).await?;
    for a in all {
        expected.entry(a.seq).or_default().push(a.hash);
    }
    let head: Option<(i64, String)> =
        sqlx::query_as("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            .fetch_optional(pool)
            .await?;
    let mut checked: u64 = 0;
    let mut broken_at: Option<i64> = None;
    let mut prev: Option<(i64, String)> = None;
    let mut from = 1i64;
    'walk: loop {
        let batch = load(pool, from, BATCH).await?;
        let Some(last) = batch.last() else { break };
        from = last.seq + 1;
        for e in &batch {
            let (want_seq, want_prev) = match &prev {
                None => (1, GENESIS_HASH.to_owned()),
                Some((s, h)) => (s + 1, h.clone()),
            };
            let anchored_ok = expected
                .get(&e.seq)
                .is_none_or(|hashes| hashes.iter().all(|h| *h == e.hash));
            if e.seq != want_seq
                || e.prev_hash != want_prev
                || audit_hash(&e.prev_hash, e) != e.hash
                || !anchored_ok
            {
                broken_at = Some(e.seq);
                break 'walk;
            }
            checked += 1;
            prev = Some((e.seq, e.hash.clone()));
        }
    }
    // An anchor beyond the verified chain (truncation) or contradicted earlier than the first
    // break also breaks it.
    let verified_to = prev.as_ref().map_or(0, |(s, _)| *s);
    if let Some((&seq, _)) = expected
        .iter()
        .find(|(seq, _)| **seq > verified_to && broken_at.is_none_or(|b| **seq < b))
    {
        broken_at = Some(seq);
    }
    Ok(AuditVerifyReport {
        result: AuditVerifyResult {
            ok: broken_at.is_none(),
            checked,
            broken_at,
            head_seq: head.as_ref().map(|h| h.0),
            head_hash: head.map(|h| h.1),
        },
        anchor_sources,
    })
}

/// `GET /audit/verify` (viewer).
pub async fn verify_handler(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<Json<AuditVerifyReport>, ApiError> {
    principal.require(Role::Viewer)?;
    verify(pool(&state)?, &state.audit_export).await.map(Json)
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct ExportQuery {
    pub from_seq: Option<i64>,
}

/// `GET /audit/export` (auditor): NDJSON, one `AuditEntry` per line, streamed by batches.
pub async fn export_ndjson(
    State(state): State<AppState>,
    principal: Principal,
    q: Result<Query<ExportQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, ApiError> {
    principal.require(Role::Auditor)?;
    let Query(q) = q.map_err(|e| ApiError::BadRequest(e.body_text()))?;
    let pool = pool(&state)?.clone();
    let start = q.from_seq.unwrap_or(1).max(1);
    let stream = futures::stream::unfold(Some(start), move |next| {
        let pool = pool.clone();
        async move {
            let from = next?;
            match load(&pool, from, BATCH).await {
                Ok(batch) if batch.is_empty() => None,
                Ok(batch) => {
                    let following = batch.last().map(|e| e.seq + 1);
                    let mut chunk = Vec::new();
                    for e in &batch {
                        if let Ok(line) = serde_json::to_vec(e) {
                            chunk.extend_from_slice(&line);
                            chunk.push(b'\n');
                        }
                    }
                    Some((Ok::<_, std::io::Error>(Bytes::from(chunk)), following))
                }
                Err(e) => Some((Err(std::io::Error::other(e.to_string())), None)),
            }
        }
    });
    Ok((
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from_stream(stream),
    )
        .into_response())
}

/// `POST /audit/export` (admin): exports the chain head now.
pub async fn export_anchor(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<Json<Anchor>, ApiError> {
    principal.require(Role::Admin)?;
    export::anchor_now(&state).await.map(Json)
}
