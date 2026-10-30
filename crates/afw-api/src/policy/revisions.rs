//! Revisions (list, detail, diff, revert) and pre-install verification (EF-10, EF-11).

use afw_core::api::{Page, Revision, RevisionDetail, RevisionDiff, Role, Session, VerifyReport};
use afw_core::events::Actor;
use afw_core::policy::PolicyDocument;
use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::PgConnection;
use sqlx::types::Json as SqlJson;
use uuid::Uuid;

use super::diff::diff_documents;
use super::sessions::revert_to;
use super::store::{self, owner_key, parse_enum, session_dto};
use super::{pool, session_header};
use crate::AppState;
use crate::auth::Principal;
use crate::error::ApiError;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/revisions", get(list_revisions))
        .route("/revisions/{n}", get(get_revision))
        .route("/revisions/{n}/diff", get(diff_revision))
        .route("/revisions/{n}/revert", post(revert))
        .route("/verify", get(verify))
}

type RawRevision = (
    i64,
    DateTime<Utc>,
    SqlJson<Actor>,
    String,
    Option<Uuid>,
    String,
    String,
);

type RawRevisionWithDoc = (
    i64,
    DateTime<Utc>,
    SqlJson<Actor>,
    String,
    Option<Uuid>,
    String,
    String,
    SqlJson<PolicyDocument>,
);

const COLUMNS: &str = "number, published_at, published_by, interface, session_id, comment, sha256";

fn from_raw(r: RawRevision) -> Result<Revision, ApiError> {
    Ok(Revision {
        number: r.0 as u64,
        published_at: r.1,
        published_by: r.2.0,
        interface: parse_enum(&r.3)?,
        session_id: r.4,
        comment: r.5,
        sha256: r.6,
    })
}

/// Revision metadata and document; 404 when absent.
pub async fn load_revision(conn: &mut PgConnection, n: u64) -> Result<RevisionDetail, ApiError> {
    let sql = format!("SELECT {COLUMNS}, document FROM revisions WHERE number = $1");
    let row: Option<RawRevisionWithDoc> = sqlx::query_as(&sql)
        .bind(n as i64)
        .fetch_optional(&mut *conn)
        .await?;
    let r = row.ok_or(ApiError::NotFound)?;
    Ok(RevisionDetail {
        revision: from_raw((r.0, r.1, r.2, r.3, r.4, r.5, r.6))?,
        document: r.7.0,
    })
}

#[derive(Deserialize)]
struct PageQuery {
    cursor: Option<String>,
    limit: Option<u32>,
}

async fn list_revisions(
    State(state): State<AppState>,
    p: Principal,
    Query(q): Query<PageQuery>,
) -> Result<Json<Page<Revision>>, ApiError> {
    p.require(Role::Viewer)?;
    let limit = i64::from(q.limit.unwrap_or(100).clamp(1, 1000));
    let below: i64 = match &q.cursor {
        Some(c) => c
            .parse()
            .map_err(|_| ApiError::BadRequest("invalid cursor".into()))?,
        None => i64::MAX,
    };
    let mut conn = pool(&state)?.acquire().await?;
    let sql =
        format!("SELECT {COLUMNS} FROM revisions WHERE number < $1 ORDER BY number DESC LIMIT $2");
    let rows: Vec<RawRevision> = sqlx::query_as(&sql)
        .bind(below)
        .bind(limit + 1)
        .fetch_all(&mut *conn)
        .await?;
    let mut items: Vec<Revision> = rows.into_iter().map(from_raw).collect::<Result<_, _>>()?;
    let next_cursor = if items.len() as i64 > limit {
        items.truncate(limit as usize);
        items.last().map(|r| r.number.to_string())
    } else {
        None
    };
    Ok(Json(Page { items, next_cursor }))
}

async fn get_revision(
    State(state): State<AppState>,
    p: Principal,
    Path(n): Path<u64>,
) -> Result<Json<RevisionDetail>, ApiError> {
    p.require(Role::Viewer)?;
    let mut conn = pool(&state)?.acquire().await?;
    Ok(Json(load_revision(&mut conn, n).await?))
}

#[derive(Deserialize)]
struct DiffQuery {
    against: Option<u64>,
}

async fn document_of(conn: &mut PgConnection, n: u64) -> Result<PolicyDocument, ApiError> {
    if n == 0 {
        return Ok(PolicyDocument::default());
    }
    Ok(load_revision(conn, n).await?.document)
}

async fn diff_revision(
    State(state): State<AppState>,
    p: Principal,
    Path(n): Path<u64>,
    Query(q): Query<DiffQuery>,
) -> Result<Json<RevisionDiff>, ApiError> {
    p.require(Role::Viewer)?;
    let mut conn = pool(&state)?.acquire().await?;
    let to = document_of(&mut conn, n).await?;
    let from_n = q.against.unwrap_or(n.saturating_sub(1));
    let from = document_of(&mut conn, from_n).await?;
    Ok(Json(RevisionDiff {
        from: from_n,
        to: n,
        changes: diff_documents(&from, &to),
    }))
}

/// Rollback: a new session of the caller whose draft is revision `n` (human admin only).
async fn revert(
    State(state): State<AppState>,
    p: Principal,
    Path(n): Path<u64>,
) -> Result<(StatusCode, Json<Session>), ApiError> {
    p.require(Role::Admin)?;
    let mut tx = pool(&state)?.begin().await?;
    let target = load_revision(&mut tx, n).await?.document;
    let session = revert_to(&mut tx, &p, &target).await?;
    let dto = session_dto(&mut tx, &session).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(dto)))
}

#[derive(Deserialize)]
struct VerifyQuery {
    revision: Option<u64>,
}

/// Verifies a revision, or the draft of the session given by `X-Afw-Session` (else the
/// caller's open session, else the published state).
async fn verify(
    State(state): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Query(q): Query<VerifyQuery>,
) -> Result<Json<VerifyReport>, ApiError> {
    p.require(Role::Viewer)?;
    let mut conn = pool(&state)?.acquire().await?;
    let doc = match q.revision {
        Some(n) => load_revision(&mut conn, n).await?.document,
        None => {
            let session = match session_header(&headers)? {
                Some(s) => Some(s),
                None => store::sessions_where(
                    &mut conn,
                    "owner_key = $1 AND state = 'open'",
                    Some(&owner_key(&p)),
                )
                .await?
                .first()
                .map(|s| s.id),
            };
            store::read_doc(&mut conn, session).await?
        }
    };
    Ok(Json(VerifyReport {
        revision: q.revision,
        findings: afw_engine::verify(&doc, Utc::now()),
    }))
}
