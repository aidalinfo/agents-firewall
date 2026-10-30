//! Human approvals of the MCP agent's widening changes (EF-52).

use afw_core::api::{Approval, ApprovalDecision, ApprovalStatus, Role};
use afw_core::events::Actor;
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgConnection;
use sqlx::types::Json as SqlJson;
use uuid::Uuid;

use super::model::parse;
use super::store::{SessionRow, enum_str, owner_key, parse_enum};
use super::{body_json, pool};
use crate::AppState;
use crate::audit;
use crate::auth::Principal;
use crate::error::ApiError;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/approvals", get(list_approvals))
        .route("/approvals/{id}", get(get_approval))
        .route("/approvals/{id}/decision", post(decide))
}

type RawApproval = (
    Uuid,
    Uuid,
    SqlJson<Actor>,
    DateTime<Utc>,
    String,
    String,
    String,
    Option<SqlJson<Actor>>,
    Option<DateTime<Utc>>,
    Option<String>,
);

const COLUMNS: &str = "id, session_id, requested_by, requested_at, summary, reason, status, \
                       decided_by, decided_at, comment";

fn from_raw(r: RawApproval) -> Result<Approval, ApiError> {
    Ok(Approval {
        id: r.0,
        session_id: r.1,
        requested_by: r.2.0,
        requested_at: r.3,
        summary: r.4,
        reason: r.5,
        status: parse_enum(&r.6)?,
        decided_by: r.7.map(|a| a.0),
        decided_at: r.8,
        comment: r.9,
    })
}

async fn load(conn: &mut PgConnection, id: Uuid, for_update: bool) -> Result<Approval, ApiError> {
    let sql = format!(
        "SELECT {COLUMNS} FROM approvals WHERE id = $1{}",
        if for_update { " FOR UPDATE" } else { "" }
    );
    let raw: Option<RawApproval> = sqlx::query_as(&sql)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
    from_raw(raw.ok_or(ApiError::NotFound)?)
}

pub enum ApprovalGate {
    /// An approved approval covers exactly this draft: publication may proceed.
    Approved,
    /// A new approval was requested (or one is pending): publication must wait.
    Requested(Box<Approval>),
}

/// Publication gate of a widening draft (fingerprint `draft_sha256`): an approval of this exact
/// draft must be approved. Pending or rejected ⇒ 409; none ⇒ a new pending approval (stale
/// pending approvals of the session are rejected as superseded).
pub async fn gate(
    conn: &mut PgConnection,
    p: &Principal,
    session: &SessionRow,
    draft_sha256: &str,
    reasons: &[String],
) -> Result<ApprovalGate, ApiError> {
    let existing: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, status FROM approvals WHERE session_id = $1 AND draft_sha256 = $2 \
         ORDER BY requested_at DESC LIMIT 1",
    )
    .bind(session.id)
    .bind(draft_sha256)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some((_, status)) = existing {
        return match parse_enum::<ApprovalStatus>(&status)? {
            ApprovalStatus::Approved => Ok(ApprovalGate::Approved),
            ApprovalStatus::Pending => Err(ApiError::Conflict {
                message: "a human approval is pending for this session".into(),
            }),
            ApprovalStatus::Rejected => Err(ApiError::Conflict {
                message: "this change was rejected by a human".into(),
            }),
        };
    }
    sqlx::query(
        "UPDATE approvals SET status = 'rejected', decided_at = now(), \
         comment = 'superseded by a later change of the session' \
         WHERE session_id = $1 AND status = 'pending'",
    )
    .bind(session.id)
    .execute(&mut *conn)
    .await?;
    let id = Uuid::new_v4();
    let summary = format!(
        "{} widening change(s) requested by {}",
        reasons.len(),
        p.actor.name
    );
    let reason = reasons.join("; ");
    sqlx::query(
        "INSERT INTO approvals (id, session_id, requested_by, requested_by_key, requested_at, \
         summary, reason, draft_sha256, status) VALUES ($1, $2, $3, $4, \
         date_trunc('milliseconds', now()), $5, $6, $7, 'pending')",
    )
    .bind(id)
    .bind(session.id)
    .bind(SqlJson(&p.actor))
    .bind(owner_key(p))
    .bind(&summary)
    .bind(&reason)
    .bind(draft_sha256)
    .execute(&mut *conn)
    .await?;
    sqlx::query("UPDATE policy_sessions SET approval_id = $2 WHERE id = $1")
        .bind(session.id)
        .bind(id)
        .execute(&mut *conn)
        .await?;
    audit::record(
        conn,
        p,
        Some(session.id),
        "approval.request",
        &format!("approval:{id}"),
        json!({"reasons": reasons, "draft_sha256": draft_sha256}),
    )
    .await?;
    Ok(ApprovalGate::Requested(Box::new(
        load(conn, id, false).await?,
    )))
}

#[derive(Deserialize)]
struct ListQuery {
    status: Option<ApprovalStatus>,
}

async fn list_approvals(
    State(state): State<AppState>,
    p: Principal,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<Approval>>, ApiError> {
    p.require(Role::Viewer)?;
    let mut conn = pool(&state)?.acquire().await?;
    let sql = format!(
        "SELECT {COLUMNS} FROM approvals WHERE ($1::text IS NULL OR status = $1) \
         ORDER BY requested_at DESC"
    );
    let rows: Vec<RawApproval> = sqlx::query_as(&sql)
        .bind(q.status.map(|s| enum_str(&s)))
        .fetch_all(&mut *conn)
        .await?;
    Ok(Json(
        rows.into_iter().map(from_raw).collect::<Result<_, _>>()?,
    ))
}

async fn get_approval(
    State(state): State<AppState>,
    p: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<Approval>, ApiError> {
    p.require(Role::Viewer)?;
    let mut conn = pool(&state)?.acquire().await?;
    Ok(Json(load(&mut conn, id, false).await?))
}

/// Human admin only, never the requester; a decided approval is final (409).
async fn decide(
    State(state): State<AppState>,
    p: Principal,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<Json<Approval>, ApiError> {
    p.require(Role::Admin)?;
    let req: ApprovalDecision = parse(body_json(&body)?)?;
    let mut tx = pool(&state)?.begin().await?;
    let a = load(&mut tx, id, true).await?;
    let requester: String =
        sqlx::query_scalar("SELECT requested_by_key FROM approvals WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if requester == owner_key(&p) {
        return Err(ApiError::Forbidden(
            "the requester cannot decide its own approval".into(),
        ));
    }
    if a.status != ApprovalStatus::Pending {
        return Err(ApiError::Conflict {
            message: "approval already decided".into(),
        });
    }
    let status = if req.approve {
        ApprovalStatus::Approved
    } else {
        ApprovalStatus::Rejected
    };
    sqlx::query(
        "UPDATE approvals SET status = $2, decided_by = $3, decided_at = \
         date_trunc('milliseconds', now()), comment = $4 WHERE id = $1",
    )
    .bind(id)
    .bind(enum_str(&status))
    .bind(SqlJson(&p.actor))
    .bind(&req.comment)
    .execute(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        &p,
        Some(a.session_id),
        if req.approve {
            "approval.approve"
        } else {
            "approval.reject"
        },
        &format!("approval:{id}"),
        json!({"comment": req.comment}),
    )
    .await?;
    let a = load(&mut tx, id, false).await?;
    tx.commit().await?;
    Ok(Json(a))
}
