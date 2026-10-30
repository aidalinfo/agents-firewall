//! Storage of the policy: published state (last revision), session drafts, locks, and the
//! single mutation path ([`apply`]) used by every write (authorization, lock, change, audit).

use afw_core::api::{ChangeOp, Session, SessionChange, SessionState};
use afw_core::events::{Actor, Interface};
use afw_core::policy::PolicyDocument;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::PgConnection;
use sqlx::types::Json;
use uuid::Uuid;

use super::authz;
use super::model::{Kind, get, resource_ref, set};
use crate::audit;
use crate::auth::Principal;
use crate::error::ApiError;

pub fn enum_str<T: serde::Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(Value::String(s)) => s,
        _ => String::new(),
    }
}

pub fn parse_enum<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, ApiError> {
    serde_json::from_value(Value::String(s.to_owned()))
        .map_err(|_| ApiError::Internal(format!("invalid stored value {s:?}")))
}

/// Stable identity of a caller, used for session ownership and approvals.
pub fn owner_key(p: &Principal) -> String {
    format!("{}:{}", enum_str(&p.actor.kind), p.actor.id)
}

#[derive(Clone, Debug)]
pub struct SessionRow {
    pub id: Uuid,
    pub owner: Actor,
    pub owner_key: String,
    pub interface: Interface,
    pub name: Option<String>,
    pub state: SessionState,
    pub opened_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub approval_id: Option<Uuid>,
    pub published_revision: Option<i64>,
}

type RawSession = (
    Uuid,
    Json<Actor>,
    String,
    String,
    Option<String>,
    String,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<Uuid>,
    Option<i64>,
);

pub const SESSION_COLUMNS: &str = "id, owner, owner_key, interface, name, state, opened_at, \
                                   closed_at, approval_id, published_revision";

pub fn session_from_raw(r: RawSession) -> Result<SessionRow, ApiError> {
    Ok(SessionRow {
        id: r.0,
        owner: r.1.0,
        owner_key: r.2,
        interface: parse_enum(&r.3)?,
        name: r.4,
        state: parse_enum(&r.5)?,
        opened_at: r.6,
        closed_at: r.7,
        approval_id: r.8,
        published_revision: r.9,
    })
}

pub async fn load_session(
    conn: &mut PgConnection,
    id: Uuid,
    for_update: bool,
) -> Result<SessionRow, ApiError> {
    let sql = format!(
        "SELECT {SESSION_COLUMNS} FROM policy_sessions WHERE id = $1{}",
        if for_update { " FOR UPDATE" } else { "" }
    );
    let raw: Option<RawSession> = sqlx::query_as(&sql)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
    session_from_raw(raw.ok_or(ApiError::NotFound)?)
}

pub async fn sessions_where(
    conn: &mut PgConnection,
    filter: &str,
    bind: Option<&str>,
) -> Result<Vec<SessionRow>, ApiError> {
    let sql =
        format!("SELECT {SESSION_COLUMNS} FROM policy_sessions WHERE {filter} ORDER BY opened_at");
    let mut q = sqlx::query_as::<_, RawSession>(&sql);
    if let Some(b) = bind {
        q = q.bind(b.to_owned());
    }
    q.fetch_all(&mut *conn)
        .await?
        .into_iter()
        .map(session_from_raw)
        .collect()
}

/// Open session owned by the caller, for a write: 404 unknown, 409 closed, 403 not the owner.
pub async fn session_for_write(
    conn: &mut PgConnection,
    p: &Principal,
    id: Uuid,
) -> Result<SessionRow, ApiError> {
    p.require_policy_write()?;
    let s = load_session(conn, id, true).await?;
    if s.owner_key != owner_key(p) {
        return Err(ApiError::Forbidden(
            "session owned by another caller".into(),
        ));
    }
    if s.state != SessionState::Open {
        return Err(ApiError::Conflict {
            message: "session is not open".into(),
        });
    }
    Ok(s)
}

/// Last published revision (number, document); `None` before the first publication.
pub async fn latest_revision(
    conn: &mut PgConnection,
) -> Result<Option<(u64, PolicyDocument)>, ApiError> {
    let row: Option<(i64, Json<PolicyDocument>, String)> = sqlx::query_as(
        "SELECT number, document, sha256 FROM revisions ORDER BY number DESC LIMIT 1",
    )
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|(n, d, sha)| check_revision(n as u64, d.0, &sha).map(|d| (n as u64, d)))
        .transpose()
}

/// Refuses a stored revision whose document does not match its fingerprint (tampering or
/// corruption): no policy is served from it.
pub fn check_revision(
    number: u64,
    document: PolicyDocument,
    sha256: &str,
) -> Result<PolicyDocument, ApiError> {
    let actual = afw_core::installed::document_sha256(&document);
    if actual != sha256 {
        tracing::error!(revision = number, expected = sha256, %actual, "revision fingerprint mismatch");
        return Err(ApiError::Internal(format!(
            "revision {number} fingerprint mismatch"
        )));
    }
    Ok(document)
}

/// Published state: the last revision's document, or an empty policy.
pub async fn published(conn: &mut PgConnection) -> Result<PolicyDocument, ApiError> {
    Ok(latest_revision(conn)
        .await?
        .map(|(_, d)| d)
        .unwrap_or_default())
}

pub struct StoredChange {
    pub kind: Kind,
    pub id: Uuid,
    pub op: ChangeOp,
    pub after: Option<Value>,
}

pub async fn changes(
    conn: &mut PgConnection,
    session: Uuid,
) -> Result<Vec<StoredChange>, ApiError> {
    let rows: Vec<(String, Uuid, String, Option<Json<Value>>)> = sqlx::query_as(
        "SELECT kind, entity_id, op, after FROM policy_session_changes WHERE session_id = $1 \
         ORDER BY seq",
    )
    .bind(session)
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter()
        .map(|(k, id, op, after)| {
            Ok(StoredChange {
                kind: Kind::parse(&k).ok_or_else(|| ApiError::Internal(format!("kind {k}")))?,
                id,
                op: parse_enum(&op)?,
                after: after.map(|j| j.0),
            })
        })
        .collect()
}

/// Draft of a session: `published` plus the session's changes.
pub async fn draft(
    conn: &mut PgConnection,
    session: Uuid,
    published: &PolicyDocument,
) -> Result<PolicyDocument, ApiError> {
    let mut doc = published.clone();
    for c in changes(conn, session).await? {
        set(&mut doc, c.kind, c.id, c.after)?;
    }
    Ok(doc)
}

/// Document read by GET requests: the draft of `session` when it is open, else the published
/// state.
pub async fn read_doc(
    conn: &mut PgConnection,
    session: Option<Uuid>,
) -> Result<PolicyDocument, ApiError> {
    let published = published(conn).await?;
    match session {
        Some(id) => {
            let s = load_session(conn, id, false).await?;
            if s.state == SessionState::Open {
                draft(conn, id, &published).await
            } else {
                Ok(published)
            }
        }
        None => Ok(published),
    }
}

/// One entity write: `after = None` deletes.
#[derive(Clone, Debug)]
pub struct Mutation {
    pub kind: Kind,
    pub id: Uuid,
    pub after: Option<Value>,
}

async fn lock(
    conn: &mut PgConnection,
    kind: Kind,
    id: Uuid,
    session: Uuid,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO policy_locks (kind, entity_id, session_id) VALUES ($1, $2, $3) \
         ON CONFLICT (kind, entity_id) DO NOTHING",
    )
    .bind(kind.as_str())
    .bind(id)
    .bind(session)
    .execute(&mut *conn)
    .await?;
    let (holder, owner): (Uuid, Json<Actor>) = sqlx::query_as(
        "SELECT l.session_id, s.owner FROM policy_locks l JOIN policy_sessions s \
         ON s.id = l.session_id WHERE l.kind = $1 AND l.entity_id = $2",
    )
    .bind(kind.as_str())
    .bind(id)
    .fetch_one(&mut *conn)
    .await?;
    if holder != session {
        return Err(ApiError::Locked { by: owner.0.name });
    }
    Ok(())
}

fn op_against(published: Option<&Value>, after: Option<&Value>) -> Option<ChangeOp> {
    match (published, after) {
        (None, None) => None,
        (Some(p), Some(a)) if p == a => None,
        (None, Some(_)) => Some(ChangeOp::Create),
        (Some(_), None) => Some(ChangeOp::Delete),
        (Some(_), Some(_)) => Some(ChangeOp::Update),
    }
}

/// Applies mutations to an open session of the caller, in order: authorization (EF-51),
/// lock (423 when held by another session), stored change, audit entry. Call inside a
/// transaction. Returns the new draft and the session changes made.
pub async fn apply(
    conn: &mut PgConnection,
    p: &Principal,
    session: &SessionRow,
    mutations: Vec<Mutation>,
) -> Result<(PolicyDocument, Vec<SessionChange>), ApiError> {
    let published = published(conn).await?;
    let mut doc = draft(conn, session.id, &published).await?;
    let mut made = Vec::new();
    for m in mutations {
        let before = get(&doc, m.kind, m.id);
        let mut next = doc.clone();
        set(&mut next, m.kind, m.id, m.after.clone())?;
        // Normalized value as stored in the document.
        let after = get(&next, m.kind, m.id).filter(|_| m.after.is_some());
        // Authorization even for a no-op write (fail closed, EF-51).
        authz::check_change(
            p,
            &published,
            &doc,
            &next,
            m.kind,
            m.id,
            before.as_ref(),
            after.as_ref(),
        )?;
        if before == after {
            continue;
        }
        lock(conn, m.kind, m.id, session.id).await?;
        let pub_value = get(&published, m.kind, m.id);
        match op_against(pub_value.as_ref(), after.as_ref()) {
            None => {
                // Back to its published state: no change left, the lock is released.
                for table in ["policy_session_changes", "policy_locks"] {
                    sqlx::query(&format!(
                        "DELETE FROM {table} WHERE session_id = $1 AND kind = $2 \
                         AND entity_id = $3"
                    ))
                    .bind(session.id)
                    .bind(m.kind.as_str())
                    .bind(m.id)
                    .execute(&mut *conn)
                    .await?;
                }
            }
            Some(op) => {
                sqlx::query(
                    "INSERT INTO policy_session_changes (session_id, kind, entity_id, op, after) \
                     VALUES ($1, $2, $3, $4, $5) ON CONFLICT (session_id, kind, entity_id) DO \
                     UPDATE SET op = EXCLUDED.op, after = EXCLUDED.after, \
                     seq = nextval(pg_get_serial_sequence('policy_session_changes', 'seq'))",
                )
                .bind(session.id)
                .bind(m.kind.as_str())
                .bind(m.id)
                .bind(enum_str(&op))
                .bind(after.as_ref().map(Json))
                .execute(&mut *conn)
                .await?;
            }
        }
        let verb = match (&before, &after) {
            (None, _) => "create",
            (_, None) => "delete",
            _ => "update",
        };
        audit::record(
            conn,
            p,
            Some(session.id),
            &format!("{}.{verb}", m.kind.as_str()),
            &format!("{}:{}", m.kind.as_str(), m.id),
            json!({"before": before, "after": after}),
        )
        .await?;
        made.push(SessionChange {
            op: match verb {
                "create" => ChangeOp::Create,
                "delete" => ChangeOp::Delete,
                _ => ChangeOp::Update,
            },
            resource: resource_ref(m.kind, m.id, after.as_ref().or(before.as_ref())),
            after: after.clone(),
        });
        doc = next;
    }
    Ok((doc, made))
}

/// Last revision published by `owner_key` that has no install request yet.
pub async fn pending_install_of(
    conn: &mut PgConnection,
    owner_key: &str,
) -> Result<Option<u64>, ApiError> {
    let n: Option<i64> = sqlx::query_scalar(
        "SELECT s.published_revision FROM policy_sessions s WHERE s.owner_key = $1 \
         AND s.published_revision IS NOT NULL \
         AND NOT EXISTS (SELECT 1 FROM installs i WHERE i.revision >= s.published_revision) \
         ORDER BY s.published_revision DESC LIMIT 1",
    )
    .bind(owner_key)
    .fetch_optional(&mut *conn)
    .await?
    .flatten();
    Ok(n.map(|n| n as u64))
}

/// API view of a session.
pub async fn session_dto(conn: &mut PgConnection, s: &SessionRow) -> Result<Session, ApiError> {
    let published = published(conn).await?;
    let doc = if s.state == SessionState::Open {
        draft(conn, s.id, &published).await?
    } else {
        published.clone()
    };
    let locks: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT kind, entity_id FROM policy_locks WHERE session_id = $1 ORDER BY locked_at, kind",
    )
    .bind(s.id)
    .fetch_all(&mut *conn)
    .await?;
    let locks = locks
        .into_iter()
        .filter_map(|(k, id)| {
            let kind = Kind::parse(&k)?;
            let v = get(&doc, kind, id).or_else(|| get(&published, kind, id));
            Some(resource_ref(kind, id, v.as_ref()))
        })
        .collect();
    let changes: i64 = if s.state == SessionState::Open {
        sqlx::query_scalar("SELECT count(*) FROM policy_session_changes WHERE session_id = $1")
            .bind(s.id)
            .fetch_one(&mut *conn)
            .await?
    } else {
        0
    };
    let pending_install = match s.published_revision {
        Some(n) => {
            let installed: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM installs WHERE revision >= $1)")
                    .bind(n)
                    .fetch_one(&mut *conn)
                    .await?;
            (!installed).then_some(n as u64)
        }
        None => None,
    };
    Ok(Session {
        id: s.id,
        owner: s.owner.clone(),
        interface: s.interface,
        state: s.state,
        opened_at: s.opened_at,
        closed_at: s.closed_at,
        locks,
        changes: changes as u32,
        approval_id: s.approval_id,
        name: s.name.clone(),
        pending_install,
    })
}

/// Opens a session for the caller (409 if one is already open).
pub async fn open_session(
    conn: &mut PgConnection,
    p: &Principal,
    name: Option<String>,
) -> Result<SessionRow, ApiError> {
    p.require_policy_write()?;
    let key = owner_key(p);
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM policy_sessions WHERE owner_key = $1 AND state = 'open'",
    )
    .bind(&key)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(id) = existing {
        return Err(ApiError::Conflict {
            message: format!("session {id} is already open for this caller"),
        });
    }
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO policy_sessions (id, owner, owner_key, interface, name, state, opened_at) \
         VALUES ($1, $2, $3, $4, $5, 'open', now())",
    )
    .bind(id)
    .bind(Json(&p.actor))
    .bind(&key)
    .bind(enum_str(&p.interface))
    .bind(&name)
    .execute(&mut *conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict {
            message: "a session is already open for this caller".into(),
        },
        other => other.into(),
    })?;
    audit::record(
        conn,
        p,
        Some(id),
        "session.open",
        &format!("session:{id}"),
        json!({"name": name}),
    )
    .await?;
    load_session(conn, id, false).await
}

/// Closes a session (`published` / `discarded`) and releases its locks.
pub async fn close_session(
    conn: &mut PgConnection,
    id: Uuid,
    state: SessionState,
    revision: Option<u64>,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE policy_sessions SET state = $2, closed_at = now(), published_revision = $3 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(enum_str(&state))
    .bind(revision.map(|n| n as i64))
    .execute(&mut *conn)
    .await?;
    sqlx::query("DELETE FROM policy_locks WHERE session_id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}
