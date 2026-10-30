//! Sessions: open, read, discard, publish (EF-10, EF-52), import (EF-70), allow-from-log
//! (EF-42).

use afw_core::api::{
    AllowDestination, AllowFromLogRequest, AllowFromLogResponse, Approval, OpenSessionRequest,
    PublishRequest, Revision, Role, Session, SessionState,
};
use afw_core::installed::document_sha256;
use afw_core::policy::{
    Action, Layer, NetObject, NetObjectSpec, PolicyDocument, Rule, Service, Track,
};
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sqlx::PgConnection;
use sqlx::types::Json as SqlJson;
use uuid::Uuid;

use super::approvals::{self, ApprovalGate};
use super::authz;
use super::diff::{diff_documents, entity_diffs};
use super::model::{ALL_KINDS, Kind, get as get_entity, list, parse};
use super::resources::{place_rule, rule_views};
use super::store::{
    self, Mutation, SessionRow, apply, close_session, enum_str, load_session, open_session,
    owner_key, session_dto, session_for_write,
};
use super::validate::{document_errors, normalize, normalize_domain};
use super::{body_json, pool};
use crate::AppState;
use crate::audit;
use crate::auth::Principal;
use crate::error::ApiError;

/// Advisory lock key serializing publications.
const PUBLISH_LOCK_KEY: i64 = 0x0061_6677_7075_626c; // "afwpubl"

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sessions", get(list_sessions).post(open))
        .route("/sessions/current", get(current))
        .route("/sessions/{id}", get(get_session))
        .route("/sessions/{id}/discard", post(discard))
        .route("/sessions/{id}/publish", post(publish))
        .route("/sessions/{id}/import", post(import))
        .route("/sessions/{id}/allow-from-log", post(allow_from_log))
}

async fn open(
    State(state): State<AppState>,
    p: Principal,
    body: Bytes,
) -> Result<(StatusCode, Json<Session>), ApiError> {
    p.require_policy_write()?;
    let req: OpenSessionRequest = if body.iter().all(u8::is_ascii_whitespace) {
        OpenSessionRequest::default()
    } else {
        parse(body_json(&body)?)?
    };
    let mut tx = pool(&state)?.begin().await?;
    let s = open_session(&mut tx, &p, req.name).await?;
    let dto = session_dto(&mut tx, &s).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(dto)))
}

async fn list_sessions(
    State(state): State<AppState>,
    p: Principal,
) -> Result<Json<Vec<Session>>, ApiError> {
    p.require(Role::Viewer)?;
    let mut conn = pool(&state)?.acquire().await?;
    let rows = store::sessions_where(&mut conn, "state = 'open'", None).await?;
    let mut out = Vec::new();
    for s in &rows {
        out.push(session_dto(&mut conn, s).await?);
    }
    Ok(Json(out))
}

/// The caller's open session; without one, its last published session whose revision is not
/// installed yet (so a client can resume the "Install" step). 404 otherwise.
async fn current(State(state): State<AppState>, p: Principal) -> Result<Json<Session>, ApiError> {
    p.require(Role::Viewer)?;
    let mut conn = pool(&state)?.acquire().await?;
    let key = owner_key(&p);
    let open =
        store::sessions_where(&mut conn, "owner_key = $1 AND state = 'open'", Some(&key)).await?;
    let pending = store::pending_install_of(&mut conn, &key).await?;
    if let Some(s) = open.first() {
        let mut dto = session_dto(&mut conn, s).await?;
        dto.pending_install = dto.pending_install.or(pending);
        return Ok(Json(dto));
    }
    let Some(n) = pending else {
        return Err(ApiError::NotFound);
    };
    let rows = store::sessions_where(
        &mut conn,
        &format!("owner_key = $1 AND published_revision = {n}"),
        Some(&key),
    )
    .await?;
    let s = rows.first().ok_or(ApiError::NotFound)?;
    Ok(Json(session_dto(&mut conn, s).await?))
}

async fn get_session(
    State(state): State<AppState>,
    p: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<Session>, ApiError> {
    p.require(Role::Viewer)?;
    let mut conn = pool(&state)?.acquire().await?;
    let s = load_session(&mut conn, id, false).await?;
    Ok(Json(session_dto(&mut conn, &s).await?))
}

/// Discard: the owner, or a human admin (to release locks of an abandoned session).
async fn discard(
    State(state): State<AppState>,
    p: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<Session>, ApiError> {
    p.require_policy_write()?;
    let mut tx = pool(&state)?.begin().await?;
    let s = load_session(&mut tx, id, true).await?;
    if s.owner_key != owner_key(&p) && p.role != Role::Admin {
        return Err(ApiError::Forbidden(
            "session owned by another caller".into(),
        ));
    }
    if s.state != SessionState::Open {
        return Err(ApiError::Conflict {
            message: "session is not open".into(),
        });
    }
    close_session(&mut tx, id, SessionState::Discarded, None).await?;
    audit::record(
        &mut tx,
        &p,
        Some(id),
        "session.discard",
        &format!("session:{id}"),
        Value::Null,
    )
    .await?;
    let s = load_session(&mut tx, id, false).await?;
    let dto = session_dto(&mut tx, &s).await?;
    tx.commit().await?;
    Ok(Json(dto))
}

/// Publishes the session's draft as revision n+1 (201), or returns the approval it needs
/// (202, EF-52).
async fn publish(
    State(state): State<AppState>,
    p: Principal,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<Response, ApiError> {
    p.require_policy_write()?;
    let req: PublishRequest = parse(body_json(&body)?)?;
    let mut tx = pool(&state)?.begin().await?;
    let session = session_for_write(&mut tx, &p, id).await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(PUBLISH_LOCK_KEY)
        .execute(&mut *tx)
        .await?;
    let latest = store::latest_revision(&mut tx).await?;
    let (prev_number, published) = latest.unwrap_or((0, PolicyDocument::default()));
    let draft = store::draft(&mut tx, id, &published).await?;
    let changes = diff_documents(&published, &draft);
    if changes.is_empty() {
        return Err(ApiError::Conflict {
            message: "nothing to publish".into(),
        });
    }
    // EF-51 again, against the current published state (delegation may have changed).
    if p.role == Role::McpAgent {
        for (kind, eid, before, after) in entity_diffs(&published, &draft) {
            authz::check_change(
                &p,
                &published,
                &published,
                &draft,
                kind,
                eid,
                before.as_ref(),
                after.as_ref(),
            )?;
        }
    }
    let errors = document_errors(&draft);
    if !errors.is_empty() {
        return Err(ApiError::Conflict {
            message: format!("policy invalid: {}", errors.join("; ")),
        });
    }
    if p.role == Role::McpAgent {
        let reasons = authz::widenings(&published, &draft);
        if !reasons.is_empty() {
            match approvals::gate(&mut tx, &p, &session, &document_sha256(&draft), &reasons).await?
            {
                ApprovalGate::Approved => {}
                ApprovalGate::Requested(a) => {
                    tx.commit().await?;
                    return Ok((StatusCode::ACCEPTED, Json::<Approval>(*a)).into_response());
                }
            }
        }
    }
    // Non-blocking findings (shadowed rules, unused objects…) are reported by /verify.
    let number = prev_number + 1;
    let sha256 = document_sha256(&draft);
    let published_at: chrono::DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO revisions (number, document, sha256, published_by, interface, session_id, \
         comment, published_at, diff) VALUES ($1, $2, $3, $4, $5, $6, $7, \
         date_trunc('milliseconds', now()), $8) RETURNING published_at",
    )
    .bind(number as i64)
    .bind(SqlJson(&draft))
    .bind(&sha256)
    .bind(SqlJson(&p.actor))
    .bind(enum_str(&p.interface))
    .bind(id)
    .bind(&req.comment)
    .bind(SqlJson(&changes))
    .fetch_one(&mut *tx)
    .await?;
    close_session(&mut tx, id, SessionState::Published, Some(number)).await?;
    audit::record(
        &mut tx,
        &p,
        Some(id),
        "session.publish",
        &format!("revision:{number}"),
        json!({"comment": req.comment, "changes": changes.len(), "sha256": sha256}),
    )
    .await?;
    tx.commit().await?;
    let rev = Revision {
        number,
        published_at,
        published_by: p.actor.clone(),
        interface: p.interface,
        session_id: Some(id),
        comment: req.comment,
        sha256,
    };
    Ok((StatusCode::CREATED, Json(rev)).into_response())
}

/// EF-70: merges a whole document (e.g. converted from egress-guard by `afw import`) into the
/// session. Human admin only. Settings are replaced only when present in the body.
async fn import(
    State(state): State<AppState>,
    p: Principal,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<Json<Session>, ApiError> {
    p.require(Role::Admin)?;
    let raw = body_json(&body)?;
    let has_settings = raw.get("settings").is_some();
    let incoming: PolicyDocument = parse(raw)?;
    let mut tx = pool(&state)?.begin().await?;
    let session = session_for_write(&mut tx, &p, id).await?;
    let published = store::published(&mut tx).await?;
    let mut doc = store::draft(&mut tx, id, &published).await?;
    let mut mutations = Vec::new();
    for kind in ALL_KINDS {
        if kind == Kind::Settings && !has_settings {
            continue;
        }
        for (eid, v) in list(&incoming, kind) {
            let v = normalize(kind, eid, v, &doc)?;
            super::model::set(&mut doc, kind, eid, Some(v.clone()))?;
            mutations.push(Mutation {
                kind,
                id: eid,
                after: Some(v),
            });
        }
    }
    apply(&mut tx, &p, &session, mutations).await?;
    let s = load_session(&mut tx, id, false).await?;
    let dto = session_dto(&mut tx, &s).await?;
    tx.commit().await?;
    Ok(Json(dto))
}

fn new_object(name: String, spec: NetObjectSpec) -> NetObject {
    NetObject {
        id: Uuid::new_v4(),
        name,
        comment: "Créé depuis le journal".into(),
        category: None,
        spec,
    }
}

/// Finds or creates the destination object of an allow-from-log rule.
fn destination_object(
    doc: &PolicyDocument,
    flow: &afw_core::events::FlowEvent,
    mode: AllowDestination,
    zone_name: &str,
    created: &mut Vec<NetObject>,
) -> Result<Uuid, ApiError> {
    let domain = flow.domain.as_deref().or(flow.sni.as_deref());
    let spec = match (domain, mode) {
        (Some(d), AllowDestination::Wildcard) => {
            let d = normalize_domain(d)?;
            let parent = d.split_once('.').map(|(_, p)| p).unwrap_or("");
            if !parent.contains('.') {
                return Err(ApiError::BadRequest(format!(
                    "wildcard of {d} would cover a whole top-level domain"
                )));
            }
            NetObjectSpec::Domain {
                pattern: format!("*.{parent}"),
            }
        }
        (Some(d), _) => NetObjectSpec::Domain {
            pattern: normalize_domain(d)?,
        },
        (None, _) => NetObjectSpec::Host { ip: flow.dst.ip() },
    };
    let exact = match doc.objects.iter().find(|o| o.spec == spec) {
        Some(o) => o.id,
        None => {
            let name = match &spec {
                NetObjectSpec::Domain { pattern } => pattern.clone(),
                _ => flow.dst.ip().to_string(),
            };
            let o = new_object(name, spec);
            created.push(o.clone());
            o.id
        }
    };
    if mode != AllowDestination::Group {
        return Ok(exact);
    }
    let group_name = format!("Autorisés depuis le journal — {zone_name}");
    let group = match doc
        .objects
        .iter()
        .find(|o| o.name == group_name && matches!(o.spec, NetObjectSpec::Group { .. }))
    {
        Some(g) => g.clone(),
        None => new_object(group_name, NetObjectSpec::Group { members: vec![] }),
    };
    let mut group = group;
    if let NetObjectSpec::Group { members } = &mut group.spec
        && !members.contains(&exact)
    {
        members.push(exact);
    }
    let id = group.id;
    created.retain(|o| o.id != id);
    created.push(group);
    Ok(id)
}

async fn allow_from_log(
    State(state): State<AppState>,
    p: Principal,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<(StatusCode, Json<AllowFromLogResponse>), ApiError> {
    p.require_policy_write()?;
    let req: AllowFromLogRequest = parse(body_json(&body)?)?;
    let lookup = state
        .flow_lookup
        .clone()
        .ok_or_else(|| ApiError::Internal("flow lookup not configured".into()))?;
    let flow = lookup
        .get_flow(req.flow_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let mut tx = pool(&state)?.begin().await?;
    let session = session_for_write(&mut tx, &p, id).await?;
    let published = store::published(&mut tx).await?;
    let doc = store::draft(&mut tx, id, &published).await?;
    let zone_id = flow
        .agent_id
        .and_then(|a| doc.agents.iter().find(|x| x.id == a).map(|x| x.zone_id))
        .or(flow.zone_id)
        .ok_or_else(|| ApiError::Conflict {
            message: "the flow has no known agent or zone".into(),
        })?;
    let zone = doc
        .zones
        .iter()
        .find(|z| z.id == zone_id)
        .ok_or_else(|| ApiError::Conflict {
            message: format!("zone {zone_id} of the flow is not in the policy"),
        })?;
    // Rights are checked before anything is created (EF-51).
    if p.role == Role::McpAgent {
        let (own, delegated) = p.zone_scope(&published);
        p.require_zone_write(zone_id, own, &delegated)?;
    }
    let mut objects = Vec::new();
    let dest = destination_object(&doc, &flow, req.destination, &zone.name, &mut objects)?;
    let mut mutations: Vec<Mutation> = Vec::new();
    let created_object = objects
        .iter()
        .find(|o| {
            !matches!(o.spec, NetObjectSpec::Group { .. })
                && get_entity(&doc, Kind::Object, o.id).is_none()
        })
        .cloned();
    for o in &objects {
        mutations.push(Mutation {
            kind: Kind::Object,
            id: o.id,
            after: Some(serde_json::to_value(o).expect("object")),
        });
    }
    let port = flow.dst.port();
    let service = doc.services.iter().find(|s| {
        s.protocol == flow.protocol
            && s.app.is_none()
            && s.ports.len() == 1
            && s.ports[0].start == port
            && s.ports[0].end == port
    });
    let service_id = match service {
        Some(s) => s.id,
        None => {
            let s = Service {
                id: Uuid::new_v4(),
                name: format!("{}-{port}", enum_str(&flow.protocol)),
                comment: "Créé depuis le journal".into(),
                protocol: flow.protocol,
                ports: vec![afw_core::policy::PortRange {
                    start: port,
                    end: port,
                }],
                app: None,
            };
            mutations.push(Mutation {
                kind: Kind::Service,
                id: s.id,
                after: Some(serde_json::to_value(&s).expect("service")),
            });
            s.id
        }
    };
    let rule_name = match &flow.domain.as_deref().or(flow.sni.as_deref()) {
        Some(d) => format!("Autoriser {}", d.to_ascii_lowercase()),
        None => format!("Autoriser {}", flow.dst),
    };
    let rule = Rule {
        id: Uuid::new_v4(),
        name: rule_name,
        layer: Layer::Zone { zone_id },
        section: None,
        position: 1,
        sources: vec![zone_id],
        destinations: vec![dest],
        services: vec![service_id],
        data_classes: vec![],
        action: Action::Accept,
        track: req.track.unwrap_or(Track::Detailed),
        expires_at: req
            .expires_in_days
            .map(|d| Utc::now() + Duration::days(i64::from(d))),
        comment: format!("Autorisé depuis le journal, flux {}", flow.id),
        enabled: true,
    };
    let rule_id = rule.id;
    let mut staged = doc.clone();
    for m in &mutations {
        super::model::set(&mut staged, m.kind, m.id, m.after.clone())?;
    }
    mutations.extend(place_rule(&staged, rule, 1));
    let (draft, changes) = apply(&mut tx, &p, &session, mutations).await?;
    let views = rule_views(&state, &mut tx, &draft, Some(id)).await?;
    tx.commit().await?;
    let rule = views
        .into_iter()
        .find(|v| v.rule.id == rule_id)
        .ok_or_else(|| ApiError::Internal("rule missing".into()))?;
    Ok((
        StatusCode::CREATED,
        Json(AllowFromLogResponse {
            rule,
            created_object,
            changes,
        }),
    ))
}

/// Opens a session whose draft equals revision `n` (rollback, EF-10). Human admin only.
pub async fn revert_to(
    conn: &mut PgConnection,
    p: &Principal,
    target: &PolicyDocument,
) -> Result<SessionRow, ApiError> {
    p.require(Role::Admin)?;
    let session = open_session(conn, p, Some("revert".into())).await?;
    let published = store::published(conn).await?;
    let mutations = entity_diffs(&published, target)
        .into_iter()
        .map(|(kind, id, _, after)| Mutation { kind, id, after })
        .collect();
    apply(conn, p, &session, mutations).await?;
    Ok(session)
}
