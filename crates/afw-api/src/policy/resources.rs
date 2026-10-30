//! CRUD of policy resources, rule views and rule base, where-used, rule moves, settings.

use std::collections::HashMap;

use afw_core::api::{
    BaselineLayerView, ChangeOp, MoveRuleRequest, Role, RuleSection, RuleView, Rulebase, WhereUsed,
    ZoneLayerView,
};
use afw_core::events::Actor;
use afw_core::policy::{Layer, PolicyDocument, Rule};
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
use sqlx::pool::PoolConnection;
use sqlx::types::Json as SqlJson;
use sqlx::{PgConnection, Postgres};
use uuid::Uuid;

use super::model::{Kind, get as get_entity, list, parse};
use super::store::{self, Mutation, apply, session_for_write};
use super::validate::{normalize, references_to};
use super::{body_json, pool, required_session, session_header};
use crate::AppState;
use crate::auth::Principal;
use crate::error::ApiError;

const COLLECTIONS: [(&str, Kind); 7] = [
    ("objects", Kind::Object),
    ("services", Kind::Service),
    ("data-classes", Kind::DataClass),
    ("zones", Kind::Zone),
    ("agents", Kind::Agent),
    ("rules", Kind::Rule),
    ("inspection-rules", Kind::InspectionRule),
];

pub fn routes() -> Router<AppState> {
    let mut r = Router::new();
    for (name, kind) in COLLECTIONS {
        let collection = if kind == Kind::Rule {
            get(list_rules).post(
                move |s: State<AppState>, p: Principal, h: HeaderMap, b: Bytes| {
                    create(s, p, h, b, kind)
                },
            )
        } else {
            get(move |s: State<AppState>, p: Principal, h: HeaderMap| list_entities(s, p, h, kind))
                .post(
                    move |s: State<AppState>, p: Principal, h: HeaderMap, b: Bytes| {
                        create(s, p, h, b, kind)
                    },
                )
        };
        r = r.route(&format!("/{name}"), collection).route(
            &format!("/{name}/{{id}}"),
            get(
                move |s: State<AppState>, p: Principal, h: HeaderMap, id: Path<Uuid>| {
                    get_one(s, p, h, id, kind)
                },
            )
            .put(
                move |s: State<AppState>, p: Principal, h: HeaderMap, id: Path<Uuid>, b: Bytes| {
                    update(s, p, h, id, b, kind)
                },
            )
            .delete(
                move |s: State<AppState>, p: Principal, h: HeaderMap, id: Path<Uuid>| {
                    delete(s, p, h, id, kind)
                },
            ),
        );
    }
    r.route("/objects/{id}/where-used", get(where_used))
        .route("/rules/{id}/move", post(move_rule))
        .route("/rulebase", get(rulebase))
        .route(
            "/settings",
            get(|s: State<AppState>, p: Principal, h: HeaderMap| get_one_settings(s, p, h)).put(
                |s: State<AppState>, p: Principal, h: HeaderMap, b: Bytes| {
                    write(s, p, h, None, b, Kind::Settings, false)
                },
            ),
        )
}

async fn read(
    state: &AppState,
    p: &Principal,
    headers: &HeaderMap,
) -> Result<(PoolConnection<Postgres>, PolicyDocument, Option<Uuid>), ApiError> {
    p.require(Role::Viewer)?;
    let session = session_header(headers)?;
    let mut conn = pool(state)?.acquire().await?;
    let doc = store::read_doc(&mut conn, session).await?;
    Ok((conn, doc, session))
}

/// Entities sorted by name (rules: evaluation order).
async fn list_entities(
    State(state): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    kind: Kind,
) -> Result<Json<Vec<Value>>, ApiError> {
    let (_, doc, _) = read(&state, &p, &headers).await?;
    let mut items: Vec<Value> = list(&doc, kind).into_iter().map(|(_, v)| v).collect();
    items.sort_by(|a, b| {
        let key = |v: &Value| {
            (
                v["name"].as_str().unwrap_or("").to_lowercase(),
                v["id"].to_string(),
            )
        };
        key(a).cmp(&key(b))
    });
    Ok(Json(items))
}

async fn get_one(
    State(state): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    kind: Kind,
) -> Result<Json<Value>, ApiError> {
    let (_, doc, _) = read(&state, &p, &headers).await?;
    get_entity(&doc, kind, id)
        .map(Json)
        .ok_or(ApiError::NotFound)
}

async fn get_one_settings(
    State(state): State<AppState>,
    p: Principal,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (_, doc, _) = read(&state, &p, &headers).await?;
    Ok(Json(
        get_entity(&doc, Kind::Settings, Uuid::nil()).unwrap_or_default(),
    ))
}

async fn create(
    s: State<AppState>,
    p: Principal,
    h: HeaderMap,
    b: Bytes,
    kind: Kind,
) -> Result<Response, ApiError> {
    write(s, p, h, None, b, kind, true).await
}

async fn update(
    s: State<AppState>,
    p: Principal,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    b: Bytes,
    kind: Kind,
) -> Result<Response, ApiError> {
    write(s, p, h, Some(id), b, kind, false).await
}

/// Mutations placing `rule` at `position` (1-based) in its layer, renumbering the layer 1..n.
/// The placed rule comes first.
pub fn place_rule(doc: &PolicyDocument, mut rule: Rule, position: u32) -> Vec<Mutation> {
    let mut layer: Vec<Rule> = doc
        .rules
        .iter()
        .filter(|r| r.layer == rule.layer && r.id != rule.id)
        .cloned()
        .collect();
    layer.sort_by_key(|r| (r.position, r.id));
    let idx = (position.max(1) as usize - 1).min(layer.len());
    rule.position = position;
    layer.insert(idx, rule.clone());
    let mut out = Vec::new();
    for (i, mut r) in layer.into_iter().enumerate() {
        r.position = i as u32 + 1;
        let v = serde_json::to_value(&r).expect("rule serializes");
        if r.id == rule.id {
            out.insert(
                0,
                Mutation {
                    kind: Kind::Rule,
                    id: r.id,
                    after: Some(v),
                },
            );
        } else if get_entity(doc, Kind::Rule, r.id).as_ref() != Some(&v) {
            out.push(Mutation {
                kind: Kind::Rule,
                id: r.id,
                after: Some(v),
            });
        }
    }
    out
}

async fn write(
    State(state): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    path_id: Option<Uuid>,
    body: Bytes,
    kind: Kind,
    create: bool,
) -> Result<Response, ApiError> {
    p.require_policy_write()?;
    let session_id = required_session(&headers)?;
    let value: Value = body_json(&body)?;
    let id = if kind == Kind::Settings {
        Uuid::nil()
    } else {
        value
            .get("id")
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| ApiError::BadRequest("missing or invalid id".into()))?
    };
    if path_id.is_some_and(|pid| pid != id) {
        return Err(ApiError::BadRequest("id in path and body differ".into()));
    }
    let mut tx = pool(&state)?.begin().await?;
    let session = session_for_write(&mut tx, &p, session_id).await?;
    let published = store::published(&mut tx).await?;
    let doc = store::draft(&mut tx, session_id, &published).await?;
    let exists = get_entity(&doc, kind, id).is_some();
    if create && exists {
        return Err(ApiError::Conflict {
            message: format!("{} {id} already exists", kind.as_str()),
        });
    }
    if !create && !exists {
        return Err(ApiError::NotFound);
    }
    // Rights first (EF-51): a refused caller learns nothing from validation errors.
    let before = get_entity(&doc, kind, id);
    let mut next = doc.clone();
    super::model::set(&mut next, kind, id, Some(value.clone()))?;
    let after = get_entity(&next, kind, id);
    super::authz::check_change(
        &p,
        &published,
        &doc,
        &next,
        kind,
        id,
        before.as_ref(),
        after.as_ref(),
    )?;
    let normalized = normalize(kind, id, value, &doc)?;
    let mutations = if kind == Kind::Rule {
        let rule: Rule = parse(normalized)?;
        let position = rule.position;
        place_rule(&doc, rule, position)
    } else {
        vec![Mutation {
            kind,
            id,
            after: Some(normalized),
        }]
    };
    let (doc, _) = apply(&mut tx, &p, &session, mutations).await?;
    tx.commit().await?;
    let out = get_entity(&doc, kind, id).unwrap_or_default();
    let status = if create {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(out)).into_response())
}

async fn delete(
    State(state): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    kind: Kind,
) -> Result<StatusCode, ApiError> {
    p.require_policy_write()?;
    let session_id = required_session(&headers)?;
    let mut tx = pool(&state)?.begin().await?;
    let session = session_for_write(&mut tx, &p, session_id).await?;
    let published = store::published(&mut tx).await?;
    let doc = store::draft(&mut tx, session_id, &published).await?;
    let before = get_entity(&doc, kind, id).ok_or(ApiError::NotFound)?;
    // Authorization first: a refused caller learns nothing about references.
    let mut next = doc.clone();
    super::model::set(&mut next, kind, id, None)?;
    super::authz::check_change(&p, &published, &doc, &next, kind, id, Some(&before), None)?;
    let refs = references_to(&doc, kind, id);
    if !refs.is_empty() {
        let names: Vec<String> = refs
            .iter()
            .map(|r| format!("{:?} {}", r.kind, r.name))
            .collect();
        return Err(ApiError::Conflict {
            message: format!("still referenced by {}", names.join(", ")),
        });
    }
    apply(
        &mut tx,
        &p,
        &session,
        vec![Mutation {
            kind,
            id,
            after: None,
        }],
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn where_used(
    State(state): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<WhereUsed>, ApiError> {
    let (_, doc, _) = read(&state, &p, &headers).await?;
    if get_entity(&doc, Kind::Object, id).is_none() {
        return Err(ApiError::NotFound);
    }
    Ok(Json(WhereUsed {
        references: afw_engine::where_used(&doc, id)
            .iter()
            .map(afw_engine::Usage::to_ref)
            .collect(),
    }))
}

async fn move_rule(
    State(state): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    p.require_policy_write()?;
    let session_id = required_session(&headers)?;
    let req: MoveRuleRequest = parse(body_json(&body)?)?;
    let mut tx = pool(&state)?.begin().await?;
    let session = session_for_write(&mut tx, &p, session_id).await?;
    let published = store::published(&mut tx).await?;
    let doc = store::draft(&mut tx, session_id, &published).await?;
    let mut rule: Rule = parse(get_entity(&doc, Kind::Rule, id).ok_or(ApiError::NotFound)?)?;
    if let Some(layer) = req.layer
        && layer != rule.layer
    {
        rule.layer = layer;
        if let Layer::Zone { zone_id } = layer {
            rule.sources = vec![zone_id];
        }
    }
    if let Some(section) = req.section {
        rule.section = (!section.trim().is_empty()).then_some(section);
    }
    let (doc, _) = apply(&mut tx, &p, &session, place_rule(&doc, rule, req.position)).await?;
    tx.commit().await?;
    Ok(Json(get_entity(&doc, Kind::Rule, id).unwrap_or_default()))
}

// ---- Rule views ------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct RuleFilter {
    zone_id: Option<Uuid>,
    q: Option<String>,
}

/// Builds the views of `doc`'s rules (evaluation order): numbers, hits, expiry, locks, and the
/// pending change in `session`.
pub async fn rule_views(
    state: &AppState,
    conn: &mut PgConnection,
    doc: &PolicyDocument,
    session: Option<Uuid>,
) -> Result<Vec<RuleView>, ApiError> {
    let numbers = doc.rule_numbers();
    let stats = match &state.rule_stats {
        Some(src) => src.rule_stats().await?,
        None => crate::logs::views::rule_stats(pool(state)?).await?,
    };
    let locks: Vec<(Uuid, SqlJson<Actor>)> = sqlx::query_as(
        "SELECT l.entity_id, s.owner FROM policy_locks l JOIN policy_sessions s \
         ON s.id = l.session_id WHERE l.kind = 'rule'",
    )
    .fetch_all(&mut *conn)
    .await?;
    let locks: HashMap<Uuid, Actor> = locks.into_iter().map(|(id, a)| (id, a.0)).collect();
    let pending: HashMap<Uuid, ChangeOp> = match session {
        Some(s) => store::changes(conn, s)
            .await?
            .into_iter()
            .filter(|c| c.kind == Kind::Rule)
            .map(|c| (c.id, c.op))
            .collect(),
        None => HashMap::new(),
    };
    let now = Utc::now();
    let mut views: Vec<RuleView> = doc
        .rules
        .iter()
        .map(|r| {
            let (hits, last_hit_at) = stats.get(&r.id).copied().unwrap_or((0, None));
            RuleView {
                number: numbers.get(&r.id).copied().unwrap_or_default(),
                hits,
                last_hit_at,
                expired: r.expires_at.is_some_and(|t| t <= now),
                locked_by: locks.get(&r.id).cloned(),
                pending_change: pending.get(&r.id).copied(),
                rule: r.clone(),
            }
        })
        .collect();
    views.sort_by_key(|v| v.number);
    Ok(views)
}

async fn list_rules(
    State(state): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Query(filter): Query<RuleFilter>,
) -> Result<Json<Vec<RuleView>>, ApiError> {
    let (mut conn, doc, session) = read(&state, &p, &headers).await?;
    let q = filter.q.map(|q| q.to_lowercase());
    let views = rule_views(&state, &mut conn, &doc, session)
        .await?
        .into_iter()
        .filter(|v| {
            filter
                .zone_id
                .is_none_or(|z| v.rule.layer == Layer::Zone { zone_id: z })
        })
        .filter(|v| {
            q.as_deref().is_none_or(|q| {
                [
                    Some(&v.rule.name),
                    Some(&v.rule.comment),
                    v.rule.section.as_ref(),
                ]
                .into_iter()
                .flatten()
                .any(|s| s.to_lowercase().contains(q))
            })
        })
        .collect();
    Ok(Json(views))
}

fn sections(views: Vec<RuleView>) -> Vec<RuleSection> {
    let mut out: Vec<RuleSection> = Vec::new();
    for v in views {
        match out.last_mut() {
            Some(s) if s.name == v.rule.section => s.rules.push(v),
            _ => out.push(RuleSection {
                name: v.rule.section.clone(),
                rules: vec![v],
            }),
        }
    }
    out
}

async fn rulebase(
    State(state): State<AppState>,
    p: Principal,
    headers: HeaderMap,
) -> Result<Json<Rulebase>, ApiError> {
    let (mut conn, doc, session) = read(&state, &p, &headers).await?;
    let views = rule_views(&state, &mut conn, &doc, session).await?;
    let (baseline, zoned): (Vec<RuleView>, Vec<RuleView>) = views
        .into_iter()
        .partition(|v| v.rule.layer == Layer::Baseline);
    let mut last = baseline.last().map(|v| v.number).unwrap_or(0);
    let mut zones = doc.zones.clone();
    zones.sort_by(|a, b| (&a.name, a.id).cmp(&(&b.name, b.id)));
    let mut layers = Vec::new();
    for z in zones {
        let rules: Vec<RuleView> = zoned
            .iter()
            .filter(|v| v.rule.layer == Layer::Zone { zone_id: z.id })
            .cloned()
            .collect();
        if let Some(v) = rules.last() {
            last = v.number;
        }
        layers.push(ZoneLayerView {
            mode: z.mode,
            zone: z,
            sections: sections(rules),
            cleanup_number: last + 1,
        });
    }
    Ok(Json(Rulebase {
        baseline: BaselineLayerView {
            sections: sections(baseline),
        },
        zones: layers,
    }))
}
