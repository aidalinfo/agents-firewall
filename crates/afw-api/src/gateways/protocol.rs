//! Gateway protocol handlers (`/gw/v1`, ADR 0004). Every handler except `register` requires an
//! [`AuthenticatedGateway`].

use afw_core::events::GatewayEvent;
use afw_core::protocol::{
    EventBatch, GatewayCommand, Heartbeat, HeartbeatResponse, PolicyAck, PolicyQuery,
    RegisterRequest, RegisterResponse,
};
use afw_core::sha256_hex;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use sqlx::types::Json as SqlJson;
use uuid::Uuid;

use super::tls::AuthenticatedGateway;
use crate::AppState;
use crate::audit;
use crate::auth::Principal;
use crate::auth::extract::JsonBody;
use crate::auth::tokens::{is_unique_violation, pool};
use crate::error::ApiError;

fn check_label(what: &str, v: &str) -> Result<(), ApiError> {
    if v.trim().is_empty() || v.len() > 253 || v.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!("invalid {what}")));
    }
    Ok(())
}

/// `POST /gw/v1/register`: one-time token + CSR -> client certificate signed by the console CA.
/// An invalid CSR or a name conflict does not consume the token.
pub async fn register(
    State(state): State<AppState>,
    JsonBody(req): JsonBody<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    let pki = state
        .gateways
        .pki
        .clone()
        .ok_or_else(|| ApiError::Internal("console PKI not configured".into()))?;
    let db = pool(&state)?;
    let digest = sha256_hex(req.token.as_bytes());
    // Cheap check first: no signature work for unauthenticated callers.
    let valid: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM gateway_registration_tokens \
         WHERE token_sha256 = $1 AND used_at IS NULL AND expires_at > now()",
    )
    .bind(&digest)
    .fetch_optional(db)
    .await?;
    let token_id = valid.ok_or(ApiError::Unauthorized)?;
    check_label("name", &req.name)?;
    check_label("hostname", &req.hostname)?;

    let gateway_id = Uuid::new_v4();
    let cert_pem = pki
        .sign_gateway_csr(
            &req.csr_pem,
            &gateway_id.to_string(),
            state.gateways.cert_days,
        )
        .map_err(|e| ApiError::BadRequest(format!("certificate request refused: {e}")))?;
    let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .and_then(Result::ok)
        .ok_or_else(|| ApiError::Internal("issued certificate does not parse".into()))?;
    let cert_sha256 = sha256_hex(der.as_ref());

    let mut tx = db.begin().await?;
    sqlx::query("INSERT INTO gateways (id, name, hostname, cert_sha256) VALUES ($1, $2, $3, $4)")
        .bind(gateway_id)
        .bind(req.name.trim())
        .bind(req.hostname.trim())
        .bind(&cert_sha256)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                ApiError::Conflict {
                    message: format!("a gateway named {:?} already exists", req.name.trim()),
                }
            } else {
                e.into()
            }
        })?;
    // Atomic consumption: a concurrent registration with the same token gets 0 rows.
    let consumed = sqlx::query(
        "UPDATE gateway_registration_tokens SET used_at = now(), gateway_id = $2 \
         WHERE id = $1 AND used_at IS NULL AND expires_at > now()",
    )
    .bind(token_id)
    .bind(gateway_id)
    .execute(&mut *tx)
    .await?;
    if consumed.rows_affected() != 1 {
        return Err(ApiError::Unauthorized);
    }
    let principal = Principal::system(&format!("gateway:{gateway_id}"), req.name.trim());
    audit::record(
        &mut tx,
        &principal,
        None,
        "gateway.register",
        &format!("gateway:{gateway_id}"),
        serde_json::json!({"after": {
            "id": gateway_id, "name": req.name.trim(), "hostname": req.hostname.trim(),
            "cert_sha256": cert_sha256, "registration_token": token_id,
        }}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            gateway_id,
            cert_pem,
            ca_pem: pki.ca_cert_pem(),
        }),
    ))
}

/// `GET /gw/v1/policy?have=<rev>`: `200` with the desired policy when it differs from `have`,
/// else `204` at the end of the long poll.
pub async fn policy(
    State(state): State<AppState>,
    AuthenticatedGateway(gateway): AuthenticatedGateway,
    Query(q): Query<PolicyQuery>,
) -> Result<Response, ApiError> {
    let deadline = tokio::time::Instant::now() + state.gateways.long_poll;
    loop {
        if let Some(p) = state
            .ports
            .policy
            .installed_policy_for(&state, gateway)
            .await?
            && Some(p.revision) != q.have
        {
            return Ok(Json(p).into_response());
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
        tokio::time::sleep(state.gateways.poll_interval.min(deadline - now)).await;
    }
}

/// `POST /gw/v1/policy/ack`.
pub async fn ack(
    State(state): State<AppState>,
    AuthenticatedGateway(gateway): AuthenticatedGateway,
    JsonBody(ack): JsonBody<PolicyAck>,
) -> Result<StatusCode, ApiError> {
    state
        .ports
        .policy
        .record_install_ack(&state, gateway, ack)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Forces the authenticated gateway id into every event: a gateway cannot report events in
/// the name of another one.
fn stamp(gateway: Uuid, events: &mut [GatewayEvent]) {
    for e in events {
        match e {
            GatewayEvent::Flow(f) => f.gateway_id = gateway,
            GatewayEvent::Dns(d) => d.gateway_id = gateway,
            GatewayEvent::Http(h) => h.gateway_id = gateway,
            GatewayEvent::Alert(_) | GatewayEvent::RuleHits { .. } => {}
        }
    }
}

/// `POST /gw/v1/events`: ingested once per `batch_id`.
pub async fn events(
    State(state): State<AppState>,
    AuthenticatedGateway(gateway): AuthenticatedGateway,
    JsonBody(mut batch): JsonBody<EventBatch>,
) -> Result<StatusCode, ApiError> {
    let db = pool(&state)?;
    let seen: Option<Uuid> =
        sqlx::query_scalar("SELECT batch_id FROM gateway_event_batches WHERE batch_id = $1")
            .bind(batch.batch_id)
            .fetch_optional(db)
            .await?;
    if seen.is_some() {
        return Ok(StatusCode::ACCEPTED);
    }
    stamp(gateway, &mut batch.events);
    state
        .ports
        .logs
        .ingest_gateway_events(&state, gateway, batch.events)
        .await?;
    sqlx::query(
        "INSERT INTO gateway_event_batches (batch_id, gateway_id) VALUES ($1, $2) \
         ON CONFLICT (batch_id) DO NOTHING",
    )
    .bind(batch.batch_id)
    .bind(gateway)
    .execute(db)
    .await?;
    Ok(StatusCode::ACCEPTED)
}

/// `POST /gw/v1/heartbeat`: records the gateway state, returns the queued commands (once).
pub async fn heartbeat(
    State(state): State<AppState>,
    AuthenticatedGateway(gateway): AuthenticatedGateway,
    JsonBody(hb): JsonBody<Heartbeat>,
) -> Result<Json<HeartbeatResponse>, ApiError> {
    let db = pool(&state)?;
    let revision = hb.revision.and_then(|r| i64::try_from(r).ok());
    sqlx::query(
        "UPDATE gateways SET last_seen_at = now(), version = $2, active_revision = $3, \
         ca_fingerprint = $4, stats = $5 WHERE id = $1",
    )
    .bind(gateway)
    .bind(&hb.version)
    .bind(revision)
    .bind(&hb.ca_fingerprint)
    .bind(SqlJson(&hb.stats))
    .execute(db)
    .await?;
    let mut queued: Vec<(SqlJson<GatewayCommand>, DateTime<Utc>)> = sqlx::query_as(
        "UPDATE gateway_commands SET delivered_at = now() WHERE id IN ( \
           SELECT id FROM gateway_commands WHERE gateway_id = $1 AND delivered_at IS NULL \
           FOR UPDATE SKIP LOCKED) \
         RETURNING command, created_at",
    )
    .bind(gateway)
    .fetch_all(db)
    .await?;
    queued.sort_by_key(|(_, at)| *at);
    let mut commands: Vec<GatewayCommand> = queued.into_iter().map(|(c, _)| c.0).collect();
    commands.extend(state.ports.logs.pending_commands(&state, gateway).await?);
    Ok(Json(HeartbeatResponse { commands }))
}

/// `POST /gw/v1/captures/{id}`: raw pcap body.
pub async fn capture(
    State(state): State<AppState>,
    AuthenticatedGateway(gateway): AuthenticatedGateway,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    if body.is_empty() {
        return Err(ApiError::BadRequest("empty capture".into()));
    }
    state
        .ports
        .logs
        .store_capture(&state, gateway, id, body)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
