//! Alert channels (`/alert-channels`) and delivery (EF-36).
//!
//! - `webhook`: generic JSON `{"alert": Alert}` POST, signed: `X-Afw-Timestamp: <unix secs>` and
//!   `X-Afw-Signature: sha256=<hex HMAC-SHA256(AFW_ALERT_WEBHOOK_SECRET, "<ts>.<body>")>`;
//! - `teams`: Microsoft Teams incoming webhook (`MessageCard`);
//! - `pulse_chat`: chat incoming webhook taking `{"text": "..."}` (generic, nothing specific to
//!   one product in the core).
//!
//! Channel URLs usually embed a secret: they are masked on read (`scheme://host/***`).
//! Reads: viewer and above; writes: admin, audited.

use afw_core::api::{Alert, AlertChannel, AlertChannelKind, Role};
use afw_core::events::Severity;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use uuid::Uuid;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Semaphore;

use super::crypto::hmac_sha256;
use super::ingest::pool;
use super::ssrf;
use super::store::{enum_str, parse_enum};
use crate::AppState;
use crate::audit;
use crate::auth::Principal;
use crate::error::ApiError;

pub const SIGNATURE_HEADER: &str = "x-afw-signature";
pub const TIMESTAMP_HEADER: &str = "x-afw-timestamp";

/// Signature of a webhook body: `sha256=<hex>` over `<timestamp>.<body>`.
pub fn sign(secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    let mut msg = timestamp.to_string().into_bytes();
    msg.push(b'.');
    msg.extend_from_slice(body);
    format!("sha256={}", hex::encode(hmac_sha256(secret, &msg)))
}

/// `scheme://host[:port]/***` when the URL has a path or a query (where secrets live).
pub fn mask_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(u) => {
            let has_secret = (u.path() != "/" && !u.path().is_empty())
                || u.query().is_some()
                || !u.username().is_empty()
                || u.password().is_some();
            let host = u.host_str().unwrap_or("");
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            if has_secret {
                format!("{}://{host}{port}/***", u.scheme())
            } else {
                format!("{}://{host}{port}/", u.scheme())
            }
        }
        Err(_) => "***".to_owned(),
    }
}

async fn validate(state: &AppState, c: &AlertChannel) -> Result<(), ApiError> {
    if c.name.trim().is_empty() || c.name.len() > 200 {
        return Err(ApiError::BadRequest(
            "name must be 1 to 200 characters".into(),
        ));
    }
    let allow = ssrf::allowlist(state.config.alert_allowed_hosts.as_deref());
    ssrf::check(&c.url, &allow)
        .await
        .map_err(|e| ApiError::BadRequest(format!("url: {e}")))?;
    if c.kind == AlertChannelKind::Webhook && state.logs.webhook_secret.is_none() {
        return Err(ApiError::BadRequest(
            "webhook channels require AFW_ALERT_WEBHOOK_SECRET (signature key)".into(),
        ));
    }
    Ok(())
}

/// Audit view of a channel: masked URL and SHA-256 of the full URL.
fn audit_view(c: &AlertChannel) -> serde_json::Value {
    serde_json::json!({
        "id": c.id, "name": c.name, "kind": c.kind, "url": mask_url(&c.url),
        "url_sha256": afw_core::sha256_hex(c.url.as_bytes()),
        "min_severity": c.min_severity, "enabled": c.enabled,
    })
}

/// Bounded alert delivery: at most `concurrency` requests in flight and `max_queue` waiting;
/// beyond, deliveries are dropped (and logged) rather than piling up.
#[derive(Clone, Debug)]
pub struct Dispatcher {
    sem: Arc<Semaphore>,
    queued: Arc<AtomicUsize>,
    max_queue: usize,
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new(8, 1000)
    }
}

impl Dispatcher {
    pub fn new(concurrency: usize, max_queue: usize) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(concurrency.max(1))),
            queued: Arc::new(AtomicUsize::new(0)),
            max_queue,
        }
    }

    /// Queues `job`; `false` when the queue is full.
    fn submit<F>(&self, job: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let prev = self.queued.fetch_add(1, Ordering::SeqCst);
        if prev >= self.max_queue {
            self.queued.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        let sem = self.sem.clone();
        let queued = self.queued.clone();
        tokio::spawn(async move {
            let permit = sem.acquire_owned().await;
            queued.fetch_sub(1, Ordering::SeqCst);
            if permit.is_ok() {
                job.await;
            }
        });
        true
    }
}

type ChannelRow = (Uuid, String, String, String, String, bool);

fn channel_of(r: ChannelRow) -> Result<AlertChannel, ApiError> {
    Ok(AlertChannel {
        id: r.0,
        name: r.1,
        kind: parse_enum(&r.2)?,
        url: r.3,
        min_severity: parse_enum(&r.4)?,
        enabled: r.5,
    })
}

fn masked(mut c: AlertChannel) -> AlertChannel {
    c.url = mask_url(&c.url);
    c
}

const COLS: &str = "id, name, kind, url, min_severity, enabled";

async fn load(state: &AppState, id: Uuid) -> Result<AlertChannel, ApiError> {
    let row: Option<ChannelRow> =
        sqlx::query_as(&format!("SELECT {COLS} FROM alert_channels WHERE id = $1"))
            .bind(id)
            .fetch_optional(pool(state)?)
            .await?;
    channel_of(row.ok_or(ApiError::NotFound)?)
}

pub async fn list(
    p: Principal,
    State(state): State<AppState>,
) -> Result<Json<Vec<AlertChannel>>, ApiError> {
    p.require(Role::Viewer)?;
    let rows: Vec<ChannelRow> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM alert_channels ORDER BY name, id"
    ))
    .fetch_all(pool(&state)?)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| channel_of(r).map(masked))
            .collect::<Result<_, _>>()?,
    ))
}

pub async fn get_one(
    p: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AlertChannel>, ApiError> {
    p.require(Role::Viewer)?;
    Ok(Json(masked(load(&state, id).await?)))
}

fn body<T>(b: Result<Json<T>, axum::extract::rejection::JsonRejection>) -> Result<T, ApiError> {
    b.map(|Json(v)| v)
        .map_err(|e| ApiError::BadRequest(e.body_text()))
}

pub async fn create(
    p: Principal,
    State(state): State<AppState>,
    b: Result<Json<AlertChannel>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<AlertChannel>), ApiError> {
    p.require(Role::Admin)?;
    let mut c = body(b)?;
    if c.id.is_nil() {
        c.id = Uuid::new_v4();
    }
    validate(&state, &c).await?;
    let mut tx = pool(&state)?.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO alert_channels (id, name, kind, url, min_severity, enabled) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING",
    )
    .bind(c.id)
    .bind(&c.name)
    .bind(enum_str(&c.kind))
    .bind(&c.url)
    .bind(enum_str(&c.min_severity))
    .bind(c.enabled)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(ApiError::Conflict {
            message: format!("alert channel {} already exists", c.id),
        });
    }
    let c_full = c.clone();
    let out = masked(c);
    audit::record(
        &mut tx,
        &p,
        None,
        "alert_channel.create",
        &format!("alert_channel:{}", out.id),
        serde_json::json!({"after": audit_view(&c_full)}),
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(out)))
}

pub async fn update(
    p: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    b: Result<Json<AlertChannel>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<AlertChannel>, ApiError> {
    p.require(Role::Admin)?;
    let mut c = body(b)?;
    if !c.id.is_nil() && c.id != id {
        return Err(ApiError::BadRequest("id does not match the path".into()));
    }
    c.id = id;
    let before = load(&state, id).await?;
    // The masked URL sent back unchanged keeps the stored one.
    if c.url == mask_url(&before.url) {
        c.url = before.url.clone();
    }
    validate(&state, &c).await?;
    let mut tx = pool(&state)?.begin().await?;
    sqlx::query(
        "UPDATE alert_channels SET name = $2, kind = $3, url = $4, min_severity = $5, \
         enabled = $6 WHERE id = $1",
    )
    .bind(id)
    .bind(&c.name)
    .bind(enum_str(&c.kind))
    .bind(&c.url)
    .bind(enum_str(&c.min_severity))
    .bind(c.enabled)
    .execute(&mut *tx)
    .await?;
    let after = audit_view(&c);
    let out = masked(c);
    audit::record(
        &mut tx,
        &p,
        None,
        "alert_channel.update",
        &format!("alert_channel:{id}"),
        serde_json::json!({"before": audit_view(&before), "after": after}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(out))
}

pub async fn delete(
    p: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    p.require(Role::Admin)?;
    let before = load(&state, id).await?;
    let mut tx = pool(&state)?.begin().await?;
    sqlx::query("DELETE FROM alert_channels WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit::record(
        &mut tx,
        &p,
        None,
        "alert_channel.delete",
        &format!("alert_channel:{id}"),
        serde_json::json!({"before": audit_view(&before)}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

fn severity_color(s: Severity) -> &'static str {
    match s {
        Severity::Info => "2E86DE",
        Severity::Warning => "F39C12",
        Severity::Critical => "C0392B",
    }
}

/// Body of the message sent to a channel.
pub fn payload(
    kind: AlertChannelKind,
    alert: &Alert,
    console_url: Option<&str>,
) -> serde_json::Value {
    let e = &alert.event;
    let title = format!(
        "[agents-firewall] {} — {}",
        enum_str(&e.severity),
        enum_str(&e.kind)
    );
    let agent = e
        .agent_id
        .map(|a| a.to_string())
        .unwrap_or_else(|| "-".to_owned());
    match kind {
        AlertChannelKind::Webhook => {
            serde_json::json!({"alert": alert, "console_url": console_url})
        }
        AlertChannelKind::Teams => serde_json::json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": title,
            "themeColor": severity_color(e.severity),
            "title": title,
            "text": e.summary,
            "sections": [{"facts": [
                {"name": "Agent", "value": agent},
                {"name": "At", "value": e.at.to_rfc3339()},
                {"name": "Alert", "value": e.id.to_string()},
            ]}],
        }),
        AlertChannelKind::PulseChat => serde_json::json!({
            "text": format!("**{title}**\n{}\nagent: {agent} · {}", e.summary, e.at.to_rfc3339()),
        }),
    }
}

/// Sends `alert` to every enabled channel whose minimum severity it reaches, in background
/// tasks (never blocks the ingestion). Failures are logged.
pub async fn dispatch(state: &AppState, alert: Alert) -> Result<(), ApiError> {
    let rows: Vec<ChannelRow> =
        sqlx::query_as(&format!("SELECT {COLS} FROM alert_channels WHERE enabled"))
            .fetch_all(pool(state)?)
            .await?;
    for row in rows {
        let ch = channel_of(row)?;
        if alert.event.severity < ch.min_severity {
            continue;
        }
        let secret = state.logs.webhook_secret.clone();
        let allow = ssrf::allowlist(state.config.alert_allowed_hosts.as_deref());
        let body = payload(ch.kind, &alert, state.config.public_url.as_deref()).to_string();
        let channel = ch.id;
        let queued = state.logs.dispatch.submit(async move {
            // Checked again at send time; the connection goes to the verified address only.
            let checked = match ssrf::check(&ch.url, &allow).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(channel = %ch.id, error = %e, "alert channel URL refused");
                    return;
                }
            };
            let mut req = ssrf::client_for(&checked)
                .post(checked.url.clone())
                .header("content-type", "application/json");
            if ch.kind == AlertChannelKind::Webhook {
                let Some(secret) = secret else {
                    tracing::error!(channel = %ch.id, "webhook not sent: no AFW_ALERT_WEBHOOK_SECRET");
                    return;
                };
                let ts = chrono::Utc::now().timestamp();
                req = req
                    .header(TIMESTAMP_HEADER, ts.to_string())
                    .header(SIGNATURE_HEADER, sign(secret.as_bytes(), ts, body.as_bytes()));
            }
            match req.body(body).send().await {
                Ok(r) if r.status().is_success() => {}
                Ok(r) => tracing::warn!(channel = %ch.id, status = %r.status(), "alert channel refused the alert"),
                Err(e) => tracing::warn!(channel = %ch.id, error = %e, "alert channel unreachable"),
            }
        });
        if !queued {
            tracing::warn!(%channel, "alert delivery queue full: alert not sent");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_masked() {
        assert_eq!(
            mask_url("https://outlook.office.com/webhook/abc/IncomingWebhook/def"),
            "https://outlook.office.com/***"
        );
        assert_eq!(mask_url("https://h:8443/?token=x"), "https://h:8443/***");
        assert_eq!(mask_url("https://h/"), "https://h/");
        assert_eq!(mask_url("not a url"), "***");
    }

    #[test]
    fn signature_is_hmac_of_timestamp_and_body() {
        let s = sign(b"k", 1700000000, b"{}");
        assert_eq!(
            s,
            format!(
                "sha256={}",
                hex::encode(hmac_sha256(b"k", b"1700000000.{}"))
            )
        );
    }
}
