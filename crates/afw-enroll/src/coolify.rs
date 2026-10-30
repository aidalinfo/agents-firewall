//! Coolify v4 API client and enrollment of Coolify-managed compose resources (EF-64).
//!
//! The change is written into Coolify itself (`docker_compose_raw`), so it survives the
//! redeployments that would overwrite a file edited on the host. API used (Coolify v4,
//! `routes/api.php` and `ServicesController`):
//! - `GET /api/v1/{applications|services}/{uuid}`: `docker_compose_raw` in clear text, only
//!   returned when the token has the `read:sensitive` permission;
//! - `PATCH /api/v1/{applications|services}/{uuid}` `{ "docker_compose_raw": <base64> }`
//!   (Coolify rejects a non-base64 value with 422);
//! - `POST /api/v1/{applications|services}/{uuid}/restart` (older v4 releases: `GET`).

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};

use crate::compose::{enroll_compose, unenroll_compose};
use crate::error::EnrollError;
use crate::spec::{EnrollOutcome, EnrollSpec};

/// Kind of Coolify resource holding a compose file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoolifyKind {
    /// An application with the `dockercompose` build pack.
    Application,
    /// A service (one-click service or "Docker Compose Empty").
    Service,
}

impl CoolifyKind {
    fn segment(self) -> &'static str {
        match self {
            Self::Application => "applications",
            Self::Service => "services",
        }
    }
}

/// A Coolify application or service as returned by the API.
#[derive(Debug, Clone, PartialEq)]
pub struct CoolifyResource {
    /// Resource UUID.
    pub uuid: String,
    /// Display name, if any.
    pub name: Option<String>,
    /// Compose file in clear text (`None` if absent or hidden by the token permissions).
    pub docker_compose_raw: Option<String>,
    /// Full JSON answer.
    pub raw: Value,
}

/// Minimal Coolify v4 API client (bearer token).
#[derive(Clone)]
pub struct CoolifyClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl fmt::Debug for CoolifyClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoolifyClient")
            .field("base_url", &self.base_url)
            .field("token", &"<redacted>")
            .finish()
    }
}

const MAX_ERROR_BODY: usize = 512;

impl CoolifyClient {
    /// `base_url` is the Coolify instance (`https://coolify.example.org`), with or without
    /// the `/api/v1` suffix.
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self, EnrollError> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self::with_http_client(base_url, token, http))
    }

    /// Same as [`CoolifyClient::new`] with a caller-provided HTTP client (proxy, CA…).
    pub fn with_http_client(
        base_url: impl Into<String>,
        token: impl Into<String>,
        http: reqwest::Client,
    ) -> Self {
        let mut base = base_url.into().trim_end_matches('/').to_string();
        if !base.ends_with("/api/v1") {
            base.push_str("/api/v1");
        }
        Self {
            base_url: base,
            token: token.into(),
            http,
        }
    }

    /// `GET /applications/{uuid}`.
    pub async fn get_application(&self, uuid: &str) -> Result<CoolifyResource, EnrollError> {
        self.get(CoolifyKind::Application, uuid).await
    }

    /// `GET /services/{uuid}`.
    pub async fn get_service(&self, uuid: &str) -> Result<CoolifyResource, EnrollError> {
        self.get(CoolifyKind::Service, uuid).await
    }

    /// `GET /{kind}/{uuid}`.
    pub async fn get(&self, kind: CoolifyKind, uuid: &str) -> Result<CoolifyResource, EnrollError> {
        let path = resource_path(kind, uuid)?;
        let resp = self
            .http
            .get(format!("{}{path}", self.base_url))
            .bearer_auth(&self.token)
            .header("accept", "application/json")
            .send()
            .await?;
        let raw: Value = check(resp, &path).await?.json().await?;
        let compose = raw
            .get("docker_compose_raw")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(decode_compose);
        Ok(CoolifyResource {
            uuid: raw
                .get("uuid")
                .and_then(Value::as_str)
                .unwrap_or(uuid)
                .to_string(),
            name: raw.get("name").and_then(Value::as_str).map(str::to_string),
            docker_compose_raw: compose,
            raw,
        })
    }

    /// `PATCH /{kind}/{uuid}` with the compose file (encoded in base64 as Coolify requires).
    pub async fn update_compose(
        &self,
        kind: CoolifyKind,
        uuid: &str,
        compose: &str,
    ) -> Result<(), EnrollError> {
        let path = resource_path(kind, uuid)?;
        let resp = self
            .http
            .patch(format!("{}{path}", self.base_url))
            .bearer_auth(&self.token)
            .header("accept", "application/json")
            .json(&json!({ "docker_compose_raw": B64.encode(compose) }))
            .send()
            .await?;
        check(resp, &path).await?;
        Ok(())
    }

    /// `POST /{kind}/{uuid}/restart` (falls back to `GET` on 405 for older Coolify v4).
    pub async fn restart(&self, kind: CoolifyKind, uuid: &str) -> Result<(), EnrollError> {
        let path = format!("{}/restart", resource_path(kind, uuid)?);
        let url = format!("{}{path}", self.base_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .header("accept", "application/json")
            .send()
            .await?;
        let resp = if resp.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED {
            self.http
                .get(&url)
                .bearer_auth(&self.token)
                .header("accept", "application/json")
                .send()
                .await?
        } else {
            resp
        };
        check(resp, &path).await?;
        Ok(())
    }

    async fn compose_of(&self, kind: CoolifyKind, uuid: &str) -> Result<String, EnrollError> {
        self.get(kind, uuid)
            .await?
            .docker_compose_raw
            .ok_or_else(|| EnrollError::NoCompose(uuid.into()))
    }
}

/// Read the compose file from Coolify → [`enroll_compose`] → write it back → restart.
/// Nothing is written if the transformation fails; nothing is restarted if the write fails.
pub async fn enroll_coolify(
    client: &CoolifyClient,
    kind: CoolifyKind,
    uuid: &str,
    spec: &EnrollSpec,
) -> Result<EnrollOutcome, EnrollError> {
    let compose = client.compose_of(kind, uuid).await?;
    let outcome = enroll_compose(&compose, spec)?;
    client.update_compose(kind, uuid, &outcome.yaml).await?;
    client.restart(kind, uuid).await?;
    Ok(outcome)
}

/// Read the compose file from Coolify → [`unenroll_compose`] → write it back → restart.
pub async fn unenroll_coolify(
    client: &CoolifyClient,
    kind: CoolifyKind,
    uuid: &str,
    agent_name: &str,
) -> Result<String, EnrollError> {
    let compose = client.compose_of(kind, uuid).await?;
    let restored = unenroll_compose(&compose, agent_name)?;
    client.update_compose(kind, uuid, &restored).await?;
    client.restart(kind, uuid).await?;
    Ok(restored)
}

fn resource_path(kind: CoolifyKind, uuid: &str) -> Result<String, EnrollError> {
    // Coolify UUIDs are short alphanumeric identifiers; refuse anything that could alter the path.
    if uuid.is_empty() || !uuid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(EnrollError::InvalidSpec(format!(
            "invalid Coolify uuid `{uuid}`"
        )));
    }
    Ok(format!("/{}/{uuid}", kind.segment()))
}

async fn check(resp: reqwest::Response, path: &str) -> Result<reqwest::Response, EnrollError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let mut body = resp.text().await.unwrap_or_default();
    if body.len() > MAX_ERROR_BODY {
        let mut cut = MAX_ERROR_BODY;
        while !body.is_char_boundary(cut) {
            cut -= 1;
        }
        body.truncate(cut);
        body.push('…');
    }
    Err(EnrollError::CoolifyStatus {
        status: status.as_u16(),
        path: path.into(),
        body,
    })
}

/// Coolify returns the compose file in clear text; accept a base64 value too (a YAML compose
/// file always contains `:` or whitespace, which base64 never does).
fn decode_compose(s: &str) -> String {
    let looks_b64 = !s.contains(':') && !s.contains(char::is_whitespace);
    if looks_b64 {
        if let Some(text) = B64
            .decode(s)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
        {
            return text;
        }
    }
    s.to_string()
}
