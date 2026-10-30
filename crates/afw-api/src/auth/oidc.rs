//! Generic OIDC: discovery, JWKS cache, validation of bearer JWTs (ID or access tokens) and
//! mapping of a claim (groups) to a role.
//!
//! Only asymmetric algorithms are accepted, the key is always taken from the provider's JWKS and
//! must match the algorithm family (no `none`, no HMAC: no algorithm confusion).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use afw_core::api::Role;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::{Mutex, RwLock};

use crate::error::ApiError;

/// How long a fetched JWKS is used before being refreshed.
const JWKS_TTL: Duration = Duration::from_secs(600);
/// Minimum delay between two refreshes forced by an unknown `kid` (abuse protection).
const FORCED_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);
/// Clock skew tolerated on `exp`, `nbf`, `iat`.
const LEEWAY_SECS: u64 = 60;
/// After a failed discovery or JWKS fetch, the provider is not contacted again for this long
/// (negative cache: an unreachable provider must not be hit on every request).
const FAILURE_COOLDOWN: Duration = Duration::from_secs(30);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// OIDC settings (`AFW_OIDC_*`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct OidcSettings {
    /// `AFW_OIDC_ISSUER`: exact issuer (`iss`) and discovery base URL.
    pub issuer: String,
    /// `AFW_OIDC_CLIENT_ID`: public client of the console (authorization code + PKCE).
    pub client_id: String,
    /// `AFW_OIDC_AUDIENCE` (comma separated), default: the client id. A token is accepted when
    /// its `aud` contains one of them.
    pub audiences: Vec<String>,
    /// `AFW_OIDC_SCOPES`, default `openid profile email`.
    pub scopes: String,
    /// `AFW_OIDC_ROLE_CLAIM`, default `groups`; a dotted path reaches nested claims
    /// (`realm_access.roles`). The claim may be a string or an array of strings.
    pub role_claim: String,
    /// `AFW_OIDC_ADMIN_GROUPS`, `AFW_OIDC_AUDITOR_GROUPS`, `AFW_OIDC_VIEWER_GROUPS` (comma
    /// separated): claim values granting each role; the highest role wins.
    pub admin_groups: Vec<String>,
    pub auditor_groups: Vec<String>,
    pub viewer_groups: Vec<String>,
    /// `AFW_OIDC_DEFAULT_ROLE` (`viewer` or `auditor`) for authenticated users matching no
    /// group; absent: such users are refused. Never `admin`.
    pub default_role: Option<Role>,
}

fn list(v: Option<String>) -> Vec<String> {
    v.map(|s| {
        s.split(',')
            .map(|x| x.trim().to_owned())
            .filter(|x| !x.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

impl OidcSettings {
    /// Reads `AFW_OIDC_*`; `None` when `AFW_OIDC_ISSUER` or `AFW_OIDC_CLIENT_ID` is missing.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let (Some(issuer), Some(client_id)) = (var("AFW_OIDC_ISSUER"), var("AFW_OIDC_CLIENT_ID"))
        else {
            return Ok(None);
        };
        let mut audiences = list(var("AFW_OIDC_AUDIENCE"));
        if audiences.is_empty() {
            audiences.push(client_id.clone());
        }
        let default_role = match var("AFW_OIDC_DEFAULT_ROLE").as_deref() {
            None => None,
            Some("viewer") => Some(Role::Viewer),
            Some("auditor") => Some(Role::Auditor),
            Some(other) => {
                anyhow::bail!("AFW_OIDC_DEFAULT_ROLE must be viewer or auditor, not {other:?}")
            }
        };
        Ok(Some(Self {
            issuer: issuer.trim_end_matches('/').to_owned(),
            client_id,
            audiences,
            scopes: var("AFW_OIDC_SCOPES").unwrap_or_else(|| "openid profile email".to_owned()),
            role_claim: var("AFW_OIDC_ROLE_CLAIM").unwrap_or_else(|| "groups".to_owned()),
            admin_groups: list(var("AFW_OIDC_ADMIN_GROUPS")),
            auditor_groups: list(var("AFW_OIDC_AUDITOR_GROUPS")),
            viewer_groups: list(var("AFW_OIDC_VIEWER_GROUPS")),
            default_role,
        }))
    }

    /// Role granted by `claims`: highest matching group, else `default_role`.
    pub fn map_role(&self, claims: &Value) -> Option<Role> {
        let mut node = claims;
        for part in self.role_claim.split('.') {
            node = node.get(part).unwrap_or(&Value::Null);
        }
        let values: Vec<&str> = match node {
            Value::String(s) => vec![s.as_str()],
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
            _ => vec![],
        };
        let has = |groups: &[String]| values.iter().any(|v| groups.iter().any(|g| g == v));
        if has(&self.admin_groups) {
            Some(Role::Admin)
        } else if has(&self.auditor_groups) {
            Some(Role::Auditor)
        } else if has(&self.viewer_groups) {
            Some(Role::Viewer)
        } else {
            self.default_role
                .filter(|r| matches!(r, Role::Viewer | Role::Auditor))
        }
    }
}

/// Provider metadata (subset of the discovery document).
#[derive(Clone, Debug, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub jwks_uri: String,
}

struct Keys {
    by_kid: HashMap<String, Jwk>,
    unnamed: Vec<Jwk>,
    fetched_at: Instant,
}

/// Validated identity of an OIDC bearer token.
#[derive(Clone, Debug, PartialEq)]
pub struct OidcIdentity {
    pub subject: String,
    pub name: String,
    pub email: Option<String>,
    /// `None`: authenticated, but no role is granted.
    pub role: Option<Role>,
}

/// Validates OIDC bearer tokens against the configured provider.
pub struct OidcVerifier {
    settings: OidcSettings,
    http: reqwest::Client,
    discovery: RwLock<Option<Discovery>>,
    keys: RwLock<Option<Keys>>,
    last_forced_refresh: Mutex<Option<Instant>>,
    last_failure: std::sync::Mutex<Option<Instant>>,
}

impl std::fmt::Debug for OidcVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcVerifier")
            .field("issuer", &self.settings.issuer)
            .finish_non_exhaustive()
    }
}

/// Whether `url` may be fetched: HTTPS, or plain HTTP to a loopback host (tests, local IdP).
fn allowed_url(url: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(url) else {
        return false;
    };
    match u.scheme() {
        "https" => true,
        "http" => match u.host_str() {
            Some("localhost") => true,
            Some(h) => h
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()),
            None => false,
        },
        _ => false,
    }
}

fn unauthorized(why: &str) -> ApiError {
    tracing::debug!(reason = why, "OIDC token refused");
    ApiError::Unauthorized
}

/// Whether `token` looks like a compact JWS (`header.payload.signature`).
pub fn looks_like_jwt(token: &str) -> bool {
    token.starts_with("eyJ") && token.split('.').count() == 3
}

impl OidcVerifier {
    pub fn new(settings: OidcSettings) -> Self {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("HTTP client");
        Self {
            settings,
            http,
            discovery: RwLock::new(None),
            keys: RwLock::new(None),
            last_forced_refresh: Mutex::new(None),
            last_failure: std::sync::Mutex::new(None),
        }
    }

    pub fn settings(&self) -> &OidcSettings {
        &self.settings
    }

    /// [`Self::fetch_json`] behind the negative cache.
    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, ApiError> {
        let recent = self
            .last_failure
            .lock()
            .map(|f| f.is_some_and(|t| t.elapsed() < FAILURE_COOLDOWN))
            .unwrap_or(false);
        if recent {
            return Err(ApiError::Internal(
                "OIDC provider failed recently; retrying later".into(),
            ));
        }
        let out = self.fetch_json(url).await;
        if let Ok(mut f) = self.last_failure.lock() {
            *f = out.is_err().then(Instant::now);
        }
        out
    }

    async fn fetch_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, ApiError> {
        if !allowed_url(url) {
            return Err(ApiError::Internal(format!(
                "OIDC URL {url:?} must use https (http only on loopback)"
            )));
        }
        let res = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| ApiError::Internal(format!("OIDC fetch {url}: {e}")))?;
        if !res.status().is_success() {
            return Err(ApiError::Internal(format!(
                "OIDC fetch {url}: status {}",
                res.status()
            )));
        }
        res.json()
            .await
            .map_err(|e| ApiError::Internal(format!("OIDC fetch {url}: {e}")))
    }

    /// Discovery document, fetched once; its `issuer` must equal the configured issuer.
    pub async fn discovery(&self) -> Result<Discovery, ApiError> {
        if let Some(d) = self.discovery.read().await.clone() {
            return Ok(d);
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.settings.issuer.trim_end_matches('/')
        );
        let d: Discovery = self.get_json(&url).await?;
        if d.issuer.trim_end_matches('/') != self.settings.issuer.trim_end_matches('/') {
            return Err(ApiError::Internal(format!(
                "OIDC discovery issuer {:?} differs from the configured issuer",
                d.issuer
            )));
        }
        *self.discovery.write().await = Some(d.clone());
        Ok(d)
    }

    async fn fetch_keys(&self) -> Result<(), ApiError> {
        let d = self.discovery().await?;
        let set: Value = self.get_json(&d.jwks_uri).await?;
        let mut by_kid = HashMap::new();
        let mut unnamed = Vec::new();
        for raw in set
            .get("keys")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            // Unknown key types are skipped, not fatal for the whole set.
            let Ok(jwk) = serde_json::from_value::<Jwk>(raw) else {
                continue;
            };
            if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
                continue; // symmetric keys are never accepted
            }
            match jwk.common.key_id.clone() {
                Some(kid) => {
                    by_kid.insert(kid, jwk);
                }
                None => unnamed.push(jwk),
            }
        }
        *self.keys.write().await = Some(Keys {
            by_kid,
            unnamed,
            fetched_at: Instant::now(),
        });
        Ok(())
    }

    async fn find_key(&self, kid: Option<&str>) -> Option<Jwk> {
        let keys = self.keys.read().await;
        let keys = keys.as_ref()?;
        match kid {
            Some(kid) => keys.by_kid.get(kid).cloned(),
            None if keys.by_kid.len() + keys.unnamed.len() == 1 => keys
                .unnamed
                .first()
                .or_else(|| keys.by_kid.values().next())
                .cloned(),
            None => None,
        }
    }

    async fn key_for(&self, kid: Option<&str>) -> Result<Jwk, ApiError> {
        let stale = match self.keys.read().await.as_ref() {
            None => true,
            Some(k) => k.fetched_at.elapsed() > JWKS_TTL,
        };
        if stale {
            self.fetch_keys().await?;
        }
        if let Some(k) = self.find_key(kid).await {
            return Ok(k);
        }
        // Unknown kid: the provider may have rotated its keys. Refresh, at most once per
        // cooldown, so forged kids cannot make us hammer the provider.
        {
            let mut last = self.last_forced_refresh.lock().await;
            if last.is_some_and(|t| t.elapsed() < FORCED_REFRESH_COOLDOWN) {
                return Err(unauthorized("unknown kid"));
            }
            *last = Some(Instant::now());
        }
        self.fetch_keys().await?;
        self.find_key(kid)
            .await
            .ok_or_else(|| unauthorized("unknown kid"))
    }

    /// Validates `token` (signature, `iss`, `aud`, `exp`, `nbf`, `sub`) and maps its role.
    /// Errors: `Unauthorized` for any invalid token, `Internal` when the provider is unreachable.
    pub async fn verify(&self, token: &str) -> Result<OidcIdentity, ApiError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| unauthorized("header"))?;
        let alg = header.alg;
        let jwk = self.key_for(header.kid.as_deref()).await?;
        let family_ok = match &jwk.algorithm {
            AlgorithmParameters::RSA(_) => matches!(
                alg,
                Algorithm::RS256
                    | Algorithm::RS384
                    | Algorithm::RS512
                    | Algorithm::PS256
                    | Algorithm::PS384
                    | Algorithm::PS512
            ),
            AlgorithmParameters::EllipticCurve(_) => {
                matches!(alg, Algorithm::ES256 | Algorithm::ES384)
            }
            AlgorithmParameters::OctetKeyPair(_) => alg == Algorithm::EdDSA,
            AlgorithmParameters::OctetKey(_) => false,
        };
        if !family_ok {
            return Err(unauthorized("algorithm does not match the key"));
        }
        if let Some(key_alg) = jwk.common.key_algorithm
            && format!("{key_alg:?}") != format!("{alg:?}")
        {
            return Err(unauthorized("algorithm differs from the key's alg"));
        }
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| unauthorized("key"))?;
        let mut validation = Validation::new(alg);
        validation.leeway = LEEWAY_SECS;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_issuer(&[self.settings.issuer.as_str()]);
        validation.set_audience(&self.settings.audiences);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let data = jsonwebtoken::decode::<Value>(token, &key, &validation)
            .map_err(|e| unauthorized(&e.to_string()))?;
        let claims = data.claims;
        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| unauthorized("sub"))?
            .to_owned();
        let email = claims
            .get("email")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let name = ["name", "preferred_username", "email"]
            .iter()
            .find_map(|k| claims.get(*k).and_then(Value::as_str))
            .unwrap_or(&subject)
            .to_owned();
        Ok(OidcIdentity {
            role: self.settings.map_role(&claims),
            subject,
            name,
            email,
        })
    }
}

/// `GET /auth/oidc/config`: public parameters for the console's authorization code + PKCE flow.
pub async fn public_config(oidc: Option<&Arc<OidcVerifier>>) -> Value {
    let Some(v) = oidc else {
        return serde_json::json!({"enabled": false});
    };
    let s = v.settings();
    let mut out = serde_json::json!({
        "enabled": true,
        "issuer": s.issuer,
        "client_id": s.client_id,
        "scopes": s.scopes,
        "authorization_endpoint": null,
        "token_endpoint": null,
        "end_session_endpoint": null,
    });
    match v.discovery().await {
        Ok(d) => {
            out["authorization_endpoint"] = d.authorization_endpoint.into();
            out["token_endpoint"] = d.token_endpoint.into();
            out["end_session_endpoint"] = d.end_session_endpoint.into();
        }
        Err(e) => tracing::warn!(error = %e, "OIDC discovery failed"),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> OidcSettings {
        OidcSettings {
            role_claim: "realm_access.roles".into(),
            admin_groups: vec!["adm".into()],
            auditor_groups: vec!["aud".into()],
            viewer_groups: vec!["view".into()],
            ..Default::default()
        }
    }

    #[test]
    fn role_mapping_takes_the_highest_and_never_defaults_to_admin() {
        let s = settings();
        let c = |v: Value| serde_json::json!({"realm_access": {"roles": v}});
        assert_eq!(
            s.map_role(&c(serde_json::json!(["view", "adm"]))),
            Some(Role::Admin)
        );
        assert_eq!(
            s.map_role(&c(serde_json::json!("aud"))),
            Some(Role::Auditor)
        );
        assert_eq!(s.map_role(&c(serde_json::json!(["x"]))), None);
        assert_eq!(s.map_role(&serde_json::json!({})), None);
        let mut d = settings();
        d.default_role = Some(Role::Admin);
        assert_eq!(d.map_role(&serde_json::json!({})), None);
        d.default_role = Some(Role::Viewer);
        assert_eq!(d.map_role(&serde_json::json!({})), Some(Role::Viewer));
    }

    #[test]
    fn only_https_or_loopback_http() {
        assert!(allowed_url("https://idp.example/x"));
        assert!(allowed_url("http://127.0.0.1:8080/x"));
        assert!(allowed_url("http://localhost/x"));
        assert!(!allowed_url("http://idp.example/x"));
        assert!(!allowed_url("file:///etc/passwd"));
    }

    #[test]
    fn jwt_shape() {
        assert!(looks_like_jwt("eyJhbGciOiJSUzI1NiJ9.e30.sig"));
        assert!(!looks_like_jwt("afw_abc"));
        assert!(!looks_like_jwt("eyJ.only"));
    }
}
