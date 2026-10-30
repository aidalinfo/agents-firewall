//! REST API client shared by the `afw` CLI and the MCP server (lot L8).
//!
//! One method per operation of `docs/api/openapi.yaml` (`/api/v1`). Every request carries
//! `Authorization: Bearer <token>`, `X-Afw-Interface` (declarative, recorded in the audit log)
//! and, when an editing session is active, `X-Afw-Session`. Errors are decoded from
//! `application/problem+json` into [`ClientError::Api`]. The client never decides what the
//! caller may do: the API is the only authority (EF-51/52).

mod error;
#[cfg(feature = "fake")]
pub mod fake;
pub mod sse;
mod views;

use std::sync::{Arc, RwLock};
use std::time::Duration;

use afw_core::api::{
    AgentOverview, Alert, AlertChannel, ApiToken, Approval, ApprovalDecision, ApprovalStatus,
    AuditVerifyResult, Capture, CaptureRequest, CreateApiToken, CreateRegistrationToken,
    CreatedApiToken, DnsPage, Enrollment, EnrollmentRequest, FlowDetail, FlowPage, FlowQuery,
    Gateway, Install, InstallRequest, InstallResult, IntentPolicy, InternalMap, Me,
    MoveRuleRequest, Page, Problem, RegistrationToken, Revision, RevisionDetail, RevisionDiff,
    Session, ToolCallBatch, VerifyReport, WhereUsed,
};
use afw_core::events::{AuditEntry, GatewayEvent, Interface, Severity, Verdict};
use afw_core::policy::{
    Agent, DataClass, InspectionRule, NetObject, PolicySettings, Service, Track, Zone,
};
use afw_core::protocol::GatewayCommand;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::{Stream, StreamExt};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use uuid::Uuid;

pub use error::ClientError;
pub use views::{AllowOutcome, PublishOutcome, RuleEntry};

pub type Result<T> = std::result::Result<T, ClientError>;

/// Policy resource collections handled by the generic CRUD methods.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PolicyKind {
    Objects,
    Services,
    DataClasses,
    Zones,
    Agents,
    Rules,
    InspectionRules,
}

impl PolicyKind {
    pub const ALL: [PolicyKind; 7] = [
        Self::Objects,
        Self::Services,
        Self::DataClasses,
        Self::Zones,
        Self::Agents,
        Self::Rules,
        Self::InspectionRules,
    ];

    /// Path segment under `/api/v1`.
    pub fn path(self) -> &'static str {
        match self {
            Self::Objects => "/objects",
            Self::Services => "/services",
            Self::DataClasses => "/data-classes",
            Self::Zones => "/zones",
            Self::Agents => "/agents",
            Self::Rules => "/rules",
            Self::InspectionRules => "/inspection-rules",
        }
    }

    /// Singular human name.
    pub fn singular(self) -> &'static str {
        match self {
            Self::Objects => "object",
            Self::Services => "service",
            Self::DataClasses => "data class",
            Self::Zones => "zone",
            Self::Agents => "agent",
            Self::Rules => "rule",
            Self::InspectionRules => "inspection rule",
        }
    }

    /// Snake-case name (`data_classes`…), as used by the MCP tools.
    pub fn snake(self) -> &'static str {
        match self {
            Self::Objects => "objects",
            Self::Services => "services",
            Self::DataClasses => "data_classes",
            Self::Zones => "zones",
            Self::Agents => "agents",
            Self::Rules => "rules",
            Self::InspectionRules => "inspection_rules",
        }
    }

    pub fn from_snake(s: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.snake() == s || k.path().trim_start_matches('/') == s)
    }
}

/// Optional client settings.
#[derive(Clone, Debug, Default)]
pub struct ClientOptions {
    /// Extra trusted CA certificate(s), PEM (private console CA).
    pub ca_cert_pem: Option<Vec<u8>>,
    /// Request timeout (default 30 s; not applied to the live stream).
    pub timeout: Option<Duration>,
}

/// `POST /sessions/{id}/allow-from-log` parameters (EF-42). Optional fields are only sent when
/// set.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AllowFromLog {
    pub flow_id: Uuid,
    /// `exact` (default), `wildcard` or `group`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track: Option<Track>,
}

/// Cursor pagination parameters.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PageQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `GET /installs` filters.
#[derive(Clone, Debug, Default, Serialize)]
pub struct InstallQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `GET /logs/stream` filters.
#[derive(Clone, Debug, Default, Serialize)]
pub struct StreamQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<Uuid>,
}

/// `GET /alerts` filters.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AlertQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acknowledged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `GET /audit` filters.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AuditQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_seq: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `GET /internal-map` filters.
#[derive(Clone, Debug, Default, Serialize)]
pub struct MapQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<Uuid>,
}

#[derive(Serialize)]
struct FilterOnly {
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<ApprovalStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    against: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_seq: Option<i64>,
}

impl FilterOnly {
    fn none() -> Self {
        Self {
            status: None,
            against: None,
            revision: None,
            from_seq: None,
        }
    }
}

/// Client of the agents-firewall control-plane API. Cheap to clone; clones share the active
/// session.
#[derive(Clone)]
pub struct AfwClient {
    http: reqwest::Client,
    stream_http: reqwest::Client,
    api: String,
    token: String,
    interface: Interface,
    session: Arc<RwLock<Option<Uuid>>>,
}

impl std::fmt::Debug for AfwClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the token.
        f.debug_struct("AfwClient")
            .field("api", &self.api)
            .field("interface", &self.interface)
            .field("session", &self.session())
            .finish_non_exhaustive()
    }
}

/// Normalizes a console URL into the API root (`…/api/v1`, without trailing slash).
pub fn api_root(base_url: &str) -> Result<String> {
    let base = base_url.trim().trim_end_matches('/');
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err(ClientError::Config(format!(
            "the API URL must start with http:// or https://, got `{base_url}`"
        )));
    }
    if base.ends_with("/api/v1") {
        Ok(base.to_string())
    } else {
        Ok(format!("{base}/api/v1"))
    }
}

fn interface_header(i: Interface) -> &'static str {
    match i {
        Interface::Ui => "ui",
        Interface::Cli => "cli",
        Interface::Mcp => "mcp",
        Interface::Api => "api",
        Interface::System => "system",
    }
}

impl AfwClient {
    /// Client for `base_url` (console URL, with or without `/api/v1`).
    pub fn new(base_url: &str, token: impl Into<String>, interface: Interface) -> Result<Self> {
        Self::with_options(base_url, token, interface, ClientOptions::default())
    }

    /// Client with a custom CA and/or timeout.
    pub fn with_options(
        base_url: &str,
        token: impl Into<String>,
        interface: Interface,
        opts: ClientOptions,
    ) -> Result<Self> {
        let api = api_root(base_url)?;
        let token = token.into();
        if token.trim().is_empty() {
            return Err(ClientError::Config("the API token is empty".into()));
        }
        let mut certs = Vec::new();
        if let Some(pem) = &opts.ca_cert_pem {
            certs = reqwest::Certificate::from_pem_bundle(pem)
                .map_err(|e| ClientError::Config(format!("invalid CA certificate: {e}")))?;
            if certs.is_empty() {
                return Err(ClientError::Config(
                    "the CA certificate file contains no certificate".into(),
                ));
            }
        }
        let build = |timeout: Option<Duration>| -> Result<reqwest::Client> {
            let mut b = reqwest::Client::builder()
                .use_rustls_tls()
                .user_agent(concat!("afw-client/", env!("CARGO_PKG_VERSION")))
                .connect_timeout(Duration::from_secs(10));
            if let Some(t) = timeout {
                b = b.timeout(t);
            }
            for c in &certs {
                b = b.add_root_certificate(c.clone());
            }
            b.build()
                .map_err(|e| ClientError::Config(format!("HTTP client: {e}")))
        };
        Ok(Self {
            http: build(Some(opts.timeout.unwrap_or(Duration::from_secs(30))))?,
            stream_http: build(None)?,
            api,
            token,
            interface,
            session: Arc::new(RwLock::new(None)),
        })
    }

    /// API root (`…/api/v1`).
    pub fn api_url(&self) -> &str {
        &self.api
    }

    pub fn interface(&self) -> Interface {
        self.interface
    }

    /// Active editing session, sent as `X-Afw-Session`.
    pub fn session(&self) -> Option<Uuid> {
        *self.session.read().expect("session lock")
    }

    pub fn set_session(&self, id: Option<Uuid>) {
        *self.session.write().expect("session lock") = id;
    }

    /// Active session, else the caller's open session on the API, else (when `open`) a new one.
    /// The session found becomes the active one.
    pub async fn ensure_session(&self, open: bool) -> Result<Uuid> {
        if let Some(id) = self.session() {
            return Ok(id);
        }
        if let Some(s) = self.current_session().await? {
            self.set_session(Some(s.id));
            return Ok(s.id);
        }
        if !open {
            return Err(ClientError::NoSession);
        }
        let s = self.open_session(None).await?;
        Ok(s.id)
    }

    fn require_session(&self) -> Result<Uuid> {
        self.session().ok_or(ClientError::NoSession)
    }

    // -----------------------------------------------------------------------------------------
    // Transport

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.request_with(&self.http, method, path)
    }

    fn request_with(&self, http: &reqwest::Client, method: Method, path: &str) -> RequestBuilder {
        let mut rb = http
            .request(method, format!("{}{}", self.api, path))
            .bearer_auth(&self.token)
            .header("X-Afw-Interface", interface_header(self.interface));
        if let Some(s) = self.session() {
            rb = rb.header("X-Afw-Session", s.to_string());
        }
        rb
    }

    async fn send(&self, rb: RequestBuilder) -> Result<Response> {
        let resp = rb.send().await?;
        if resp.status().is_success() {
            Ok(resp)
        } else {
            Err(api_error(resp).await)
        }
    }

    async fn json<T: DeserializeOwned>(&self, rb: RequestBuilder) -> Result<T> {
        let resp = self.send(rb).await?;
        decode_json(resp).await
    }

    async fn empty(&self, rb: RequestBuilder) -> Result<()> {
        self.send(rb).await.map(|_| ())
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.json(self.request(Method::GET, path)).await
    }

    async fn get_q<T: DeserializeOwned, Q: Serialize + ?Sized>(
        &self,
        path: &str,
        q: &Q,
    ) -> Result<T> {
        self.json(self.request(Method::GET, path).query(q)).await
    }

    async fn post<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.json(self.request(Method::POST, path).json(body)).await
    }

    async fn put<T: DeserializeOwned, B: Serialize + ?Sized>(&self, path: &str, body: &B) -> Result<T> {
        self.json(self.request(Method::PUT, path).json(body)).await
    }

    async fn delete_path(&self, path: &str) -> Result<()> {
        self.empty(self.request(Method::DELETE, path)).await
    }

    // -----------------------------------------------------------------------------------------
    // Policy resources (generic, JSON)

    /// `GET /<kind>` as raw JSON (reads the active session's draft when one is active).
    pub async fn list_raw(&self, kind: PolicyKind) -> Result<Vec<Value>> {
        self.get(kind.path()).await
    }

    pub async fn get_raw(&self, kind: PolicyKind, id: Uuid) -> Result<Value> {
        self.get(&format!("{}/{id}", kind.path())).await
    }

    /// `POST /<kind>` in the active session.
    pub async fn create_raw(&self, kind: PolicyKind, body: &Value) -> Result<Value> {
        self.require_session()?;
        self.post(kind.path(), body).await
    }

    /// `PUT /<kind>/{id}` in the active session.
    pub async fn update_raw(&self, kind: PolicyKind, id: Uuid, body: &Value) -> Result<Value> {
        self.require_session()?;
        self.put(&format!("{}/{id}", kind.path()), body).await
    }

    /// `DELETE /<kind>/{id}` in the active session.
    pub async fn delete_resource(&self, kind: PolicyKind, id: Uuid) -> Result<()> {
        self.require_session()?;
        self.delete_path(&format!("{}/{id}", kind.path())).await
    }

    /// Resolves a name (or an id) to an id. Names must match exactly one resource.
    pub async fn resolve(&self, kind: PolicyKind, name_or_id: &str) -> Result<Uuid> {
        if let Ok(id) = Uuid::parse_str(name_or_id) {
            return Ok(id);
        }
        let items = self.list_raw(kind).await?;
        let matches: Vec<Uuid> = items
            .iter()
            .filter(|v| v.get("name").and_then(Value::as_str) == Some(name_or_id))
            .filter_map(|v| v.get("id").and_then(Value::as_str))
            .filter_map(|s| Uuid::parse_str(s).ok())
            .collect();
        one(kind.singular(), name_or_id, matches)
    }

    /// Resolves a gateway name (or id).
    pub async fn resolve_gateway(&self, name_or_id: &str) -> Result<Uuid> {
        if let Ok(id) = Uuid::parse_str(name_or_id) {
            return Ok(id);
        }
        let matches = self
            .list_gateways()
            .await?
            .into_iter()
            .filter(|g| g.name == name_or_id || g.hostname == name_or_id)
            .map(|g| g.id)
            .collect();
        one("gateway", name_or_id, matches)
    }

    // -----------------------------------------------------------------------------------------
    // Policy resources (typed)

    pub async fn list_objects(&self) -> Result<Vec<NetObject>> {
        self.get("/objects").await
    }
    pub async fn get_object(&self, id: Uuid) -> Result<NetObject> {
        self.get(&format!("/objects/{id}")).await
    }
    pub async fn create_object(&self, o: &NetObject) -> Result<NetObject> {
        self.require_session()?;
        self.post("/objects", o).await
    }
    pub async fn update_object(&self, o: &NetObject) -> Result<NetObject> {
        self.require_session()?;
        self.put(&format!("/objects/{}", o.id), o).await
    }
    pub async fn delete_object(&self, id: Uuid) -> Result<()> {
        self.delete_resource(PolicyKind::Objects, id).await
    }
    pub async fn object_where_used(&self, id: Uuid) -> Result<WhereUsed> {
        self.get(&format!("/objects/{id}/where-used")).await
    }

    pub async fn list_services(&self) -> Result<Vec<Service>> {
        self.get("/services").await
    }
    pub async fn get_service(&self, id: Uuid) -> Result<Service> {
        self.get(&format!("/services/{id}")).await
    }
    pub async fn create_service(&self, s: &Service) -> Result<Service> {
        self.require_session()?;
        self.post("/services", s).await
    }
    pub async fn update_service(&self, s: &Service) -> Result<Service> {
        self.require_session()?;
        self.put(&format!("/services/{}", s.id), s).await
    }
    pub async fn delete_service(&self, id: Uuid) -> Result<()> {
        self.delete_resource(PolicyKind::Services, id).await
    }

    pub async fn list_data_classes(&self) -> Result<Vec<DataClass>> {
        self.get("/data-classes").await
    }
    pub async fn get_data_class(&self, id: Uuid) -> Result<DataClass> {
        self.get(&format!("/data-classes/{id}")).await
    }
    pub async fn create_data_class(&self, d: &DataClass) -> Result<DataClass> {
        self.require_session()?;
        self.post("/data-classes", d).await
    }
    pub async fn update_data_class(&self, d: &DataClass) -> Result<DataClass> {
        self.require_session()?;
        self.put(&format!("/data-classes/{}", d.id), d).await
    }
    pub async fn delete_data_class(&self, id: Uuid) -> Result<()> {
        self.delete_resource(PolicyKind::DataClasses, id).await
    }

    pub async fn list_zones(&self) -> Result<Vec<Zone>> {
        self.get("/zones").await
    }
    pub async fn get_zone(&self, id: Uuid) -> Result<Zone> {
        self.get(&format!("/zones/{id}")).await
    }
    pub async fn create_zone(&self, z: &Zone) -> Result<Zone> {
        self.require_session()?;
        self.post("/zones", z).await
    }
    pub async fn update_zone(&self, z: &Zone) -> Result<Zone> {
        self.require_session()?;
        self.put(&format!("/zones/{}", z.id), z).await
    }
    pub async fn delete_zone(&self, id: Uuid) -> Result<()> {
        self.delete_resource(PolicyKind::Zones, id).await
    }

    pub async fn list_agents(&self) -> Result<Vec<Agent>> {
        self.get("/agents").await
    }
    pub async fn get_agent(&self, id: Uuid) -> Result<Agent> {
        self.get(&format!("/agents/{id}")).await
    }
    pub async fn create_agent(&self, a: &Agent) -> Result<Agent> {
        self.require_session()?;
        self.post("/agents", a).await
    }
    pub async fn update_agent(&self, a: &Agent) -> Result<Agent> {
        self.require_session()?;
        self.put(&format!("/agents/{}", a.id), a).await
    }
    pub async fn delete_agent(&self, id: Uuid) -> Result<()> {
        self.delete_resource(PolicyKind::Agents, id).await
    }

    /// `GET /rules`: plain rules or rule views, decoded tolerantly.
    pub async fn list_rules(&self) -> Result<Vec<RuleEntry>> {
        let raw: Vec<Value> = self.get("/rules").await?;
        raw.into_iter().map(RuleEntry::from_value).collect()
    }
    pub async fn get_rule(&self, id: Uuid) -> Result<RuleEntry> {
        RuleEntry::from_value(self.get(&format!("/rules/{id}")).await?)
    }
    pub async fn create_rule(&self, r: &afw_core::policy::Rule) -> Result<RuleEntry> {
        self.require_session()?;
        RuleEntry::from_value(self.post("/rules", r).await?)
    }
    pub async fn update_rule(&self, r: &afw_core::policy::Rule) -> Result<RuleEntry> {
        self.require_session()?;
        RuleEntry::from_value(self.put(&format!("/rules/{}", r.id), r).await?)
    }
    pub async fn delete_rule(&self, id: Uuid) -> Result<()> {
        self.delete_resource(PolicyKind::Rules, id).await
    }
    /// `POST /rules/{id}/move`.
    pub async fn move_rule(&self, id: Uuid, req: &MoveRuleRequest) -> Result<RuleEntry> {
        self.require_session()?;
        RuleEntry::from_value(self.post(&format!("/rules/{id}/move"), req).await?)
    }

    pub async fn list_inspection_rules(&self) -> Result<Vec<InspectionRule>> {
        self.get("/inspection-rules").await
    }
    pub async fn get_inspection_rule(&self, id: Uuid) -> Result<InspectionRule> {
        self.get(&format!("/inspection-rules/{id}")).await
    }
    pub async fn create_inspection_rule(&self, r: &InspectionRule) -> Result<InspectionRule> {
        self.require_session()?;
        self.post("/inspection-rules", r).await
    }
    pub async fn update_inspection_rule(&self, r: &InspectionRule) -> Result<InspectionRule> {
        self.require_session()?;
        self.put(&format!("/inspection-rules/{}", r.id), r).await
    }
    pub async fn delete_inspection_rule(&self, id: Uuid) -> Result<()> {
        self.delete_resource(PolicyKind::InspectionRules, id).await
    }

    pub async fn get_settings(&self) -> Result<PolicySettings> {
        self.get("/settings").await
    }
    pub async fn update_settings(&self, s: &PolicySettings) -> Result<PolicySettings> {
        self.require_session()?;
        self.put("/settings", s).await
    }

    // -----------------------------------------------------------------------------------------
    // Alert channels (not session-bound)

    pub async fn list_alert_channels(&self) -> Result<Vec<AlertChannel>> {
        self.get("/alert-channels").await
    }
    pub async fn get_alert_channel(&self, id: Uuid) -> Result<AlertChannel> {
        self.get(&format!("/alert-channels/{id}")).await
    }
    pub async fn create_alert_channel(&self, c: &AlertChannel) -> Result<AlertChannel> {
        self.post("/alert-channels", c).await
    }
    pub async fn update_alert_channel(&self, c: &AlertChannel) -> Result<AlertChannel> {
        self.put(&format!("/alert-channels/{}", c.id), c).await
    }
    pub async fn delete_alert_channel(&self, id: Uuid) -> Result<()> {
        self.delete_path(&format!("/alert-channels/{id}")).await
    }

    // -----------------------------------------------------------------------------------------
    // Sessions

    pub async fn list_sessions(&self) -> Result<Vec<Session>> {
        self.get("/sessions").await
    }

    /// `POST /sessions`; the new session becomes the active one. `name` is only sent when set.
    pub async fn open_session(&self, name: Option<&str>) -> Result<Session> {
        let rb = self.request(Method::POST, "/sessions");
        let rb = match name {
            Some(n) => rb.json(&serde_json::json!({ "name": n })),
            None => rb,
        };
        let s: Session = self.json(rb).await?;
        self.set_session(Some(s.id));
        Ok(s)
    }

    /// `GET /sessions/current`; `None` when the caller has no open session (404).
    pub async fn current_session(&self) -> Result<Option<Session>> {
        match self.get::<Session>("/sessions/current").await {
            Ok(s) => Ok(Some(s)),
            Err(ClientError::Api { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn get_session(&self, id: Uuid) -> Result<Session> {
        self.get(&format!("/sessions/{id}")).await
    }

    /// `POST /sessions/{id}/discard`; clears the active session when it is this one.
    pub async fn discard_session(&self, id: Uuid) -> Result<Session> {
        let s = self
            .json(self.request(Method::POST, &format!("/sessions/{id}/discard")))
            .await?;
        self.forget_session(id);
        Ok(s)
    }

    /// `POST /sessions/{id}/publish`: 201 → new revision, 202 → pending approval (EF-52).
    pub async fn publish_session(&self, id: Uuid, comment: &str) -> Result<PublishOutcome> {
        let resp = self
            .send(
                self.request(Method::POST, &format!("/sessions/{id}/publish"))
                    .json(&afw_core::api::PublishRequest {
                        comment: comment.to_string(),
                    }),
            )
            .await?;
        if resp.status() == StatusCode::ACCEPTED {
            let approval: Approval = decode_json(resp).await?;
            Ok(PublishOutcome::PendingApproval { approval })
        } else {
            let revision: Revision = decode_json(resp).await?;
            self.forget_session(id);
            Ok(PublishOutcome::Published { revision })
        }
    }

    /// `POST /sessions/{id}/allow-from-log` (EF-42).
    pub async fn allow_from_log(&self, session: Uuid, req: &AllowFromLog) -> Result<AllowOutcome> {
        let v: Value = self
            .post(&format!("/sessions/{session}/allow-from-log"), req)
            .await?;
        AllowOutcome::from_value(v)
    }

    /// `POST /sessions/{id}/import`: merges a whole policy document into the session (EF-70).
    pub async fn import_document(&self, session: Uuid, document: &Value) -> Result<Session> {
        self.post(&format!("/sessions/{session}/import"), document)
            .await
    }

    fn forget_session(&self, id: Uuid) {
        let mut g = self.session.write().expect("session lock");
        if *g == Some(id) {
            *g = None;
        }
    }

    // -----------------------------------------------------------------------------------------
    // Revisions, verification, installation

    pub async fn list_revisions(&self, q: &PageQuery) -> Result<Page<Revision>> {
        self.get_q("/revisions", q).await
    }
    pub async fn get_revision(&self, n: u64) -> Result<RevisionDetail> {
        self.get(&format!("/revisions/{n}")).await
    }
    /// `GET /revisions/{n}/diff?against=m` (default n-1).
    pub async fn diff_revision(&self, n: u64, against: Option<u64>) -> Result<RevisionDiff> {
        let q = FilterOnly {
            against,
            ..FilterOnly::none()
        };
        self.get_q(&format!("/revisions/{n}/diff"), &q).await
    }
    /// `POST /revisions/{n}/revert`: opens a session holding revision n; it becomes active.
    pub async fn revert_to_revision(&self, n: u64) -> Result<Session> {
        let s: Session = self
            .json(self.request(Method::POST, &format!("/revisions/{n}/revert")))
            .await?;
        self.set_session(Some(s.id));
        Ok(s)
    }
    /// `GET /verify?revision=n` (EF-11); `None` = the active session's draft.
    pub async fn verify(&self, revision: Option<u64>) -> Result<VerifyReport> {
        let q = FilterOnly {
            revision,
            ..FilterOnly::none()
        };
        self.get_q("/verify", &q).await
    }
    pub async fn list_installs(&self, q: &InstallQuery) -> Result<Page<Install>> {
        self.get_q("/installs", q).await
    }
    /// `POST /installs` (202): empty `gateways` = all gateways.
    pub async fn install(&self, req: &InstallRequest) -> Result<InstallResult> {
        self.post("/installs", req).await
    }

    // -----------------------------------------------------------------------------------------
    // Gateways

    pub async fn list_gateways(&self) -> Result<Vec<Gateway>> {
        self.get("/gateways").await
    }
    pub async fn get_gateway(&self, id: Uuid) -> Result<Gateway> {
        self.get(&format!("/gateways/{id}")).await
    }
    pub async fn delete_gateway(&self, id: Uuid) -> Result<()> {
        self.delete_path(&format!("/gateways/{id}")).await
    }
    pub async fn create_registration_token(
        &self,
        req: &CreateRegistrationToken,
    ) -> Result<RegistrationToken> {
        self.post("/gateways/registration-tokens", req).await
    }
    /// `POST /gateways/{id}/commands` (202, delivered with the next heartbeat).
    pub async fn send_gateway_command(&self, id: Uuid, cmd: &GatewayCommand) -> Result<()> {
        self.empty(
            self.request(Method::POST, &format!("/gateways/{id}/commands"))
                .json(cmd),
        )
        .await
    }

    // -----------------------------------------------------------------------------------------
    // Logs (EF-41)

    pub async fn list_flows(&self, q: &FlowQuery) -> Result<FlowPage> {
        self.get_q("/logs/flows", &query_pairs(q)?).await
    }
    pub async fn get_flow(&self, id: Uuid) -> Result<FlowDetail> {
        self.get(&format!("/logs/flows/{id}")).await
    }
    pub async fn list_dns(&self, q: &FlowQuery) -> Result<DnsPage> {
        self.get_q("/logs/dns", &query_pairs(q)?).await
    }

    /// `GET /logs/stream` (Server-Sent Events): live gateway events. Messages whose `data` is
    /// not a `GatewayEvent` are reported as `Decode` errors without ending the stream.
    pub async fn stream_logs(
        &self,
        q: &StreamQuery,
    ) -> Result<impl Stream<Item = Result<GatewayEvent>> + Send + 'static + use<>> {
        let resp = self
            .send(
                self.request_with(&self.stream_http, Method::GET, "/logs/stream")
                    .header(reqwest::header::ACCEPT, "text/event-stream")
                    .query(q),
            )
            .await?;
        let bytes = resp.bytes_stream();
        let state = (Box::pin(bytes), sse::SseParser::new(), Vec::<Result<GatewayEvent>>::new());
        Ok(futures::stream::unfold(state, |(mut bytes, mut parser, mut pending)| async move {
            loop {
                if !pending.is_empty() {
                    let item = pending.remove(0);
                    return Some((item, (bytes, parser, pending)));
                }
                match bytes.next().await {
                    None => return None,
                    Some(Err(e)) => return Some((Err(ClientError::Transport(e)), (bytes, parser, pending))),
                    Some(Ok(chunk)) => {
                        let text = String::from_utf8_lossy(&chunk);
                        for m in parser.push(&text) {
                            pending.push(serde_json::from_str::<GatewayEvent>(&m.data).map_err(|e| {
                                ClientError::Decode {
                                    status: 200,
                                    message: format!("event `{}`: {e}", m.event),
                                }
                            }));
                        }
                    }
                }
            }
        }))
    }

    // -----------------------------------------------------------------------------------------
    // Captures

    pub async fn list_captures(&self, q: &PageQuery) -> Result<Page<Capture>> {
        self.get_q("/captures", q).await
    }
    /// `POST /captures` (202).
    pub async fn start_capture(&self, req: &CaptureRequest) -> Result<Capture> {
        self.post("/captures", req).await
    }
    pub async fn get_capture(&self, id: Uuid) -> Result<Capture> {
        self.get(&format!("/captures/{id}")).await
    }
    /// `GET /captures/{id}/download`: the pcap file (audited by the API).
    pub async fn download_capture(&self, id: Uuid) -> Result<Bytes> {
        let resp = self
            .send(self.request(Method::GET, &format!("/captures/{id}/download")))
            .await?;
        Ok(resp.bytes().await?)
    }

    // -----------------------------------------------------------------------------------------
    // Alerts, map, agent view

    pub async fn list_alerts(&self, q: &AlertQuery) -> Result<Page<Alert>> {
        self.get_q("/alerts", q).await
    }
    pub async fn acknowledge_alert(&self, id: Uuid) -> Result<Alert> {
        self.json(self.request(Method::POST, &format!("/alerts/{id}/ack")))
            .await
    }
    pub async fn internal_map(&self, q: &MapQuery) -> Result<InternalMap> {
        self.get_q("/internal-map", q).await
    }
    /// `GET /agents/{id}/overview` (EF-43).
    pub async fn agent_overview(&self, id: Uuid) -> Result<AgentOverview> {
        self.get(&format!("/agents/{id}/overview")).await
    }

    // -----------------------------------------------------------------------------------------
    // Audit, approvals, identity, tokens

    pub async fn list_audit(&self, q: &AuditQuery) -> Result<Page<AuditEntry>> {
        self.get_q("/audit", q).await
    }
    pub async fn verify_audit(&self) -> Result<AuditVerifyResult> {
        self.get("/audit/verify").await
    }
    /// `GET /audit/export`: raw NDJSON (one `AuditEntry` per line).
    pub async fn export_audit(&self, from_seq: Option<i64>) -> Result<Bytes> {
        let q = FilterOnly {
            from_seq,
            ..FilterOnly::none()
        };
        let resp = self
            .send(self.request(Method::GET, "/audit/export").query(&q))
            .await?;
        Ok(resp.bytes().await?)
    }
    pub async fn list_approvals(&self, status: Option<ApprovalStatus>) -> Result<Vec<Approval>> {
        let q = FilterOnly {
            status,
            ..FilterOnly::none()
        };
        self.get_q("/approvals", &q).await
    }
    pub async fn get_approval(&self, id: Uuid) -> Result<Approval> {
        self.get(&format!("/approvals/{id}")).await
    }
    pub async fn decide_approval(&self, id: Uuid, d: &ApprovalDecision) -> Result<Approval> {
        self.post(&format!("/approvals/{id}/decision"), d).await
    }
    pub async fn me(&self) -> Result<Me> {
        self.get("/me").await
    }
    pub async fn list_tokens(&self) -> Result<Vec<ApiToken>> {
        self.get("/tokens").await
    }
    pub async fn create_token(&self, req: &CreateApiToken) -> Result<CreatedApiToken> {
        self.post("/tokens", req).await
    }
    pub async fn revoke_token(&self, id: Uuid) -> Result<()> {
        self.delete_path(&format!("/tokens/{id}")).await
    }

    // -----------------------------------------------------------------------------------------
    // Hermes plugin and enrollment

    /// `GET /intent-policy` (`agent_plugin` token only).
    pub async fn intent_policy(&self) -> Result<IntentPolicy> {
        self.get("/intent-policy").await
    }
    /// `POST /ingest/tool-calls` (`agent_plugin` token only, 202).
    pub async fn ingest_tool_calls(&self, batch: &ToolCallBatch) -> Result<()> {
        self.empty(self.request(Method::POST, "/ingest/tool-calls").json(batch))
            .await
    }
    /// `POST /enrollments`: creates the agent in a session (plus a Hermes plugin token).
    pub async fn enroll(&self, req: &EnrollmentRequest) -> Result<Enrollment> {
        self.post("/enrollments", req).await
    }
}

fn one(kind: &str, name: &str, matches: Vec<Uuid>) -> Result<Uuid> {
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(ClientError::NotFound {
            kind: kind.into(),
            name: name.into(),
        }),
        count => Err(ClientError::Ambiguous {
            kind: kind.into(),
            name: name.into(),
            count,
        }),
    }
}

/// `FlowQuery` as query pairs, `None` fields omitted.
fn query_pairs(q: &FlowQuery) -> Result<Vec<(String, String)>> {
    let v = serde_json::to_value(q).map_err(|e| ClientError::Config(e.to_string()))?;
    let mut out = Vec::new();
    if let Value::Object(m) = v {
        for (k, v) in m {
            match v {
                Value::Null => {}
                Value::String(s) => out.push((k, s)),
                other => out.push((k, other.to_string())),
            }
        }
    }
    Ok(out)
}

async fn decode_json<T: DeserializeOwned>(resp: Response) -> Result<T> {
    let status = resp.status().as_u16();
    let bytes = resp.bytes().await?;
    serde_json::from_slice(&bytes).map_err(|e| ClientError::Decode {
        status,
        message: e.to_string(),
    })
}

async fn api_error(resp: Response) -> ClientError {
    let status = resp.status();
    let bytes = resp.bytes().await.unwrap_or_default();
    let problem = serde_json::from_slice::<Problem>(&bytes).unwrap_or_else(|_| {
        let text = String::from_utf8_lossy(&bytes);
        let text = text.trim();
        Problem {
            kind: "about:blank".into(),
            title: status
                .canonical_reason()
                .unwrap_or("Error")
                .to_string(),
            status: status.as_u16(),
            detail: (!text.is_empty()).then(|| text.chars().take(500).collect()),
            instance: None,
        }
    });
    ClientError::Api {
        status: status.as_u16(),
        problem,
    }
}
