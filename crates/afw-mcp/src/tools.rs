//! Declarative tool table: name, description, JSON schema of the arguments, and execution
//! through `afw-client`. No authorization is decided here: the API is the authority (EF-51/52);
//! its refusals are turned into readable tool errors.

use afw_client::{
    AfwClient, AlertQuery, AllowFromLog, AuditQuery, ClientError, InstallQuery, MapQuery,
    PageQuery, PolicyKind, PublishOutcome, RuleEntry,
};
use afw_core::api::{FlowQuery, InstallRequest, MoveRuleRequest};
use afw_core::policy::Layer;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Map, Value, json};
use uuid::Uuid;

/// Reminder appended to every tool that changes the policy.
pub const WRITE_RULES: &str = "Changes go to your editing session (your open session, or a new one opened automatically) \
and apply only after publish_session then install_revision. You may only change zones delegated to you: \
you can NEVER modify your own zone, a rule whose source is your own zone, the baseline, nor move an agent \
into or out of your own zone; the API refuses such changes with 403. Widening changes (wildcard on the \
Internet, any destination, letting secrets out) are held for a human approval when you publish.";

pub struct ToolDef {
    pub name: &'static str,
    pub description: String,
    pub schema: Value,
    /// Changes something (policy, installation, alerts).
    pub write: bool,
}

fn obj(props: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": props, "required": required, "additionalProperties": false })
}

fn kind_prop() -> Value {
    json!({
        "type": "string",
        "enum": ["objects", "services", "data_classes", "zones", "agents", "rules", "inspection_rules"],
        "description": "Policy resource collection"
    })
}

fn s(desc: &str) -> Value {
    json!({ "type": "string", "description": desc })
}

fn int(desc: &str) -> Value {
    json!({ "type": "integer", "minimum": 0, "description": desc })
}

fn log_filters() -> Value {
    json!({
        "agent": s("Agent name or id"),
        "zone": s("Zone name or id"),
        "destination": s("Destination domain, IP or CIDR"),
        "verdict": { "type": "string", "enum": ["allow", "deny"] },
        "rule": s("Rule name or id"),
        "from": s("Start: RFC 3339 time or a duration ago (15m, 2h, 7d)"),
        "to": s("End: RFC 3339 time or a duration ago"),
        "q": s("Free text search"),
        "limit": int("Page size (default 100, max 1000)"),
        "cursor": s("next_cursor of the previous page"),
    })
}

/// Every tool exposed to the approved agent.
pub fn tools() -> Vec<ToolDef> {
    let w = |d: &str| format!("{d} {WRITE_RULES}");
    let r = |d: &str| d.to_string();
    let t = |name, description, schema, write| ToolDef {
        name,
        description,
        schema,
        write,
    };
    vec![
        t(
            "whoami",
            r(
                "Your identity on the firewall: role, agent id and the zones you may modify (writable_zones).",
            ),
            obj(json!({}), &[]),
            false,
        ),
        t(
            "list_resources",
            r(
                "List policy resources of a collection (objects, services, data_classes, zones, agents, rules, inspection_rules); reads your session draft when a session is open.",
            ),
            obj(json!({"kind": kind_prop()}), &["kind"]),
            false,
        ),
        t(
            "get_resource",
            r("Get one policy resource by name or id."),
            obj(
                json!({"kind": kind_prop(), "id": s("Name or id")}),
                &["kind", "id"],
            ),
            false,
        ),
        t(
            "create_resource",
            w(
                "Create a policy resource (JSON in the afw-core format of the collection; `id` is generated when absent). A rule's source is always a zone.",
            ),
            obj(
                json!({"kind": kind_prop(), "resource": {"type": "object", "description": "Resource body"}}),
                &["kind", "resource"],
            ),
            true,
        ),
        t(
            "update_resource",
            w("Update a policy resource: the given fields replace the current ones."),
            obj(
                json!({"kind": kind_prop(), "id": s("Name or id"), "fields": {"type": "object", "description": "Fields to change"}}),
                &["kind", "id", "fields"],
            ),
            true,
        ),
        t(
            "delete_resource",
            w("Delete a policy resource."),
            obj(
                json!({"kind": kind_prop(), "id": s("Name or id")}),
                &["kind", "id"],
            ),
            true,
        ),
        t(
            "where_used",
            r("Rules, groups and inspection rules referencing an object."),
            obj(json!({"object": s("Object name or id")}), &["object"]),
            false,
        ),
        t(
            "move_rule",
            w("Move a rule to a position (1 = first), optionally to another layer or section."),
            obj(
                json!({"rule": s("Rule name or id"), "position": int("New position"), "zone": s("Move to this zone's layer"), "baseline": {"type": "boolean"}, "section": s("New section")}),
                &["rule", "position"],
            ),
            true,
        ),
        t(
            "get_rulebase",
            r(
                "The whole rule base in evaluation order: baseline, then each zone by name, with rule numbers, hits and pending changes.",
            ),
            obj(json!({}), &[]),
            false,
        ),
        t(
            "open_session",
            r("Open an editing session (changes stay private until published)."),
            obj(json!({"name": s("Optional name")}), &[]),
            true,
        ),
        t(
            "current_session",
            r("Your open editing session (locks, pending changes, approval), if any."),
            obj(json!({}), &[]),
            false,
        ),
        t(
            "discard_session",
            r("Discard your open session and all its pending changes."),
            obj(json!({}), &[]),
            true,
        ),
        t(
            "publish_session",
            w(
                "Publish your session as a new revision. Returns the revision, or pending_approval when a human must approve the change first (then do not retry: wait for the approval).",
            ),
            obj(json!({"comment": s("Why this change")}), &["comment"]),
            true,
        ),
        t(
            "allow_from_log",
            w(
                "Prepare an accept rule in your session from a denied flow of the log (EF-42): source = the agent's zone, destination = the flow's.",
            ),
            obj(
                json!({"flow_id": s("Flow id"), "destination": {"type": "string", "enum": ["exact", "wildcard", "group"]}, "expires_in_days": int("Expiry of the rule, in days"), "track": {"type": "string", "enum": ["none", "log", "detailed", "capture"]}}),
                &["flow_id"],
            ),
            true,
        ),
        t(
            "verify_policy",
            r(
                "Pre-install verification: shadowed rules, unused objects, expired rules (of a revision, or of your session draft).",
            ),
            obj(
                json!({"revision": int("Revision; absent = your session draft")}),
                &[],
            ),
            false,
        ),
        t(
            "list_revisions",
            r("Published revisions, newest first."),
            obj(
                json!({"limit": int("Page size"), "cursor": s("Cursor")}),
                &[],
            ),
            false,
        ),
        t(
            "diff_revision",
            r("Changes between a revision and another one (default: the previous one)."),
            obj(
                json!({"revision": int("Revision"), "against": int("Other revision")}),
                &["revision"],
            ),
            false,
        ),
        t(
            "install_revision",
            w(
                "Install a published revision on gateways (none listed = all gateways); returns one installation per gateway.",
            ),
            obj(
                json!({"revision": int("Revision"), "gateways": {"type": "array", "items": {"type": "string"}, "description": "Gateway names or ids"}}),
                &["revision"],
            ),
            true,
        ),
        t(
            "list_installs",
            r("Installations per gateway (pending, installed, failed)."),
            obj(
                json!({"revision": int("Revision"), "gateway": s("Gateway name or id")}),
                &[],
            ),
            false,
        ),
        t(
            "list_gateways",
            r("Gateways: status, desired and active revisions."),
            obj(json!({}), &[]),
            false,
        ),
        t(
            "policy_status",
            r("Latest published and installed revisions, gateways up to date."),
            obj(json!({}), &[]),
            false,
        ),
        t(
            "search_flows",
            r("Search the traffic log (newest first) with filters."),
            obj(log_filters(), &[]),
            false,
        ),
        t(
            "get_flow",
            r(
                "Flow detail: HTTP exchanges, rule trace, correlated tool call, message received by the agent, allow proposal.",
            ),
            obj(json!({"flow_id": s("Flow id")}), &["flow_id"]),
            false,
        ),
        t(
            "search_dns",
            r("Search DNS queries with filters."),
            obj(log_filters(), &[]),
            false,
        ),
        t(
            "agent_overview",
            r(
                "Agent view: zone, gateway, 24 h counters, top destinations, recent denials, tool calls and alerts.",
            ),
            obj(json!({"agent": s("Agent name or id")}), &["agent"]),
            false,
        ),
        t(
            "internal_map",
            r("Internal flows map (agents and internal hosts, new edges flagged)."),
            obj(
                json!({"period": {"type": "string", "enum": ["1h", "24h", "7d"]}, "zone": s("Zone name or id")}),
                &[],
            ),
            false,
        ),
        t(
            "list_alerts",
            r("Alerts, newest first."),
            obj(
                json!({"agent": s("Agent name or id"), "severity": {"type": "string", "enum": ["info", "warning", "critical"]}, "acknowledged": {"type": "boolean"}, "limit": int("Page size"), "cursor": s("Cursor")}),
                &[],
            ),
            false,
        ),
        t(
            "ack_alert",
            r("Acknowledge an alert."),
            obj(json!({"id": s("Alert id")}), &["id"]),
            true,
        ),
        t(
            "list_audit",
            r("Audit log entries, most recent first (order=asc for oldest first)."),
            obj(
                json!({"from_seq": int("First sequence"), "actor": s("Actor"), "action": s("Action"), "interface": {"type": "string", "enum": ["ui", "cli", "mcp", "api", "system"]}, "order": {"type": "string", "enum": ["desc", "asc"]}, "limit": int("Page size"), "cursor": s("Cursor")}),
                &[],
            ),
            false,
        ),
        t(
            "verify_audit",
            r("Verify the audit hash chain."),
            obj(json!({}), &[]),
            false,
        ),
        t(
            "list_approvals",
            r("Approvals of widening changes (yours included) and their status."),
            obj(
                json!({"status": {"type": "string", "enum": ["pending", "approved", "rejected"]}}),
                &[],
            ),
            false,
        ),
    ]
}

/// Outcome of a tool: text for the agent, error flag.
pub struct Outcome {
    pub text: String,
    pub is_error: bool,
}

impl Outcome {
    fn ok(v: &impl serde::Serialize) -> Self {
        Self {
            text: serde_json::to_string_pretty(v).unwrap_or_default(),
            is_error: false,
        }
    }
    fn text(t: String) -> Self {
        Self {
            text: t,
            is_error: false,
        }
    }
    pub fn error(t: String) -> Self {
        Self {
            text: t,
            is_error: true,
        }
    }
}

/// Readable text for an API refusal.
pub fn explain(e: &ClientError) -> String {
    let base = e.to_string();
    match e.status() {
        Some(401) => format!(
            "{base}\nThe MCP server's API token is missing, invalid or expired: tell a human administrator."
        ),
        Some(403) => format!(
            "Refused by the agents-firewall API (403 Forbidden): {}\nThe API decides what you may change: only zones delegated to you, never your own zone, a rule whose source is your own zone, the baseline, nor an agent moving into or out of your zone. Do not retry this change; ask a human administrator if it is needed.",
            e.problem().and_then(|p| p.detail.clone()).unwrap_or(base)
        ),
        Some(409) => format!(
            "{base}\nConflict: the state changed (approval pending, nothing to publish, name already used…)."
        ),
        Some(423) => {
            format!("{base}\nLocked: another session is editing this resource; try later.")
        }
        _ => base,
    }
}

// ---------------------------------------------------------------------------------------------
// Argument helpers

struct Args(Map<String, Value>);

impl Args {
    fn str(&self, k: &str) -> Option<String> {
        self.0.get(k).and_then(Value::as_str).map(str::to_string)
    }
    fn req(&self, k: &str) -> Result<String, String> {
        self.str(k).ok_or_else(|| format!("missing argument `{k}`"))
    }
    fn u64(&self, k: &str) -> Result<Option<u64>, String> {
        match self.0.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v
                .as_u64()
                .map(Some)
                .ok_or_else(|| format!("`{k}` must be a non-negative integer")),
        }
    }
    fn u32(&self, k: &str) -> Result<Option<u32>, String> {
        Ok(self.u64(k)?.map(|n| n.min(u32::MAX as u64) as u32))
    }
    fn bool(&self, k: &str) -> Option<bool> {
        self.0.get(k).and_then(Value::as_bool)
    }
    fn uuid(&self, k: &str) -> Result<Uuid, String> {
        Uuid::parse_str(&self.req(k)?).map_err(|_| format!("`{k}` must be a UUID"))
    }
    fn kind(&self) -> Result<PolicyKind, String> {
        let k = self.req("kind")?;
        PolicyKind::from_snake(&k).ok_or_else(|| format!("unknown kind `{k}`"))
    }
    fn word<T: serde::de::DeserializeOwned>(&self, k: &str) -> Result<Option<T>, String> {
        match self.str(k) {
            None => Ok(None),
            Some(w) => serde_json::from_value(json!(w))
                .map(Some)
                .map_err(|_| format!("invalid `{k}`: {w}")),
        }
    }
    fn time(&self, k: &str) -> Result<Option<DateTime<Utc>>, String> {
        let Some(v) = self.str(k) else {
            return Ok(None);
        };
        if let Ok(t) = DateTime::parse_from_rfc3339(&v) {
            return Ok(Some(t.with_timezone(&Utc)));
        }
        let (num, unit) = v.split_at(v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len()));
        let n: i64 = num.parse().map_err(|_| format!("invalid `{k}`: {v}"))?;
        let d = match unit {
            "s" => Duration::try_seconds(n),
            "m" => Duration::try_minutes(n),
            "h" => Duration::try_hours(n),
            "d" => Duration::try_days(n),
            _ => None,
        }
        .ok_or_else(|| format!("invalid `{k}`: {v}"))?;
        Ok(Some(Utc::now() - d))
    }
}

enum Fail {
    Arg(String),
    Api(ClientError),
}

impl From<ClientError> for Fail {
    fn from(e: ClientError) -> Self {
        Self::Api(e)
    }
}

impl From<String> for Fail {
    fn from(e: String) -> Self {
        Self::Arg(e)
    }
}

/// Runs a tool.
pub async fn call(c: &AfwClient, name: &str, args: Map<String, Value>) -> Outcome {
    match run(c, name, Args(args)).await {
        Ok(o) => o,
        Err(Fail::Arg(m)) => Outcome::error(format!("invalid arguments for {name}: {m}")),
        Err(Fail::Api(e)) => Outcome::error(explain(&e)),
    }
}

async fn opt_resolve(
    c: &AfwClient,
    kind: PolicyKind,
    v: Option<String>,
) -> Result<Option<Uuid>, Fail> {
    match v {
        Some(s) => Ok(Some(c.resolve(kind, &s).await?)),
        None => Ok(None),
    }
}

async fn flow_query(c: &AfwClient, a: &Args) -> Result<FlowQuery, Fail> {
    Ok(FlowQuery {
        agent: opt_resolve(c, PolicyKind::Agents, a.str("agent")).await?,
        zone: opt_resolve(c, PolicyKind::Zones, a.str("zone")).await?,
        destination: a.str("destination"),
        verdict: a.word("verdict")?,
        rule: opt_resolve(c, PolicyKind::Rules, a.str("rule")).await?,
        from: a.time("from")?,
        to: a.time("to")?,
        q: a.str("q"),
        cursor: a.str("cursor"),
        limit: a.u32("limit")?,
    })
}

/// Reads see the draft of your open session, if any.
async fn attach(c: &AfwClient) -> Result<(), Fail> {
    if c.session().is_none()
        && let Some(s) = c.open_session_of_caller().await?
    {
        c.set_session(Some(s.id));
    }
    Ok(())
}

/// Session for a write: the active one, your open one, else a new one.
async fn session(c: &AfwClient) -> Result<Uuid, Fail> {
    Ok(c.ensure_session(true).await?)
}

async fn run(c: &AfwClient, name: &str, a: Args) -> Result<Outcome, Fail> {
    Ok(match name {
        "whoami" => Outcome::ok(&c.me().await?),
        "list_resources" => {
            let kind = a.kind()?;
            attach(c).await?;
            match kind {
                PolicyKind::Rules => Outcome::ok(&c.list_rules().await?),
                k => Outcome::ok(&c.list_raw(k).await?),
            }
        }
        "get_resource" => {
            let kind = a.kind()?;
            attach(c).await?;
            let id = c.resolve(kind, &a.req("id")?).await?;
            Outcome::ok(&c.get_raw(kind, id).await?)
        }
        "create_resource" => {
            let kind = a.kind()?;
            let mut body = a.0.get("resource").cloned().unwrap_or(Value::Null);
            let o = body
                .as_object_mut()
                .ok_or("`resource` must be an object".to_string())?;
            o.entry("id").or_insert_with(|| json!(Uuid::new_v4()));
            session(c).await?;
            Outcome::ok(&c.create_raw(kind, &body).await?)
        }
        "update_resource" => {
            let kind = a.kind()?;
            session(c).await?;
            let id = c.resolve(kind, &a.req("id")?).await?;
            let fields =
                a.0.get("fields")
                    .and_then(Value::as_object)
                    .cloned()
                    .ok_or("`fields` must be an object".to_string())?;
            let current = c.get_raw(kind, id).await?;
            let mut body = match kind {
                PolicyKind::Rules => serde_json::to_value(RuleEntry::from_value(current)?.rule)
                    .map_err(|e| e.to_string())?,
                _ => current,
            };
            if let Some(o) = body.as_object_mut() {
                for (k, v) in fields {
                    o.insert(k, v);
                }
                o.insert("id".into(), json!(id));
            }
            Outcome::ok(&c.update_raw(kind, id, &body).await?)
        }
        "delete_resource" => {
            let kind = a.kind()?;
            let sid = session(c).await?;
            let id = c.resolve(kind, &a.req("id")?).await?;
            c.delete_resource(kind, id).await?;
            Outcome::ok(&json!({"deleted": id, "session": sid}))
        }
        "where_used" => {
            attach(c).await?;
            let id = c.resolve(PolicyKind::Objects, &a.req("object")?).await?;
            Outcome::ok(&c.object_where_used(id).await?)
        }
        "move_rule" => {
            session(c).await?;
            let id = c.resolve(PolicyKind::Rules, &a.req("rule")?).await?;
            let position = a
                .u32("position")?
                .ok_or("missing argument `position`".to_string())?;
            let layer = if a.bool("baseline") == Some(true) {
                Some(Layer::Baseline)
            } else {
                opt_resolve(c, PolicyKind::Zones, a.str("zone"))
                    .await?
                    .map(|zone_id| Layer::Zone { zone_id })
            };
            Outcome::ok(
                &c.move_rule(
                    id,
                    &MoveRuleRequest {
                        position,
                        layer,
                        section: a.str("section"),
                    },
                )
                .await?,
            )
        }
        "get_rulebase" => Outcome::ok(&c.get_rulebase().await?),
        "open_session" => Outcome::ok(&c.open_session(a.str("name").as_deref()).await?),
        "current_session" => match c.current_session().await? {
            Some(s) => {
                if s.state == afw_core::api::SessionState::Open {
                    c.set_session(Some(s.id));
                }
                Outcome::ok(&s)
            }
            None => Outcome::text("No open session.".into()),
        },
        "discard_session" => match c.ensure_session(false).await {
            Ok(id) => Outcome::ok(&c.discard_session(id).await?),
            Err(afw_client::ClientError::NoSession) => {
                Outcome::text("No open session: nothing to discard.".into())
            }
            Err(e) => return Err(e.into()),
        },
        "publish_session" => {
            let comment = a.req("comment")?;
            let id = c.ensure_session(false).await?;
            match c.publish_session(id, &comment).await? {
                PublishOutcome::Published { revision } => Outcome::text(format!(
                    "Published revision {}. Install it with install_revision.\n{}",
                    revision.number,
                    serde_json::to_string_pretty(&revision).unwrap_or_default()
                )),
                PublishOutcome::PendingApproval { approval } => Outcome::text(format!(
                    "PENDING HUMAN APPROVAL (202): this change widens access ({}: {}). It is NOT published. \
                     Approval {} must be accepted by a human administrator; once approved, call publish_session again. \
                     Do not try to work around it.\n{}",
                    approval.summary,
                    approval.reason,
                    approval.id,
                    serde_json::to_string_pretty(&approval).unwrap_or_default()
                )),
            }
        }
        "allow_from_log" => {
            let flow_id = a.uuid("flow_id")?;
            let sid = session(c).await?;
            let out = c
                .allow_from_log(
                    sid,
                    &AllowFromLog {
                        flow_id,
                        destination: a.str("destination"),
                        expires_in_days: a.u32("expires_in_days")?,
                        track: a.word("track")?,
                    },
                )
                .await?;
            Outcome::ok(&out)
        }
        "verify_policy" => {
            let revision = a.u64("revision")?;
            if revision.is_none()
                && c.session().is_none()
                && let Some(s) = c.open_session_of_caller().await?
            {
                c.set_session(Some(s.id));
            }
            Outcome::ok(&c.verify(revision).await?)
        }
        "list_revisions" => Outcome::ok(
            &c.list_revisions(&PageQuery {
                cursor: a.str("cursor"),
                limit: a.u32("limit")?,
            })
            .await?,
        ),
        "diff_revision" => {
            let n = a
                .u64("revision")?
                .ok_or("missing argument `revision`".to_string())?;
            Outcome::ok(&c.diff_revision(n, a.u64("against")?).await?)
        }
        "revert_revision" => {
            let n = a
                .u64("revision")?
                .ok_or("missing argument `revision`".to_string())?;
            Outcome::ok(&c.revert_to_revision(n).await?)
        }
        "list_captures" => Outcome::ok(
            &c.list_captures(&PageQuery {
                cursor: a.str("cursor"),
                limit: a.u32("limit")?,
            })
            .await?,
        ),
        "start_capture" => {
            let agent_id = c.resolve(PolicyKind::Agents, &a.req("agent")?).await?;
            let duration_secs = a.u32("duration_secs")?.unwrap_or(60);
            Outcome::ok(
                &c.start_capture(&afw_core::api::CaptureRequest {
                    agent_id,
                    duration_secs,
                })
                .await?,
            )
        }
        "list_alert_channels" => Outcome::ok(&c.list_alert_channels().await?),
        "get_intent_policy" => Outcome::ok(&c.intent_policy().await?),
        "update_intent_policy" => {
            let mut v =
                a.0.get("intent_policy")
                    .cloned()
                    .filter(Value::is_object)
                    .ok_or("`intent_policy` must be an object".to_string())?;
            v.as_object_mut()
                .expect("object")
                .entry("version")
                .or_insert(json!(0));
            let p: afw_core::api::IntentPolicy =
                serde_json::from_value(v).map_err(|e| format!("invalid intent policy: {e}"))?;
            Outcome::ok(&c.update_intent_policy(&p).await?)
        }
        "install_revision" => {
            let revision = a
                .u64("revision")?
                .ok_or("missing argument `revision`".to_string())?;
            let mut gateways = Vec::new();
            for g in
                a.0.get("gateways")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
            {
                let g = g
                    .as_str()
                    .ok_or("`gateways` must hold strings".to_string())?
                    .to_string();
                gateways.push(c.resolve_gateway(&g).await?);
            }
            Outcome::ok(&c.install(&InstallRequest { revision, gateways }).await?)
        }
        "list_installs" => {
            let gateway = match a.str("gateway") {
                Some(g) => Some(c.resolve_gateway(&g).await?),
                None => None,
            };
            Outcome::ok(
                &c.list_installs(&InstallQuery {
                    gateway,
                    revision: a.u64("revision")?,
                    ..Default::default()
                })
                .await?,
            )
        }
        "list_gateways" => Outcome::ok(&c.list_gateways().await?),
        "policy_status" => Outcome::ok(&c.policy_status().await?),
        "search_flows" => {
            let q = flow_query(c, &a).await?;
            Outcome::ok(&c.list_flows_raw(&q).await?)
        }
        "get_flow" => Outcome::ok(&c.get_flow_raw(a.uuid("flow_id")?).await?),
        "search_dns" => {
            let q = flow_query(c, &a).await?;
            Outcome::ok(&c.list_dns(&q).await?)
        }
        "agent_overview" => {
            let id = c.resolve(PolicyKind::Agents, &a.req("agent")?).await?;
            Outcome::ok(&c.agent_overview(id).await?)
        }
        "internal_map" => Outcome::ok(
            &c.internal_map(&MapQuery {
                period: a.str("period"),
                zone: opt_resolve(c, PolicyKind::Zones, a.str("zone")).await?,
                ..Default::default()
            })
            .await?,
        ),
        "list_alerts" => Outcome::ok(
            &c.list_alerts(&AlertQuery {
                agent: opt_resolve(c, PolicyKind::Agents, a.str("agent")).await?,
                severity: a.word("severity")?,
                acknowledged: a.bool("acknowledged"),
                cursor: a.str("cursor"),
                limit: a.u32("limit")?,
                ..Default::default()
            })
            .await?,
        ),
        "ack_alert" => Outcome::ok(&c.acknowledge_alert(a.uuid("id")?).await?),
        "list_audit" => Outcome::ok(
            &c.list_audit(&AuditQuery {
                interface: a.word("interface")?,
                from_seq: a.u64("from_seq")?.map(|n| n as i64),
                actor: a.str("actor"),
                action: a.str("action"),
                cursor: a.str("cursor"),
                limit: a.u32("limit")?,
                order: a.word("order")?,
                ..Default::default()
            })
            .await?,
        ),
        "verify_audit" => Outcome::ok(&c.verify_audit().await?),
        "list_approvals" => Outcome::ok(&c.list_approvals(a.word("status")?).await?),
        other => return Err(Fail::Arg(format!("unknown tool `{other}`"))),
    })
}
