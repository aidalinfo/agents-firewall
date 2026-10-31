//! Policy resources (objects, services, data classes, zones, agents, rules, inspection rules)
//! and alert channels: list, show, create, update, delete. Creation and update build the JSON
//! body from defaults, an optional file and the flags, validate it against the `afw-core`
//! type, then send it in the caller's session.

use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

use afw_client::{AfwClient, PolicyKind, RuleEntry};
use afw_core::api::AlertChannel;
use afw_core::policy::{Agent, DataClass, InspectionRule, Layer, NetObject, Rule, Service, Zone};
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::Ctx;
use crate::cli::{
    AgentArgs, AlertChannelArgs, CategoryArg, DataClassArgs, FileArg, InspectionArgs, ObjectArgs,
    RuleArgs, ServiceArgs, ZoneArgs,
};
use crate::output::{Col, col, colf, scalar, table};
use crate::util::{enum_word, key_value, parse_future};

/// Flags of a create/update command.
pub enum KindArgs {
    Object(ObjectArgs),
    Service(ServiceArgs),
    DataClass(DataClassArgs),
    Zone(ZoneArgs),
    Agent(AgentArgs),
    Rule(RuleArgs),
    Inspection(InspectionArgs),
}

// ---------------------------------------------------------------------------------------------
// Commands

pub async fn list(ctx: &mut Ctx<'_>, kind: PolicyKind) -> Result<()> {
    let c = ctx.attach_session().await?;
    let items = match kind {
        PolicyKind::Rules => c
            .list_rules()
            .await?
            .into_iter()
            .map(|r| r.raw)
            .collect::<Vec<_>>(),
        _ => c.list_raw(kind).await?,
    };
    if ctx.json {
        return ctx.print_json(&items);
    }
    let names = Names::load(&c, kind).await?;
    let cols = columns(kind, names);
    table(ctx.out, &items, &cols)?;
    Ok(())
}

pub async fn show(ctx: &mut Ctx<'_>, kind: PolicyKind, id: &str) -> Result<()> {
    let c = ctx.attach_session().await?;
    let id = c.resolve(kind, id).await?;
    let v = c.get_raw(kind, id).await?;
    ctx.print_json(&v)
}

pub async fn delete(ctx: &mut Ctx<'_>, kind: PolicyKind, id: &str) -> Result<()> {
    let c = ctx.client()?;
    let session = ctx.session().await?;
    let id = c.resolve(kind, id).await?;
    c.delete_resource(kind, id).await?;
    if ctx.json {
        return ctx.print_json(&json!({ "deleted": id, "session": session }));
    }
    ctx.say(&format!(
        "Deleted {} {id} in session {session}.",
        kind.singular()
    ))
}

pub async fn create(
    ctx: &mut Ctx<'_>,
    kind: PolicyKind,
    file: &FileArg,
    args: KindArgs,
) -> Result<()> {
    let c = ctx.client()?;
    let mut v = defaults(kind);
    merge_file(&mut v, file)?;
    // Validate what can be checked offline before opening a session.
    if let KindArgs::Object(a) = &args
        && a.group.is_none()
    {
        let mut probe = v.clone();
        apply(&c, kind, &args, &mut probe, true).await?;
        validate(kind, probe)?;
    }
    let session = ctx.session().await?;
    apply(&c, kind, &args, &mut v, true).await?;
    finish_defaults(&c, kind, &mut v).await?;
    let body = validate(kind, v)?;
    let created = c.create_raw(kind, &body).await?;
    report(ctx, kind, "Created", &created, session)
}

pub async fn update(
    ctx: &mut Ctx<'_>,
    kind: PolicyKind,
    id: &str,
    file: &FileArg,
    args: KindArgs,
) -> Result<()> {
    let c = ctx.client()?;
    let session = ctx.session().await?;
    let id = c.resolve(kind, id).await?;
    let current = c.get_raw(kind, id).await?;
    let mut v = match kind {
        PolicyKind::Rules => serde_json::to_value(RuleEntry::from_value(current)?.rule)?,
        _ => current,
    };
    merge_file(&mut v, file)?;
    apply(&c, kind, &args, &mut v, false).await?;
    if let Some(o) = v.as_object_mut() {
        o.insert("id".into(), json!(id));
    }
    let body = validate(kind, v)?;
    let updated = c.update_raw(kind, id, &body).await?;
    report(ctx, kind, "Updated", &updated, session)
}

fn report(ctx: &mut Ctx<'_>, kind: PolicyKind, verb: &str, v: &Value, session: Uuid) -> Result<()> {
    if ctx.json {
        return ctx.print_json(v);
    }
    ctx.say(&format!(
        "{verb} {} {} ({}) in session {session}. Publish with: afw session publish -m <comment>",
        kind.singular(),
        scalar(v.get("name")),
        scalar(v.get("id")),
    ))
}

/// `afw rules move`.
pub async fn move_rule(
    ctx: &mut Ctx<'_>,
    rule: &str,
    position: u32,
    zone: Option<&str>,
    baseline: bool,
    section: Option<String>,
) -> Result<()> {
    let c = ctx.client()?;
    let session = ctx.session().await?;
    let id = c.resolve(PolicyKind::Rules, rule).await?;
    let layer = if baseline {
        Some(Layer::Baseline)
    } else if let Some(z) = zone {
        Some(Layer::Zone {
            zone_id: c.resolve(PolicyKind::Zones, z).await?,
        })
    } else {
        None
    };
    let moved = c
        .move_rule(
            id,
            &afw_core::api::MoveRuleRequest {
                position,
                layer,
                section,
            },
        )
        .await?;
    report(ctx, PolicyKind::Rules, "Moved", &moved.raw, session)
}

/// `afw where-used <object>`.
pub async fn where_used(ctx: &mut Ctx<'_>, object: &str) -> Result<()> {
    let c = ctx.attach_session().await?;
    let id = c.resolve(PolicyKind::Objects, object).await?;
    let w = c.object_where_used(id).await?;
    if ctx.json {
        return ctx.print_json(&w);
    }
    if w.references.is_empty() {
        return ctx.say("Not used.");
    }
    let items: Vec<Value> = w
        .references
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?;
    table(
        ctx.out,
        &items,
        &[col("KIND", "/kind"), col("NAME", "/name"), col("ID", "/id")],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Alert channels (not session-bound, typed directly)

pub async fn channels_list(ctx: &mut Ctx<'_>) -> Result<()> {
    let c = ctx.client()?;
    let items = c.list_alert_channels().await?;
    if ctx.json {
        return ctx.print_json(&items);
    }
    let items: Vec<Value> = items
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?;
    table(
        ctx.out,
        &items,
        &[
            col("ID", "/id"),
            col("NAME", "/name"),
            col("KIND", "/kind"),
            col("MIN SEVERITY", "/min_severity"),
            col("ENABLED", "/enabled"),
            col("URL", "/url"),
        ],
    )?;
    Ok(())
}

async fn channel_id(c: &AfwClient, s: &str) -> Result<Uuid> {
    if let Ok(id) = Uuid::parse_str(s) {
        return Ok(id);
    }
    let found: Vec<Uuid> = c
        .list_alert_channels()
        .await?
        .into_iter()
        .filter(|ch| ch.name == s)
        .map(|ch| ch.id)
        .collect();
    match found.as_slice() {
        [id] => Ok(*id),
        [] => bail!("alert channel `{s}` not found"),
        _ => bail!("alert channel name `{s}` is ambiguous: use its id"),
    }
}

pub async fn channels_show(ctx: &mut Ctx<'_>, id: &str) -> Result<()> {
    let c = ctx.client()?;
    let id = channel_id(&c, id).await?;
    let ch = c.get_alert_channel(id).await?;
    ctx.print_json(&ch)
}

pub async fn channels_delete(ctx: &mut Ctx<'_>, id: &str) -> Result<()> {
    let c = ctx.client()?;
    let id = channel_id(&c, id).await?;
    c.delete_alert_channel(id).await?;
    ctx.say(&format!("Deleted alert channel {id}."))
}

pub async fn channels_save(
    ctx: &mut Ctx<'_>,
    id: Option<&str>,
    file: &FileArg,
    a: &AlertChannelArgs,
) -> Result<()> {
    let c = ctx.client()?;
    let (existing, mut v) = match id {
        Some(id) => {
            let id = channel_id(&c, id).await?;
            (
                Some(id),
                serde_json::to_value(c.get_alert_channel(id).await?)?,
            )
        }
        None => (
            None,
            json!({"id": Uuid::new_v4(), "kind": "webhook", "min_severity": "warning", "enabled": true}),
        ),
    };
    merge_file(&mut v, file)?;
    let o = obj(&mut v)?;
    set_opt(o, "name", &a.name);
    set_opt(o, "kind", &a.kind);
    set_opt(o, "url", &a.target_url);
    set_opt(o, "min_severity", &a.min_severity);
    if let Some(e) = a.enabled {
        o.insert("enabled".into(), json!(e));
    }
    let ch: AlertChannel =
        serde_json::from_value(v).map_err(|e| anyhow!("invalid alert channel: {e}"))?;
    let saved = match existing {
        Some(_) => c.update_alert_channel(&ch).await?,
        None => c.create_alert_channel(&ch).await?,
    };
    if ctx.json {
        return ctx.print_json(&saved);
    }
    ctx.say(&format!(
        "{} alert channel {} ({}).",
        if existing.is_some() {
            "Updated"
        } else {
            "Created"
        },
        saved.name,
        saved.id
    ))
}

// ---------------------------------------------------------------------------------------------
// Body construction

fn defaults(kind: PolicyKind) -> Value {
    let id = Uuid::new_v4();
    match kind {
        PolicyKind::Objects => json!({"id": id, "comment": ""}),
        PolicyKind::Services => json!({"id": id, "comment": "", "protocol": "tcp", "ports": []}),
        PolicyKind::DataClasses => {
            json!({"id": id, "comment": "", "category": "custom", "detectors": []})
        }
        PolicyKind::Zones => {
            json!({"id": id, "comment": "", "mode": "enforce", "delegated_to_mcp": false})
        }
        PolicyKind::Agents => json!({
            "id": id, "kind": "container", "addresses": [], "labels": {},
            "hermes": false, "mcp_admin": false
        }),
        PolicyKind::Rules => json!({
            "id": id, "sources": [], "destinations": [], "services": [], "data_classes": [],
            "track": "detailed", "comment": "", "enabled": true
        }),
        PolicyKind::InspectionRules => {
            json!({"id": id, "zones": [], "destinations": [], "action": "inspect"})
        }
    }
}

/// Reads a JSON or YAML file (`-` = stdin) and merges its top-level fields into `v`.
fn merge_file(v: &mut Value, file: &FileArg) -> Result<()> {
    let Some(path) = &file.file else {
        return Ok(());
    };
    let text = read_input(path)?;
    let parsed: Value = serde_yaml::from_str(&text)
        .with_context(|| format!("{} is not valid JSON or YAML", path.display()))?;
    let Value::Object(fields) = parsed else {
        bail!("{} must contain an object", path.display());
    };
    let o = obj(v)?;
    for (k, val) in fields {
        o.insert(k, val);
    }
    Ok(())
}

pub fn read_input(path: &Path) -> Result<String> {
    if path.as_os_str() == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
        Ok(s)
    } else {
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))
    }
}

fn obj(v: &mut Value) -> Result<&mut Map<String, Value>> {
    v.as_object_mut()
        .ok_or_else(|| anyhow!("the resource must be a JSON object"))
}

fn set_opt(o: &mut Map<String, Value>, key: &str, val: &Option<String>) {
    if let Some(s) = val {
        o.insert(key.into(), json!(s));
    }
}

async fn ids(c: &AfwClient, kind: PolicyKind, names: &[String]) -> Result<Value> {
    let mut out = Vec::with_capacity(names.len());
    for n in names {
        out.push(json!(c.resolve(kind, n).await?));
    }
    Ok(Value::Array(out))
}

async fn apply(
    c: &AfwClient,
    kind: PolicyKind,
    args: &KindArgs,
    v: &mut Value,
    creating: bool,
) -> Result<()> {
    let o = obj(v)?;
    match args {
        KindArgs::Object(a) => {
            set_opt(o, "name", &a.name);
            set_opt(o, "comment", &a.comment);
            if let Some(cat) = a.category {
                let val = match cat {
                    CategoryArg::None => Value::Null,
                    CategoryArg::LlmProvider => json!("llm_provider"),
                    CategoryArg::CloudMetadata => json!("cloud_metadata"),
                    CategoryArg::Internal => json!("internal"),
                };
                o.insert("category".into(), val);
            }
            let spec = if let Some(d) = &a.domain {
                Some(json!({"type": "domain", "pattern": d}))
            } else if let Some(h) = &a.host {
                Some(json!({"type": "host", "ip": h}))
            } else if let Some(n) = &a.network {
                Some(json!({"type": "network", "cidr": n}))
            } else if let Some(r) = &a.range {
                let (s, e) = r
                    .split_once('-')
                    .ok_or_else(|| anyhow!("--range expects START-END"))?;
                Some(json!({"type": "range", "start": s.trim(), "end": e.trim()}))
            } else if let Some(g) = &a.group {
                Some(json!({"type": "group", "members": ids(c, PolicyKind::Objects, g).await?}))
            } else if a.any {
                Some(json!({"type": "any"}))
            } else {
                None
            };
            if let Some(s) = spec {
                o.insert("spec".into(), s);
            } else if creating && !o.contains_key("spec") {
                bail!(
                    "an object needs one of --domain, --host, --network, --range, --group, --any"
                );
            }
        }
        KindArgs::Service(a) => {
            set_opt(o, "name", &a.name);
            set_opt(o, "comment", &a.comment);
            set_opt(o, "protocol", &a.protocol);
            if !a.ports.is_empty() {
                let ports = a
                    .ports
                    .iter()
                    .map(|p| port_range(p))
                    .collect::<Result<Vec<_>>>()?;
                o.insert("ports".into(), Value::Array(ports));
            }
            if a.app.is_some() || !a.methods.is_empty() || !a.path_prefixes.is_empty() {
                let mut app = o
                    .get("app")
                    .cloned()
                    .filter(Value::is_object)
                    .unwrap_or_else(|| json!({"methods": [], "path_prefixes": []}));
                if let Some(p) = &a.app {
                    app["proto"] = json!(p);
                }
                if !a.methods.is_empty() {
                    app["methods"] = json!(
                        a.methods
                            .iter()
                            .map(|m| m.to_uppercase())
                            .collect::<Vec<_>>()
                    );
                }
                if !a.path_prefixes.is_empty() {
                    app["path_prefixes"] = json!(a.path_prefixes);
                }
                if app.get("proto").is_none() {
                    bail!("--method/--path-prefix need --app");
                }
                o.insert("app".into(), app);
            }
        }
        KindArgs::DataClass(a) => {
            set_opt(o, "name", &a.name);
            set_opt(o, "comment", &a.comment);
            set_opt(o, "category", &a.category);
            if !a.builtins.is_empty() || !a.regexes.is_empty() {
                let mut det: Vec<Value> = a
                    .builtins
                    .iter()
                    .map(|id| json!({"type": "builtin", "id": id}))
                    .collect();
                for r in &a.regexes {
                    let (name, pattern) = key_value(r)?;
                    det.push(json!({"type": "regex", "name": name, "pattern": pattern}));
                }
                o.insert("detectors".into(), Value::Array(det));
            }
        }
        KindArgs::Zone(a) => {
            set_opt(o, "name", &a.name);
            set_opt(o, "comment", &a.comment);
            set_opt(o, "mode", &a.mode);
            if let Some(d) = a.delegated_to_mcp {
                o.insert("delegated_to_mcp".into(), json!(d));
            }
        }
        KindArgs::Agent(a) => {
            set_opt(o, "name", &a.name);
            set_opt(o, "kind", &a.kind);
            if let Some(z) = &a.zone {
                o.insert(
                    "zone_id".into(),
                    json!(c.resolve(PolicyKind::Zones, z).await?),
                );
            }
            if let Some(g) = &a.gateway {
                o.insert("gateway_id".into(), json!(c.resolve_gateway(g).await?));
            }
            if !a.addresses.is_empty() {
                o.insert("addresses".into(), json!(a.addresses));
            }
            if !a.labels.is_empty() {
                let mut m = Map::new();
                for l in &a.labels {
                    let (k, v) = key_value(l)?;
                    m.insert(k, json!(v));
                }
                o.insert("labels".into(), Value::Object(m));
            }
            if let Some(h) = a.hermes {
                o.insert("hermes".into(), json!(h));
            }
            if let Some(m) = a.mcp_admin {
                o.insert("mcp_admin".into(), json!(m));
            }
        }
        KindArgs::Rule(a) => {
            set_opt(o, "name", &a.name);
            set_opt(o, "comment", &a.comment);
            set_opt(o, "action", &a.action);
            set_opt(o, "track", &a.track);
            if let Some(s) = &a.section {
                o.insert("section".into(), json!(s));
            }
            if let Some(p) = a.position {
                o.insert("position".into(), json!(p));
            }
            if a.baseline {
                o.insert("layer".into(), json!({"type": "baseline"}));
            } else if let Some(z) = &a.zone {
                let zid = c.resolve(PolicyKind::Zones, z).await?;
                o.insert("layer".into(), json!({"type": "zone", "zone_id": zid}));
                if creating && a.sources.is_empty() {
                    o.insert("sources".into(), json!([zid]));
                }
            }
            if !a.sources.is_empty() {
                o.insert(
                    "sources".into(),
                    ids(c, PolicyKind::Zones, &a.sources).await?,
                );
            }
            if !a.destinations.is_empty() {
                o.insert(
                    "destinations".into(),
                    ids(c, PolicyKind::Objects, &a.destinations).await?,
                );
            }
            if !a.services.is_empty() {
                o.insert(
                    "services".into(),
                    ids(c, PolicyKind::Services, &a.services).await?,
                );
            }
            if !a.data_classes.is_empty() {
                o.insert(
                    "data_classes".into(),
                    ids(c, PolicyKind::DataClasses, &a.data_classes).await?,
                );
            }
            if let Some(e) = &a.expires {
                let val = if e == "never" {
                    Value::Null
                } else {
                    json!(parse_future(e)?)
                };
                o.insert("expires_at".into(), val);
            }
            if let Some(en) = a.enabled {
                o.insert("enabled".into(), json!(en));
            }
            if creating && !o.contains_key("layer") {
                bail!("a rule needs --zone <zone> or --baseline");
            }
            if creating && !o.contains_key("action") {
                bail!("a rule needs --action accept|deny");
            }
        }
        KindArgs::Inspection(a) => {
            set_opt(o, "name", &a.name);
            set_opt(o, "action", &a.action);
            if let Some(p) = a.position {
                o.insert("position".into(), json!(p));
            }
            if !a.zones.is_empty() {
                o.insert("zones".into(), ids(c, PolicyKind::Zones, &a.zones).await?);
            }
            if !a.destinations.is_empty() {
                o.insert(
                    "destinations".into(),
                    ids(c, PolicyKind::Objects, &a.destinations).await?,
                );
            }
        }
    }
    let _ = kind;
    Ok(())
}

/// Defaults needing the API: position at the end of the layer.
async fn finish_defaults(c: &AfwClient, kind: PolicyKind, v: &mut Value) -> Result<()> {
    if v.get("position").is_some() {
        return Ok(());
    }
    let next = match kind {
        PolicyKind::Rules => {
            let layer = v.get("layer").cloned().unwrap_or(Value::Null);
            c.list_rules()
                .await?
                .iter()
                .filter(|r| serde_json::to_value(r.rule.layer).ok().as_ref() == Some(&layer))
                .map(|r| r.rule.position)
                .max()
                .map_or(1, |p| p + 1)
        }
        PolicyKind::InspectionRules => c
            .list_inspection_rules()
            .await?
            .iter()
            .map(|r| r.position)
            .max()
            .map_or(1, |p| p + 1),
        _ => return Ok(()),
    };
    obj(v)?.insert("position".into(), json!(next));
    Ok(())
}

fn port_range(p: &str) -> Result<Value> {
    let (s, e) = p.split_once('-').unwrap_or((p, p));
    let s: u16 = s
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid port `{p}`"))?;
    let e: u16 = e
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid port `{p}`"))?;
    if s > e {
        bail!("invalid port range `{p}`");
    }
    Ok(json!({"start": s, "end": e}))
}

/// Checks the body against the `afw-core` type and returns its canonical JSON.
fn validate(kind: PolicyKind, v: Value) -> Result<Value> {
    fn check<T: serde::de::DeserializeOwned + serde::Serialize>(
        what: &str,
        v: Value,
    ) -> Result<Value> {
        let t: T = serde_json::from_value(v).map_err(|e| anyhow!("invalid {what}: {e}"))?;
        Ok(serde_json::to_value(t)?)
    }
    let what = kind.singular();
    match kind {
        PolicyKind::Objects => check::<NetObject>(what, v),
        PolicyKind::Services => check::<Service>(what, v),
        PolicyKind::DataClasses => check::<DataClass>(what, v),
        PolicyKind::Zones => check::<Zone>(what, v),
        PolicyKind::Agents => check::<Agent>(what, v),
        PolicyKind::Rules => check::<Rule>(what, v),
        PolicyKind::InspectionRules => check::<InspectionRule>(what, v),
    }
}

// ---------------------------------------------------------------------------------------------
// Tables

/// Id → name of the resources referenced by a listing.
#[derive(Default)]
pub struct Names(HashMap<String, String>);

impl Names {
    pub async fn load(c: &AfwClient, kind: PolicyKind) -> Result<Rc<Self>> {
        let needed: &[PolicyKind] = match kind {
            PolicyKind::Agents => &[PolicyKind::Zones],
            PolicyKind::Rules => &[
                PolicyKind::Zones,
                PolicyKind::Objects,
                PolicyKind::Services,
                PolicyKind::DataClasses,
            ],
            PolicyKind::InspectionRules => &[PolicyKind::Zones, PolicyKind::Objects],
            PolicyKind::Objects => &[PolicyKind::Objects],
            _ => &[],
        };
        let mut m = HashMap::new();
        for k in needed {
            for v in c.list_raw(*k).await.unwrap_or_default() {
                if let (Some(id), Some(name)) = (
                    v.get("id").and_then(Value::as_str),
                    v.get("name").and_then(Value::as_str),
                ) {
                    m.insert(id.to_string(), name.to_string());
                }
            }
        }
        Ok(Rc::new(Self(m)))
    }

    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Rc<Self> {
        Rc::new(Self(pairs.into_iter().collect()))
    }

    pub fn name(&self, id: &Value) -> String {
        match id.as_str() {
            Some(s) => self.0.get(s).cloned().unwrap_or_else(|| s.to_string()),
            None => "-".into(),
        }
    }

    pub fn list(&self, ids: Option<&Value>, empty: &str) -> String {
        match ids.and_then(Value::as_array) {
            Some(a) if !a.is_empty() => {
                a.iter().map(|i| self.name(i)).collect::<Vec<_>>().join(",")
            }
            _ => empty.into(),
        }
    }
}

fn spec_value(spec: &Value, names: &Names) -> String {
    match spec.get("type").and_then(Value::as_str) {
        Some("domain") => scalar(spec.get("pattern")),
        Some("host") => scalar(spec.get("ip")),
        Some("network") => scalar(spec.get("cidr")),
        Some("range") => format!("{}-{}", scalar(spec.get("start")), scalar(spec.get("end"))),
        Some("group") => names.list(spec.get("members"), "-"),
        Some("any") => "*".into(),
        _ => "-".into(),
    }
}

fn ports(v: &Value) -> String {
    match v.get("ports").and_then(Value::as_array) {
        Some(a) if !a.is_empty() => a
            .iter()
            .map(|p| {
                let (s, e) = (scalar(p.get("start")), scalar(p.get("end")));
                if s == e { s } else { format!("{s}-{e}") }
            })
            .collect::<Vec<_>>()
            .join(","),
        _ => "any".into(),
    }
}

fn columns(kind: PolicyKind, names: Rc<Names>) -> Vec<Col> {
    match kind {
        PolicyKind::Objects => {
            let n = names.clone();
            vec![
                col("ID", "/id"),
                col("NAME", "/name"),
                col("TYPE", "/spec/type"),
                colf("VALUE", move |v| spec_value(&v["spec"], &n)),
                col("CATEGORY", "/category"),
            ]
        }
        PolicyKind::Services => vec![
            col("ID", "/id"),
            col("NAME", "/name"),
            col("PROTOCOL", "/protocol"),
            colf("PORTS", ports),
            col("APP", "/app/proto"),
        ],
        PolicyKind::DataClasses => vec![
            col("ID", "/id"),
            col("NAME", "/name"),
            col("CATEGORY", "/category"),
            colf("DETECTORS", |v| {
                v["detectors"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|d| scalar(d.get("id").or(d.get("name"))))
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default()
            }),
        ],
        PolicyKind::Zones => vec![
            col("ID", "/id"),
            col("NAME", "/name"),
            col("MODE", "/mode"),
            col("MCP", "/delegated_to_mcp"),
            col("COMMENT", "/comment"),
        ],
        PolicyKind::Agents => {
            let n = names.clone();
            vec![
                col("ID", "/id"),
                col("NAME", "/name"),
                colf("ZONE", move |v| n.name(&v["zone_id"])),
                col("KIND", "/kind"),
                col("ADDRESSES", "/addresses"),
                col("HERMES", "/hermes"),
                col("MCP ADMIN", "/mcp_admin"),
            ]
        }
        PolicyKind::Rules => {
            let (n1, n2, n3, n4) = (names.clone(), names.clone(), names.clone(), names.clone());
            vec![
                col("NO", "/number"),
                col("NAME", "/name"),
                colf("LAYER", move |v| match v["layer"]["type"].as_str() {
                    Some("zone") => n1.name(&v["layer"]["zone_id"]),
                    other => other.unwrap_or("-").to_string(),
                }),
                col("POS", "/position"),
                colf("SOURCES", move |v| n2.list(v.get("sources"), "all zones")),
                colf("DESTINATIONS", move |v| {
                    n3.list(v.get("destinations"), "any")
                }),
                colf("SERVICES", move |v| n4.list(v.get("services"), "any")),
                col("ACTION", "/action"),
                col("TRACK", "/track"),
                col("ENABLED", "/enabled"),
                col("HITS", "/hits"),
                col("ID", "/id"),
            ]
        }
        PolicyKind::InspectionRules => {
            let (n1, n2) = (names.clone(), names);
            vec![
                col("POS", "/position"),
                col("NAME", "/name"),
                colf("ZONES", move |v| n1.list(v.get("zones"), "all zones")),
                colf("DESTINATIONS", move |v| {
                    n2.list(v.get("destinations"), "any")
                }),
                col("ACTION", "/action"),
                col("ID", "/id"),
            ]
        }
    }
}

/// `afw gateways command` word → `GatewayCommand` JSON.
pub fn gateway_command(word: &str) -> Value {
    json!({ "type": enum_word(word) })
}
