//! Docker Compose enrollment and its exact inverse.
//!
//! The document is handled as a [`serde_yaml::Value`]: [`Mapping`] keeps insertion order, so
//! untouched keys keep their position. YAML merge keys (`<<`) are resolved before anything else
//! (otherwise a capability hidden behind an anchor would escape the audit); comments and anchors
//! are not preserved (serde_yaml limitation, see ADR 0023).

use serde_yaml::{Mapping, Value};

use crate::error::EnrollError;
use crate::netinit::{HOLDER_CA_DIR, HOLDER_CA_SRC, READY_FILE, script};
use crate::spec::{
    CA_DIR, EnrollOutcome, EnrollSpec, EnrollWarning, LABEL_AGENT, LABEL_ENROLLED,
    is_dangerous_cap, is_runtime_socket,
};

/// Top-level extension holding the original state of every enrolled service.
pub const ORIGINAL_KEY: &str = "x-afw-original";

/// Agent-service keys that Docker refuses next to `network_mode: service:…`; they are moved to
/// the `afw-net-<agent>` container, which owns the network namespace.
const MOVED_TO_HOLDER: &[&str] = &[
    "hostname",
    "domainname",
    "mac_address",
    "ports",
    "expose",
    "extra_hosts",
    "dns_search",
    "dns_opt",
];

/// Agent-service keys that are dropped (they are replaced by the gateway network and DNS).
const DROPPED: &[&str] = &["networks", "dns", "links"];

/// Name of the per-agent volume holding the CA bundle built by the holder.
pub(crate) fn ca_volume_name(agent: &str) -> String {
    format!("afw-ca-{agent}")
}

/// Enroll `spec.service` behind the gateway (ADR 0003, ADR 0023).
///
/// Adds the `afw-net-<agent>` network-namespace holder (only `NET_ADMIN`, fixed address, routes
/// and DNS to the gateway, CA bundle), moves the agent into its namespace without `NET_RAW`,
/// sets proxy and CA variables, mounts the CA directory (and the Hermes plugin if requested),
/// declares the gateway network as external and records the original state under
/// [`ORIGINAL_KEY`] so that [`unenroll_compose`] is an exact inverse.
pub fn enroll_compose(yaml: &str, spec: &EnrollSpec) -> Result<EnrollOutcome, EnrollError> {
    spec.validate()?;
    let mut doc = parse_document(yaml)?;
    let net_name = spec.net_service_name();
    let agent = spec.agent_name.as_str();
    let volume = ca_volume_name(agent);

    // --- idempotence: one enrollment per agent and per service.
    if let Some(Value::Mapping(ann)) = doc.get(ORIGINAL_KEY) {
        if ann.contains_key(agent) {
            return Err(EnrollError::AlreadyEnrolled(agent.into()));
        }
        for (other, entry) in ann {
            if entry.get("service").and_then(Value::as_str) == Some(spec.service.as_str()) {
                return Err(EnrollError::AlreadyEnrolled(
                    other.as_str().unwrap_or(agent).into(),
                ));
            }
        }
    }
    let services = doc
        .get("services")
        .and_then(Value::as_mapping)
        .ok_or_else(|| EnrollError::ServiceNotFound(spec.service.clone()))?;
    if services.contains_key(net_name.as_str()) {
        return Err(EnrollError::AlreadyEnrolled(agent.into()));
    }
    let original = services
        .get(spec.service.as_str())
        .ok_or_else(|| EnrollError::ServiceNotFound(spec.service.clone()))?
        .clone();
    let svc = original.as_mapping().ok_or_else(|| {
        EnrollError::InvalidYaml(format!("service `{}` is not a mapping", spec.service))
    })?;
    if svc.contains_key("extends") {
        return Err(EnrollError::Unsupported(format!(
            "service `{}` uses `extends`: inline it before enrolling (inherited keys cannot be audited)",
            spec.service
        )));
    }

    // --- network mode: host is a hard error, anything else is unsupported.
    if let Some(mode) = svc.get("network_mode") {
        let mode = mode.as_str().unwrap_or_default().to_string();
        if mode == "host" {
            return Err(EnrollError::HostNetwork(spec.service.clone()));
        }
        if mode.starts_with("service:afw-net-") {
            return Err(EnrollError::AlreadyEnrolled(agent.into()));
        }
        return Err(EnrollError::UnsupportedNetworkMode {
            service: spec.service.clone(),
            mode,
        });
    }

    // --- audit: the agent, then every service joining its network namespace.
    let mut warnings = audit_service(&spec.service, svc);
    let container_name = svc.get("container_name").and_then(Value::as_str);
    let mut joins = vec![
        format!("service:{}", spec.service),
        format!("service:{net_name}"),
        format!("container:{net_name}"),
    ];
    if let Some(cn) = container_name {
        joins.push(format!("container:{cn}"));
    }
    for (name, other) in services {
        let (Some(name), Some(other)) = (name.as_str(), other.as_mapping()) else {
            continue;
        };
        if name == spec.service {
            continue;
        }
        let mode = other.get("network_mode").and_then(Value::as_str);
        if mode.is_some_and(|m| joins.iter().any(|j| j == m)) {
            warnings.push(EnrollWarning::JoinsAgentNetwork {
                service: name.into(),
            });
            warnings.extend(audit_service(name, other));
        }
    }

    // --- network-namespace holder.
    let mut holder = Mapping::new();
    holder.insert("image".into(), spec.netinit_image.clone().into());
    holder.insert("restart".into(), "unless-stopped".into());
    holder.insert("cap_drop".into(), seq(["ALL"]));
    holder.insert("cap_add".into(), seq(["NET_ADMIN"]));
    holder.insert(
        "environment".into(),
        map([
            ("AFW_GATEWAY_IP", spec.gateway_ip.to_string()),
            ("AFW_AGENT_IP", spec.agent_ip.to_string()),
        ]),
    );
    // `$$` is the Compose escape of a literal `$` (no interpolation inside the script).
    holder.insert(
        "command".into(),
        seq([
            "sh".to_string(),
            "-c".to_string(),
            script(spec.gateway_ip, spec.agent_ip).replace('$', "$$"),
        ]),
    );
    let addr_key = if spec.agent_ip.is_ipv4() {
        "ipv4_address"
    } else {
        "ipv6_address"
    };
    let mut attach = Mapping::new();
    attach.insert(addr_key.into(), spec.agent_ip.to_string().into());
    let mut nets = Mapping::new();
    nets.insert(spec.network.clone().into(), Value::Mapping(attach));
    holder.insert("networks".into(), Value::Mapping(nets));
    holder.insert("dns".into(), seq([spec.gateway_ip.to_string()]));
    // The gateway forwards between agents of the same subnet: never follow an ICMP redirect.
    let fam = if spec.gateway_ip.is_ipv4() {
        "ipv4"
    } else {
        "ipv6"
    };
    let mut sysctls = Mapping::new();
    for scope in ["all", "default"] {
        sysctls.insert(
            format!("net.{fam}.conf.{scope}.accept_redirects").into(),
            0.into(),
        );
    }
    holder.insert("sysctls".into(), Value::Mapping(sysctls));
    holder.insert(
        "volumes".into(),
        seq([
            format!("{}:{HOLDER_CA_SRC}:ro", spec.ca_path_host),
            format!("{volume}:{HOLDER_CA_DIR}"),
        ]),
    );
    holder.insert(
        "healthcheck".into(),
        serde_yaml::to_value(serde_json::json!({
            "test": ["CMD-SHELL", format!("test -f {READY_FILE} && test -s {HOLDER_CA_DIR}/bundle.pem")],
            "interval": "5s",
            "timeout": "3s",
            "retries": 12,
        }))?,
    );
    for key in MOVED_TO_HOLDER {
        if let Some(v) = svc.get(*key) {
            holder.insert((*key).into(), v.clone());
        }
    }
    if svc.contains_key("ports") {
        warnings.push(EnrollWarning::PortsNotPublished {
            service: spec.service.clone(),
        });
    }
    holder.insert(
        "labels".into(),
        map([
            (LABEL_ENROLLED, "true".to_string()),
            (LABEL_AGENT, spec.agent_name.clone()),
        ]),
    );

    // --- agent service.
    let mut agent_svc = svc.clone();
    if agent_svc.contains_key("links") {
        warnings.push(EnrollWarning::LinksRemoved {
            service: spec.service.clone(),
        });
    }
    for key in MOVED_TO_HOLDER.iter().chain(DROPPED) {
        agent_svc.shift_remove(*key);
    }
    let removed = remove_net_sysctls(&mut agent_svc);
    if !removed.is_empty() {
        warnings.push(EnrollWarning::NetSysctlsRemoved {
            service: spec.service.clone(),
            keys: removed,
        });
    }
    drop_net_raw(&mut agent_svc);
    agent_svc.insert("network_mode".into(), format!("service:{net_name}").into());
    depend_on_healthy(&mut agent_svc, &net_name);
    set_pairs(&mut agent_svc, "environment", &spec.agent_environment());
    let mut mounts = vec![format!("{volume}:{CA_DIR}:ro")];
    if let Some(h) = &spec.hermes {
        mounts.push(format!("{}:{}:ro", h.plugin_dir_host, h.container_dir()));
    }
    append_volumes(&mut agent_svc, &mounts);
    set_pairs(
        &mut agent_svc,
        "labels",
        &[
            (LABEL_ENROLLED.to_string(), "true".to_string()),
            (LABEL_AGENT.to_string(), spec.agent_name.clone()),
        ],
    );

    // --- annotation (computed before touching the top level).
    let root = doc.as_mapping_mut().expect("checked by parse_document");
    let mut entry = Mapping::new();
    entry.insert("service".into(), spec.service.clone().into());
    entry.insert("network".into(), spec.network.clone().into());
    entry.insert("definition".into(), original.clone());
    let existing: Vec<Value> = root
        .get(ORIGINAL_KEY)
        .and_then(Value::as_mapping)
        .map(|ann| ann.values().cloned().collect())
        .unwrap_or_default();
    match existing.first() {
        // Another agent is already enrolled: the top level is no longer original, inherit the
        // recorded original state so that the last unenroll restores it.
        Some(first) => {
            for key in [
                "networks_key",
                "networks_null",
                "volumes_key",
                "volumes_null",
            ] {
                if let Some(v) = first.get(key) {
                    entry.insert(key.into(), v.clone());
                }
            }
        }
        None => {
            for top in ["networks", "volumes"] {
                let v = root.get(top);
                entry.insert(format!("{top}_key").into(), Value::Bool(v.is_some()));
                entry.insert(
                    format!("{top}_null").into(),
                    Value::Bool(v.is_some_and(Value::is_null)),
                );
            }
        }
    }
    let same_net = existing
        .iter()
        .find(|e| e.get("network").and_then(Value::as_str) == Some(spec.network.as_str()));
    match same_net {
        Some(other) => {
            if let Some(v) = other.get("network_declaration") {
                entry.insert("network_declaration".into(), v.clone());
            }
        }
        None => {
            if let Some(decl) = root
                .get("networks")
                .and_then(|n| n.get(spec.network.as_str()))
            {
                entry.insert("network_declaration".into(), decl.clone());
            }
        }
    }

    // --- services: holder inserted right before the agent.
    let services = root
        .get_mut("services")
        .and_then(Value::as_mapping_mut)
        .expect("checked above");
    let mut rebuilt = Mapping::new();
    for (k, v) in std::mem::take(services) {
        if k.as_str() == Some(spec.service.as_str()) {
            rebuilt.insert(net_name.clone().into(), Value::Mapping(holder.clone()));
            rebuilt.insert(k, Value::Mapping(agent_svc.clone()));
        } else {
            rebuilt.insert(k, v);
        }
    }
    *services = rebuilt;

    // --- top level: gateway network (external) and CA volume.
    top_map(root, "networks")?.insert(spec.network.clone().into(), map([("external", true)]));
    top_map(root, "volumes")?.insert(volume.into(), Value::Mapping(Mapping::new()));

    let ann = root
        .entry(ORIGINAL_KEY.into())
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    let ann = ann.as_mapping_mut().ok_or_else(|| {
        EnrollError::BrokenAnnotation(agent.into(), format!("`{ORIGINAL_KEY}` is not a mapping"))
    })?;
    ann.insert(agent.into(), Value::Mapping(entry));

    Ok(EnrollOutcome {
        yaml: serde_yaml::to_string(&doc)?,
        warnings,
    })
}

/// Undo [`enroll_compose`] for `agent_name`: the original service definition and top-level
/// declarations are restored, the holder, its volume and the annotation are removed.
pub fn unenroll_compose(yaml: &str, agent_name: &str) -> Result<String, EnrollError> {
    let mut doc = parse_document(yaml)?;
    let root = doc.as_mapping_mut().expect("checked by parse_document");
    let broken = |why: &str| EnrollError::BrokenAnnotation(agent_name.into(), why.into());

    let entry = root
        .get(ORIGINAL_KEY)
        .and_then(Value::as_mapping)
        .and_then(|ann| ann.get(agent_name))
        .cloned()
        .ok_or_else(|| EnrollError::NotEnrolled(agent_name.into()))?;
    let entry = entry
        .as_mapping()
        .ok_or_else(|| broken("entry is not a mapping"))?;
    let text = |k: &str| {
        entry
            .get(k)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| broken(&format!("missing `{k}`")))
    };
    let flag = |k: &str| {
        entry
            .get(k)
            .and_then(Value::as_bool)
            .ok_or_else(|| broken(&format!("missing `{k}`")))
    };
    let service = text("service")?;
    let network = text("network")?;
    let definition = entry
        .get("definition")
        .filter(|d| d.is_mapping())
        .ok_or_else(|| broken("missing `definition`"))?
        .clone();
    let (networks_key, networks_null) = (flag("networks_key")?, flag("networks_null")?);
    let (volumes_key, volumes_null) = (flag("volumes_key")?, flag("volumes_null")?);
    let declaration = entry.get("network_declaration").cloned();

    // --- services.
    let services = root
        .get_mut("services")
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| EnrollError::ServiceNotFound(service.clone()))?;
    if !services.contains_key(service.as_str()) {
        return Err(EnrollError::ServiceNotFound(service));
    }
    services.insert(service.into(), definition);
    services.shift_remove(crate::spec::net_service_name(agent_name).as_str());

    // --- annotation.
    let ann = root
        .get_mut(ORIGINAL_KEY)
        .and_then(Value::as_mapping_mut)
        .expect("read above");
    ann.shift_remove(agent_name);
    let still_used = ann
        .values()
        .any(|e| e.get("network").and_then(Value::as_str) == Some(network.as_str()));
    if ann.is_empty() {
        root.shift_remove(ORIGINAL_KEY);
    }

    // --- network declaration, restored by the last agent using it; CA volume.
    if let Some(Value::Mapping(nets)) = root.get_mut("networks")
        && !still_used
    {
        match declaration {
            Some(decl) => {
                nets.insert(network.into(), decl);
            }
            None => {
                nets.shift_remove(network.as_str());
            }
        }
    }
    if let Some(Value::Mapping(vols)) = root.get_mut("volumes") {
        vols.shift_remove(ca_volume_name(agent_name).as_str());
    }
    restore_top(root, "networks", networks_key, networks_null);
    restore_top(root, "volumes", volumes_key, volumes_null);

    Ok(serde_yaml::to_string(&doc)?)
}

fn restore_top(root: &mut Mapping, key: &str, had_key: bool, was_null: bool) {
    let empty = matches!(root.get(key), Some(Value::Mapping(m)) if m.is_empty());
    if !empty {
        return;
    }
    if !had_key {
        root.shift_remove(key);
    } else if was_null {
        root.insert(key.into(), Value::Null);
    }
}

fn top_map<'a>(root: &'a mut Mapping, key: &str) -> Result<&'a mut Mapping, EnrollError> {
    let slot = root
        .entry(key.into())
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    if slot.is_null() {
        *slot = Value::Mapping(Mapping::new());
    }
    slot.as_mapping_mut()
        .ok_or_else(|| EnrollError::InvalidYaml(format!("top-level `{key}` is not a mapping")))
}

fn parse_document(yaml: &str) -> Result<Value, EnrollError> {
    let mut doc: Value = serde_yaml::from_str(yaml)?;
    if !doc.is_mapping() {
        return Err(EnrollError::InvalidYaml(
            "a compose file must be a mapping".into(),
        ));
    }
    doc.apply_merge()?;
    Ok(doc)
}

/// Non-blocking findings ([Killian]: privileged containers are reported, not refused).
fn audit_service(name: &str, svc: &Mapping) -> Vec<EnrollWarning> {
    let service = || name.to_string();
    let mut out = Vec::new();
    if svc.get("privileged").and_then(Value::as_bool) == Some(true) {
        out.push(EnrollWarning::Privileged { service: service() });
    }
    if let Some(Value::Sequence(caps)) = svc.get("cap_add") {
        for cap in caps.iter().filter_map(Value::as_str) {
            if is_dangerous_cap(cap) {
                out.push(EnrollWarning::DangerousCapability {
                    service: service(),
                    capability: cap.into(),
                });
            }
        }
    }
    if let Some(Value::Sequence(vols)) = svc.get("volumes") {
        for v in vols {
            let source = match v {
                Value::String(s) => s.split(':').next().map(str::to_string),
                Value::Mapping(m) => m.get("source").and_then(Value::as_str).map(str::to_string),
                _ => None,
            };
            if let Some(src) = source.filter(|s| is_runtime_socket(s)) {
                out.push(EnrollWarning::RuntimeSocket {
                    service: service(),
                    mount: src,
                });
            }
        }
    }
    for ns in ["pid", "ipc", "uts", "userns_mode", "cgroup"] {
        let Some(mode) = svc.get(ns).and_then(Value::as_str) else {
            continue;
        };
        let namespace = ns.trim_end_matches("_mode").to_string();
        if mode == "host" {
            out.push(EnrollWarning::HostNamespace {
                service: service(),
                namespace,
            });
        } else if mode.starts_with("service:") || mode.starts_with("container:") {
            out.push(EnrollWarning::SharedNamespace {
                service: service(),
                namespace,
                with: mode.into(),
            });
        }
    }
    if let Some(Value::Sequence(froms)) = svc.get("volumes_from") {
        for f in froms.iter().filter_map(Value::as_str) {
            out.push(EnrollWarning::VolumesFrom {
                service: service(),
                from: f.into(),
            });
        }
    }
    out
}

/// Docker refuses `net.*` sysctls on a container that joins another network namespace.
fn remove_net_sysctls(svc: &mut Mapping) -> Vec<String> {
    let mut removed = Vec::new();
    match svc.get_mut("sysctls") {
        Some(Value::Mapping(m)) => {
            let keys: Vec<Value> = m
                .keys()
                .filter(|k| k.as_str().is_some_and(|s| s.starts_with("net.")))
                .cloned()
                .collect();
            for k in keys {
                removed.push(k.as_str().unwrap_or_default().to_string());
                m.shift_remove(&k);
            }
        }
        Some(Value::Sequence(list)) => list.retain(|e| {
            let s = e.as_str().unwrap_or_default();
            let net = s.starts_with("net.");
            if net {
                removed.push(s.split('=').next().unwrap_or(s).to_string());
            }
            !net
        }),
        _ => {}
    }
    let empty = match svc.get("sysctls") {
        Some(Value::Mapping(m)) => m.is_empty(),
        Some(Value::Sequence(s)) => s.is_empty(),
        _ => false,
    };
    if empty && !removed.is_empty() {
        svc.shift_remove("sysctls");
    }
    removed
}

/// `NET_RAW` (granted by Docker by default) allows ARP/IP spoofing on the internal network.
fn drop_net_raw(svc: &mut Mapping) {
    let slot = svc
        .entry("cap_drop".into())
        .or_insert_with(|| Value::Sequence(Vec::new()));
    if !slot.is_sequence() {
        *slot = Value::Sequence(Vec::new());
    }
    let list = slot.as_sequence_mut().expect("just set");
    let covered = list.iter().filter_map(Value::as_str).any(|c| {
        let up = c.to_ascii_uppercase();
        matches!(up.strip_prefix("CAP_").unwrap_or(&up), "NET_RAW" | "ALL")
    });
    if !covered {
        list.push("NET_RAW".into());
    }
}

/// The agent starts once the holder is healthy (routes set, CA bundle built).
fn depend_on_healthy(svc: &mut Mapping, holder: &str) {
    let mut deps = Mapping::new();
    match svc.get("depends_on") {
        Some(Value::Sequence(list)) => {
            for d in list.iter().filter_map(Value::as_str) {
                deps.insert(d.into(), map([("condition", "service_started")]));
            }
        }
        Some(Value::Mapping(m)) => deps = m.clone(),
        _ => {}
    }
    deps.insert(holder.into(), map([("condition", "service_healthy")]));
    svc.insert("depends_on".into(), Value::Mapping(deps));
}

/// Set `KEY=value` pairs, keeping the existing form (list or mapping) and positions.
fn set_pairs(svc: &mut Mapping, key: &str, vars: &[(String, String)]) {
    let slot = svc
        .entry(key.into())
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    if slot.is_null() {
        *slot = Value::Mapping(Mapping::new());
    }
    match slot {
        Value::Sequence(list) => {
            for (k, v) in vars {
                let line = Value::String(format!("{k}={v}"));
                let pos = list.iter().position(|e| {
                    e.as_str()
                        .map(|s| s.split_once('=').map_or(s, |(n, _)| n) == k)
                        .unwrap_or(false)
                });
                match pos {
                    Some(i) => list[i] = line,
                    None => list.push(line),
                }
            }
        }
        Value::Mapping(m) => {
            for (k, v) in vars {
                m.insert(k.clone().into(), v.clone().into());
            }
        }
        other => {
            // Unknown shape: replace by a mapping (the original is kept in the annotation).
            let mut m = Mapping::new();
            for (k, v) in vars {
                m.insert(k.clone().into(), v.clone().into());
            }
            *other = Value::Mapping(m);
        }
    }
}

fn append_volumes(svc: &mut Mapping, mounts: &[String]) {
    let slot = svc
        .entry("volumes".into())
        .or_insert_with(|| Value::Sequence(Vec::new()));
    if !slot.is_sequence() {
        *slot = Value::Sequence(Vec::new());
    }
    let list = slot.as_sequence_mut().expect("just set");
    for m in mounts {
        list.push(m.clone().into());
    }
}

fn seq<I, S>(items: I) -> Value
where
    I: IntoIterator<Item = S>,
    S: Into<Value>,
{
    Value::Sequence(items.into_iter().map(Into::into).collect())
}

fn map<I, V>(items: I) -> Value
where
    I: IntoIterator<Item = (&'static str, V)>,
    V: Into<Value>,
{
    let mut m = Mapping::new();
    for (k, v) in items {
        m.insert(k.into(), v.into());
    }
    Value::Mapping(m)
}
