//! Docker Compose enrollment and its exact inverse.
//!
//! The document is handled as a [`serde_yaml::Value`]: [`Mapping`] keeps insertion order, so
//! untouched keys keep their position. Comments and anchors are not preserved (serde_yaml
//! limitation, see ADR 0023).

use serde_yaml::{Mapping, Value};

use crate::error::EnrollError;
use crate::spec::{
    CA_CONTAINER_PATH, EnrollOutcome, EnrollSpec, EnrollWarning, LABEL_AGENT, LABEL_ENROLLED,
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

/// Enroll `spec.service` behind the gateway (ADR 0003).
///
/// Adds the `afw-net-<agent>` network-namespace holder, moves the agent into its namespace,
/// sets proxy and CA variables, mounts the CA (and the Hermes plugin if requested), declares
/// the gateway network as external and records the original state under [`ORIGINAL_KEY`] so
/// that [`unenroll_compose`] is an exact inverse.
pub fn enroll_compose(yaml: &str, spec: &EnrollSpec) -> Result<EnrollOutcome, EnrollError> {
    spec.validate()?;
    let mut doc = parse_document(yaml)?;
    let net_name = spec.net_service_name();
    let agent = spec.agent_name.as_str();

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

    let mut warnings = audit_service(svc);

    // --- network-namespace holder.
    let mut holder = Mapping::new();
    holder.insert("image".into(), spec.netinit_image.clone().into());
    holder.insert("restart".into(), "unless-stopped".into());
    holder.insert("cap_add".into(), seq(["NET_ADMIN"]));
    holder.insert(
        "environment".into(),
        map([("AFW_GATEWAY_IP", spec.gateway_ip.to_string())]),
    );
    holder.insert(
        "command".into(),
        // `$$` is the Compose escape of a literal `$` (no interpolation of `$!`).
        seq([
            "sh".to_string(),
            "-c".to_string(),
            route_script(spec.gateway_ip).replace('$', "$$"),
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
    for key in MOVED_TO_HOLDER {
        if let Some(v) = svc.get(*key) {
            holder.insert((*key).into(), v.clone());
        }
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
        warnings.push(EnrollWarning::LinksRemoved);
    }
    for key in MOVED_TO_HOLDER.iter().chain(DROPPED) {
        agent_svc.shift_remove(*key);
    }
    agent_svc.insert("network_mode".into(), format!("service:{net_name}").into());
    set_environment(&mut agent_svc, &spec.agent_environment());
    let mut mounts = vec![format!("{}:{CA_CONTAINER_PATH}:ro", spec.ca_path_host)];
    if let Some(h) = &spec.hermes {
        mounts.push(format!("{}:{}:ro", h.plugin_dir_host, h.container_dir()));
    }
    append_volumes(&mut agent_svc, &mounts);
    set_labels(
        &mut agent_svc,
        &[
            (LABEL_ENROLLED, "true".to_string()),
            (LABEL_AGENT, spec.agent_name.clone()),
        ],
    );

    // --- annotation (computed before touching top-level networks).
    let root = doc.as_mapping_mut().expect("checked by parse_document");
    let mut entry = Mapping::new();
    entry.insert("service".into(), spec.service.clone().into());
    entry.insert("network".into(), spec.network.clone().into());
    entry.insert("definition".into(), original.clone());
    let shared = root
        .get(ORIGINAL_KEY)
        .and_then(Value::as_mapping)
        .and_then(|ann| {
            ann.values()
                .find(|e| e.get("network").and_then(Value::as_str) == Some(spec.network.as_str()))
                .cloned()
        });
    match shared {
        // Another agent already uses this network: inherit the true original declaration.
        Some(other) => {
            for key in ["networks_key", "network_declaration"] {
                if let Some(v) = other.get(key) {
                    entry.insert(key.into(), v.clone());
                }
            }
        }
        None => {
            let top = root.get("networks");
            entry.insert("networks_key".into(), Value::Bool(top.is_some()));
            if let Some(decl) = top.and_then(|n| n.get(spec.network.as_str())) {
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

    // --- top-level network declared external.
    let networks = root
        .entry("networks".into())
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    if networks.is_null() {
        *networks = Value::Mapping(Mapping::new());
    }
    let networks = networks
        .as_mapping_mut()
        .ok_or_else(|| EnrollError::InvalidYaml("top-level `networks` is not a mapping".into()))?;
    networks.insert(spec.network.clone().into(), map([("external", true)]));

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

/// Undo [`enroll_compose`] for `agent_name`: the original service definition and network
/// declaration are restored, the holder and the annotation are removed.
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
    let service = entry
        .get("service")
        .and_then(Value::as_str)
        .ok_or_else(|| broken("missing `service`"))?
        .to_string();
    let network = entry
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| broken("missing `network`"))?
        .to_string();
    let definition = entry
        .get("definition")
        .filter(|d| d.is_mapping())
        .ok_or_else(|| broken("missing `definition`"))?
        .clone();
    let networks_key = entry
        .get("networks_key")
        .and_then(Value::as_bool)
        .ok_or_else(|| broken("missing `networks_key`"))?;
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

    // --- network declaration, restored by the last agent using it.
    if !still_used && let Some(Value::Mapping(nets)) = root.get_mut("networks") {
        match declaration {
            Some(decl) => {
                nets.insert(network.into(), decl);
            }
            None => {
                nets.shift_remove(network.as_str());
            }
        }
        if nets.is_empty() && !networks_key {
            root.shift_remove("networks");
        }
    }

    Ok(serde_yaml::to_string(&doc)?)
}

fn parse_document(yaml: &str) -> Result<Value, EnrollError> {
    let doc: Value = serde_yaml::from_str(yaml)?;
    if !doc.is_mapping() {
        return Err(EnrollError::InvalidYaml(
            "a compose file must be a mapping".into(),
        ));
    }
    Ok(doc)
}

/// Shell loop run by the holder: (re)sets the default route to the gateway every 10 s.
/// The internal network has no route of its own, so until this succeeds the agent has no
/// network at all (fail closed).
pub(crate) fn route_script(gateway_ip: std::net::IpAddr) -> String {
    let ip = if gateway_ip.is_ipv4() { "ip" } else { "ip -6" };
    format!(
        "trap 'exit 0' TERM INT; while :; do {ip} route replace default via {gw} || echo 'afw-net: cannot set the default route' >&2; sleep 10 & wait $!; done",
        gw = gateway_ip
    )
}

/// Non-blocking findings ([Killian]: privileged containers are reported, not refused).
fn audit_service(svc: &Mapping) -> Vec<EnrollWarning> {
    let mut out = Vec::new();
    if svc.get("privileged").and_then(Value::as_bool) == Some(true) {
        out.push(EnrollWarning::Privileged);
    }
    if let Some(Value::Sequence(caps)) = svc.get("cap_add") {
        for cap in caps.iter().filter_map(Value::as_str) {
            let norm = cap.to_ascii_uppercase();
            let norm = norm.strip_prefix("CAP_").unwrap_or(&norm);
            if matches!(norm, "NET_ADMIN" | "SYS_ADMIN" | "ALL") {
                out.push(EnrollWarning::DangerousCapability {
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
            if let Some(src) = source.filter(|s| s.ends_with("docker.sock")) {
                out.push(EnrollWarning::DockerSocket { mount: src });
            }
        }
    }
    for ns in ["pid", "ipc", "uts", "userns_mode"] {
        if svc.get(ns).and_then(Value::as_str) == Some("host") {
            out.push(EnrollWarning::HostNamespace {
                namespace: ns.trim_end_matches("_mode").into(),
            });
        }
    }
    out
}

/// Set `KEY=value` pairs, keeping the existing form (list or mapping) and positions.
fn set_environment(svc: &mut Mapping, vars: &[(String, String)]) {
    set_pairs(svc, "environment", vars);
}

fn set_labels(svc: &mut Mapping, labels: &[(&str, String)]) {
    let owned: Vec<(String, String)> = labels
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect();
    set_pairs(svc, "labels", &owned);
}

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
