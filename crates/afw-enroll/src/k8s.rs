//! Kubernetes enrollment (ADR 0003, Kubernetes section; ADR 0023).
//!
//! One gateway per agent namespace, running in its own dedicated namespace (agents cannot
//! create a pod that impersonates it). Egress of enrolled pods is restricted by a
//! `NetworkPolicy` to the gateway pods only (namespace + pod selector), pod DNS points to the
//! gateway, proxy variables are set and a CA bundle (system roots + gateway CA) is built by an
//! init container into an `emptyDir` mounted read-only as a directory.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use serde_yaml::{Mapping, Value};

use crate::error::EnrollError;
use crate::netinit::k8s_bundle_script;
use crate::spec::{
    CA_DIR, DEFAULT_NETINIT_IMAGE, EnrollOutcome, EnrollWarning, LABEL_AGENT, LABEL_ENROLLED,
    NO_PROXY, is_dangerous_cap, is_runtime_socket, proxy_environment, validate_agent_name,
};

/// Key of the CA in the `ConfigMap`.
const CA_KEY: &str = "ca.crt";
/// Volume holding the `ConfigMap` (source of the bundle).
const CA_SRC_VOLUME: &str = "afw-gateway-ca";
/// `emptyDir` volume holding `gateway.crt` and `bundle.pem`.
const CA_VOLUME: &str = "afw-ca";
/// Init container building the bundle.
const CA_INIT: &str = "afw-ca-bundle";
const CA_SRC_MOUNT: &str = "/afw-ca-src";
const CA_BUILD_MOUNT: &str = "/afw-ca";
/// Namespace label set by Kubernetes on every namespace (1.21+).
const NS_NAME_LABEL: &str = "kubernetes.io/metadata.name";

/// Reference to a key of an existing Secret (never a secret value in clear).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretKeyRef {
    /// Secret name, in the gateway namespace.
    pub name: String,
    /// Key inside the Secret.
    pub key: String,
}

/// Gateway parameters for one agent namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct K8sSpec {
    /// Namespace of the agents.
    pub namespace: String,
    /// Dedicated namespace of the gateway (must differ from `namespace`).
    pub gateway_namespace: String,
    /// Gateway name (Deployment, Service and prefix of the other objects), e.g. `afw-gateway`.
    pub gateway_name: String,
    /// Gateway image.
    pub gateway_image: String,
    /// Image of the init container building the CA bundle (sh + system CA bundle).
    pub netinit_image: String,
    /// Fixed `ClusterIP` of the gateway Service (pod DNS server, inside the service CIDR).
    pub gateway_cluster_ip: IpAddr,
    /// Console URL the gateway registers with.
    pub console_url: String,
    /// Existing Secret (gateway namespace) holding the one-time registration token.
    pub registration_secret: SecretKeyRef,
    /// Public inspection CA (PEM) once known; `None` creates an empty ConfigMap to fill later.
    #[serde(default)]
    pub ca_pem: Option<String>,
    /// Explicit proxy port (default 3128).
    pub proxy_port: u16,
    /// Transparent listener port (default 15001).
    pub transparent_port: u16,
    /// Size of the gateway state volume (CA key, certificate, last policy), e.g. `1Gi`.
    pub state_size: String,
    /// Cluster DNS domain (default `cluster.local`).
    pub cluster_domain: String,
}

impl K8sSpec {
    /// Spec with defaults: gateway namespace `afw-gw-<namespace>`, ports 3128/15001, `1Gi`
    /// state, `cluster.local`, Secret key `registration-token`.
    pub fn new(
        namespace: impl Into<String>,
        gateway_image: impl Into<String>,
        gateway_cluster_ip: IpAddr,
        console_url: impl Into<String>,
        registration_secret_name: impl Into<String>,
    ) -> Self {
        let namespace = namespace.into();
        Self {
            gateway_namespace: format!("afw-gw-{namespace}"),
            namespace,
            gateway_name: "afw-gateway".into(),
            gateway_image: gateway_image.into(),
            netinit_image: DEFAULT_NETINIT_IMAGE.into(),
            gateway_cluster_ip,
            console_url: console_url.into(),
            registration_secret: SecretKeyRef {
                name: registration_secret_name.into(),
                key: "registration-token".into(),
            },
            ca_pem: None,
            proxy_port: 3128,
            transparent_port: 15001,
            state_size: "1Gi".into(),
            cluster_domain: "cluster.local".into(),
        }
    }

    fn validate(&self) -> Result<(), EnrollError> {
        for (what, v) in [
            ("namespace", &self.namespace),
            ("gateway_namespace", &self.gateway_namespace),
            ("gateway_name", &self.gateway_name),
        ] {
            if !is_dns_label(v) {
                return Err(EnrollError::InvalidSpec(format!(
                    "{what} `{v}` is not a valid DNS-1123 label"
                )));
            }
        }
        if self.gateway_namespace == self.namespace {
            return Err(EnrollError::InvalidSpec(
                "the gateway must run in a dedicated namespace, distinct from the agents".into(),
            ));
        }
        for (what, v) in [
            ("gateway_image", &self.gateway_image),
            ("netinit_image", &self.netinit_image),
            ("registration_secret.name", &self.registration_secret.name),
            ("registration_secret.key", &self.registration_secret.key),
        ] {
            if v.trim().is_empty() {
                return Err(EnrollError::InvalidSpec(format!("{what} is empty")));
            }
        }
        if self.proxy_port == 0 || self.transparent_port == 0 {
            return Err(EnrollError::InvalidSpec("ports must be non-zero".into()));
        }
        Ok(())
    }

    fn proxy_url(&self) -> String {
        match self.gateway_cluster_ip {
            IpAddr::V4(ip) => format!("http://{ip}:{}", self.proxy_port),
            IpAddr::V6(ip) => format!("http://[{ip}]:{}", self.proxy_port),
        }
    }

    fn selector(&self) -> Json {
        json!({
            "app.kubernetes.io/name": "afw-gateway",
            "app.kubernetes.io/instance": self.gateway_name,
        })
    }

    /// Ports the enrolled pods may reach on the gateway (and nothing else).
    fn gateway_ports(&self) -> Vec<(&'static str, &'static str, u16)> {
        vec![
            ("proxy", "TCP", self.proxy_port),
            ("transparent", "TCP", self.transparent_port),
            ("http", "TCP", 80),
            ("https", "TCP", 443),
            ("dns-udp", "UDP", 53),
            ("dns-tcp", "TCP", 53),
        ]
    }
}

/// Manifests: Namespace of the gateway, ConfigMap (public CA, agent namespace),
/// PersistentVolumeClaim (state), Deployment, Service (fixed ClusterIP), NetworkPolicy
/// (egress of enrolled pods → gateway pods only, agent namespace) and NetworkPolicy (gateway
/// ingress ← enrolled pods only). The registration token is read from an existing Secret.
pub fn k8s_manifests(spec: &K8sSpec) -> Result<Vec<Value>, EnrollError> {
    spec.validate()?;
    let ns = &spec.namespace;
    let gw_ns = &spec.gateway_namespace;
    let name = &spec.gateway_name;
    let labels = spec.selector();
    let ports_np: Vec<Json> = spec
        .gateway_ports()
        .iter()
        .map(|(_, proto, port)| json!({ "protocol": proto, "port": port }))
        .collect();
    let mut cm_meta = json!({ "name": format!("{name}-ca"), "namespace": ns, "labels": labels });
    if spec.ca_pem.is_none() {
        cm_meta["annotations"] = json!({ "afw.ca-pending": "true" });
    }

    let manifests = vec![
        json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": gw_ns, "labels": { "app.kubernetes.io/part-of": "agents-firewall" } },
        }),
        json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": cm_meta,
            "data": { CA_KEY: spec.ca_pem.clone().unwrap_or_default() },
        }),
        json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": { "name": format!("{name}-state"), "namespace": gw_ns, "labels": labels },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": { "requests": { "storage": spec.state_size } },
            },
        }),
        json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": name, "namespace": gw_ns, "labels": labels },
            "spec": {
                "replicas": 1,
                // The state volume is ReadWriteOnce and the CA key must stay unique.
                "strategy": { "type": "Recreate" },
                "selector": { "matchLabels": labels },
                "template": {
                    "metadata": { "labels": labels },
                    "spec": {
                        "automountServiceAccountToken": false,
                        "securityContext": {
                            "runAsNonRoot": true, "runAsUser": 10001, "fsGroup": 10001,
                            // Non-root process listening on 53/80/443 without any capability.
                            "sysctls": [{ "name": "net.ipv4.ip_unprivileged_port_start", "value": "0" }],
                        },
                        "containers": [{
                            "name": "gateway",
                            "image": spec.gateway_image,
                            "env": [
                                { "name": "AFW_MODE", "value": "kubernetes" },
                                { "name": "AFW_GATEWAY_NAME", "value": name },
                                { "name": "AFW_CONSOLE_URL", "value": spec.console_url },
                                { "name": "AFW_STATE_DIR", "value": "/var/lib/afw" },
                                { "name": "AFW_REGISTRATION_TOKEN", "valueFrom": { "secretKeyRef": {
                                    "name": spec.registration_secret.name,
                                    "key": spec.registration_secret.key } } },
                            ],
                            "ports": spec.gateway_ports().iter().map(|(n, proto, port)| json!({
                                "name": n, "containerPort": port, "protocol": proto })).chain(
                                std::iter::once(json!({ "name": "health", "containerPort": 9090, "protocol": "TCP" }))
                            ).collect::<Vec<_>>(),
                            "securityContext": {
                                "allowPrivilegeEscalation": false,
                                "readOnlyRootFilesystem": true,
                                "capabilities": { "drop": ["ALL"] },
                            },
                            "readinessProbe": { "tcpSocket": { "port": 9090 }, "periodSeconds": 5 },
                            "livenessProbe": { "tcpSocket": { "port": 9090 }, "periodSeconds": 10 },
                            "volumeMounts": [{ "name": "state", "mountPath": "/var/lib/afw" }],
                        }],
                        "volumes": [{ "name": "state", "persistentVolumeClaim": { "claimName": format!("{name}-state") } }],
                    },
                },
            },
        }),
        json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": name, "namespace": gw_ns, "labels": labels },
            "spec": {
                "type": "ClusterIP",
                "clusterIP": spec.gateway_cluster_ip.to_string(),
                "selector": labels,
                "ports": spec.gateway_ports().iter().map(|(n, proto, port)| json!({
                    "name": n, "port": port, "targetPort": port, "protocol": proto })).collect::<Vec<_>>(),
            },
        }),
        json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": { "name": format!("{name}-enrolled-egress"), "namespace": ns, "labels": labels },
            "spec": {
                "podSelector": { "matchLabels": { LABEL_ENROLLED: "true" } },
                "policyTypes": ["Egress"],
                "egress": [{
                    // Same peer element: namespace AND pod selector.
                    "to": [{
                        "namespaceSelector": { "matchLabels": { NS_NAME_LABEL: gw_ns } },
                        "podSelector": { "matchLabels": labels },
                    }],
                    "ports": ports_np,
                }],
            },
        }),
        json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": { "name": format!("{name}-ingress"), "namespace": gw_ns, "labels": labels },
            "spec": {
                "podSelector": { "matchLabels": labels },
                "policyTypes": ["Ingress"],
                "ingress": [{
                    "from": [{
                        "namespaceSelector": { "matchLabels": { NS_NAME_LABEL: ns } },
                        "podSelector": { "matchLabels": { LABEL_ENROLLED: "true" } },
                    }],
                    "ports": ports_np,
                }],
            },
        }),
    ];
    manifests
        .into_iter()
        .map(|m| serde_yaml::to_value(m).map_err(EnrollError::from))
        .collect()
}

/// Enroll the pods of a workload (Deployment, StatefulSet, DaemonSet, ReplicaSet, Job,
/// CronJob or Pod): label `afw.enrolled=true` (selected by the egress NetworkPolicy),
/// annotation `afw.agent`, no service-account token, DNS on the gateway, proxy variables,
/// `NET_RAW` dropped, CA bundle built by an init container and mounted as a directory.
/// `hostNetwork: true` is refused (NetworkPolicies do not apply to it).
pub fn patch_pod_template(
    workload_yaml: &str,
    spec: &K8sSpec,
    agent_name: &str,
) -> Result<EnrollOutcome, EnrollError> {
    spec.validate()?;
    validate_agent_name(agent_name)?;
    let mut doc: Value = serde_yaml::from_str(workload_yaml)?;
    doc.apply_merge()?;
    let kind = doc
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| EnrollError::InvalidYaml("missing `kind`".into()))?
        .to_string();
    let workload_name = doc
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("workload")
        .to_string();
    let template: &mut Value = match kind.as_str() {
        "Pod" => &mut doc,
        "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet" | "Job" => doc
            .get_mut("spec")
            .and_then(|s| s.get_mut("template"))
            .ok_or_else(|| EnrollError::InvalidYaml("missing `spec.template`".into()))?,
        "CronJob" => doc
            .get_mut("spec")
            .and_then(|s| s.get_mut("jobTemplate"))
            .and_then(|s| s.get_mut("spec"))
            .and_then(|s| s.get_mut("template"))
            .ok_or_else(|| {
                EnrollError::InvalidYaml("missing `spec.jobTemplate.spec.template`".into())
            })?,
        other => {
            return Err(EnrollError::InvalidSpec(format!(
                "unsupported kind `{other}`"
            )));
        }
    };
    let tmpl = template
        .as_mapping_mut()
        .ok_or_else(|| EnrollError::InvalidYaml("pod template is not a mapping".into()))?;

    // --- metadata: label + annotation, idempotence.
    let meta = child_map(tmpl, "metadata")?;
    let labels = child_map(meta, "labels")?;
    if labels.contains_key(LABEL_ENROLLED) {
        return Err(EnrollError::AlreadyEnrolled(agent_name.into()));
    }
    labels.insert(LABEL_ENROLLED.into(), "true".into());
    child_map(meta, "annotations")?.insert(LABEL_AGENT.into(), agent_name.into());

    // --- pod spec.
    let pod = child_map(tmpl, "spec")?;
    if pod.get("hostNetwork").and_then(Value::as_bool) == Some(true) {
        return Err(EnrollError::HostNetwork(workload_name));
    }
    let mut warnings = Vec::new();
    for (key, ns) in [("hostPID", "pid"), ("hostIPC", "ipc")] {
        if pod.get(key).and_then(Value::as_bool) == Some(true) {
            warnings.push(EnrollWarning::HostNamespace {
                service: workload_name.clone(),
                namespace: ns.into(),
            });
        }
    }
    if let Some(Value::Sequence(vols)) = pod.get("volumes") {
        for v in vols {
            if let Some(path) = v
                .get("hostPath")
                .and_then(|h| h.get("path"))
                .and_then(Value::as_str)
            {
                warnings.push(EnrollWarning::HostPath {
                    service: workload_name.clone(),
                    path: path.into(),
                });
                if is_runtime_socket(path) {
                    warnings.push(EnrollWarning::RuntimeSocket {
                        service: workload_name.clone(),
                        mount: path.into(),
                    });
                }
            }
        }
    }
    pod.insert("automountServiceAccountToken".into(), Value::Bool(false));
    pod.insert("dnsPolicy".into(), "None".into());
    let d = &spec.cluster_domain;
    pod.insert(
        "dnsConfig".into(),
        serde_yaml::to_value(json!({
            "nameservers": [spec.gateway_cluster_ip.to_string()],
            "searches": [format!("{}.svc.{d}", spec.namespace), format!("svc.{d}"), d],
            "options": [{ "name": "ndots", "value": "5" }],
        }))?,
    );
    let vols = child_seq(pod, "volumes")?;
    vols.retain(|v| {
        !matches!(
            v.get("name").and_then(Value::as_str),
            Some(CA_SRC_VOLUME | CA_VOLUME)
        )
    });
    vols.push(serde_yaml::to_value(json!({
        "name": CA_SRC_VOLUME,
        "configMap": { "name": format!("{}-ca", spec.gateway_name) },
    }))?);
    vols.push(serde_yaml::to_value(
        json!({ "name": CA_VOLUME, "emptyDir": {} }),
    )?);

    let env = proxy_environment(&spec.proxy_url(), NO_PROXY);
    for list in ["initContainers", "containers"] {
        let Some(Value::Sequence(containers)) = pod.get_mut(list) else {
            continue;
        };
        for c in containers.iter_mut() {
            let c = c
                .as_mapping_mut()
                .ok_or_else(|| EnrollError::InvalidYaml("container is not a mapping".into()))?;
            let cname = c
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string();
            let sc = c.get("securityContext");
            if sc
                .and_then(|s| s.get("privileged"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                warnings.push(EnrollWarning::Privileged {
                    service: cname.clone(),
                });
            }
            if let Some(Value::Sequence(caps)) = sc
                .and_then(|s| s.get("capabilities"))
                .and_then(|c| c.get("add"))
            {
                for cap in caps.iter().filter_map(Value::as_str) {
                    if is_dangerous_cap(cap) {
                        warnings.push(EnrollWarning::DangerousCapability {
                            service: cname.clone(),
                            capability: cap.into(),
                        });
                    }
                }
            }
            drop_net_raw(c)?;
            let envs = child_seq(c, "env")?;
            for (k, v) in &env {
                let entry = serde_yaml::to_value(json!({ "name": k, "value": v }))?;
                match envs
                    .iter()
                    .position(|e| e.get("name").and_then(Value::as_str) == Some(k.as_str()))
                {
                    Some(i) => envs[i] = entry,
                    None => envs.push(entry),
                }
            }
            let mounts = child_seq(c, "volumeMounts")?;
            mounts.retain(|m| m.get("name").and_then(Value::as_str) != Some(CA_VOLUME));
            // A directory mount (no subPath): a refreshed bundle is visible without restart.
            mounts.push(serde_yaml::to_value(json!({
                "name": CA_VOLUME, "mountPath": CA_DIR, "readOnly": true,
            }))?);
        }
    }

    // --- init container building the bundle, first of all.
    let init = serde_yaml::to_value(json!({
        "name": CA_INIT,
        "image": spec.netinit_image,
        "command": ["sh", "-c", k8s_bundle_script(&format!("{CA_SRC_MOUNT}/{CA_KEY}"), CA_BUILD_MOUNT)],
        "securityContext": {
            "runAsNonRoot": true,
            "runAsUser": 65534,
            "allowPrivilegeEscalation": false,
            "readOnlyRootFilesystem": true,
            "capabilities": { "drop": ["ALL"] },
        },
        "volumeMounts": [
            { "name": CA_SRC_VOLUME, "mountPath": CA_SRC_MOUNT, "readOnly": true },
            { "name": CA_VOLUME, "mountPath": CA_BUILD_MOUNT },
        ],
    }))?;
    let inits = child_seq(pod, "initContainers")?;
    inits.retain(|c| c.get("name").and_then(Value::as_str) != Some(CA_INIT));
    inits.insert(0, init);

    Ok(EnrollOutcome {
        yaml: serde_yaml::to_string(&doc)?,
        warnings,
    })
}

/// Report existing NetworkPolicies that may select enrolled pods and allow egress elsewhere
/// than the gateway. NetworkPolicies are additive: one extra allow rule is enough to bypass
/// the gateway.
pub fn check_networkpolicies(existing: &[Value]) -> Vec<EnrollWarning> {
    let mut out = Vec::new();
    for np in existing {
        if np.get("kind").and_then(Value::as_str) != Some("NetworkPolicy") {
            continue;
        }
        let name = format!(
            "{}/{}",
            np["metadata"]["namespace"].as_str().unwrap_or("?"),
            np["metadata"]["name"].as_str().unwrap_or("?")
        );
        let spec = &np["spec"];
        if !may_select_enrolled(&spec["podSelector"]) {
            continue;
        }
        let egress_type = spec["policyTypes"]
            .as_sequence()
            .map(|t| t.iter().any(|x| x.as_str() == Some("Egress")))
            .unwrap_or_else(|| spec.get("egress").is_some());
        if !egress_type {
            continue;
        }
        let Some(rules) = spec["egress"].as_sequence() else {
            continue; // Egress with no rule = deny all, never wider.
        };
        for rule in rules {
            if let Some(reason) = broad_reason(rule) {
                out.push(EnrollWarning::BroadEgressPolicy {
                    policy: name.clone(),
                    reason,
                });
            }
        }
    }
    out
}

/// A pod selector may select enrolled pods unless it explicitly excludes `afw.enrolled=true`.
fn may_select_enrolled(sel: &Value) -> bool {
    if let Some(v) = sel["matchLabels"].get(LABEL_ENROLLED) {
        return v.as_str() == Some("true");
    }
    if let Some(exprs) = sel["matchExpressions"].as_sequence() {
        for e in exprs {
            if e["key"].as_str() != Some(LABEL_ENROLLED) {
                continue;
            }
            let values: Vec<&str> = e["values"]
                .as_sequence()
                .map(|v| v.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            match e["operator"].as_str() {
                Some("DoesNotExist") => return false,
                Some("NotIn") if values.contains(&"true") => return false,
                Some("In") if !values.contains(&"true") => return false,
                _ => {}
            }
        }
    }
    true
}

fn broad_reason(rule: &Value) -> Option<String> {
    let Some(peers) = rule.get("to").and_then(Value::as_sequence) else {
        return Some("an egress rule without `to` allows every destination".into());
    };
    if peers.is_empty() {
        return Some("an egress rule with an empty `to` allows every destination".into());
    }
    for p in peers {
        if let Some(cidr) = p["ipBlock"]["cidr"].as_str() {
            return Some(format!("ipBlock {cidr}"));
        }
        let gateway = p["podSelector"]["matchLabels"]["app.kubernetes.io/name"].as_str()
            == Some("afw-gateway");
        if !gateway {
            return Some(format!(
                "peer {} is not the gateway",
                serde_yaml::to_string(p)
                    .unwrap_or_default()
                    .trim()
                    .replace('\n', " ")
            ));
        }
    }
    None
}

/// `NET_RAW` allows spoofing on the pod network; dropped on every agent container.
fn drop_net_raw(c: &mut Mapping) -> Result<(), EnrollError> {
    let sc = child_map(c, "securityContext")?;
    let caps = child_map(sc, "capabilities")?;
    let drop = child_seq(caps, "drop")?;
    let covered = drop.iter().filter_map(Value::as_str).any(|d| {
        matches!(
            d.to_ascii_uppercase().as_str(),
            "NET_RAW" | "ALL" | "CAP_NET_RAW"
        )
    });
    if !covered {
        drop.push("NET_RAW".into());
    }
    Ok(())
}

fn child_map<'a>(m: &'a mut Mapping, key: &str) -> Result<&'a mut Mapping, EnrollError> {
    let slot = m
        .entry(key.into())
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    if slot.is_null() {
        *slot = Value::Mapping(Mapping::new());
    }
    slot.as_mapping_mut()
        .ok_or_else(|| EnrollError::InvalidYaml(format!("`{key}` is not a mapping")))
}

fn child_seq<'a>(m: &'a mut Mapping, key: &str) -> Result<&'a mut Vec<Value>, EnrollError> {
    let slot = m
        .entry(key.into())
        .or_insert_with(|| Value::Sequence(Vec::new()));
    if slot.is_null() {
        *slot = Value::Sequence(Vec::new());
    }
    slot.as_sequence_mut()
        .ok_or_else(|| EnrollError::InvalidYaml(format!("`{key}` is not a list")))
}

fn is_dns_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}
