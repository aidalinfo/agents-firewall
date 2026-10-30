//! Kubernetes enrollment (ADR 0003, Kubernetes section): one gateway per namespace, egress of
//! enrolled pods restricted by a `NetworkPolicy` to the gateway only, pod DNS pointed to the
//! gateway, proxy variables and the inspection CA mounted from a `ConfigMap`.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use serde_yaml::{Mapping, Value};

use crate::error::EnrollError;
use crate::spec::{
    CA_CONTAINER_PATH, EnrollOutcome, EnrollWarning, LABEL_AGENT, LABEL_ENROLLED, NO_PROXY,
    proxy_environment, validate_agent_name,
};

/// Name of the CA `ConfigMap` key and of the pod volume.
const CA_KEY: &str = "ca.crt";
const CA_VOLUME: &str = "afw-gateway-ca";

/// Per-namespace gateway parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct K8sSpec {
    /// Namespace of the agents (one gateway per namespace).
    pub namespace: String,
    /// Gateway name (Deployment, Service and prefix of the other objects), e.g. `afw-gateway`.
    pub gateway_name: String,
    /// Gateway image.
    pub gateway_image: String,
    /// Fixed `ClusterIP` of the gateway Service (pod DNS server, inside the service CIDR).
    pub gateway_cluster_ip: IpAddr,
    /// Console URL the gateway registers with.
    pub console_url: String,
    /// One-time gateway registration token (stored in a Secret).
    pub registration_token: String,
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
    /// Spec with the default ports, state size and cluster domain.
    pub fn new(
        namespace: impl Into<String>,
        gateway_image: impl Into<String>,
        gateway_cluster_ip: IpAddr,
        console_url: impl Into<String>,
        registration_token: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            gateway_name: "afw-gateway".into(),
            gateway_image: gateway_image.into(),
            gateway_cluster_ip,
            console_url: console_url.into(),
            registration_token: registration_token.into(),
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
            ("gateway_name", &self.gateway_name),
        ] {
            if !is_dns_label(v) {
                return Err(EnrollError::InvalidSpec(format!(
                    "{what} `{v}` is not a valid DNS-1123 label"
                )));
            }
        }
        if self.gateway_image.trim().is_empty() {
            return Err(EnrollError::InvalidSpec("gateway_image is empty".into()));
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

/// Manifests of the per-namespace gateway: Secret (registration token), ConfigMap (public CA),
/// PersistentVolumeClaim (state), Deployment, Service (fixed ClusterIP) and two
/// NetworkPolicies (egress of enrolled pods → gateway only; gateway ingress ← enrolled pods).
pub fn k8s_manifests(spec: &K8sSpec) -> Result<Vec<Value>, EnrollError> {
    spec.validate()?;
    let ns = &spec.namespace;
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
            "kind": "Secret",
            "metadata": { "name": format!("{name}-identity"), "namespace": ns, "labels": labels },
            "type": "Opaque",
            "stringData": { "registration-token": spec.registration_token },
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
            "metadata": { "name": format!("{name}-state"), "namespace": ns, "labels": labels },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": { "requests": { "storage": spec.state_size } },
            },
        }),
        json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": name, "namespace": ns, "labels": labels },
            "spec": {
                "replicas": 1,
                // The state volume is ReadWriteOnce and the CA key must stay unique.
                "strategy": { "type": "Recreate" },
                "selector": { "matchLabels": labels },
                "template": {
                    "metadata": { "labels": labels },
                    "spec": {
                        "automountServiceAccountToken": false,
                        "securityContext": { "runAsNonRoot": true, "runAsUser": 10001, "fsGroup": 10001 },
                        "containers": [{
                            "name": "gateway",
                            "image": spec.gateway_image,
                            "env": [
                                { "name": "AFW_MODE", "value": "kubernetes" },
                                { "name": "AFW_GATEWAY_NAME", "value": name },
                                { "name": "AFW_CONSOLE_URL", "value": spec.console_url },
                                { "name": "AFW_STATE_DIR", "value": "/var/lib/afw" },
                                { "name": "AFW_REGISTRATION_TOKEN", "valueFrom": { "secretKeyRef": {
                                    "name": format!("{name}-identity"), "key": "registration-token" } } },
                            ],
                            "ports": spec.gateway_ports().iter().map(|(n, proto, port)| json!({
                                "name": n, "containerPort": port, "protocol": proto })).chain(
                                std::iter::once(json!({ "name": "health", "containerPort": 9090, "protocol": "TCP" }))
                            ).collect::<Vec<_>>(),
                            "securityContext": {
                                "allowPrivilegeEscalation": false,
                                "readOnlyRootFilesystem": true,
                                "capabilities": { "drop": ["ALL"], "add": ["NET_BIND_SERVICE"] },
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
            "metadata": { "name": name, "namespace": ns, "labels": labels },
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
                    "to": [{ "podSelector": { "matchLabels": labels } }],
                    "ports": ports_np,
                }],
            },
        }),
        json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": { "name": format!("{name}-ingress"), "namespace": ns, "labels": labels },
            "spec": {
                "podSelector": { "matchLabels": labels },
                "policyTypes": ["Ingress"],
                "ingress": [{
                    "from": [{ "podSelector": { "matchLabels": { LABEL_ENROLLED: "true" } } }],
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
/// annotation `afw.agent`, DNS on the gateway, proxy variables and CA mounted in every
/// container. `hostNetwork: true` is refused (the NetworkPolicy does not apply to it).
pub fn patch_pod_template(
    workload_yaml: &str,
    spec: &K8sSpec,
    agent_name: &str,
) -> Result<EnrollOutcome, EnrollError> {
    spec.validate()?;
    validate_agent_name(agent_name)?;
    let mut doc: Value = serde_yaml::from_str(workload_yaml)?;
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
    if let Some(Value::Sequence(vols)) = pod.get("volumes") {
        for v in vols {
            if let Some(path) = v
                .get("hostPath")
                .and_then(|h| h.get("path"))
                .and_then(Value::as_str)
                .filter(|p| p.ends_with("docker.sock") || p.ends_with("containerd.sock"))
            {
                warnings.push(EnrollWarning::DockerSocket { mount: path.into() });
            }
        }
    }
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
    vols.retain(|v| v.get("name").and_then(Value::as_str) != Some(CA_VOLUME));
    vols.push(serde_yaml::to_value(json!({
        "name": CA_VOLUME,
        "configMap": { "name": format!("{}-ca", spec.gateway_name), "items": [{ "key": CA_KEY, "path": CA_KEY }] },
    }))?);

    let env = proxy_environment(&spec.proxy_url(), NO_PROXY, CA_CONTAINER_PATH);
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
            if c.get("securityContext")
                .and_then(|s| s.get("privileged"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                warnings.push(EnrollWarning::PodPrivileged { container: cname });
            }
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
            mounts.push(serde_yaml::to_value(json!({
                "name": CA_VOLUME, "mountPath": CA_CONTAINER_PATH, "subPath": CA_KEY, "readOnly": true,
            }))?);
        }
    }

    Ok(EnrollOutcome {
        yaml: serde_yaml::to_string(&doc)?,
        warnings,
    })
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
