//! Kubernetes manifests and pod template patching.

use afw_enroll::{
    CA_CONTAINER_PATH, EnrollError, EnrollWarning, K8sSpec, k8s_manifests, patch_pod_template,
};
use serde_yaml::Value;

fn spec() -> K8sSpec {
    K8sSpec::new(
        "agents",
        "afw-gateway:local",
        "10.96.80.10".parse().unwrap(),
        "https://afw.example.org",
        "reg-token-123",
    )
}

fn kind_of(v: &Value) -> &str {
    v["kind"].as_str().unwrap()
}

fn find<'a>(ms: &'a [Value], kind: &str, name: &str) -> &'a Value {
    ms.iter()
        .find(|m| kind_of(m) == kind && m["metadata"]["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("{kind}/{name} missing"))
}

const DEPLOYMENT: &str = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: acme-bot
  namespace: agents
spec:
  selector:
    matchLabels: { app: acme-bot }
  template:
    metadata:
      labels: { app: acme-bot }
    spec:
      initContainers:
        - name: init
          image: busybox
      containers:
        - name: bot
          image: alpine:3.20
          env:
            - name: HTTPS_PROXY
              value: http://old:8080
            - name: KEEP
              value: "1"
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          emptyDir: {}
"#;

// ---------------------------------------------------------------- bypass tests first

#[test]
fn network_policy_only_allows_the_gateway() {
    let ms = k8s_manifests(&spec()).unwrap();
    let np = find(&ms, "NetworkPolicy", "afw-gateway-enrolled-egress");
    assert_eq!(
        np["spec"]["podSelector"]["matchLabels"]["afw.enrolled"].as_str(),
        Some("true")
    );
    let types: Vec<_> = np["spec"]["policyTypes"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert_eq!(types, vec!["Egress"]);
    let rules = np["spec"]["egress"].as_sequence().unwrap();
    assert!(!rules.is_empty());
    for r in rules {
        let to = r["to"]
            .as_sequence()
            .expect("an egress rule without `to` allows everything");
        assert!(!to.is_empty(), "empty `to` allows everything");
        for peer in to {
            assert!(peer.get("ipBlock").is_none(), "no ipBlock");
            assert!(
                peer.get("namespaceSelector").is_none(),
                "no namespaceSelector"
            );
            assert_eq!(
                peer["podSelector"]["matchLabels"]["app.kubernetes.io/name"].as_str(),
                Some("afw-gateway")
            );
        }
        let ports = r["ports"].as_sequence().expect("ports are mandatory");
        let mut got: Vec<(String, u64)> = ports
            .iter()
            .map(|p| {
                (
                    p["protocol"].as_str().unwrap().to_string(),
                    p["port"].as_u64().unwrap(),
                )
            })
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("TCP".to_string(), 53),
                ("TCP".to_string(), 80),
                ("TCP".to_string(), 443),
                ("TCP".to_string(), 3128),
                ("TCP".to_string(), 15001),
                ("UDP".to_string(), 53),
            ]
        );
    }
}

#[test]
fn host_network_pod_is_refused() {
    let y = "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  hostNetwork: true\n  containers: [{name: c, image: x}]\n";
    assert!(matches!(
        patch_pod_template(y, &spec(), "p").unwrap_err(),
        EnrollError::HostNetwork(ref n) if n == "p"
    ));
}

#[test]
fn privileged_container_and_runtime_socket_are_reported() {
    let y = r#"
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: c
      image: x
      securityContext: {privileged: true}
  volumes:
    - name: sock
      hostPath: {path: /var/run/docker.sock}
"#;
    let out = patch_pod_template(y, &spec(), "p").unwrap();
    assert!(out.warnings.contains(&EnrollWarning::PodPrivileged {
        container: "c".into()
    }));
    assert!(out.warnings.contains(&EnrollWarning::DockerSocket {
        mount: "/var/run/docker.sock".into()
    }));
}

#[test]
fn patching_twice_is_refused() {
    let once = patch_pod_template(DEPLOYMENT, &spec(), "acme").unwrap();
    assert!(matches!(
        patch_pod_template(&once.yaml, &spec(), "acme").unwrap_err(),
        EnrollError::AlreadyEnrolled(_)
    ));
}

// ---------------------------------------------------------------- shape

#[test]
fn manifests_are_structurally_valid() {
    let ms = k8s_manifests(&spec()).unwrap();
    let kinds: Vec<_> = ms.iter().map(kind_of).collect();
    assert_eq!(
        kinds,
        vec![
            "Secret",
            "ConfigMap",
            "PersistentVolumeClaim",
            "Deployment",
            "Service",
            "NetworkPolicy",
            "NetworkPolicy"
        ]
    );
    for m in &ms {
        assert!(m["apiVersion"].as_str().is_some());
        assert_eq!(m["metadata"]["namespace"].as_str(), Some("agents"));
        assert!(m["metadata"]["name"].as_str().is_some());
    }
    let secret = find(&ms, "Secret", "afw-gateway-identity");
    assert_eq!(
        secret["stringData"]["registration-token"].as_str(),
        Some("reg-token-123")
    );
    let svc = find(&ms, "Service", "afw-gateway");
    assert_eq!(svc["spec"]["clusterIP"].as_str(), Some("10.96.80.10"));
    assert_eq!(svc["spec"]["type"].as_str(), Some("ClusterIP"));
    let dep = find(&ms, "Deployment", "afw-gateway");
    // Selector matches the template labels and the Service selector.
    assert_eq!(
        dep["spec"]["selector"]["matchLabels"],
        dep["spec"]["template"]["metadata"]["labels"]
    );
    assert_eq!(
        svc["spec"]["selector"],
        dep["spec"]["selector"]["matchLabels"]
    );
    // The gateway itself is never selected by the enrolled-egress policy.
    assert!(
        dep["spec"]["template"]["metadata"]["labels"]
            .get("afw.enrolled")
            .is_none()
    );
    let c = &dep["spec"]["template"]["spec"]["containers"][0];
    assert_eq!(
        c["securityContext"]["allowPrivilegeEscalation"].as_bool(),
        Some(false)
    );
    assert_eq!(
        c["env"][4]["valueFrom"]["secretKeyRef"]["name"].as_str(),
        Some("afw-gateway-identity")
    );
    let cm = find(&ms, "ConfigMap", "afw-gateway-ca");
    assert_eq!(
        cm["metadata"]["annotations"]["afw.ca-pending"].as_str(),
        Some("true")
    );
    // Every document serializes to YAML.
    for m in &ms {
        serde_yaml::to_string(m).unwrap();
    }
}

#[test]
fn ca_configmap_carries_the_public_ca_when_known() {
    let mut s = spec();
    s.ca_pem = Some("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n".into());
    let ms = k8s_manifests(&s).unwrap();
    let cm = find(&ms, "ConfigMap", "afw-gateway-ca");
    assert!(
        cm["data"]["ca.crt"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
    assert!(cm["metadata"].get("annotations").is_none());
    assert!(!serde_yaml::to_string(&ms).unwrap().contains("PRIVATE KEY"));
}

#[test]
fn invalid_spec_is_refused() {
    let mut s = spec();
    s.namespace = "Agents".into();
    assert!(matches!(
        k8s_manifests(&s).unwrap_err(),
        EnrollError::InvalidSpec(_)
    ));
    assert!(matches!(
        patch_pod_template(
            "apiVersion: v1\nkind: Service\nmetadata: {name: x}\n",
            &spec(),
            "x"
        )
        .unwrap_err(),
        EnrollError::InvalidSpec(_)
    ));
}

#[test]
fn pod_template_is_patched() {
    let out = patch_pod_template(DEPLOYMENT, &spec(), "acme").unwrap();
    assert!(out.warnings.is_empty());
    let doc: Value = serde_yaml::from_str(&out.yaml).unwrap();
    let t = &doc["spec"]["template"];
    assert_eq!(
        t["metadata"]["labels"]["afw.enrolled"].as_str(),
        Some("true")
    );
    assert_eq!(t["metadata"]["labels"]["app"].as_str(), Some("acme-bot"));
    assert_eq!(
        t["metadata"]["annotations"]["afw.agent"].as_str(),
        Some("acme")
    );
    // The Deployment selector is untouched (immutable field).
    assert_eq!(
        doc["spec"]["selector"]["matchLabels"]["app"].as_str(),
        Some("acme-bot")
    );
    let pod = &t["spec"];
    assert_eq!(pod["dnsPolicy"].as_str(), Some("None"));
    assert_eq!(
        pod["dnsConfig"]["nameservers"][0].as_str(),
        Some("10.96.80.10")
    );
    assert_eq!(
        pod["dnsConfig"]["searches"][0].as_str(),
        Some("agents.svc.cluster.local")
    );
    let vols = pod["volumes"].as_sequence().unwrap();
    assert_eq!(vols.len(), 2);
    assert_eq!(
        vols[1]["configMap"]["name"].as_str(),
        Some("afw-gateway-ca")
    );
    for list in ["initContainers", "containers"] {
        let c = &pod[list][0];
        let env = c["env"].as_sequence().unwrap();
        let get = |n: &str| {
            let hits: Vec<_> = env
                .iter()
                .filter(|e| e["name"].as_str() == Some(n))
                .collect();
            assert!(hits.len() <= 1, "duplicate {n}");
            hits.first()
                .and_then(|e| e["value"].as_str())
                .map(str::to_string)
        };
        assert_eq!(
            get("HTTPS_PROXY").as_deref(),
            Some("http://10.96.80.10:3128"),
            "{list}"
        );
        assert_eq!(
            get("http_proxy").as_deref(),
            Some("http://10.96.80.10:3128")
        );
        assert_eq!(get("SSL_CERT_FILE").as_deref(), Some(CA_CONTAINER_PATH));
        let mounts = c["volumeMounts"].as_sequence().unwrap();
        let ca = mounts
            .iter()
            .find(|m| m["name"].as_str() == Some("afw-gateway-ca"))
            .unwrap();
        assert_eq!(ca["mountPath"].as_str(), Some(CA_CONTAINER_PATH));
        assert_eq!(ca["subPath"].as_str(), Some("ca.crt"));
        assert_eq!(ca["readOnly"].as_bool(), Some(true));
    }
    assert_eq!(
        pod["containers"][0]["env"][1]["value"].as_str(),
        Some("1"),
        "KEEP preserved in place"
    );
}

#[test]
fn cronjob_and_pod_are_supported() {
    let cj = r#"
apiVersion: batch/v1
kind: CronJob
metadata: {name: nightly}
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers: [{name: job, image: x}]
"#;
    let out = patch_pod_template(cj, &spec(), "nightly").unwrap();
    let doc: Value = serde_yaml::from_str(&out.yaml).unwrap();
    let t = &doc["spec"]["jobTemplate"]["spec"]["template"];
    assert_eq!(
        t["metadata"]["labels"]["afw.enrolled"].as_str(),
        Some("true")
    );
    assert_eq!(t["spec"]["dnsPolicy"].as_str(), Some("None"));

    let pod = "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers: [{name: c, image: x}]\n";
    let out = patch_pod_template(pod, &spec(), "p").unwrap();
    let doc: Value = serde_yaml::from_str(&out.yaml).unwrap();
    assert_eq!(
        doc["metadata"]["labels"]["afw.enrolled"].as_str(),
        Some("true")
    );
    assert_eq!(doc["metadata"]["name"].as_str(), Some("p"));
}

#[test]
fn ipv6_cluster_ip_proxy_url_is_bracketed() {
    let mut s = spec();
    s.gateway_cluster_ip = "fd00:96::10".parse().unwrap();
    let out = patch_pod_template(DEPLOYMENT, &s, "acme").unwrap();
    assert!(out.yaml.contains("http://[fd00:96::10]:3128"));
}
