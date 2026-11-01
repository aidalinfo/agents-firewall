//! Kubernetes manifests, pod template patching and NetworkPolicy checks.

use afw_enroll::{
    CA_BUNDLE_PATH, CA_CERT_PATH, CA_DIR, EnrollError, EnrollWarning, K8sSpec,
    check_networkpolicies, k8s_manifests, patch_pod_template,
};
use serde_yaml::Value;

fn spec() -> K8sSpec {
    K8sSpec::new(
        "agents",
        "afw-gateway:local",
        "10.96.80.10".parse().unwrap(),
        "https://afw.example.org",
        "afw-registration",
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

fn y(s: &str) -> Value {
    serde_yaml::from_str(s).unwrap()
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
fn network_policy_only_allows_the_gateway_in_its_own_namespace() {
    let ms = k8s_manifests(&spec()).unwrap();
    let np = find(&ms, "NetworkPolicy", "afw-gateway-enrolled-egress");
    assert_eq!(np["metadata"]["namespace"].as_str(), Some("agents"));
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
    assert_eq!(rules.len(), 1);
    for r in rules {
        let to = r["to"]
            .as_sequence()
            .expect("an egress rule without `to` allows everything");
        assert!(!to.is_empty(), "empty `to` allows everything");
        for peer in to {
            assert!(peer.get("ipBlock").is_none(), "no ipBlock");
            // Namespace AND pod selector in the same peer: a pod of the agent namespace
            // labelled like the gateway is not a valid target.
            assert_eq!(
                peer["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"].as_str(),
                Some("afw-gw-agents")
            );
            assert_eq!(
                peer["podSelector"]["matchLabels"]["app.kubernetes.io/name"].as_str(),
                Some("afw-gateway")
            );
        }
        let mut got: Vec<(String, u64)> = r["ports"]
            .as_sequence()
            .expect("ports are mandatory")
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
    // Our own policies are never reported as broad.
    assert!(check_networkpolicies(&ms).is_empty());
}

#[test]
fn gateway_must_run_in_a_dedicated_namespace() {
    let mut s = spec();
    s.gateway_namespace = "agents".into();
    assert!(matches!(
        k8s_manifests(&s).unwrap_err(),
        EnrollError::InvalidSpec(_)
    ));
}

#[test]
fn host_network_pod_is_refused() {
    let p = "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  hostNetwork: true\n  containers: [{name: c, image: x}]\n";
    assert!(matches!(
        patch_pod_template(p, &spec(), "p").unwrap_err(),
        EnrollError::HostNetwork(ref n) if n == "p"
    ));
}

#[test]
fn privileged_host_namespaces_host_paths_and_caps_are_reported() {
    let p = r#"
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  hostPID: true
  hostIPC: true
  containers:
    - name: c
      image: x
      securityContext:
        privileged: true
        capabilities: {add: [SYS_MODULE]}
  volumes:
    - name: sock
      hostPath: {path: /var/run/docker.sock}
    - name: logs
      hostPath: {path: /var/log}
"#;
    let w = patch_pod_template(p, &spec(), "p").unwrap().warnings;
    for expected in [
        EnrollWarning::Privileged {
            service: "c".into(),
        },
        EnrollWarning::DangerousCapability {
            service: "c".into(),
            capability: "SYS_MODULE".into(),
        },
        EnrollWarning::HostNamespace {
            service: "p".into(),
            namespace: "pid".into(),
        },
        EnrollWarning::HostNamespace {
            service: "p".into(),
            namespace: "ipc".into(),
        },
        EnrollWarning::RuntimeSocket {
            service: "p".into(),
            mount: "/var/run/docker.sock".into(),
        },
        EnrollWarning::HostPath {
            service: "p".into(),
            path: "/var/log".into(),
        },
    ] {
        assert!(w.contains(&expected), "{expected:?} missing in {w:?}");
    }
}

#[test]
fn patching_twice_is_refused() {
    let once = patch_pod_template(DEPLOYMENT, &spec(), "acme").unwrap();
    assert!(matches!(
        patch_pod_template(&once.yaml, &spec(), "acme").unwrap_err(),
        EnrollError::AlreadyEnrolled(_)
    ));
}

#[test]
fn broad_existing_networkpolicies_are_reported() {
    let policies = vec![
        // allow-all egress for every pod of the namespace: additive, defeats the gateway.
        y(
            "kind: NetworkPolicy\nmetadata: {name: allow-all, namespace: agents}\nspec:\n  podSelector: {}\n  policyTypes: [Egress]\n  egress: [{}]\n",
        ),
        y(
            "kind: NetworkPolicy\nmetadata: {name: to-internet, namespace: agents}\nspec:\n  podSelector: {matchLabels: {app: acme}}\n  egress:\n  - to: [{ipBlock: {cidr: 0.0.0.0/0}}]\n",
        ),
        y(
            "kind: NetworkPolicy\nmetadata: {name: to-db, namespace: agents}\nspec:\n  podSelector: {}\n  policyTypes: [Egress]\n  egress:\n  - to: [{podSelector: {matchLabels: {app: db}}}]\n",
        ),
        // Not selecting enrolled pods: ignored.
        y(
            "kind: NetworkPolicy\nmetadata: {name: others, namespace: agents}\nspec:\n  podSelector: {matchExpressions: [{key: afw.enrolled, operator: DoesNotExist}]}\n  policyTypes: [Egress]\n  egress: [{}]\n",
        ),
        // Ingress only: ignored.
        y(
            "kind: NetworkPolicy\nmetadata: {name: ingress, namespace: agents}\nspec:\n  podSelector: {}\n  policyTypes: [Ingress]\n  ingress: [{}]\n",
        ),
        // Deny-all egress: never wider.
        y(
            "kind: NetworkPolicy\nmetadata: {name: deny, namespace: agents}\nspec:\n  podSelector: {}\n  policyTypes: [Egress]\n",
        ),
    ];
    let w = check_networkpolicies(&policies);
    let names: Vec<_> = w
        .iter()
        .map(|x| match x {
            EnrollWarning::BroadEgressPolicy { policy, .. } => policy.as_str(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        names,
        vec!["agents/allow-all", "agents/to-internet", "agents/to-db"]
    );
}

// ---------------------------------------------------------------- shape

#[test]
fn manifests_are_structurally_valid() {
    let ms = k8s_manifests(&spec()).unwrap();
    let kinds: Vec<_> = ms.iter().map(kind_of).collect();
    assert_eq!(
        kinds,
        vec![
            "Namespace",
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
        assert!(m["metadata"]["name"].as_str().is_some());
    }
    assert_eq!(
        find(&ms, "Namespace", "afw-gw-agents")["metadata"]["name"].as_str(),
        Some("afw-gw-agents")
    );
    // CA in the agent namespace (mounted by agents), the rest in the gateway namespace.
    assert_eq!(
        find(&ms, "ConfigMap", "afw-gateway-ca")["metadata"]["namespace"].as_str(),
        Some("agents")
    );
    for (k, n) in [
        ("PersistentVolumeClaim", "afw-gateway-state"),
        ("Deployment", "afw-gateway"),
        ("Service", "afw-gateway"),
        ("NetworkPolicy", "afw-gateway-ingress"),
    ] {
        assert_eq!(
            find(&ms, k, n)["metadata"]["namespace"].as_str(),
            Some("afw-gw-agents"),
            "{k}/{n}"
        );
    }
    // No Secret is generated: the registration token is never written in clear.
    assert!(!ms.iter().any(|m| kind_of(m) == "Secret"));
    let svc = find(&ms, "Service", "afw-gateway");
    assert_eq!(svc["spec"]["clusterIP"].as_str(), Some("10.96.80.10"));
    let dep = find(&ms, "Deployment", "afw-gateway");
    assert_eq!(
        dep["spec"]["selector"]["matchLabels"],
        dep["spec"]["template"]["metadata"]["labels"]
    );
    assert_eq!(
        svc["spec"]["selector"],
        dep["spec"]["selector"]["matchLabels"]
    );
    assert!(
        dep["spec"]["template"]["metadata"]["labels"]
            .get("afw.enrolled")
            .is_none()
    );
    let pod = &dep["spec"]["template"]["spec"];
    // Non-root gateway binding 53/80/443 through the sysctl, without any capability.
    assert_eq!(
        pod["securityContext"]["sysctls"][0]["name"].as_str(),
        Some("net.ipv4.ip_unprivileged_port_start")
    );
    assert_eq!(
        pod["securityContext"]["sysctls"][0]["value"].as_str(),
        Some("0")
    );
    let c = &pod["containers"][0];
    assert_eq!(
        c["securityContext"]["allowPrivilegeEscalation"].as_bool(),
        Some(false)
    );
    assert!(c["securityContext"]["capabilities"].get("add").is_none());
    let token = c["env"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|e| e["name"].as_str() == Some("AFW_REGISTRATION_TOKEN"))
        .unwrap();
    assert!(token.get("value").is_none());
    assert_eq!(
        token["valueFrom"]["secretKeyRef"]["name"].as_str(),
        Some("afw-registration")
    );
    assert_eq!(
        token["valueFrom"]["secretKeyRef"]["key"].as_str(),
        Some("registration-token")
    );
    let cm = find(&ms, "ConfigMap", "afw-gateway-ca");
    assert_eq!(
        cm["metadata"]["annotations"]["afw.ca-pending"].as_str(),
        Some("true")
    );
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
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
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
    assert_eq!(
        doc["spec"]["selector"]["matchLabels"]["app"].as_str(),
        Some("acme-bot")
    );
    let pod = &t["spec"];
    assert_eq!(pod["automountServiceAccountToken"].as_bool(), Some(false));
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
    assert_eq!(vols.len(), 3);
    assert_eq!(
        vols[1]["configMap"]["name"].as_str(),
        Some("afw-gateway-ca")
    );
    assert!(vols[2]["emptyDir"].is_mapping());
    // The bundle is built first, by an unprivileged init container.
    let init = &pod["initContainers"][0];
    assert_eq!(init["name"].as_str(), Some("afw-ca-bundle"));
    assert_eq!(init["image"].as_str(), Some("afw-netinit:local"));
    assert_eq!(
        init["securityContext"]["runAsNonRoot"].as_bool(),
        Some(true)
    );
    let script = init["command"][2].as_str().unwrap();
    assert!(script.contains("/etc/ssl/certs/ca-certificates.crt") && script.contains("bundle.pem"));
    for (list, idx) in [("initContainers", 1), ("containers", 0)] {
        let c = &pod[list][idx];
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
        assert_eq!(get("SSL_CERT_FILE").as_deref(), Some(CA_BUNDLE_PATH));
        assert_eq!(get("NODE_EXTRA_CA_CERTS").as_deref(), Some(CA_CERT_PATH));
        let mounts = c["volumeMounts"].as_sequence().unwrap();
        let ca = mounts
            .iter()
            .find(|m| m["name"].as_str() == Some("afw-ca"))
            .unwrap();
        assert_eq!(ca["mountPath"].as_str(), Some(CA_DIR));
        assert!(ca.get("subPath").is_none(), "directory mount, no subPath");
        assert_eq!(ca["readOnly"].as_bool(), Some(true));
        let drop: Vec<_> = c["securityContext"]["capabilities"]["drop"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|d| d.as_str().unwrap())
            .collect();
        assert_eq!(drop, vec!["NET_RAW"]);
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
