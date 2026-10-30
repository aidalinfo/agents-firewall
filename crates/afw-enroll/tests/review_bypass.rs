//! Bypass tests from the independent review of PR #6 (kept as regression tests).
use afw_enroll::{EnrollSpec, K8sSpec, enroll_compose, patch_pod_template, unenroll_compose};
use serde_yaml::Value;

fn spec() -> EnrollSpec {
    EnrollSpec {
        agent_name: "bot".into(),
        service: "bot".into(),
        gateway_ip: "10.80.0.2".parse().unwrap(),
        agent_ip: "10.80.0.11".parse().unwrap(),
        network: "afw-internal".into(),
        proxy_url: "http://10.80.0.2:3128".into(),
        ca_path_host: "/etc/afw/ca.crt".into(),
        hermes: None,
        netinit_image: "afw-netinit:local".into(),
    }
}

// 1. YAML merge key hides NET_ADMIN / privileged: no warning, and the key survives on the agent.
#[test]
fn merge_key_hides_net_admin() {
    let y = "x-common: &common\n  cap_add: [NET_ADMIN]\n  privileged: true\nservices:\n  bot:\n    <<: *common\n    image: bot\n";
    let out = enroll_compose(y, &spec()).unwrap();
    let doc: Value = serde_yaml::from_str(&out.yaml).unwrap();
    let agent = &doc["services"]["bot"];
    eprintln!(
        "agent after enroll: {}",
        serde_yaml::to_string(agent).unwrap()
    );
    assert!(
        !out.warnings.is_empty(),
        "NET_ADMIN/privileged via merge key not reported: {:?}",
        out.warnings
    );
}

// 2. Sidecar joining the agent namespace with NET_ADMIN is not audited.
#[test]
fn sidecar_in_agent_namespace_not_audited() {
    let y = "services:\n  bot:\n    image: bot\n  helper:\n    image: alpine\n    network_mode: service:bot\n    cap_add: [NET_ADMIN]\n";
    let out = enroll_compose(y, &spec()).unwrap();
    assert!(
        !out.warnings.is_empty(),
        "sidecar with NET_ADMIN sharing the agent netns: no warning"
    );
}

// 3. pid/ipc shared with another (unenrolled) service, /var/run mount: not reported.
#[test]
fn shared_ns_and_var_run_not_reported() {
    let y = "services:\n  bot:\n    image: bot\n    pid: service:helper\n    ipc: service:helper\n    volumes: ['/var/run:/host-run']\n  helper:\n    image: alpine\n";
    let out = enroll_compose(y, &spec()).unwrap();
    assert!(
        !out.warnings.is_empty(),
        "pid/ipc service: and /var/run mount: no warning"
    );
}

// 4. NET_RAW (Docker default) is not dropped on the agent.
#[test]
fn agent_keeps_net_raw() {
    let out = enroll_compose("services:\n  bot:\n    image: bot\n", &spec()).unwrap();
    let doc: Value = serde_yaml::from_str(&out.yaml).unwrap();
    assert!(
        doc["services"]["bot"]["cap_drop"].as_sequence().is_some(),
        "agent keeps default NET_RAW (ARP/IP spoofing on the internal network)"
    );
}

// 5. net.* sysctls stay on the agent (Docker refuses them with a shared netns).
#[test]
fn net_sysctls_stay_on_agent() {
    let y = "services:\n  bot:\n    image: bot\n    sysctls:\n      net.ipv4.ip_forward: 1\n";
    let out = enroll_compose(y, &spec()).unwrap();
    let doc: Value = serde_yaml::from_str(&out.yaml).unwrap();
    assert!(
        doc["services"]["bot"].get("sysctls").is_none(),
        "net.* sysctls left on the agent"
    );
}

// 6. Exactness: `networks:` (null) at top level.
#[test]
fn unenroll_null_networks() {
    let y = "services:\n  bot:\n    image: bot\nnetworks:\n";
    let out = enroll_compose(y, &spec()).unwrap();
    let back = unenroll_compose(&out.yaml, "bot").unwrap();
    let a: Value = serde_yaml::from_str(y).unwrap();
    let b: Value = serde_yaml::from_str(&back).unwrap();
    assert_eq!(a, b, "back:\n{back}");
}

// 7. K8s: hostPID / hostIPC / NET_ADMIN not reported.
#[test]
fn k8s_host_pid_not_reported() {
    let s = K8sSpec::new(
        "agents",
        "img",
        "10.96.0.53".parse().unwrap(),
        "https://c",
        "t",
    );
    let y = "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  hostPID: true\n  containers:\n  - name: a\n    image: a\n";
    let out = patch_pod_template(y, &s, "bot").unwrap();
    assert!(!out.warnings.is_empty(), "hostPID not reported");
}
