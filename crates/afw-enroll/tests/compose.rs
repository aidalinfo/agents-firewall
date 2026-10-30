//! Docker Compose enrollment: bypass tests first, then shape, snapshots and exact inverse.

use std::net::IpAddr;
use std::path::PathBuf;

use afw_enroll::{
    CA_CONTAINER_PATH, EnrollError, EnrollSpec, EnrollWarning, HermesSpec, ORIGINAL_KEY,
    enroll_compose, unenroll_compose,
};
use serde_yaml::Value;

fn fixture(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn spec(agent: &str, service: &str) -> EnrollSpec {
    EnrollSpec {
        agent_name: agent.into(),
        service: service.into(),
        gateway_ip: "10.80.0.2".parse().unwrap(),
        agent_ip: "10.80.0.11".parse().unwrap(),
        network: "afw-internal".into(),
        proxy_url: "http://10.80.0.2:3128".into(),
        ca_path_host: "/etc/afw/gateway-ca.crt".into(),
        hermes: None,
        netinit_image: "afw-netinit:local".into(),
    }
}

fn hermes_spec() -> EnrollSpec {
    EnrollSpec {
        hermes: Some(HermesSpec {
            console_url: "https://afw.example.org".into(),
            agent_token_env: "AFW_TOKEN_DANIEL".into(),
            plugin_dir_host: "/opt/afw/integrations/hermes".into(),
            plugin_dir_container: None,
        }),
        ..spec("daniel", "daniel-bot")
    }
}

fn parse(s: &str) -> Value {
    serde_yaml::from_str(s).unwrap()
}

fn service<'a>(doc: &'a Value, name: &str) -> &'a Value {
    &doc["services"][name]
}

fn env_of(svc: &Value) -> Vec<(String, String)> {
    match &svc["environment"] {
        Value::Mapping(m) => m
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().unwrap().to_string(),
                    v.as_str().map(str::to_string).unwrap_or_default(),
                )
            })
            .collect(),
        Value::Sequence(s) => s
            .iter()
            .map(|e| {
                let (k, v) = e.as_str().unwrap().split_once('=').unwrap();
                (k.to_string(), v.to_string())
            })
            .collect(),
        _ => vec![],
    }
}

fn env_get(svc: &Value, key: &str) -> Option<String> {
    let all: Vec<_> = env_of(svc).into_iter().filter(|(k, _)| k == key).collect();
    assert!(all.len() <= 1, "duplicate env {key}");
    all.into_iter().next().map(|(_, v)| v)
}

fn strings(v: &Value) -> Vec<String> {
    v.as_sequence()
        .map(|s| s.iter().map(|e| e.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------- bypass tests first

#[test]
fn host_network_is_refused() {
    let yaml = "services:\n  bot:\n    image: x\n    network_mode: host\n";
    let err = enroll_compose(yaml, &spec("bot", "bot")).unwrap_err();
    assert!(matches!(err, EnrollError::HostNetwork(ref s) if s == "bot"), "{err}");
    assert!(err.to_string().contains("network_mode: host"));
}

#[test]
fn foreign_network_mode_is_refused() {
    for mode in ["service:other", "container:abc", "none", "bridge"] {
        let yaml = format!("services:\n  bot:\n    image: x\n    network_mode: \"{mode}\"\n");
        let err = enroll_compose(&yaml, &spec("bot", "bot")).unwrap_err();
        assert!(
            matches!(err, EnrollError::UnsupportedNetworkMode { .. }),
            "{mode}: {err}"
        );
    }
}

#[test]
fn enrolled_agent_cannot_reach_network_except_through_netns_holder() {
    let out = enroll_compose(&fixture("hermes-bot.yml"), &hermes_spec()).unwrap();
    let doc = parse(&out.yaml);
    let agent = service(&doc, "daniel-bot");
    assert_eq!(agent["network_mode"].as_str(), Some("service:afw-net-daniel"));
    for k in [
        "networks", "ports", "dns", "dns_search", "dns_opt", "hostname", "links", "extra_hosts",
        "expose", "mac_address", "cap_add", "privileged",
    ] {
        assert!(agent.get(k).is_none(), "agent still has `{k}`");
    }
    // The holder alone has NET_ADMIN, the fixed IP, the gateway DNS and the published ports.
    let net = service(&doc, "afw-net-daniel");
    assert_eq!(strings(&net["cap_add"]), vec!["NET_ADMIN"]);
    assert_eq!(
        net["networks"]["afw-internal"]["ipv4_address"].as_str(),
        Some("10.80.0.11")
    );
    assert_eq!(net["networks"].as_mapping().unwrap().len(), 1, "only the internal network");
    assert_eq!(strings(&net["dns"]), vec!["10.80.0.2"]);
    assert_eq!(strings(&net["ports"]), vec!["8080:8080"]);
    assert_eq!(net["hostname"].as_str(), Some("daniel"));
    assert_eq!(net["restart"].as_str(), Some("unless-stopped"));
    assert_eq!(net["image"].as_str(), Some("afw-netinit:local"));
    let cmd = strings(&net["command"]).join(" ");
    assert!(cmd.contains("ip route replace default via 10.80.0.2"), "{cmd}");
    assert!(cmd.contains("sleep"), "{cmd}");
    assert_eq!(net["labels"]["afw.enrolled"].as_str(), Some("true"));
    assert_eq!(net["labels"]["afw.agent"].as_str(), Some("daniel"));
    // The gateway network is external (created with `internal: true` by the gateway deployment).
    assert_eq!(doc["networks"]["afw-internal"]["external"].as_bool(), Some(true));
}

#[test]
fn privileged_agent_is_enrolled_with_warning() {
    let yaml = "services:\n  bot:\n    image: x\n    privileged: true\n";
    let out = enroll_compose(yaml, &spec("bot", "bot")).unwrap();
    assert!(out.warnings.contains(&EnrollWarning::Privileged));
    // The flag is kept: [Killian] rejected refusing privileged containers.
    assert_eq!(parse(&out.yaml)["services"]["bot"]["privileged"].as_bool(), Some(true));
}

#[test]
fn net_admin_and_sys_admin_caps_are_reported() {
    let yaml =
        "services:\n  bot:\n    image: x\n    cap_add: [CHOWN, net_admin, CAP_SYS_ADMIN, ALL]\n";
    let out = enroll_compose(yaml, &spec("bot", "bot")).unwrap();
    let caps: Vec<_> = out
        .warnings
        .iter()
        .filter_map(|w| match w {
            EnrollWarning::DangerousCapability { capability } => Some(capability.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(caps, vec!["net_admin", "CAP_SYS_ADMIN", "ALL"]);
}

#[test]
fn docker_socket_mount_is_reported_short_and_long_syntax() {
    let yaml = r#"
services:
  bot:
    image: x
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - type: bind
        source: /run/docker.sock
        target: /sock
      - ./data:/data
"#;
    let out = enroll_compose(yaml, &spec("bot", "bot")).unwrap();
    let n = out
        .warnings
        .iter()
        .filter(|w| matches!(w, EnrollWarning::DockerSocket { .. }))
        .count();
    assert_eq!(n, 2, "{:?}", out.warnings);
}

#[test]
fn host_pid_is_reported() {
    let yaml = "services:\n  bot:\n    image: x\n    pid: host\n";
    let out = enroll_compose(yaml, &spec("bot", "bot")).unwrap();
    assert!(out.warnings.contains(&EnrollWarning::HostNamespace {
        namespace: "pid".into()
    }));
}

#[test]
fn enrolling_twice_is_a_clear_error() {
    let s = hermes_spec();
    let once = enroll_compose(&fixture("hermes-bot.yml"), &s).unwrap();
    let err = enroll_compose(&once.yaml, &s).unwrap_err();
    assert!(matches!(err, EnrollError::AlreadyEnrolled(ref a) if a == "daniel"), "{err}");
    assert!(err.to_string().contains("already enrolled"));
    // Same service under another agent name: still refused.
    let other = EnrollSpec {
        agent_name: "daniel2".into(),
        agent_ip: "10.80.0.12".parse().unwrap(),
        ..s
    };
    assert!(matches!(
        enroll_compose(&once.yaml, &other).unwrap_err(),
        EnrollError::AlreadyEnrolled(_)
    ));
}

#[test]
fn existing_service_name_collision_is_refused() {
    let yaml = "services:\n  afw-net-bot:\n    image: y\n  bot:\n    image: x\n";
    assert!(matches!(
        enroll_compose(yaml, &spec("bot", "bot")).unwrap_err(),
        EnrollError::AlreadyEnrolled(_)
    ));
}

#[test]
fn unknown_service_and_invalid_spec_are_errors() {
    let yaml = fixture("plain-agent.yml");
    assert!(matches!(
        enroll_compose(&yaml, &spec("x", "nope")).unwrap_err(),
        EnrollError::ServiceNotFound(_)
    ));
    for bad in ["", "Daniel", "-x", "a b", "a/b", &"a".repeat(64)] {
        assert!(
            matches!(
                enroll_compose(&yaml, &spec(bad, "laurent-bot")).unwrap_err(),
                EnrollError::InvalidSpec(_)
            ),
            "{bad:?}"
        );
    }
    let mut s = spec("laurent", "laurent-bot");
    s.agent_ip = "fd00::11".parse().unwrap();
    assert!(matches!(
        enroll_compose(&yaml, &s).unwrap_err(),
        EnrollError::InvalidSpec(_)
    ));
    assert!(matches!(
        enroll_compose("- a\n- b\n", &spec("x", "x")).unwrap_err(),
        EnrollError::InvalidYaml(_)
    ));
    assert!(matches!(
        enroll_compose("services: [", &spec("x", "x")).unwrap_err(),
        EnrollError::InvalidYaml(_)
    ));
}

// ---------------------------------------------------------------- shape

#[test]
fn proxy_and_ca_variables_are_set_and_override_existing_ones() {
    let out = enroll_compose(&fixture("hermes-bot.yml"), &hermes_spec()).unwrap();
    let doc = parse(&out.yaml);
    let agent = service(&doc, "daniel-bot");
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        assert_eq!(env_get(agent, k).as_deref(), Some("http://10.80.0.2:3128"), "{k}");
    }
    for k in [
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "NODE_EXTRA_CA_CERTS",
        "CURL_CA_BUNDLE",
    ] {
        assert_eq!(env_get(agent, k).as_deref(), Some(CA_CONTAINER_PATH), "{k}");
    }
    // Pre-existing variables are kept.
    assert_eq!(env_get(agent, "HERMES_HOME").as_deref(), Some("/opt/data"));
    let vols = strings(&agent["volumes"]);
    assert!(vols.contains(&format!("/etc/afw/gateway-ca.crt:{CA_CONTAINER_PATH}:ro")));
    assert!(vols.contains(&"./data/daniel:/opt/data".to_string()));
}

#[test]
fn map_environment_is_extended_as_a_map() {
    let out = enroll_compose(&fixture("plain-agent.yml"), &spec("laurent", "laurent-bot")).unwrap();
    let doc = parse(&out.yaml);
    let agent = service(&doc, "laurent-bot");
    assert!(agent["environment"].is_mapping());
    assert_eq!(env_get(agent, "LOG_LEVEL").as_deref(), Some("debug"));
    assert_eq!(env_get(agent, "HTTPS_PROXY").as_deref(), Some("http://10.80.0.2:3128"));
    assert!(env_get(agent, "AFW_AGENT_TOKEN").is_none(), "no Hermes vars for a plain agent");
    assert_eq!(env_get(agent, "NO_PROXY").as_deref(), Some("localhost,127.0.0.1,::1"));
    assert_eq!(agent["labels"]["team"].as_str(), Some("ops"));
    assert_eq!(agent["labels"]["afw.enrolled"].as_str(), Some("true"));
    assert!(out.warnings.is_empty());
    // No top-level networks before: one is created with only the external gateway network.
    assert_eq!(doc["networks"].as_mapping().unwrap().len(), 1);
}

#[test]
fn hermes_plugin_is_mounted_and_token_is_referenced_not_inlined() {
    let out = enroll_compose(&fixture("hermes-bot.yml"), &hermes_spec()).unwrap();
    let doc = parse(&out.yaml);
    let agent = service(&doc, "daniel-bot");
    assert_eq!(env_get(agent, "AFW_CONSOLE_URL").as_deref(), Some("https://afw.example.org"));
    assert_eq!(env_get(agent, "AFW_AGENT_TOKEN").as_deref(), Some("${AFW_TOKEN_DANIEL}"));
    assert_eq!(env_get(agent, "AFW_AGENT_NAME").as_deref(), Some("daniel"));
    // The plugin reaches the console without the explicit proxy (still routed via the gateway).
    for k in ["NO_PROXY", "no_proxy"] {
        assert_eq!(
            env_get(agent, k).as_deref(),
            Some("localhost,127.0.0.1,::1,afw.example.org"),
            "{k}"
        );
    }
    assert!(
        strings(&agent["volumes"])
            .contains(&"/opt/afw/integrations/hermes:/opt/data/plugins/agents-firewall:ro".into())
    );
}

#[test]
fn ipv6_agent_gets_ipv6_address() {
    let mut s = spec("laurent", "laurent-bot");
    s.gateway_ip = "fd00:80::2".parse().unwrap();
    s.agent_ip = "fd00:80::11".parse().unwrap();
    s.proxy_url = "http://[fd00:80::2]:3128".into();
    let out = enroll_compose(&fixture("plain-agent.yml"), &s).unwrap();
    let doc = parse(&out.yaml);
    let net = service(&doc, "afw-net-laurent");
    assert_eq!(
        net["networks"]["afw-internal"]["ipv6_address"].as_str(),
        Some("fd00:80::11")
    );
    assert!(strings(&net["command"]).join(" ").contains("ip -6 route replace default via fd00:80::2"));
}

#[test]
fn order_is_preserved_and_holder_is_inserted_before_agent() {
    let out = enroll_compose(&fixture("hermes-bot.yml"), &hermes_spec()).unwrap();
    let doc = parse(&out.yaml);
    let names: Vec<_> = doc["services"]
        .as_mapping()
        .unwrap()
        .keys()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["postgres", "afw-net-daniel", "daniel-bot"]);
    let top: Vec<_> = doc
        .as_mapping()
        .unwrap()
        .keys()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    assert_eq!(top, vec!["name", "services", "networks", "volumes", ORIGINAL_KEY]);
    // The agent keeps its key order (image first, restart second…).
    let agent_keys: Vec<_> = service(&doc, "daniel-bot")
        .as_mapping()
        .unwrap()
        .keys()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    assert_eq!(&agent_keys[..3], &["image", "restart", "environment"]);
}

#[test]
fn snapshots() {
    let cases: Vec<(&str, EnrollSpec)> = vec![
        ("hermes-bot", hermes_spec()),
        ("plain-agent", spec("laurent", "laurent-bot")),
        ("declared-network", spec("acme", "acme-bot")),
    ];
    let update = std::env::var_os("AFW_UPDATE_SNAPSHOTS").is_some();
    for (name, s) in cases {
        let out = enroll_compose(&fixture(&format!("{name}.yml")), &s).unwrap();
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("{name}.enrolled.yml"));
        if update {
            std::fs::write(&path, &out.yaml).unwrap();
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("missing snapshot {}", path.display()));
        assert_eq!(out.yaml, expected, "snapshot {name} differs");
    }
}

// ---------------------------------------------------------------- exact inverse

#[test]
fn unenroll_is_the_exact_inverse() {
    let cases: Vec<(&str, EnrollSpec)> = vec![
        ("hermes-bot", hermes_spec()),
        ("plain-agent", spec("laurent", "laurent-bot")),
        ("declared-network", spec("acme", "acme-bot")),
    ];
    for (name, s) in cases {
        let original = fixture(&format!("{name}.yml"));
        let enrolled = enroll_compose(&original, &s).unwrap().yaml;
        let restored = unenroll_compose(&enrolled, &s.agent_name).unwrap();
        assert_eq!(parse(&restored), parse(&original), "{name}");
    }
}

#[test]
fn two_agents_unenrolled_in_any_order_restore_the_original() {
    let original = r#"
services:
  a:
    image: x
    networks: [front]
  b:
    image: y
networks:
  front: {}
"#;
    let sa = spec("a", "a");
    let sb = EnrollSpec {
        agent_ip: "10.80.0.12".parse().unwrap(),
        ..spec("b", "b")
    };
    let both = enroll_compose(&enroll_compose(original, &sa).unwrap().yaml, &sb)
        .unwrap()
        .yaml;
    let doc = parse(&both);
    assert_eq!(doc["networks"]["afw-internal"]["external"].as_bool(), Some(true));
    for order in [["a", "b"], ["b", "a"]] {
        let step = unenroll_compose(&both, order[0]).unwrap();
        // The shared gateway network stays while one agent remains enrolled.
        assert_eq!(parse(&step)["networks"]["afw-internal"]["external"].as_bool(), Some(true));
        let back = unenroll_compose(&step, order[1]).unwrap();
        assert_eq!(parse(&back), parse(original), "{order:?}");
    }
}

#[test]
fn unenroll_errors() {
    let yaml = fixture("plain-agent.yml");
    assert!(matches!(
        unenroll_compose(&yaml, "laurent").unwrap_err(),
        EnrollError::NotEnrolled(_)
    ));
    let enrolled = enroll_compose(&yaml, &spec("laurent", "laurent-bot")).unwrap().yaml;
    let mut doc = parse(&enrolled);
    doc[ORIGINAL_KEY]["laurent"] = Value::String("garbage".into());
    let damaged = serde_yaml::to_string(&doc).unwrap();
    assert!(matches!(
        unenroll_compose(&damaged, "laurent").unwrap_err(),
        EnrollError::BrokenAnnotation(..)
    ));
}

#[test]
fn spec_ip_types_are_plain_ipaddr() {
    // Guard against accidental API changes of the public spec.
    let s = spec("a", "a");
    let _: IpAddr = s.gateway_ip;
    let _: IpAddr = s.agent_ip;
}
