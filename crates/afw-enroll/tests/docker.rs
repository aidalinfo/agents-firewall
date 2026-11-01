//! `docker run` enrollment (EF-63).

use afw_enroll::{EnrollSpec, HermesSpec, docker_run_args, netinit_command, netinit_run_args};

fn spec() -> EnrollSpec {
    EnrollSpec {
        agent_name: "solo".into(),
        service: "solo".into(),
        gateway_ip: "10.80.0.2".parse().unwrap(),
        agent_ip: "10.80.0.20".parse().unwrap(),
        network: "afw-internal".into(),
        proxy_url: "http://10.80.0.2:3128".into(),
        ca_path_host: "/etc/afw/ca.crt".into(),
        hermes: Some(HermesSpec {
            console_url: "https://afw.example.org".into(),
            agent_token_env: "SOLO_TOKEN".into(),
            plugin_dir_host: "/opt/afw/hermes".into(),
            plugin_dir_container: Some("/home/hermes/.hermes/plugins/afw".into()),
        }),
        netinit_image: "afw-netinit:local".into(),
    }
}

fn pairs(args: &[String], flag: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .collect()
}

#[test]
fn agent_joins_holder_namespace_without_capabilities() {
    let a = docker_run_args(&spec());
    assert_eq!(pairs(&a, "--network"), vec!["container:afw-net-solo"]);
    assert_eq!(pairs(&a, "--cap-drop"), vec!["NET_RAW"]);
    for forbidden in [
        "--cap-add",
        "--privileged",
        "-p",
        "--publish",
        "--dns",
        "--ip",
    ] {
        assert!(!a.iter().any(|x| x == forbidden), "{forbidden}");
    }
    let env = pairs(&a, "-e");
    assert!(env.contains(&"HTTPS_PROXY=http://10.80.0.2:3128".to_string()));
    assert!(env.contains(&"AFW_AGENT_NAME=solo".to_string()));
    // The token is inherited, never written on the command line.
    assert!(env.contains(&"AFW_AGENT_TOKEN".to_string()));
    assert!(!a.iter().any(|x| x.contains("SOLO_TOKEN")));
    let vols = pairs(&a, "-v");
    assert!(vols.contains(&"afw-ca-solo:/usr/local/share/ca-certificates/afw:ro".to_string()));
    assert!(!vols.iter().any(|v| v.starts_with("/etc/afw/ca.crt")));
    assert!(vols.contains(&"/opt/afw/hermes:/home/hermes/.hermes/plugins/afw:ro".to_string()));
}

#[test]
fn holder_has_net_admin_fixed_ip_and_gateway_dns() {
    let s = spec();
    let a = netinit_run_args(&s);
    assert_eq!(pairs(&a, "--name"), vec!["afw-net-solo"]);
    assert_eq!(pairs(&a, "--cap-drop"), vec!["ALL"]);
    assert_eq!(pairs(&a, "--cap-add"), vec!["NET_ADMIN"]);
    assert_eq!(
        pairs(&a, "--sysctl"),
        vec![
            "net.ipv4.conf.all.accept_redirects=0",
            "net.ipv4.conf.default.accept_redirects=0"
        ]
    );
    assert_eq!(
        pairs(&a, "-v"),
        vec![
            "/etc/afw/ca.crt:/afw-ca-src/gateway.crt:ro",
            "afw-ca-solo:/afw-ca"
        ]
    );
    assert!(pairs(&a, "--health-cmd")[0].contains("/tmp/afw-ready"));
    assert_eq!(pairs(&a, "--network"), vec!["afw-internal"]);
    assert_eq!(pairs(&a, "--ip"), vec!["10.80.0.20"]);
    assert_eq!(pairs(&a, "--dns"), vec!["10.80.0.2"]);
    assert_eq!(a.last().unwrap(), "afw-netinit:local");
    let cmd = netinit_command(&s);
    assert_eq!(&cmd[..2], &["sh", "-c"]);
    assert_eq!(cmd[2], afw_enroll::netinit_script(&s));
    assert!(
        cmd[2].contains("wait $!"),
        "no compose escaping outside compose"
    );
}
