//! `afw-demo-enroll compose <agents.base.yml>`: enrolls the demo agents with `afw_enroll::enroll_compose`
//! and prints the Compose overlay used by the demo (demo/docker-compose.agents.yml).
//! `afw-demo-enroll netinit`: prints `afw_enroll::netinit_script` for the demo spec of laurent-bot.
//! `afw-demo-enroll enroll <file|-> <agent> <agent-ip> <gateway-ip> <network> <ca-path> <ingress-network>
//! <ingress-gateway-ip>`, `unenroll <file> <agent>` and `normalize <file>`: plain `enroll_compose` /
//! `unenroll_compose` / YAML round trip, for the integration tests (deploy/tests/ingress.sh).

use std::net::IpAddr;

use afw_enroll::{
    EnrollSpec, HOLDER_CA_SRC, HermesSpec, IngressSpec, enroll_compose, netinit_script,
    unenroll_compose,
};
use serde_yaml::Value;

const GATEWAY: &str = "10.77.0.2";
/// In the demo the gateway CA comes from the gateway's public volume, not from a host file.
const CA_VOLUME: &str = "gateway-public";

fn spec(agent: &str, ip: &str, hermes: bool) -> EnrollSpec {
    EnrollSpec {
        agent_name: agent.into(),
        service: agent.into(),
        gateway_ip: GATEWAY.parse::<IpAddr>().unwrap(),
        agent_ip: ip.parse().unwrap(),
        network: "afw-internal".into(),
        proxy_url: format!("http://{GATEWAY}:3128"),
        ca_path_host: format!("/__afw_demo_ca__/{agent}"),
        hermes: hermes.then(|| HermesSpec {
            console_url: "http://10.76.0.10:8080".into(),
            agent_token_env: "AFW_DEMO_DANIEL_TOKEN".into(),
            plugin_dir_host: "../integrations/hermes".into(),
            plugin_dir_container: None,
        }),
        netinit_image: "afw-netinit:local".into(),
        ingress: None,
    }
}

const AGENTS: [(&str, &str, bool); 3] = [
    ("daniel-bot", "10.77.0.10", true),
    ("laurent-bot", "10.77.0.11", false),
    ("acme-bot", "10.77.0.12", false),
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("netinit") => print!(
            "{}",
            netinit_script(&spec("laurent-bot", "10.77.0.11", false))
        ),
        Some("compose") => {
            let mut yaml = std::fs::read_to_string(&args[2]).expect("read base compose");
            for (agent, ip, hermes) in AGENTS {
                let out = enroll_compose(&yaml, &spec(agent, ip, hermes))
                    .unwrap_or_else(|e| panic!("enroll {agent}: {e}"));
                for w in &out.warnings {
                    eprintln!("warning ({agent}): {w:?}");
                }
                yaml = out.yaml;
            }
            print!("{}", overlay(&yaml));
        }
        Some("enroll") if args.len() == 10 => {
            let yaml = read_input(&args[2]);
            let gateway: IpAddr = args[5].parse().expect("gateway ip");
            let s = EnrollSpec {
                agent_name: args[3].clone(),
                service: args[3].clone(),
                gateway_ip: gateway,
                agent_ip: args[4].parse().expect("agent ip"),
                network: args[6].clone(),
                proxy_url: format!("http://{gateway}:3128"),
                ca_path_host: args[7].clone(),
                hermes: None,
                netinit_image: "afw-netinit:local".into(),
                ingress: Some(IngressSpec {
                    network: args[8].clone(),
                    gateway_ip: args[9].parse().expect("ingress gateway ip"),
                }),
            };
            let out = enroll_compose(&yaml, &s).unwrap_or_else(|e| panic!("enroll: {e}"));
            for w in &out.warnings {
                eprintln!("warning: {w}");
            }
            print!("{}", out.yaml);
        }
        Some("unenroll") if args.len() == 4 => {
            let yaml = read_input(&args[2]);
            print!(
                "{}",
                unenroll_compose(&yaml, &args[3]).unwrap_or_else(|e| panic!("unenroll: {e}"))
            );
        }
        Some("normalize") if args.len() == 3 => {
            let yaml = read_input(&args[2]);
            let doc: Value = serde_yaml::from_str(&yaml).expect("yaml");
            print!("{}", serde_yaml::to_string(&doc).unwrap());
        }
        _ => {
            eprintln!(
                "usage: afw-demo-enroll compose <agents.base.yml> | netinit | enroll … | unenroll <file> <agent> | normalize <file>"
            );
            std::process::exit(2);
        }
    }
}

/// Contents of `path`, or of the standard input for `-`.
fn read_input(path: &str) -> String {
    if path == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s).expect("read stdin");
        s
    } else {
        std::fs::read_to_string(path).expect("read compose")
    }
}

/// Turns the enrolled document into an overlay of demo/docker-compose.yml: the internal network is
/// defined by the main file (drop the `external` declaration) and the gateway CA file mount becomes the
/// gateway's public volume (the gateway exports `gateway.crt` there).
fn overlay(yaml: &str) -> String {
    let mut doc: Value = serde_yaml::from_str(yaml).expect("enrolled yaml");
    let root = doc.as_mapping_mut().unwrap();
    root.remove("networks");
    if let Some(Value::Mapping(services)) = root.get_mut("services") {
        for (_, svc) in services.iter_mut() {
            if let Some(Value::Sequence(vols)) = svc.get_mut("volumes") {
                for v in vols.iter_mut() {
                    if let Value::String(s) = v {
                        if s.starts_with("/__afw_demo_ca__/") {
                            let dir = HOLDER_CA_SRC.rsplit_once('/').unwrap().0;
                            *s = format!("{CA_VOLUME}:{dir}:ro");
                        }
                    }
                }
            }
        }
    }
    let body = serde_yaml::to_string(&doc).unwrap();
    format!(
        "# GENERATED by deploy/tools/demo-enroll from demo/agents.base.yml with afw_enroll::enroll_compose.\n\
         # Do not edit: run deploy/tests/enroll-sync.sh --write. Checked by deploy/tests/enroll-sync.sh.\n{body}"
    )
}
