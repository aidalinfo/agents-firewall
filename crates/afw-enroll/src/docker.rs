//! Enrollment of a container started with plain `docker run` (EF-63).
//!
//! Two containers, as with Compose: first the holder
//! (`docker run <netinit_run_args…> <netinit_command…>`), then the agent with
//! `docker_run_args` placed before its image.

use crate::compose::ca_volume_name;
use crate::netinit::{HOLDER_CA_DIR, HOLDER_CA_SRC, READY_FILE, script};
use crate::spec::{CA_DIR, EnrollSpec, LABEL_AGENT, LABEL_ENROLLED};

/// Arguments of `docker run` for the `afw-net-<agent>` holder, up to (and including) its image.
pub fn netinit_run_args(spec: &EnrollSpec) -> Vec<String> {
    let (ip_flag, fam) = if spec.agent_ip.is_ipv4() {
        ("--ip", "ipv4")
    } else {
        ("--ip6", "ipv6")
    };
    let mut args: Vec<String> = vec![
        "-d".into(),
        "--name".into(),
        spec.net_service_name(),
        "--restart".into(),
        "unless-stopped".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--cap-add".into(),
        "NET_ADMIN".into(),
        "--network".into(),
        spec.network.clone(),
        ip_flag.into(),
        spec.agent_ip.to_string(),
        "--dns".into(),
        spec.gateway_ip.to_string(),
    ];
    for scope in ["all", "default"] {
        args.push("--sysctl".into());
        args.push(format!("net.{fam}.conf.{scope}.accept_redirects=0"));
    }
    args.extend([
        "-v".into(),
        format!("{}:{HOLDER_CA_SRC}:ro", spec.ca_path_host),
        "-v".into(),
        format!("{}:{HOLDER_CA_DIR}", ca_volume_name(&spec.agent_name)),
        "--health-cmd".into(),
        format!("test -f {READY_FILE} && test -s {HOLDER_CA_DIR}/bundle.pem"),
        "--health-interval".into(),
        "5s".into(),
        "-e".into(),
        format!("AFW_GATEWAY_IP={}", spec.gateway_ip),
        "-e".into(),
        format!("AFW_AGENT_IP={}", spec.agent_ip),
        "--label".into(),
        format!("{LABEL_ENROLLED}=true"),
        "--label".into(),
        format!("{LABEL_AGENT}={}", spec.agent_name),
        spec.netinit_image.clone(),
    ]);
    args
}

/// Command of the holder container ([`crate::netinit_script`], without Compose escaping).
pub fn netinit_command(spec: &EnrollSpec) -> Vec<String> {
    vec![
        "sh".into(),
        "-c".into(),
        script(spec.gateway_ip, spec.agent_ip),
    ]
}

/// Arguments to add to the agent's `docker run`, before its image. The agent joins the
/// holder's namespace without `NET_RAW`; published ports belong on the holder. Start it once
/// the holder is healthy.
pub fn docker_run_args(spec: &EnrollSpec) -> Vec<String> {
    let mut args = vec![
        "--network".into(),
        format!("container:{}", spec.net_service_name()),
        "--cap-drop".into(),
        "NET_RAW".into(),
    ];
    for (k, v) in spec.agent_environment() {
        args.push("-e".into());
        if k == "AFW_AGENT_TOKEN" {
            // Inherited from the environment of `docker run`: the secret never appears on a
            // command line (visible in `ps`). The caller exports it from `agent_token_env`.
            args.push(k);
        } else {
            args.push(format!("{k}={v}"));
        }
    }
    args.push("-v".into());
    args.push(format!("{}:{CA_DIR}:ro", ca_volume_name(&spec.agent_name)));
    if let Some(h) = &spec.hermes {
        args.push("-v".into());
        args.push(format!("{}:{}:ro", h.plugin_dir_host, h.container_dir()));
    }
    args.push("--label".into());
    args.push(format!("{LABEL_ENROLLED}=true"));
    args.push("--label".into());
    args.push(format!("{LABEL_AGENT}={}", spec.agent_name));
    args
}
