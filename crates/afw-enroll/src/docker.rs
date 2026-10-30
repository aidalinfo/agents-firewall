//! Enrollment of a container started with plain `docker run` (EF-63).
//!
//! Two containers, as with Compose: first the holder (`netinit_run_args` + image +
//! `netinit_command`), then the agent with `docker_run_args` placed before its image.

use crate::compose::route_script;
use crate::spec::{CA_CONTAINER_PATH, EnrollSpec, LABEL_AGENT, LABEL_ENROLLED};

/// Arguments of `docker run` for the `afw-net-<agent>` holder, up to (and including) its image.
///
/// `docker run <netinit_run_args…> <netinit_command…>`
pub fn netinit_run_args(spec: &EnrollSpec) -> Vec<String> {
    let ip_flag = if spec.agent_ip.is_ipv4() {
        "--ip"
    } else {
        "--ip6"
    };
    vec![
        "-d".into(),
        "--name".into(),
        spec.net_service_name(),
        "--restart".into(),
        "unless-stopped".into(),
        "--cap-add".into(),
        "NET_ADMIN".into(),
        "--network".into(),
        spec.network.clone(),
        ip_flag.into(),
        spec.agent_ip.to_string(),
        "--dns".into(),
        spec.gateway_ip.to_string(),
        "-e".into(),
        format!("AFW_GATEWAY_IP={}", spec.gateway_ip),
        "--label".into(),
        format!("{LABEL_ENROLLED}=true"),
        "--label".into(),
        format!("{LABEL_AGENT}={}", spec.agent_name),
        spec.netinit_image.clone(),
    ]
}

/// Command of the holder container (default route to the gateway, re-applied every 10 s).
pub fn netinit_command(spec: &EnrollSpec) -> Vec<String> {
    vec!["sh".into(), "-c".into(), route_script(spec.gateway_ip)]
}

/// Arguments to add to the agent's `docker run`, before its image. The agent joins the
/// holder's namespace and gets no capability; published ports belong on the holder.
pub fn docker_run_args(spec: &EnrollSpec) -> Vec<String> {
    let mut args = vec![
        "--network".into(),
        format!("container:{}", spec.net_service_name()),
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
    args.push(format!("{}:{CA_CONTAINER_PATH}:ro", spec.ca_path_host));
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
