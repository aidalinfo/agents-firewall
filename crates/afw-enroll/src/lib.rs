//! Enrollment of containerized agents behind an agents-firewall gateway.
//!
//! Network enrollment follows ADR 0003 (the "pause" pattern): a small `afw-net-<agent>`
//! container holding `NET_ADMIN` owns the network namespace, points the default route and DNS
//! to the gateway, and the agent joins it with `network_mode: service:afw-net-<agent>`
//! without any capability. See ADR 0023 for the choices made by this crate.

mod compose;
mod coolify;
mod docker;
mod error;
mod k8s;
mod spec;

pub use compose::{ORIGINAL_KEY, enroll_compose, unenroll_compose};
pub use coolify::{
    CoolifyClient, CoolifyKind, CoolifyResource, enroll_coolify, unenroll_coolify,
};
pub use docker::{docker_run_args, netinit_command, netinit_run_args};
pub use error::EnrollError;
pub use k8s::{K8sSpec, k8s_manifests, patch_pod_template};
pub use spec::{
    CA_CONTAINER_PATH, DEFAULT_HERMES_PLUGIN_DIR, DEFAULT_NETINIT_IMAGE, EnrollOutcome,
    EnrollSpec, EnrollWarning, HermesSpec, LABEL_AGENT, LABEL_ENROLLED, NO_PROXY,
    net_service_name, validate_agent_name,
};
