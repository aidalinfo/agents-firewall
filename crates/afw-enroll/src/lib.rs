//! Enrollment of containerized agents behind an agents-firewall gateway.
//!
//! Network enrollment follows ADR 0003 (the "pause" pattern): a small `afw-net-<agent>`
//! container holding only `NET_ADMIN` owns the network namespace, points the routes and DNS
//! to the gateway (and nothing else), and the agent joins it with
//! `network_mode: service:afw-net-<agent>` without `NET_RAW`. See ADR 0023.

mod compose;
mod coolify;
mod docker;
mod error;
mod k8s;
mod netinit;
mod spec;

pub use compose::{ORIGINAL_KEY, enroll_compose, unenroll_compose};
pub use coolify::{CoolifyClient, CoolifyKind, CoolifyResource, enroll_coolify, unenroll_coolify};
pub use docker::{docker_run_args, netinit_command, netinit_run_args};
pub use error::EnrollError;
pub use k8s::{K8sSpec, SecretKeyRef, check_networkpolicies, k8s_manifests, patch_pod_template};
pub use netinit::{HOLDER_CA_DIR, HOLDER_CA_SRC, READY_FILE, netinit_script};
pub use spec::{
    CA_BUNDLE_PATH, CA_CERT_PATH, CA_DIR, DEFAULT_HERMES_PLUGIN_DIR, DEFAULT_NETINIT_IMAGE,
    EnrollOutcome, EnrollSpec, EnrollWarning, HermesSpec, LABEL_AGENT, LABEL_ENROLLED, NO_PROXY,
    net_service_name, validate_agent_name,
};
