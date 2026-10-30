//! Import of egress-guard policy files into the agents-firewall model (lot L10, EF-70 to
//! EF-72, ADR 0026).
//!
//! [`import`] turns a `pulse-mcp-guardrails.yaml`-style file (« v2 egress-first ») into an
//! [`ImportPlan`]: objects, services, data classes, a zone (observe mode by default), rules and
//! the Hermes intent policy, plus an [`ImportReport`]. The plan is applied by the API inside a
//! session ([`ImportPlan::to_session_changes`]); this crate does no I/O.

pub mod egress_guard;
mod plan;
mod report;

pub use egress_guard::{ImportOptions, import};
pub use plan::{ImportPlan, SessionChange, ZoneChange};
pub use report::{ImportReport, MappedItem, ReportItem};

/// Import failure. Recoverable problems (unknown fields, invalid patterns, unsupported
/// entries) are not errors: they go to the [`ImportReport`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ImportError {
    /// The file is not valid YAML (message includes line and column).
    #[error("invalid YAML: {0}")]
    Yaml(String),
    /// The YAML is valid but does not have the egress-guard shape.
    #[error("invalid egress-guard policy at `{path}`: {message}")]
    Invalid { path: String, message: String },
    /// A size limit was exceeded (file, nesting, number of patterns).
    #[error("import limit exceeded: {0}")]
    Limit(String),
    #[error("invalid import options: {0}")]
    Options(String),
}
