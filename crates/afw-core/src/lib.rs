//! Shared contracts of agents-firewall (lot L0): policy model, installed policy, gateway
//! protocol, events, REST DTOs, canonical JSON and audit chain.
//!
//! Every crate (gateway, API, CLI, MCP, engine) depends on these types; changing a field is a
//! contract change (see `docs/adr/0011-contrats-partages.md`).

pub mod api;
pub mod audit;
pub mod canon;
pub mod events;
pub mod installed;
pub mod policy;
pub mod protocol;

pub use canon::{canonical_json, sha256_hex};
pub use installed::{INSTALLED_POLICY_FORMAT, InstalledPolicy, PolicyIntegrityError};
