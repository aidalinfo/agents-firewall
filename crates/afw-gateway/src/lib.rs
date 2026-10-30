//! agents-firewall gateway (data plane, lot L6).
//!
//! One gateway per agents host: transparent TCP interception (`SO_ORIGINAL_DST`), explicit
//! proxy, filtering DNS, TLS inspection, content analysis, L4 filtering, events, alerts and
//! captures. It never fails open: no valid policy, an engine error or an analysis failure all
//! mean deny. See ADR 0003, 0004, 0005, 0017, 0018 and 0019.

pub mod admin;
pub mod alerts;
pub mod capture;
pub mod config;
pub mod console_client;
pub mod dlp;
pub mod dns;
pub mod engine;
mod engine_shim;
pub mod events;
pub mod explicit_proxy;
pub mod flow;
pub mod health;
pub mod http_pipeline;
pub mod io;
pub mod l4;
pub mod metrics;
pub mod policy_store;
pub mod sniff;
pub mod state;
pub mod tls_mitm;
pub mod transparent;
pub mod upstream;
pub mod websocket;

pub use state::{BoundAddrs, Gateway, GatewayOptions, GatewayState, MapOrigDst, OrigDst, RunningGateway, SoOriginalDst};
