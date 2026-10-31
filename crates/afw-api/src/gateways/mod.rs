//! Gateways: registration tokens, management routes, and the mTLS gateway protocol `/gw/v1`
//! (lot L7c).
//!
//! The gateway protocol is only served by the dedicated TLS listener ([`tls::serve`]): the
//! gateway identity comes from the verified client certificate (never from a header), and the
//! certificate must be the one issued at registration (pinned SHA-256), for a gateway that was
//! not removed.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use afw_tls::ConsolePki;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};

use crate::AppState;

pub mod manage;
pub mod ports;
pub mod protocol;
pub mod tls;

/// Maximum size of an uploaded pcap.
pub const MAX_CAPTURE_BYTES: usize = 256 * 1024 * 1024;
/// Maximum size of an event batch.
pub const MAX_EVENT_BATCH_BYTES: usize = 32 * 1024 * 1024;

/// Gateway PKI and protocol timings.
#[derive(Clone, Debug)]
pub struct GatewayContext {
    /// Console CA (`AFW_PKI_DIR`): signs gateway CSRs. `None`: registration is unavailable.
    pub pki: Option<Arc<ConsolePki>>,
    /// Long poll of `GET /gw/v1/policy` (25 s).
    pub long_poll: Duration,
    /// Polling period of the installed policy during a long poll.
    pub poll_interval: Duration,
    /// A gateway not seen for this long is `offline` (`AFW_GW_OFFLINE_AFTER_SECS`, 90 s).
    pub offline_after: Duration,
    /// Validity of gateway client certificates (`AFW_GW_CERT_DAYS`, 365).
    pub cert_days: u32,
    /// Simultaneous connections on the gateway listener (`AFW_GW_MAX_CONNECTIONS`, 1024);
    /// connections beyond are closed at once.
    pub max_connections: usize,
    /// Time allowed to receive the headers of a request (`AFW_GW_HEADER_TIMEOUT_SECS`, 10 s),
    /// including the first one after the handshake.
    pub header_read_timeout: Duration,
}

impl Default for GatewayContext {
    fn default() -> Self {
        Self {
            pki: None,
            long_poll: Duration::from_secs(afw_core::protocol::POLICY_LONG_POLL_SECS),
            poll_interval: Duration::from_secs(1),
            offline_after: Duration::from_secs(90),
            cert_days: 365,
            max_connections: 1024,
            header_read_timeout: Duration::from_secs(10),
        }
    }
}

/// Settings of the gateway listener (`AFW_GW_*`, `AFW_PKI_DIR`).
#[derive(Clone, Debug, PartialEq)]
pub struct GatewaySettings {
    /// `AFW_GW_LISTEN`, default `0.0.0.0:8443`.
    pub listen: String,
    /// `AFW_PKI_DIR`, default `/var/lib/afw/pki`: console CA (key 0600, never leaves it).
    pub pki_dir: PathBuf,
    /// `AFW_CONSOLE_CA_EXPORT`: where to copy the PUBLIC console CA certificate (never the key),
    /// for the gateways' `AFW_CONSOLE_CA_FILE` (first contact). `None`: no export.
    pub console_ca_export: Option<PathBuf>,
    /// `AFW_GW_SERVER_NAMES` (comma separated DNS names or IPs of the console seen by the
    /// gateways), default: host of `AFW_PUBLIC_URL`, plus `localhost` and `127.0.0.1`.
    pub server_names: Vec<String>,
    pub offline_after: Duration,
    pub cert_days: u32,
    pub max_connections: usize,
    pub header_read_timeout: Duration,
}

impl GatewaySettings {
    pub fn from_env(public_url: Option<&str>) -> anyhow::Result<Self> {
        Self::from_vars(|k| std::env::var(k).ok(), public_url)
    }

    /// [`Self::from_env`] with an injectable variable source (tests).
    pub fn from_vars(
        get: impl Fn(&str) -> Option<String>,
        public_url: Option<&str>,
    ) -> anyhow::Result<Self> {
        let var = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let mut server_names: Vec<String> = var("AFW_GW_SERVER_NAMES")
            .map(|s| {
                s.split(',')
                    .map(|x| x.trim().to_owned())
                    .filter(|x| !x.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        if server_names.is_empty() {
            if let Some(host) = public_url
                .and_then(|u| reqwest::Url::parse(u).ok())
                .and_then(|u| u.host_str().map(|h| h.trim_matches(['[', ']']).to_owned()))
            {
                server_names.push(host);
            }
            for n in ["localhost", "127.0.0.1"] {
                if !server_names.iter().any(|s| s == n) {
                    server_names.push(n.to_owned());
                }
            }
        }
        let num = |k: &str, d: u64| -> anyhow::Result<u64> {
            var(k).map_or(Ok(d), |v| {
                v.parse()
                    .map_err(|_| anyhow::anyhow!("{k} must be an integer"))
            })
        };
        Ok(Self {
            listen: var("AFW_GW_LISTEN").unwrap_or_else(|| "0.0.0.0:8443".to_owned()),
            // Default: `$AFW_STATE_DIR/pki` (the API state volume, writable by the non-root
            // runtime user), else `/var/lib/afw/pki`.
            pki_dir: var("AFW_PKI_DIR").map(PathBuf::from).unwrap_or_else(|| {
                var("AFW_STATE_DIR")
                    .map_or_else(|| PathBuf::from("/var/lib/afw"), PathBuf::from)
                    .join("pki")
            }),
            console_ca_export: var("AFW_CONSOLE_CA_EXPORT").map(PathBuf::from),
            server_names,
            offline_after: Duration::from_secs(num("AFW_GW_OFFLINE_AFTER_SECS", 90)?),
            cert_days: u32::try_from(num("AFW_GW_CERT_DAYS", 365)?)?,
            max_connections: usize::try_from(num("AFW_GW_MAX_CONNECTIONS", 1024)?.max(1))?,
            header_read_timeout: Duration::from_secs(num("AFW_GW_HEADER_TIMEOUT_SECS", 10)?.max(1)),
        })
    }
}

/// Writes the public console CA certificate to `path` (0644, atomic rename). Only the
/// certificate: the CA private key never leaves `AFW_PKI_DIR`.
pub fn export_console_ca(pki: &ConsolePki, path: &std::path::Path) -> anyhow::Result<()> {
    use anyhow::Context as _;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, pki.ca_cert_pem()).with_context(|| format!("writing {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Management routes, nested under `/api/v1` by [`crate::router`].
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/gateways", get(manage::list))
        .route(
            "/gateways/registration-tokens",
            post(manage::create_registration_token),
        )
        .route(
            "/gateways/{id}",
            get(manage::get_one).delete(manage::remove),
        )
        .route("/gateways/{id}/commands", post(manage::send_command))
}

/// Gateway protocol routes; each path starts with `/gw/v1`
/// (`afw_core::protocol::GATEWAY_API_PREFIX`). Served only by [`tls::serve`].
pub fn gw_routes() -> Router<AppState> {
    Router::new()
        .route("/gw/v1/register", post(protocol::register))
        .route("/gw/v1/policy", get(protocol::policy))
        .route("/gw/v1/policy/ack", post(protocol::ack))
        .route(
            "/gw/v1/events",
            post(protocol::events).layer(DefaultBodyLimit::max(MAX_EVENT_BATCH_BYTES)),
        )
        .route("/gw/v1/heartbeat", post(protocol::heartbeat))
        .route(
            "/gw/v1/captures/{id}",
            post(protocol::capture).layer(DefaultBodyLimit::max(MAX_CAPTURE_BYTES)),
        )
}

/// Router of the gateway listener.
pub fn gw_router(state: AppState) -> Router {
    gw_routes().with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn settings(vars: &[(&str, &str)]) -> GatewaySettings {
        let m: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        GatewaySettings::from_vars(|k| m.get(k).cloned(), None).unwrap()
    }

    #[test]
    fn pki_dir_defaults_to_the_state_dir() {
        assert_eq!(
            settings(&[("AFW_STATE_DIR", "/var/lib/afw-api")]).pki_dir,
            PathBuf::from("/var/lib/afw-api/pki")
        );
        assert_eq!(settings(&[]).pki_dir, PathBuf::from("/var/lib/afw/pki"));
        assert_eq!(
            settings(&[("AFW_STATE_DIR", "/s"), ("AFW_PKI_DIR", "/p")]).pki_dir,
            PathBuf::from("/p")
        );
    }

    #[test]
    fn console_ca_export_writes_only_the_public_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let pki = ConsolePki::load_or_create(&dir.path().join("pki")).unwrap();
        let out = dir.path().join("public/console-ca.crt");
        let s = settings(&[("AFW_CONSOLE_CA_EXPORT", out.to_str().unwrap())]);
        assert_eq!(s.console_ca_export.as_deref(), Some(out.as_path()));
        export_console_ca(&pki, &out).unwrap();
        let pem = std::fs::read_to_string(&out).unwrap();
        assert_eq!(pem, pki.ca_cert_pem());
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(!pem.contains("PRIVATE KEY"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }
    }
}
