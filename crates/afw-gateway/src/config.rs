//! Command line and environment configuration.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "afw-gateway", version, about = "agents-firewall gateway (data plane)")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
    #[command(flatten)]
    pub run: RunArgs,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Run the gateway (default).
    Run(RunArgs),
    /// Register with the console using a one-time token, then exit.
    Register(RegisterArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Intercept {
    /// nftables redirection (transparent listener) + explicit proxy + DNS.
    Transparent,
    /// Explicit proxy and DNS only (Kubernetes: NetworkPolicy does the isolation).
    ProxyDns,
}

#[derive(Debug, Clone, Args)]
pub struct RunArgs {
    /// Console URL (`https://host:8443`). Without it the gateway runs standalone.
    #[arg(long, env = "AFW_CONSOLE_URL")]
    pub console_url: Option<String>,
    /// Console CA certificate used for the registration call.
    #[arg(long, env = "AFW_CONSOLE_CA_FILE")]
    pub console_ca_file: Option<PathBuf>,
    /// One-time registration token (registers at start-up when not registered yet).
    #[arg(long, env = "AFW_REGISTRATION_TOKEN", hide_env_values = true)]
    pub registration_token: Option<String>,
    /// Gateway name shown in the console (default: host name).
    #[arg(long, env = "AFW_GATEWAY_NAME")]
    pub gateway_name: Option<String>,
    /// State directory: identity, inspection CA (private key never leaves it), policy, spool.
    #[arg(long, env = "AFW_STATE_DIR", default_value = "/var/lib/afw")]
    pub state_dir: PathBuf,
    /// Where to export the PUBLIC inspection CA certificate (never the key).
    #[arg(long, env = "AFW_CA_EXPORT", default_value = "/var/lib/afw/public/inspection-ca.crt")]
    pub ca_export: PathBuf,
    /// Upstream DNS server (`ip` or `ip:port`); default: first nameserver of /etc/resolv.conf.
    #[arg(long, env = "AFW_UPSTREAM_DNS")]
    pub upstream_dns: Option<String>,
    /// Extra CA certificates trusted for upstream TLS (PEM files, comma separated).
    /// `AFW_EXTRA_CA` is accepted as an alias.
    #[arg(long, env = "AFW_UPSTREAM_CA_FILE", value_delimiter = ',')]
    pub upstream_ca_file: Vec<PathBuf>,
    /// Internal interface (used by the entrypoint's nftables rules; informative here).
    #[arg(long, env = "AFW_INTERNAL_IFACE")]
    pub internal_iface: Option<String>,
    /// Internal subnets (used by the entrypoint's nftables rules; informative here).
    #[arg(long, env = "AFW_INTERNAL_SUBNETS")]
    pub internal_subnets: Option<String>,
    #[arg(long, env = "AFW_INTERCEPT", value_enum, default_value = "transparent")]
    pub intercept: Intercept,
    #[arg(long, env = "AFW_LISTEN_IP", default_value = "0.0.0.0")]
    pub listen_ip: IpAddr,
    #[arg(long, env = "AFW_TRANSPARENT_PORT", default_value_t = 15001)]
    pub transparent_port: u16,
    #[arg(long, env = "AFW_PROXY_PORT", default_value_t = 3128)]
    pub proxy_port: u16,
    #[arg(long, env = "AFW_DNS_PORT", default_value_t = 53)]
    pub dns_port: u16,
    #[arg(long, env = "AFW_HEALTH_PORT", default_value_t = 9090)]
    pub health_port: u16,
    /// Install this InstalledPolicy file at start-up (tests, recette without console).
    #[arg(long, env = "AFW_STANDALONE_POLICY")]
    pub standalone_policy: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct RegisterArgs {
    #[arg(long, env = "AFW_CONSOLE_URL")]
    pub console: String,
    #[arg(long, env = "AFW_REGISTRATION_TOKEN", hide_env_values = true)]
    pub token: String,
    #[arg(long, env = "AFW_GATEWAY_NAME")]
    pub name: Option<String>,
    #[arg(long, env = "AFW_CONSOLE_CA_FILE")]
    pub console_ca_file: Option<PathBuf>,
    #[arg(long, env = "AFW_STATE_DIR", default_value = "/var/lib/afw")]
    pub state_dir: PathBuf,
}

impl RunArgs {
    pub fn upstream_dns_addr(&self) -> anyhow::Result<Option<SocketAddr>> {
        let Some(v) = self.upstream_dns.as_deref().map(str::trim).filter(|v| !v.is_empty()) else {
            return Ok(None);
        };
        if let Ok(a) = v.parse::<SocketAddr>() {
            return Ok(Some(a));
        }
        let ip: IpAddr = v.parse().map_err(|_| anyhow::anyhow!("invalid AFW_UPSTREAM_DNS {v:?}"))?;
        Ok(Some(SocketAddr::new(ip, 53)))
    }

    /// Extra upstream roots (PEM contents). An unreadable file is an error, never skipped.
    pub fn extra_roots(&self) -> anyhow::Result<Vec<String>> {
        let mut files: Vec<PathBuf> = self.upstream_ca_file.iter().filter(|p| !p.as_os_str().is_empty()).cloned().collect();
        if let Ok(alias) = std::env::var("AFW_EXTRA_CA") {
            files.extend(alias.split(',').map(str::trim).filter(|s| !s.is_empty()).map(PathBuf::from));
        }
        files
            .iter()
            .map(|p| std::fs::read_to_string(p).map_err(|e| anyhow::anyhow!("upstream CA {}: {e}", p.display())))
            .collect()
    }
}

pub fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "afw-gateway".into())
}
