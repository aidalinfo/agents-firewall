//! `afw-gateway` binary: `run` (default) and `register`.

use std::net::SocketAddr;

use afw_gateway::config::{Cli, Cmd, Intercept, RunArgs, hostname};
use afw_gateway::console_client::{is_registered, register};
use afw_gateway::{Gateway, GatewayOptions};
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Register(a)) => {
            let ca = a
                .console_ca_file
                .as_ref()
                .map(std::fs::read_to_string)
                .transpose()?;
            let id = register(
                &a.console,
                &a.token,
                &a.name.unwrap_or_else(hostname),
                ca,
                &a.state_dir,
            )
            .await?;
            println!("registered as gateway {id}");
            Ok(())
        }
        Some(Cmd::Run(a)) => run(a).await,
        None => run(cli.run).await,
    }
}

async fn run(a: RunArgs) -> anyhow::Result<()> {
    if let (Some(url), Some(token)) = (
        &a.console_url,
        a.registration_token.as_deref().filter(|t| !t.is_empty()),
    ) && !is_registered(&a.state_dir)
    {
        let ca = a
            .console_ca_file
            .as_ref()
            .filter(|p| !p.as_os_str().is_empty())
            .map(std::fs::read_to_string)
            .transpose()?;
        let name = a.gateway_name.clone().unwrap_or_else(hostname);
        match register(url, token, &name, ca, &a.state_dir).await {
            Ok(id) => tracing::info!(%id, "registered with the console"),
            Err(e) => {
                tracing::error!(error = %e, "registration failed: enforcing the local policy (deny all if none)")
            }
        }
    }
    let mut o = GatewayOptions::new(a.state_dir.clone());
    let at = |p: u16| SocketAddr::new(a.listen_ip, p);
    o.transparent = (a.intercept == Intercept::Transparent).then(|| at(a.transparent_port));
    o.proxy = Some(at(a.proxy_port));
    o.dns = Some(at(a.dns_port));
    o.health = Some(at(a.health_port));
    o.resolver = afw_gateway::upstream::default_resolver(a.upstream_dns_addr()?);
    o.extra_roots = a.extra_roots()?;
    o.console_url = a.console_url.clone().filter(|u| !u.is_empty());
    o.ca_export = Some(a.ca_export.clone());
    o.standalone_policy = a.standalone_policy.clone();
    o.own_addresses = local_addresses();
    let gw = Gateway::start(o).await?;
    tracing::info!(addrs = ?gw.addrs, revision = ?gw.state.store.revision(), "gateway started");
    tokio::select! {
        _ = gw.wait() => {}
        _ = tokio::signal::ctrl_c() => tracing::info!("stopping"),
    }
    Ok(())
}

/// Addresses of this host's interfaces (loop guard for the transparent listener).
fn local_addresses() -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    // SAFETY: getifaddrs/freeifaddrs pair; only reads the returned list.
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let addr = (*cur).ifa_addr;
            if !addr.is_null() {
                match (*addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sin = &*(addr as *const libc::sockaddr_in);
                        out.push(
                            std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)).into(),
                        );
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(addr as *const libc::sockaddr_in6);
                        out.push(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr).into());
                    }
                    _ => {}
                }
            }
            cur = (*cur).ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}
