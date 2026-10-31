//! `afw-mcp`: administration MCP server (lot L9).

use std::net::SocketAddr;
use std::path::PathBuf;

use afw_client::{AfwClient, ClientOptions};
use afw_core::events::Interface;
use afw_mcp::{AfwMcp, http_router};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rmcp::ServiceExt;

/// agents-firewall administration MCP server, for the single approved agent.
///
/// The API token (role `mcp_agent`) comes from AFW_TOKEN or --token-file; it is never accepted
/// on the command line.
#[derive(Parser, Debug)]
#[command(name = "afw-mcp", version)]
struct Cli {
    /// Console URL.
    #[arg(long, env = "AFW_URL")]
    url: String,
    /// File holding the API token (default: AFW_TOKEN).
    #[arg(long = "token-file", env = "AFW_TOKEN_FILE")]
    token_file: Option<PathBuf>,
    /// Extra trusted CA certificate (PEM).
    #[arg(long = "ca-cert", env = "AFW_CA_CERT")]
    ca_cert: Option<PathBuf>,
    #[command(subcommand)]
    transport: Option<Transport>,
}

#[derive(Subcommand, Debug)]
enum Transport {
    /// MCP over stdin/stdout (default).
    Stdio,
    /// MCP over streamable HTTP on /mcp; clients must send `Authorization: Bearer
    /// $AFW_MCP_LISTEN_TOKEN`.
    Http {
        #[arg(long, default_value = "127.0.0.1:8765", env = "AFW_MCP_LISTEN")]
        listen: SocketAddr,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logs on stderr only: stdout carries the MCP protocol in stdio mode.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("AFW_MCP_LOG")
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();
    let cli = Cli::parse();
    let token = match &cli.token_file {
        Some(p) => std::fs::read_to_string(p)
            .with_context(|| format!("cannot read {}", p.display()))?
            .trim()
            .to_string(),
        None => std::env::var("AFW_TOKEN").unwrap_or_default(),
    };
    if token.trim().is_empty() {
        bail!("no API token: set AFW_TOKEN or --token-file (an `mcp_agent` token)");
    }
    let ca_cert_pem = match &cli.ca_cert {
        Some(p) => Some(std::fs::read(p).with_context(|| format!("cannot read {}", p.display()))?),
        None => None,
    };
    let client = AfwClient::with_options(
        &cli.url,
        token,
        Interface::Mcp,
        ClientOptions {
            ca_cert_pem,
            timeout: None,
        },
    )?;
    let server = AfwMcp::new(client);
    match cli.transport.unwrap_or(Transport::Stdio) {
        Transport::Stdio => {
            let running = server.serve(rmcp::transport::stdio()).await?;
            running.waiting().await?;
        }
        Transport::Http { listen } => {
            let listen_token = std::env::var("AFW_MCP_LISTEN_TOKEN").unwrap_or_default();
            if listen_token.len() < 16 {
                bail!("HTTP mode needs AFW_MCP_LISTEN_TOKEN (at least 16 characters): clients send it as a bearer token");
            }
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("cannot listen on {listen}"))?;
            eprintln!("afw-mcp listening on http://{listen}/mcp");
            axum::serve(listener, http_router(server, listen_token))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
    }
    Ok(())
}
