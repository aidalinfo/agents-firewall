//! Inbound relay listener (issues #22 and #24): `CONNECT <agent ip>:<port>` from the
//! `afw-in-<agent>` relays, on the gateway's ingress network only (nftables, see the entrypoint).
//!
//! The relays used to route packets addressed to the agent through the gateway. On a Docker host
//! that filters bridged traffic (br_netfilter), the isolation rules of an `internal` network drop
//! every packet whose source or destination is outside that network's subnet, before the gateway
//! sees it. Here every hop stays inside its own subnet: relay -> gateway ingress address, then
//! gateway internal address -> agent. The agent sees the gateway as the peer and answers through
//! its single route; stopping the gateway cuts the inbound path as well.
//!
//! Only IP literals inside the internal subnets are accepted (no name resolution, never the
//! gateway itself), so the listener cannot be used as an exit.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::state::GatewayState;

/// Default port of the listener (`AFW_INGRESS_PORT`); `afw enroll` relays connect to it.
pub const DEFAULT_INGRESS_PORT: u16 = 15002;

const MAX_HEAD: usize = 4096;
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 4096;

/// Why a request is refused (HTTP status sent back before closing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    BadRequest,
    MethodNotAllowed,
    Forbidden,
}

impl Refusal {
    fn response(self) -> &'static [u8] {
        match self {
            Refusal::BadRequest => b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n",
            Refusal::MethodNotAllowed => {
                b"HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nConnection: close\r\n\r\n"
            }
            Refusal::Forbidden => b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n",
        }
    }
}

/// Destination of a `CONNECT` request head (request line and headers, up to the empty line).
/// Only `CONNECT <ip>:<port> HTTP/1.x` with an IP literal and a non-zero port is accepted.
pub fn parse_connect(head: &[u8]) -> Result<SocketAddr, Refusal> {
    let head = std::str::from_utf8(head).map_err(|_| Refusal::BadRequest)?;
    let line = head.split("\r\n").next().unwrap_or_default();
    let mut parts = line.split(' ');
    let (Some(method), Some(authority), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refusal::BadRequest);
    };
    if !version.starts_with("HTTP/1.") {
        return Err(Refusal::BadRequest);
    }
    if method != "CONNECT" {
        return Err(Refusal::MethodNotAllowed);
    }
    let dst: SocketAddr = authority.parse().map_err(|_| Refusal::Forbidden)?;
    if dst.port() == 0 {
        return Err(Refusal::Forbidden);
    }
    Ok(dst)
}

/// A destination is allowed when it lies in an internal subnet and is not the gateway itself
/// (`own` holds every address of the gateway, loopback included).
pub fn allowed(dst: IpAddr, targets: &[IpNet], own: &[IpAddr]) -> bool {
    let dst = match dst {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(dst, IpAddr::V4),
        v4 => v4,
    };
    !dst.is_unspecified() && !own.contains(&dst) && targets.iter().any(|n| n.contains(&dst))
}

pub async fn serve(state: Arc<GatewayState>, listener: TcpListener, targets: Arc<Vec<IpNet>>) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            crate::io::reset(stream);
            continue;
        };
        let state = state.clone();
        let targets = targets.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle(&state, &targets, stream, peer).await {
                tracing::debug!(%peer, error = %e, "ingress connection ended");
            }
        });
    }
}

async fn handle(
    state: &GatewayState,
    targets: &[IpNet],
    mut client: TcpStream,
    peer: SocketAddr,
) -> std::io::Result<()> {
    let (head, rest) = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client)).await {
        Ok(Ok(Some(h))) => h,
        Ok(Ok(None)) => return client.write_all(Refusal::BadRequest.response()).await,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Ok(()),
    };
    let dst = match parse_connect(&head) {
        Ok(dst) if allowed(dst.ip(), targets, &state.own_addresses) => dst,
        Ok(dst) => {
            tracing::warn!(%peer, %dst, "ingress: destination outside the internal subnets refused");
            return client.write_all(Refusal::Forbidden.response()).await;
        }
        Err(r) => return client.write_all(r.response()).await,
    };
    let mut upstream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(dst)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) | Err(_) => {
            return client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
        }
    };
    client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    if !rest.is_empty() {
        upstream.write_all(&rest).await?;
    }
    tracing::debug!(%peer, %dst, "ingress relayed");
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Reads up to the end of the request head. Returns the head and the bytes read past it, or
/// `None` when the head is larger than [`MAX_HEAD`] or the client closes first.
async fn read_head(s: &mut TcpStream) -> std::io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Ok(Some((buf, rest)));
        }
        if buf.len() > MAX_HEAD {
            return Ok(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_connect_to_an_ip_literal_is_parsed() {
        assert_eq!(
            parse_connect(b"CONNECT 10.77.0.21:8080 HTTP/1.0\r\n\r\n"),
            Ok("10.77.0.21:8080".parse().unwrap())
        );
        assert_eq!(
            parse_connect(b"CONNECT [fd00:77::21]:80 HTTP/1.1\r\nHost: x\r\n\r\n"),
            Ok("[fd00:77::21]:80".parse().unwrap())
        );
        for (head, want) in [
            ("GET / HTTP/1.1\r\n\r\n", Refusal::MethodNotAllowed),
            (
                "CONNECT agent.local:80 HTTP/1.1\r\n\r\n",
                Refusal::Forbidden,
            ),
            ("CONNECT 10.77.0.21:0 HTTP/1.1\r\n\r\n", Refusal::Forbidden),
            ("CONNECT 10.77.0.21 HTTP/1.1\r\n\r\n", Refusal::Forbidden),
            ("CONNECT 10.77.0.21:80\r\n\r\n", Refusal::BadRequest),
            ("CONNECT 10.77.0.21:80 SPDY/3\r\n\r\n", Refusal::BadRequest),
            (
                "CONNECT  10.77.0.21:80 HTTP/1.1\r\n\r\n",
                Refusal::BadRequest,
            ),
        ] {
            assert_eq!(parse_connect(head.as_bytes()), Err(want), "{head}");
        }
        assert_eq!(parse_connect(b"\xff\xfe\r\n\r\n"), Err(Refusal::BadRequest));
    }

    #[test]
    fn only_internal_subnets_and_never_the_gateway() {
        let targets: Vec<IpNet> = vec!["10.77.0.0/24".parse().unwrap()];
        let own: Vec<IpAddr> = vec!["10.77.0.2".parse().unwrap(), "10.78.0.2".parse().unwrap()];
        let ok = |ip: &str| allowed(ip.parse().unwrap(), &targets, &own);
        assert!(ok("10.77.0.21"));
        assert!(ok("::ffff:10.77.0.21"));
        for ip in [
            "10.77.0.2",
            "::ffff:10.77.0.2",
            "10.78.0.2",
            "10.78.0.21",
            "198.18.99.20",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
        ] {
            assert!(!ok(ip), "{ip} allowed");
        }
        assert!(!allowed("10.77.0.21".parse().unwrap(), &[], &own));
    }
}
