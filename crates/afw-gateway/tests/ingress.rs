//! Inbound relay listener (issue #24): `CONNECT` to an internal address only.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn ingress() -> Harness {
    harness_with(None, |o| {
        o.ingress = Some("127.0.0.1:0".parse().unwrap());
        o.ingress_targets = vec![format!("{INTERNAL_IP}/32").parse().unwrap()];
    })
    .await
}

/// Sends `head`, returns the status line of the answer and the open stream.
async fn request(h: &Harness, head: &str) -> (String, TcpStream) {
    let mut s = TcpStream::connect(h.gw.addrs.ingress.unwrap())
        .await
        .unwrap();
    s.write_all(head.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        match tokio::time::timeout(Duration::from_secs(5), s.read(&mut b))
            .await
            .unwrap()
        {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        buf.push(b[0]);
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    (text.lines().next().unwrap_or_default().to_string(), s)
}

#[tokio::test]
async fn connect_to_an_internal_address_is_relayed() {
    let h = ingress().await;
    let (status, mut s) =
        request(&h, &format!("CONNECT {} HTTP/1.0\r\n\r\n", h.internal_addr)).await;
    assert_eq!(status, "HTTP/1.1 200 Connection established");
    s.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"ping");
}

#[tokio::test]
async fn bytes_sent_with_the_head_reach_the_agent() {
    let h = ingress().await;
    let (status, mut s) = request(
        &h,
        &format!(
            "CONNECT {} HTTP/1.1\r\nHost: x\r\n\r\nearly",
            h.internal_addr
        ),
    )
    .await;
    assert_eq!(status, "HTTP/1.1 200 Connection established");
    let mut got = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"early");
}

#[tokio::test]
async fn the_listener_is_not_an_exit() {
    let h = ingress().await;
    // A public upstream, a name, the gateway's own listeners: never relayed.
    let proxy: SocketAddr = h.proxy();
    for (head, want) in [
        (
            format!("CONNECT {} HTTP/1.1\r\n\r\n", h.upstream_addr),
            "403",
        ),
        (format!("CONNECT {proxy} HTTP/1.1\r\n\r\n"), "403"),
        ("CONNECT allowed.test:443 HTTP/1.1\r\n\r\n".into(), "403"),
        (
            format!("GET http://{}/ HTTP/1.1\r\n\r\n", h.internal_addr),
            "405",
        ),
        ("garbage\r\n\r\n".into(), "400"),
    ] {
        let (status, _) = request(&h, &head).await;
        assert!(status.contains(want), "{head:?} -> {status}");
    }
    // An oversized head is refused without relaying (the 400 may be lost in the reset caused by
    // the unread bytes).
    let (status, _) = request(
        &h,
        &format!(
            "CONNECT {} HTTP/1.1\r\nX: {}\r\n\r\n",
            h.internal_addr,
            "a".repeat(8192)
        ),
    )
    .await;
    assert!(status.is_empty() || status.contains("400"), "{status}");
}

#[tokio::test]
async fn an_unreachable_agent_gets_502() {
    let h = harness_with(None, |o| {
        o.ingress = Some("127.0.0.1:0".parse().unwrap());
        o.ingress_targets = vec![format!("{UNKNOWN_IP}/32").parse().unwrap()];
    })
    .await;
    let (status, _) = request(&h, &format!("CONNECT {UNKNOWN_IP}:9 HTTP/1.1\r\n\r\n")).await;
    assert!(status.contains("502"), "{status}");
}

#[tokio::test]
async fn ingress_without_targets_does_not_start() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = afw_gateway::GatewayOptions::for_tests(dir.path().to_path_buf());
    o.ingress = Some("127.0.0.1:0".parse().unwrap());
    assert!(afw_gateway::Gateway::start(o).await.is_err());
}
