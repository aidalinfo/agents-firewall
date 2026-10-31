//! ENF-01 latency measurement (not a pass/fail test). Run in release mode:
//!   scripts/cargo.sh test --release -p afw-gateway --test latency -- --ignored --nocapture
//! Compares, on loopback, an HTTPS GET sent directly to the upstream with the same request
//! through the gateway (transparent interception, TLS inspection, decision, DLP, logging),
//! for new connections and for requests reusing a keep-alive connection.

mod common;

use std::time::{Duration, Instant};

use afw_core::policy::ZoneMode;
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const N: usize = 300;

fn pct(mut v: Vec<Duration>) -> (f64, f64) {
    v.sort();
    let at = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize].as_secs_f64() * 1000.0;
    (at(0.5), at(0.95))
}

async fn read_response<S: tokio::io::AsyncRead + Unpin>(s: &mut S) {
    // Responses are `ok:/x` with a content-length: read until the body is complete.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = s.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed early");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| {
                    l.strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap())
                })
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                assert!(head.starts_with("http/1.1 200"), "{head}");
                return;
            }
        }
    }
}

const REQ: &[u8] = b"GET /x HTTP/1.1\r\nHost: allowed.test\r\n\r\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measurement: run with --ignored --nocapture in release mode"]
async fn latency_direct_vs_gateway() {
    let h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let up_ca = std::fs::read_to_string(h._up_dir.path().join("ca").join("ca.crt")).unwrap();

    // New connection per request.
    let mut direct = Vec::new();
    let mut via = Vec::new();
    let mut handshake = Vec::new();
    for _ in 0..N {
        let t = Instant::now();
        let tcp = tokio::net::TcpStream::connect(h.upstream_addr)
            .await
            .unwrap();
        tcp.set_nodelay(true).unwrap();
        let mut s = tls_with(tcp, "allowed.test", &up_ca, vec![b"http/1.1".to_vec()])
            .await
            .unwrap();
        s.write_all(REQ).await.unwrap();
        read_response(&mut s).await;
        direct.push(t.elapsed());

        let t = Instant::now();
        let tcp = h.transparent(AGENT_IP, h.upstream_addr).await;
        let mut s = h.tls(tcp, "allowed.test").await.unwrap();
        handshake.push(t.elapsed());
        s.write_all(REQ).await.unwrap();
        read_response(&mut s).await;
        via.push(t.elapsed());
    }
    let (d50, d95) = pct(direct);
    let (g50, g95) = pct(via);
    let (hs50, hs95) = pct(handshake);
    println!("new connection   gateway TLS handshake p50 {hs50:.2} ms  p95 {hs95:.2} ms");
    println!("new connection   direct  p50 {d50:.2} ms  p95 {d95:.2} ms");
    println!(
        "new connection   gateway p50 {g50:.2} ms  p95 {g95:.2} ms  (overhead p50 {:.2} ms)",
        g50 - d50
    );

    // Keep-alive: request overhead only.
    let tcp = tokio::net::TcpStream::connect(h.upstream_addr)
        .await
        .unwrap();
    let mut ds = tls_with(tcp, "allowed.test", &up_ca, vec![b"http/1.1".to_vec()])
        .await
        .unwrap();
    let tcp = h.transparent(AGENT_IP, h.upstream_addr).await;
    let mut gs = h.tls(tcp, "allowed.test").await.unwrap();
    let mut direct = Vec::new();
    let mut via = Vec::new();
    for _ in 0..N {
        let t = Instant::now();
        ds.write_all(REQ).await.unwrap();
        read_response(&mut ds).await;
        direct.push(t.elapsed());
        let t = Instant::now();
        gs.write_all(REQ).await.unwrap();
        read_response(&mut gs).await;
        via.push(t.elapsed());
    }
    let (d50, d95) = pct(direct);
    let (g50, g95) = pct(via);
    println!("keep-alive       direct  p50 {d50:.2} ms  p95 {d95:.2} ms");
    println!(
        "keep-alive       gateway p50 {g50:.2} ms  p95 {g95:.2} ms  (overhead p50 {:.2} ms)",
        g50 - d50
    );
    let (p50, p95) = h.gw.state.metrics.percentiles();
    println!("decision latency p50 {p50} us  p95 {p95} us");
}
