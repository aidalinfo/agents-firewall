//! Bypass tests of the gateway (written before the implementation). Every test runs a real
//! in-process gateway on loopback with a standalone policy and local upstream servers.
//!
//! Tests that need nftables and `SO_ORIGINAL_DST` are in `tests/nftables.rs` (`#[ignore]`) and
//! in `deploy/docker/isolation-test/run.sh` (real network isolation, ENF-07).

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use afw_core::events::{AdminSystem, AlertKind, GatewayEvent, Verdict};
use afw_core::policy::ZoneMode;
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn flow(ev: &GatewayEvent) -> Option<&afw_core::events::FlowEvent> {
    match ev {
        GatewayEvent::Flow(f) => Some(f),
        _ => None,
    }
}

fn http(ev: &GatewayEvent) -> Option<&afw_core::events::HttpEvent> {
    match ev {
        GatewayEvent::Http(h) => Some(h),
        _ => None,
    }
}


#[tokio::test]
async fn no_policy_denies_everything() {
    let mut h = harness(None).await;
    // Explicit proxy, plain HTTP to a destination that would be allowed by any policy.
    let mut s = tokio::net::TcpStream::connect(h.proxy()).await.unwrap();
    let req = format!(
        "GET http://allowed.test:{}/x HTTP/1.1\r\nHost: allowed.test:{}\r\nConnection: close\r\n\r\n",
        h.plain_addr.port(),
        h.plain_addr.port()
    );
    let resp = http_raw(&mut s, req.as_bytes()).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(resp.contains("x-agents-firewall: denied"), "{resp}");
    assert!(resp.contains("(rule no-policy)"), "{resp}");
    // Transparent raw TCP: reset.
    let mut t = h.transparent(AGENT_IP, h.internal_addr).await;
    let _ = t.write_all(b"hello").await;
    let mut buf = [0u8; 16];
    let r = tokio::time::timeout(Duration::from_secs(5), t.read(&mut buf)).await.unwrap();
    assert!(matches!(r, Ok(0) | Err(_)), "connection must be refused: {r:?}");
    let ev = h.wait_event(|e| flow(e).is_some_and(|f| f.verdict == Verdict::Deny && f.decision.revision.is_none())).await;
    assert_eq!(flow(&ev).unwrap().decision.rule_name, "no-policy");
    assert!(h.log.all().is_empty(), "nothing may reach an upstream");
}

#[tokio::test]
async fn corrupted_policy_keeps_last_valid() {
    let h = harness(Some(installed(5, ZoneMode::Enforce))).await;
    let store = &h.gw.state.store;
    assert_eq!(store.revision(), Some(5));
    // Wrong fingerprint.
    let mut bad = installed(6, ZoneMode::Enforce);
    bad.sha256 = "00".repeat(32);
    assert!(store.install(bad).is_err());
    // Unknown format.
    let mut bad = installed(7, ZoneMode::Enforce);
    bad.format = 2;
    assert!(store.install(bad).is_err());
    // Garbage.
    assert!(store.install_bytes(b"{not json").is_err());
    // Downgrade without rollback flag.
    assert!(store.install(installed(4, ZoneMode::Enforce)).is_err());
    assert_eq!(store.revision(), Some(5));
    // The persisted file is still the valid revision 5: a restart keeps enforcing it.
    let reloaded = afw_gateway::policy_store::PolicyStore::load(h._dir.path().join("policy.json"));
    assert_eq!(reloaded.revision(), Some(5));
    // A corrupt file on disk at startup = deny everything (never open).
    std::fs::write(h._dir.path().join("policy.json"), b"garbage").unwrap();
    let reloaded = afw_gateway::policy_store::PolicyStore::load(h._dir.path().join("policy.json"));
    assert_eq!(reloaded.revision(), None);
}

#[tokio::test]
async fn unknown_agent_denied() {
    let mut h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let s = h.transparent(UNKNOWN_IP, h.upstream_addr).await;
    let mut tls = h.tls(s, "allowed.test").await.unwrap();
    let resp = http_raw(&mut tls, &get("allowed.test", "/")).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(resp.contains("(rule unknown-agent)"), "{resp}");
    h.wait_event(|e| flow(e).is_some_and(|f| f.verdict == Verdict::Deny && f.agent_id.is_none())).await;
    assert!(h.log.all().is_empty());
}

#[tokio::test]
async fn denied_https_gets_explicit_403_message() {
    let mut h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let s = h.transparent(AGENT_IP, h.upstream_addr).await;
    let mut tls = h.tls(s, "denied.test").await.unwrap();
    let resp = http_raw(&mut tls, &get("denied.test", "/v1/data")).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(resp.to_ascii_lowercase().contains("x-agents-firewall: denied"), "{resp}");
    let body = resp.split("\r\n\r\n").nth(1).unwrap();
    assert_eq!(
        body.trim_end(),
        "blocked by agents-firewall: denied.test not allowed for daniel-bot (rule default-deny)"
    );
    let ev = h.wait_event(|e| flow(e).is_some_and(|f| f.verdict == Verdict::Deny)).await;
    let f = flow(&ev).unwrap();
    assert_eq!(f.sni.as_deref(), Some("denied.test"));
    assert_eq!(f.agent_id, Some(id(AGENT)));
    assert!(h.log.all().is_empty());
}

#[tokio::test]
async fn denied_tcp_is_reset_and_logged() {
    let mut h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    // An arbitrary public TCP destination (nothing listens there; it must not even be tried).
    let dst: SocketAddr = "198.51.100.7:4444".parse().unwrap();
    let mut t = h.transparent(AGENT_IP, dst).await;
    let _ = t.write_all(b"\x00\x01binary").await;
    let mut buf = [0u8; 16];
    let r = tokio::time::timeout(Duration::from_secs(5), t.read(&mut buf)).await.unwrap();
    match r {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset, "{e}"),
        Ok(n) => panic!("expected RST, read {n} bytes"),
    }
    let ev = h.wait_event(|e| flow(e).is_some_and(|f| f.verdict == Verdict::Deny)).await;
    let f = flow(&ev).unwrap();
    assert_eq!(f.dst, dst);
    assert_eq!(f.decision.rule_name, "default-deny");
}

#[tokio::test]
async fn connect_to_denied_host_refused() {
    let mut h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let mut s = tokio::net::TcpStream::connect(h.proxy()).await.unwrap();
    let port = h.upstream_addr.port();
    let req = format!("CONNECT denied.test:{port} HTTP/1.1\r\nHost: denied.test:{port}\r\n\r\n");
    let resp = http_raw(&mut s, req.as_bytes()).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(resp.contains("blocked by agents-firewall: denied.test not allowed for daniel-bot (rule default-deny)"), "{resp}");
    h.wait_event(|e| flow(e).is_some_and(|f| f.verdict == Verdict::Deny && f.domain.as_deref() == Some("denied.test"))).await;
    assert!(h.log.all().is_empty());
}

#[tokio::test]
async fn connect_to_allowed_host_is_inspected() {
    let mut h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let mut s = tokio::net::TcpStream::connect(h.proxy()).await.unwrap();
    let port = h.upstream_addr.port();
    s.write_all(format!("CONNECT allowed.test:{port} HTTP/1.1\r\nHost: allowed.test:{port}\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = vec![0u8; 0];
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut b).await.unwrap();
        head.push(b[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
    let mut tls = h.tls(s, "allowed.test").await.unwrap();
    let resp = http_raw(&mut tls, &get("allowed.test", "/hello")).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.ends_with("ok:/hello"), "{resp}");
    let ev = h.wait_event(|e| http(e).is_some()).await;
    let ev = http(&ev).unwrap();
    assert_eq!(ev.status, Some(200));
    assert_eq!(ev.method, "GET");
}

#[tokio::test]
async fn host_header_mismatch_with_sni_denied() {
    let mut h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let s = h.transparent(AGENT_IP, h.upstream_addr).await;
    // Domain fronting: allowed SNI, denied Host.
    let mut tls = h.tls(s, "allowed.test").await.unwrap();
    let resp = http_raw(&mut tls, &get("denied.test", "/")).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(resp.contains("x-agents-firewall: denied"), "{resp}");
    h.wait_event(|e| flow(e).is_some_and(|f| f.verdict == Verdict::Deny)).await;
    assert!(h.log.all().is_empty(), "fronted request reached upstream");
}

#[tokio::test]
async fn agent_supplied_ip_ignored_when_name_present() {
    let h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    // The agent targets an address of its choice; nothing listens there. The gateway must
    // connect to the address it resolved itself for the SNI name.
    let dst: SocketAddr = format!("{EVIL_IP}:{}", h.upstream_addr.port()).parse().unwrap();
    let s = h.transparent(AGENT_IP, dst).await;
    let mut tls = h.tls(s, "allowed.test").await.unwrap();
    let resp = http_raw(&mut tls, &get("allowed.test", "/pinned")).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.ends_with("ok:/pinned"));
    assert_eq!(h.log.all()[0].path, "/pinned");
}

#[tokio::test]
async fn plain_http_transparent_uses_host_name() {
    let h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let dst: SocketAddr = format!("{EVIL_IP}:{}", h.plain_addr.port()).parse().unwrap();
    let mut s = h.transparent(AGENT_IP, dst).await;
    let resp = http_raw(&mut s, &get(&format!("allowed.test:{}", h.plain_addr.port()), "/plain")).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    // HTTP/1.0 without Host: no name, the agent's IP target is judged by the policy (denied).
    let mut s = h.transparent(AGENT_IP, dst).await;
    let resp = http_raw(&mut s, b"GET /old HTTP/1.0\r\n\r\n").await;
    assert!(resp.starts_with("HTTP/1.1 403") || resp.starts_with("HTTP/1.0 403"), "{resp}");
}

async fn post_tls(h: &Harness, host: &str, raw: Vec<u8>) -> String {
    let s = h.transparent(AGENT_IP, h.upstream_addr).await;
    let mut tls = h.tls(s, host).await.unwrap();
    http_raw(&mut tls, &raw).await
}

#[tokio::test]
async fn secret_in_body_blocked() {
    let mut h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let resp = post_tls(&h, "allowed.test", post("allowed.test", "/upload", &format!("key={AWS_KEY}"))).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(resp.contains("(rule 2)"), "{resp}");
    assert!(!h.log.contains_bytes(AWS_KEY.as_bytes()));
    let ev = h.wait_event(|e| matches!(e, GatewayEvent::Alert(a) if a.kind == AlertKind::SecretDetected)).await;
    assert!(!serde_json::to_string(&ev).unwrap().contains(AWS_KEY));
    // A clean body still goes through.
    let resp = post_tls(&h, "allowed.test", post("allowed.test", "/upload", "hello")).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
}

#[tokio::test]
async fn secret_in_url_or_header_blocked() {
    let h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let resp = post_tls(&h, "allowed.test", get("allowed.test", &format!("/q?k={AWS_KEY}"))).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    let raw = format!("GET / HTTP/1.1\r\nHost: allowed.test\r\nX-Key: {AWS_KEY}\r\nConnection: close\r\n\r\n");
    let resp = post_tls(&h, "allowed.test", raw.into_bytes()).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(h.log.all().is_empty());
}

#[tokio::test]
async fn secret_in_chunked_body_blocked() {
    let h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let body = format!("data={AWS_KEY}");
    let raw = format!(
        "POST /c HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
        body.len()
    );
    let resp = post_tls(&h, "allowed.test", raw.into_bytes()).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(!h.log.contains_bytes(AWS_KEY.as_bytes()));
}

#[tokio::test]
async fn secret_split_across_chunks_blocked() {
    let h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    // Small buffered body split across two HTTP chunks.
    let (a, b) = AWS_KEY.split_at(9);
    let raw = format!(
        "POST /s HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\nk={a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
        a.len() + 2,
        b.len()
    );
    let resp = post_tls(&h, "allowed.test", raw.into_bytes()).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    // Large body (beyond max_buffered_body = 64 KiB): streamed analysis, the secret straddles
    // a chunk boundary far into the body; the gateway must cut before relaying it.
    let s = h.transparent(AGENT_IP, h.upstream_addr).await;
    let mut tls = h.tls(s, "allowed.test").await.unwrap();
    tls.write_all(b"POST /big HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
    let filler = vec![b'a'; 100 * 1024];
    let mut first = filler.clone();
    first.extend_from_slice(b" ");
    first.extend_from_slice(a.as_bytes());
    let mut tail = b" ".to_vec();
    tail.extend_from_slice(&[b'z'; 1024]);
    for chunk in [first, b.as_bytes().to_vec(), tail] {
        tls.write_all(format!("{:x}\r\n", chunk.len()).as_bytes()).await.unwrap();
        tls.write_all(&chunk).await.unwrap();
        tls.write_all(b"\r\n").await.unwrap();
        tls.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = tls.write_all(b"0\r\n\r\n").await;
    let resp = read_all(&mut tls).await;
    assert!(!resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(!h.log.contains_bytes(AWS_KEY.as_bytes()), "secret reached the upstream");
}

async fn ws_connect(h: &Harness, host: &str) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let s = h.transparent(AGENT_IP, h.upstream_addr).await;
    let mut tls = h.tls(s, host).await.unwrap();
    let req = format!(
        "GET /ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tls.read_exact(&mut b).await.unwrap();
        head.push(b[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 101"), "{}", String::from_utf8_lossy(&head));
    tls
}

#[tokio::test]
async fn secret_in_websocket_frame_cuts_connection() {
    let mut h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let mut ws = ws_connect(&h, "allowed.test").await;
    ws.write_all(&ws_frame(0x1, b"hello", true)).await.unwrap();
    let (op, echo) = read_frame(&mut ws).await.expect("echo");
    assert_eq!((op, echo.as_slice()), (0x1, b"hello".as_slice()));
    ws.write_all(&ws_frame(0x1, format!("leak {AWS_KEY}").as_bytes(), true)).await.unwrap();
    // Connection cut: no echo of the secret, stream closed.
    let r = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut ws)).await.unwrap();
    assert!(r.is_none() || r.is_some_and(|(op, _)| op == 0x8), "connection must be cut");
    assert!(!h.log.contains_bytes(AWS_KEY.as_bytes()));
    h.wait_event(|e| matches!(e, GatewayEvent::Alert(a) if a.kind == AlertKind::SecretDetected)).await;
}

#[tokio::test]
async fn secret_split_across_websocket_messages_cut() {
    let h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let mut ws = ws_connect(&h, "allowed.test").await;
    let (a, b) = AWS_KEY.split_at(10);
    ws.write_all(&ws_frame(0x1, a.as_bytes(), true)).await.unwrap();
    let _ = read_frame(&mut ws).await;
    ws.write_all(&ws_frame(0x1, b.as_bytes(), true)).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut ws)).await.unwrap();
    assert!(r.is_none() || r.is_some_and(|(op, _)| op == 0x8), "connection must be cut");
    assert!(!h.log.all().iter().any(|s| s.ws_messages.iter().any(|m| m == b.as_bytes())));
}

#[tokio::test]
async fn secret_to_llm_provider_allowed_but_masked_in_logs() {
    let mut h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let resp = post_tls(&h, "llm.test", post("llm.test", "/v1/messages", &format!("context {AWS_KEY}"))).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(h.log.contains_bytes(AWS_KEY.as_bytes()), "LLM provider receives the content");
    let ev = h.wait_event(|e| http(e).is_some()).await;
    let json = serde_json::to_string(&ev).unwrap();
    assert!(!json.contains(AWS_KEY), "secret must be masked in logs: {json}");
    let ev = http(&ev).unwrap();
    assert!(ev.request_body.as_ref().unwrap().data.contains("[SECRET:aws_access_key:"));
    assert_eq!(ev.findings.len(), 1);
    let fev = h.wait_event(|e| flow(e).is_some_and(|f| f.verdict == Verdict::Allow)).await;
    assert!(flow(&fev).unwrap().llm_provider);
    // And it is still alerted.
    h.wait_event(|e| matches!(e, GatewayEvent::Alert(a) if a.kind == AlertKind::SecretDetected)).await;
}

#[tokio::test]
async fn cloud_metadata_denied_even_in_observe_mode() {
    let mut h = harness(Some(installed(1, ZoneMode::Observe))).await;
    // Direct IP.
    let mut t = h.transparent(AGENT_IP, "169.254.169.254:80".parse().unwrap()).await;
    let resp = http_raw(&mut t, &get("169.254.169.254", "/latest/meta-data/")).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    h.wait_event(|e| matches!(e, GatewayEvent::Alert(a) if a.kind == AlertKind::CloudMetadata)).await;
    // Through a name resolving to the metadata address.
    let mut s = tokio::net::TcpStream::connect(h.proxy()).await.unwrap();
    let resp = http_raw(&mut s, b"GET http://metadata.test/latest HTTP/1.1\r\nHost: metadata.test\r\nConnection: close\r\n\r\n").await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(h.log.all().is_empty());
}

#[tokio::test]
async fn observe_mode_allows_and_marks_observed() {
    let mut h = harness(Some(installed(1, ZoneMode::Observe))).await;
    let s = h.transparent(AGENT_IP, h.upstream_addr).await;
    let mut tls = h.tls(s, "other.test").await.unwrap();
    let resp = http_raw(&mut tls, &get("other.test", "/obs")).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    let ev = h.wait_event(|e| flow(e).is_some_and(|f| f.observed)).await;
    assert_eq!(flow(&ev).unwrap().verdict, Verdict::Allow);
}

#[tokio::test]
async fn dns_query_for_denied_name_refused_and_logged() {
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    let mut h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let sock = tokio::net::UdpSocket::bind(format!("{AGENT_IP}:0")).await.unwrap();
    let ask = |name: &str, id: u16| {
        let mut m = Message::new();
        m.set_id(id).set_message_type(MessageType::Query).set_op_code(OpCode::Query).set_recursion_desired(true);
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        m.to_vec().unwrap()
    };
    sock.send_to(&ask("denied.test.", 1), h.dns()).await.unwrap();
    let mut buf = [0u8; 1500];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await.unwrap().unwrap();
    let resp = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(resp.response_code(), ResponseCode::Refused);
    assert!(resp.answers().is_empty());
    let ev = h.wait_event(|e| matches!(e, GatewayEvent::Dns(d) if d.qname == "denied.test")).await;
    let GatewayEvent::Dns(d) = ev else { unreachable!() };
    assert_eq!(d.verdict, Verdict::Deny);
    // An allowed name resolves (through the gateway's own resolver).
    sock.send_to(&ask("allowed.test.", 2), h.dns()).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await.unwrap().unwrap();
    let resp = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert_eq!(resp.answers().len(), 1);
    // Unknown agent: refused.
    let other = tokio::net::UdpSocket::bind(format!("{UNKNOWN_IP}:0")).await.unwrap();
    other.send_to(&ask("allowed.test.", 3), h.dns()).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), other.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(Message::from_vec(&buf[..n]).unwrap().response_code(), ResponseCode::Refused);
}

#[tokio::test]
async fn internal_flow_allowed_and_logged_detailed() {
    let mut h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let mut t = h.transparent(AGENT_IP, h.internal_addr).await;
    // Server-first or binary protocol: no HTTP/TLS, relayed at L4 after the sniff delay.
    t.write_all(b"\x00ping").await.unwrap();
    let mut buf = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), t.read_exact(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf, b"\x00ping");
    drop(t);
    let ev = h.wait_event(|e| flow(e).is_some_and(|f| f.internal)).await;
    let f = flow(&ev).unwrap();
    assert_eq!(f.verdict, Verdict::Allow);
    assert_eq!(f.decision.rule_name, "internal-monitor");
    assert!(f.bytes_out >= 5 && f.bytes_in >= 5, "{f:?}");
    h.wait_event(|e| matches!(e, GatewayEvent::Alert(a) if a.kind == AlertKind::NewInternalHost)).await;
}

#[tokio::test]
async fn admin_api_exec_recognized() {
    let mut h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let resp = post_tls(&h, "k8s.test", post("k8s.test", "/api/v1/namespaces/prod/pods/web-0/exec", "")).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    let ev = h.wait_event(|e| http(e).is_some_and(|h| h.admin_action.is_some())).await;
    let a = http(&ev).unwrap().admin_action.clone().unwrap();
    assert_eq!(a.system, AdminSystem::Kubernetes);
    assert_eq!(a.action, "exec");
    assert_eq!(a.resource, "namespaces/prod/pods/web-0");
    h.wait_event(|e| matches!(e, GatewayEvent::Alert(a) if a.kind == AlertKind::UnusualAdminAction)).await;
}

#[tokio::test]
async fn console_unreachable_keeps_enforcing() {
    // A console URL that refuses connections: the gateway keeps its persisted policy.
    let h = harness_with(Some(installed(3, ZoneMode::Enforce)), |o| {
        o.console_url = Some("https://127.0.0.1:9".into());
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(h.gw.state.store.revision(), Some(3));
    let resp = post_tls(&h, "allowed.test", get("allowed.test", "/still")).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    let resp = post_tls(&h, "denied.test", get("denied.test", "/")).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
}

#[tokio::test]
async fn sni_flood_is_rate_limited() {
    let mut h = harness(Some(installed(1, ZoneMode::Observe))).await;
    let mut refused = 0;
    for i in 0..30 {
        let s = h.transparent(AGENT_IP, h.upstream_addr).await;
        if h.tls(s, &format!("n{i}.flood.test")).await.is_err() {
            refused += 1;
        }
    }
    assert!(refused >= 5, "leaf minting must be rate limited per agent ({refused})");
    h.wait_event(|e| matches!(e, GatewayEvent::Alert(_))).await;
}

#[tokio::test]
async fn denied_sni_towards_allowed_ip_is_denied() {
    let mut h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    // The agent targets an IP accepted by an IP object, but names a denied host: the name
    // decides (the gateway would connect to the name's address, not to the agent's choice).
    let dst: SocketAddr = format!("{TRUSTED_IP}:{}", h.upstream_addr.port()).parse().unwrap();
    let s = h.transparent(AGENT_IP, dst).await;
    let mut tls = h.tls(s, "denied.test").await.unwrap();
    let resp = http_raw(&mut tls, &get("denied.test", "/")).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(resp.contains("denied.test not allowed for daniel-bot (rule default-deny)"), "{resp}");
    h.wait_event(|e| flow(e).is_some_and(|f| f.verdict == Verdict::Deny)).await;
    assert!(h.log.all().is_empty());
}

#[tokio::test]
async fn rewritten_host_or_absolute_uri_denied() {
    let h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    for raw in [
        // Absolute URI towards another host behind an allowed SNI.
        b"GET https://denied.test/ HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n".to_vec(),
        // Host with a trailing label.
        get("allowed.test.denied.test", "/"),
        // Host with userinfo-like trick.
        get("allowed.test@denied.test", "/"),
    ] {
        let resp = post_tls(&h, "allowed.test", raw).await;
        assert!(resp.starts_with("HTTP/1.1 403") || resp.starts_with("HTTP/1.1 400"), "{resp}");
    }
    assert!(h.log.all().is_empty());
}

#[tokio::test]
async fn denied_path_behind_allowed_connection() {
    let h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let resp = post_tls(&h, "allowed.test", get("allowed.test", "/data")).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    for path in ["/admin", "/admin/users", "/x/../admin", "/x/..;/admin", "/%61dmin", "//admin"] {
        let resp = post_tls(&h, "allowed.test", get("allowed.test", path)).await;
        assert!(resp.starts_with("HTTP/1.1 403"), "{path}: {resp}");
        assert!(resp.contains("(rule 4)"), "{path}: {resp}");
    }
    assert_eq!(h.log.all().len(), 1, "only /data reached the upstream");
}

#[tokio::test]
async fn path_accept_rule_is_evaluated_per_request() {
    let h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let resp = post_tls(&h, "path.test", get("path.test", "/v1/ok")).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    let resp = post_tls(&h, "path.test", get("path.test", "/other")).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(resp.contains("(rule default-deny)"), "{resp}");
    // Several requests on one connection: each one is judged.
    let s = h.transparent(AGENT_IP, h.upstream_addr).await;
    let mut tls = h.tls(s, "path.test").await.unwrap();
    let both = b"GET /v1/a HTTP/1.1\r\nHost: path.test\r\n\r\nGET /admin HTTP/1.1\r\nHost: path.test\r\nConnection: close\r\n\r\n";
    let resp = http_raw(&mut tls, both).await;
    assert!(resp.contains("HTTP/1.1 200") && resp.contains("HTTP/1.1 403"), "{resp}");
    assert_eq!(h.log.all().iter().filter(|s| s.path.starts_with("/v1/")).count(), 2);
    assert!(!h.log.all().iter().any(|s| s.path == "/admin" || s.path == "/other"));
}
