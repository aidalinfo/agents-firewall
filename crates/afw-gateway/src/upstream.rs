//! Upstream name resolution and connection.
//!
//! When a flow carries a name (SNI, Host, CONNECT target), the gateway resolves it itself and
//! connects to the address it resolved: the address chosen by the agent is never used
//! (ADR 0018). Resolutions to cloud metadata addresses are refused unless the decision comes
//! from an explicit baseline rule.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use futures::future::BoxFuture;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const DNS_TIMEOUT: Duration = Duration::from_secs(4);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Cloud metadata endpoints (AWS/GCP/Azure/OpenStack IPv4, AWS IPv6).
/// Aligned with the engine's built-in list (ADR 0016 §16): all of 169.254.0.0/16 (link
/// local), 100.100.100.200 (Alibaba) and fd00:ec2::254 (AWS IPv6); mapped IPv4 included.
pub fn is_cloud_metadata(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => (v4.octets()[0] == 169 && v4.octets()[1] == 254) || v4 == Ipv4Addr::new(100, 100, 100, 200),
        IpAddr::V6(v6) => v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254),
    }
}

/// Well-known metadata host names.
pub fn is_cloud_metadata_name(name: &str) -> bool {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    n == "metadata.google.internal" || n == "metadata.goog" || n == "metadata" || n == "instance-data" || n == "instance-data.ec2.internal"
}

pub trait Resolver: Send + Sync {
    /// Resolves `name` to addresses (A then AAAA).
    fn lookup<'a>(&'a self, name: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>>;
    /// Forwards a raw DNS query (types other than A/AAAA). `None` when unsupported.
    fn forward<'a>(&'a self, _query: &'a [u8]) -> BoxFuture<'a, Option<Vec<u8>>> {
        Box::pin(async { None })
    }
}

/// Fixed name table (tests, recette).
pub struct StaticResolver(HashMap<String, Vec<IpAddr>>);

impl StaticResolver {
    pub fn new(map: HashMap<String, Vec<IpAddr>>) -> Self {
        Self(map.into_iter().map(|(k, v)| (normalize(&k), v)).collect())
    }
}

impl Resolver for StaticResolver {
    fn lookup<'a>(&'a self, name: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            self.0
                .get(&normalize(name))
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no address for {name}")))
        })
    }
}

/// Resolver querying a DNS server over UDP (TCP when truncated).
pub struct DnsResolver {
    pub server: SocketAddr,
}

impl DnsResolver {
    async fn exchange(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let bind: SocketAddr = if self.server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(self.server).await?;
        sock.send(query).await?;
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(DNS_TIMEOUT, sock.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream DNS timeout"))??;
        buf.truncate(n);
        // Truncated: retry over TCP.
        if n >= 3 && buf[2] & 0x02 != 0 {
            return self.exchange_tcp(query).await;
        }
        Ok(buf)
    }

    async fn exchange_tcp(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let fut = async {
            let mut s = TcpStream::connect(self.server).await?;
            s.write_all(&(query.len() as u16).to_be_bytes()).await?;
            s.write_all(query).await?;
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await?;
            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut buf).await?;
            Ok(buf)
        };
        tokio::time::timeout(DNS_TIMEOUT, fut)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream DNS timeout"))?
    }

    async fn query(&self, name: &str, rtype: RecordType) -> io::Result<Vec<IpAddr>> {
        let fqdn = format!("{}.", name.trim_end_matches('.'));
        let qname = Name::from_ascii(&fqdn).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut m = Message::new();
        m.set_id(rand_id())
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true);
        m.add_query(Query::query(qname, rtype));
        let raw = m.to_vec().map_err(|e| io::Error::other(e.to_string()))?;
        let resp = Message::from_vec(&self.exchange(&raw).await?).map_err(|e| io::Error::other(e.to_string()))?;
        if resp.id() != m.id() {
            return Err(io::Error::other("DNS response id mismatch"));
        }
        Ok(resp
            .answers()
            .iter()
            .filter_map(|r| match r.data() {
                Some(RData::A(a)) => Some(IpAddr::V4(a.0)),
                Some(RData::AAAA(a)) => Some(IpAddr::V6(a.0)),
                _ => None,
            })
            .collect())
    }
}

impl Resolver for DnsResolver {
    fn lookup<'a>(&'a self, name: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            let mut ips = self.query(name, RecordType::A).await.unwrap_or_default();
            if ips.is_empty() {
                ips = self.query(name, RecordType::AAAA).await?;
            }
            if ips.is_empty() {
                return Err(io::Error::new(io::ErrorKind::NotFound, format!("no address for {name}")));
            }
            Ok(ips)
        })
    }

    fn forward<'a>(&'a self, query: &'a [u8]) -> BoxFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move { self.exchange(query).await.ok() })
    }
}

/// Resolver of the host (`getaddrinfo`), used when no upstream DNS server is known.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn lookup<'a>(&'a self, name: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            let addrs = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((name, 0)))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "resolution timeout"))??;
            let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            if ips.is_empty() {
                return Err(io::Error::new(io::ErrorKind::NotFound, format!("no address for {name}")));
            }
            Ok(ips)
        })
    }
}

/// `AFW_UPSTREAM_DNS` if set, else the first `nameserver` of `/etc/resolv.conf`, else the
/// system resolver.
pub fn default_resolver(upstream_dns: Option<SocketAddr>) -> std::sync::Arc<dyn Resolver> {
    if let Some(server) = upstream_dns {
        return std::sync::Arc::new(DnsResolver { server });
    }
    if let Ok(conf) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in conf.lines() {
            let mut it = line.split_whitespace();
            if it.next() == Some("nameserver")
                && let Some(ip) = it.next().and_then(|s| s.parse::<IpAddr>().ok())
            {
                return std::sync::Arc::new(DnsResolver {
                    server: SocketAddr::new(ip, 53),
                });
            }
        }
    }
    std::sync::Arc::new(SystemResolver)
}

pub fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn rand_id() -> u16 {
    let mut b = [0u8; 2];
    let _ = rustls::crypto::ring::default_provider().secure_random.fill(&mut b);
    u16::from_ne_bytes(b)
}

/// Connects to `addr` with a timeout.
pub async fn connect(addr: SocketAddr) -> io::Result<TcpStream> {
    let s = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream connect timeout"))??;
    let _ = s.set_nodelay(true);
    Ok(s)
}
