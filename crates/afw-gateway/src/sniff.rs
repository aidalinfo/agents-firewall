//! Application detection from the first bytes of a connection: TLS ClientHello (SNI), HTTP
//! request (Host), SSH banner, anything else.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Bytes read at most while sniffing.
pub const MAX_SNIFF: usize = 16 * 1024 + 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sniff {
    NeedMore,
    Tls { sni: Option<String> },
    Http { host: Option<String> },
    Ssh,
    Other,
}

const METHODS: &[&str] = &[
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
];

pub fn classify(buf: &[u8]) -> Sniff {
    if buf.is_empty() {
        return Sniff::NeedMore;
    }
    if buf[0] == 0x16 {
        if buf.len() < 5 {
            return Sniff::NeedMore;
        }
        if buf[1] != 0x03 {
            return Sniff::Other;
        }
        let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if buf.len() < 5 + len {
            return Sniff::NeedMore;
        }
        return Sniff::Tls {
            sni: parse_sni(&buf[5..5 + len]),
        };
    }
    if buf.starts_with(b"SSH-") {
        return Sniff::Ssh;
    }
    if b"SSH-".starts_with(&buf[..buf.len().min(4)]) {
        return Sniff::NeedMore;
    }
    let text = &buf[..buf.len().min(8)];
    let maybe_method = METHODS.iter().any(|m| {
        let m = m.as_bytes();
        let n = text.len().min(m.len());
        text[..n] == m[..n]
    });
    if !maybe_method {
        return Sniff::Other;
    }
    if !METHODS.iter().any(|m| buf.starts_with(m.as_bytes())) {
        return Sniff::NeedMore;
    }
    match find(buf, b"\r\n\r\n") {
        Some(end) => Sniff::Http {
            host: header(&buf[..end], "host"),
        },
        None if buf.len() >= MAX_SNIFF => Sniff::Http { host: None },
        None => Sniff::NeedMore,
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Value of a header in a raw HTTP/1 head (first occurrence).
pub fn header(head: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n").skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

/// Host part of a `Host` header / authority (`name`, `name:port`, `[v6]:port`), lowercased,
/// trailing dot removed.
pub fn host_only(authority: &str) -> String {
    let a = authority.trim();
    let h = if let Some(rest) = a.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if a.matches(':').count() == 1 {
        a.split(':').next().unwrap_or(a)
    } else {
        a
    };
    h.trim_end_matches('.').to_ascii_lowercase()
}

/// SNI host name from a TLS handshake record body (ClientHello). `None` when absent or when
/// the hello is malformed.
pub fn parse_sni(hs: &[u8]) -> Option<String> {
    let mut p = Parser(hs);
    if p.u8()? != 0x01 {
        return None;
    }
    p.skip(3)?; // handshake length (may exceed this record; parse what is present)
    p.skip(2 + 32)?; // version, random
    let sid = p.u8()? as usize;
    p.skip(sid)?;
    let cs = p.u16()? as usize;
    p.skip(cs)?;
    let comp = p.u8()? as usize;
    p.skip(comp)?;
    let ext_len = p.u16()? as usize;
    let mut ext = Parser(p.take(ext_len.min(p.0.len()))?);
    while ext.0.len() >= 4 {
        let typ = ext.u16()?;
        let len = ext.u16()? as usize;
        let data = ext.take(len)?;
        if typ == 0 {
            let mut d = Parser(data);
            let list = d.u16()? as usize;
            let mut l = Parser(d.take(list)?);
            while !l.0.is_empty() {
                let kind = l.u8()?;
                let n = l.u16()? as usize;
                let name = l.take(n)?;
                if kind == 0 {
                    let s = std::str::from_utf8(name).ok()?;
                    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_graphic()) {
                        return None;
                    }
                    return Some(s.trim_end_matches('.').to_ascii_lowercase());
                }
            }
        }
    }
    None
}

struct Parser<'a>(&'a [u8]);

impl<'a> Parser<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}

/// Reads until the protocol is recognised, `timeout` elapses without data (server-first
/// protocols) or [`MAX_SNIFF`] bytes are read.
pub async fn read_initial<S: AsyncRead + Unpin>(
    s: &mut S,
    timeout: Duration,
) -> std::io::Result<(Vec<u8>, Sniff)> {
    let mut buf = Vec::with_capacity(2048);
    let deadline = tokio::time::Instant::now() + timeout;
    let mut chunk = [0u8; 4096];
    loop {
        let c = classify(&buf);
        if c != Sniff::NeedMore {
            return Ok((buf, c));
        }
        if buf.len() >= MAX_SNIFF {
            return Ok((buf, Sniff::Other));
        }
        let want = chunk.len().min(MAX_SNIFF - buf.len());
        match tokio::time::timeout_at(deadline, s.read(&mut chunk[..want])).await {
            Err(_) => return Ok((buf, Sniff::Other)),
            Ok(Ok(0)) => return Ok((buf, Sniff::Other)),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_host_detected() {
        assert_eq!(
            classify(b"GET / HTTP/1.1\r\nHost: Example.COM.:8080\r\n\r\n"),
            Sniff::Http {
                host: Some("Example.COM.:8080".into())
            }
        );
        assert_eq!(classify(b"GE"), Sniff::NeedMore);
        assert_eq!(
            classify(b"GET / HTTP/1.0\r\n\r\n"),
            Sniff::Http { host: None }
        );
        assert_eq!(classify(b"\x00\x01"), Sniff::Other);
        assert_eq!(classify(b"SSH-2.0-OpenSSH"), Sniff::Ssh);
        assert_eq!(host_only("Example.COM.:8080"), "example.com");
        assert_eq!(host_only("[::1]:443"), "::1");
        assert_eq!(host_only("::1"), "::1");
    }

    #[test]
    fn garbage_hello_has_no_sni() {
        assert_eq!(parse_sni(&[1, 0, 0, 5, 3, 3]), None);
        assert_eq!(
            classify(&[0x16, 0x03, 0x01, 0x00, 0x02, 1, 0]),
            Sniff::Tls { sni: None }
        );
    }
}
