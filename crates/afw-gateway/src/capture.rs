//! On-demand packet captures per agent (EF-33), written in the libpcap format without libpcap:
//! `LINKTYPE_RAW` (101) records holding reconstructed IPv4/IPv6 + TCP headers around the bytes
//! seen on the agent side of the gateway (the cleartext after TLS termination when inspected).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use uuid::Uuid;

/// Upper bound of one capture file.
pub const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;
/// Upper bound of a capture duration.
pub const MAX_CAPTURE_SECS: u32 = 3600;
const LINKTYPE_RAW: u32 = 101;
const MAX_SEGMENT: usize = 65_000;

pub struct CaptureSession {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub until: Instant,
    data: Mutex<Vec<u8>>,
}

impl CaptureSession {
    pub fn new(id: Uuid, agent_id: Uuid, duration: Duration) -> Self {
        Self {
            id,
            agent_id,
            until: Instant::now() + duration,
            data: Mutex::new(pcap_header()),
        }
    }

    pub fn active(&self) -> bool {
        Instant::now() < self.until
    }

    /// Records `payload` sent from `src` to `dst` (one or more TCP segments).
    pub fn record(&self, src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32, payload: &[u8]) {
        if !self.active() {
            return;
        }
        let mut data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let mut seq = seq;
        for chunk in payload.chunks(MAX_SEGMENT) {
            let pkt = packet(src, dst, seq, ack, chunk);
            if data.len() + 16 + pkt.len() > MAX_CAPTURE_BYTES {
                return;
            }
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
            data.extend_from_slice(&(now.as_secs() as u32).to_le_bytes());
            data.extend_from_slice(&now.subsec_micros().to_le_bytes());
            data.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
            data.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
            data.extend_from_slice(&pkt);
            seq = seq.wrapping_add(chunk.len() as u32);
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.data.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

pub fn pcap_header() -> Vec<u8> {
    let mut h = Vec::with_capacity(24);
    h.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    h.extend_from_slice(&2u16.to_le_bytes());
    h.extend_from_slice(&4u16.to_le_bytes());
    h.extend_from_slice(&0i32.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());
    h.extend_from_slice(&65535u32.to_le_bytes());
    h.extend_from_slice(&LINKTYPE_RAW.to_le_bytes());
    h
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in data.chunks(2) {
        let w = if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], 0]) };
        sum += w as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_header(src: u16, dst: u16, seq: u32, ack: u32) -> Vec<u8> {
    let mut t = Vec::with_capacity(20);
    t.extend_from_slice(&src.to_be_bytes());
    t.extend_from_slice(&dst.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    t.push(5 << 4); // data offset
    t.push(0x18); // PSH | ACK
    t.extend_from_slice(&65535u16.to_be_bytes());
    t.extend_from_slice(&[0, 0, 0, 0]); // checksum (not computed), urgent
    t
}

/// IPv4 or IPv6 packet carrying one TCP segment. Mixed families are mapped to IPv6.
pub fn packet(src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
    let tcp = tcp_header(src.port(), dst.port(), seq, ack);
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = (20 + tcp.len() + payload.len()) as u16;
            let mut ip = vec![0x45, 0];
            ip.extend_from_slice(&total.to_be_bytes());
            ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]);
            ip.extend_from_slice(&s.octets());
            ip.extend_from_slice(&d.octets());
            let c = checksum(&ip);
            ip[10..12].copy_from_slice(&c.to_be_bytes());
            ip.extend_from_slice(&tcp);
            ip.extend_from_slice(payload);
            ip
        }
        (s, d) => {
            let v6 = |a: IpAddr| match a {
                IpAddr::V4(v) => v.to_ipv6_mapped(),
                IpAddr::V6(v) => v,
            };
            let mut ip = vec![0x60, 0, 0, 0];
            ip.extend_from_slice(&((tcp.len() + payload.len()) as u16).to_be_bytes());
            ip.push(6);
            ip.push(64);
            ip.extend_from_slice(&v6(s).octets());
            ip.extend_from_slice(&v6(d).octets());
            ip.extend_from_slice(&tcp);
            ip.extend_from_slice(payload);
            ip
        }
    }
}

/// Active captures, by agent.
#[derive(Default)]
pub struct Captures {
    active: Mutex<HashMap<Uuid, Arc<CaptureSession>>>,
}

impl Captures {
    pub fn start(&self, id: Uuid, agent_id: Uuid, duration_secs: u32) -> Arc<CaptureSession> {
        let secs = duration_secs.clamp(1, MAX_CAPTURE_SECS);
        let s = Arc::new(CaptureSession::new(id, agent_id, Duration::from_secs(secs as u64)));
        self.active.lock().unwrap_or_else(|e| e.into_inner()).insert(agent_id, s.clone());
        s
    }

    pub fn for_agent(&self, agent_id: Option<Uuid>) -> Option<Arc<CaptureSession>> {
        let agent_id = agent_id?;
        let map = self.active.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&agent_id).filter(|s| s.active()).cloned()
    }

    pub fn finish(&self, s: &CaptureSession) {
        let mut map = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if map.get(&s.agent_id).is_some_and(|x| x.id == s.id) {
            map.remove(&s.agent_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_records_are_well_formed() {
        let s = CaptureSession::new(Uuid::nil(), Uuid::nil(), Duration::from_secs(5));
        s.record("10.0.0.2:4000".parse().unwrap(), "1.2.3.4:443".parse().unwrap(), 1, 1, b"hello");
        let b = s.bytes();
        assert_eq!(&b[..4], &0xa1b2c3d4u32.to_le_bytes());
        assert_eq!(u32::from_le_bytes(b[20..24].try_into().unwrap()), 101);
        let incl = u32::from_le_bytes(b[32..36].try_into().unwrap()) as usize;
        assert_eq!(incl, 20 + 20 + 5);
        let pkt = &b[40..40 + incl];
        assert_eq!(pkt[0], 0x45);
        assert_eq!(checksum(&pkt[..20]), 0, "valid IPv4 header checksum");
        assert_eq!(&pkt[40..], b"hello");
    }
}
