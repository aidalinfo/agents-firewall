//! Matching primitives: host names, domain patterns, address sets, paths.
//!
//! Matching is three-valued ([`M`]): a malformed host or path is `Unsure`, which satisfies a
//! deny rule but never an accept rule (fail closed, ADR 0016).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use afw_core::policy::{NetObject, NetObjectSpec};
use ipnet::IpNet;
use uuid::Uuid;

/// Three-valued match result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum M {
    No,
    Unsure,
    Yes,
}

impl M {
    /// Logical AND: `No` wins, then `Unsure`.
    pub(crate) fn and(self, other: M) -> M {
        self.min(other)
    }
    /// Logical OR: `Yes` wins, then `Unsure`.
    pub(crate) fn or(self, other: M) -> M {
        self.max(other)
    }
    fn rank(self) -> u8 {
        match self {
            M::No => 0,
            M::Unsure => 1,
            M::Yes => 2,
        }
    }
    fn min(self, o: M) -> M {
        if self.rank() <= o.rank() { self } else { o }
    }
    fn max(self, o: M) -> M {
        if self.rank() >= o.rank() { self } else { o }
    }
}

/// A host as seen in the flow, normalised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Host<'a> {
    Absent,
    /// Lowercase ASCII name without trailing dot.
    Name(Cow<'a, str>),
    Ip(IpAddr),
    /// Not a valid ASCII host name (non-ASCII, empty label, forbidden character…).
    Invalid,
    /// Looks like an address but is not a canonical literal (`2852039166`, `0xa9fea9fe`,
    /// `169.254.43518`, `[fe80::1%eth0]`, `host:443`…): uncertain for every set.
    IpLike,
}

/// Canonical form of an address: IPv4-mapped (`::ffff:a.b.c.d`), NAT64 (`64:ff9b::/96`) and
/// IPv4-compatible (`::a.b.c.d`, except `::` and `::1`) IPv6 addresses become IPv4.
pub(crate) fn canon_ip(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let low = ((s[6] as u32) << 16) | s[7] as u32;
            let nat64 = s[..6] == [0x64, 0xff9b, 0, 0, 0, 0];
            let compat = s[..6] == [0; 6] && low > 1;
            if nat64 || compat {
                IpAddr::V4(std::net::Ipv4Addr::from(low))
            } else {
                IpAddr::V6(v6)
            }
        }
        v4 => v4,
    }
}

/// Canonical form of a network: an IPv4-mapped IPv6 network becomes the IPv4 network.
pub(crate) fn canon_net(net: IpNet) -> IpNet {
    let net = net.trunc();
    if let IpNet::V6(v6) = net
        && v6.prefix_len() >= 96
        && let Some(v4) = v6.network().to_ipv4_mapped()
    {
        return IpNet::new(IpAddr::V4(v4), v6.prefix_len() - 96)
            .expect("prefix fits")
            .trunc();
    }
    net
}

/// A name whose last label is numeric (`1234`, `0x1f`) is an inet_aton-style address form.
fn numeric_form(name: &str) -> bool {
    let last = name.rsplit('.').next().unwrap_or("");
    !last.is_empty()
        && (last.bytes().all(|c| c.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .is_some_and(|h| h.bytes().all(|c| c.is_ascii_hexdigit())))
}

/// Validates a lowercase name without trailing dot: ASCII labels of `[a-z0-9_-]`, 1 to 63
/// characters each, 253 characters at most.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
        })
}

/// Normalises a flow host: IP literal (with or without brackets), else case-insensitive name
/// with one trailing dot ignored. Non-ASCII names are `Invalid` (no IDN mapping, ADR 0016).
pub(crate) fn classify_host(raw: &str) -> Host<'_> {
    if let Some(inner) = raw.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return match inner.parse::<std::net::Ipv6Addr>() {
            Ok(ip) => Host::Ip(canon_ip(IpAddr::V6(ip))),
            Err(_) => Host::IpLike,
        };
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Host::Ip(canon_ip(ip));
    }
    if raw.contains(['[', ']', ':', '%']) {
        return Host::IpLike;
    }
    let name = raw.strip_suffix('.').unwrap_or(raw);
    if numeric_form(&name.to_ascii_lowercase()) {
        return Host::IpLike;
    }
    if !name.is_ascii() {
        return Host::Invalid;
    }
    let name: Cow<'_, str> = if name.bytes().any(|c| c.is_ascii_uppercase()) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    };
    if valid_name(&name) {
        Host::Name(name)
    } else {
        Host::Invalid
    }
}

/// A resolved destination leaf.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Leaf {
    Any,
    /// Exact lowercase name.
    Exact(Box<str>),
    /// Wildcard `*.example.com`, stored as the suffix `.example.com`.
    Suffix(Box<str>),
    Net(IpNet),
    Range(IpAddr, IpAddr),
}

/// Parses a domain pattern of a network object. `None` when invalid.
pub(crate) fn parse_domain_pattern(pattern: &str) -> Option<Leaf> {
    let p = pattern.strip_suffix('.').unwrap_or(pattern);
    if !p.is_ascii() || p.parse::<IpAddr>().is_ok() {
        return None;
    }
    let p = p.to_ascii_lowercase();
    if let Some(rest) = p.strip_prefix("*.") {
        valid_name(rest).then(|| Leaf::Suffix(format!(".{rest}").into()))
    } else {
        valid_name(&p).then(|| Leaf::Exact(p.into()))
    }
}

/// Leaf of a non-group object; `None` for groups or invalid specs.
pub(crate) fn leaf_of(spec: &NetObjectSpec) -> Option<Leaf> {
    match spec {
        NetObjectSpec::Domain { pattern } => parse_domain_pattern(pattern),
        NetObjectSpec::Host { ip } => Some(Leaf::Net(IpNet::from(canon_ip(*ip)))),
        NetObjectSpec::Network { cidr } => Some(Leaf::Net(canon_net(*cidr))),
        NetObjectSpec::Range { start, end } => {
            let (s, e) = (canon_ip(*start), canon_ip(*end));
            (s.is_ipv4() == e.is_ipv4() && s <= e).then_some(Leaf::Range(s, e))
        }
        NetObjectSpec::Any => Some(Leaf::Any),
        NetObjectSpec::Group { .. } => None,
    }
}

/// Resolves objects to leaves through (nested) groups. Tolerates cycles and dangling members
/// (they are skipped); `compile` rejects those beforehand.
pub(crate) struct Resolver<'a> {
    objects: HashMap<Uuid, &'a NetObject>,
}

impl<'a> Resolver<'a> {
    pub(crate) fn new(objects: &'a [NetObject]) -> Self {
        Self {
            objects: objects.iter().map(|o| (o.id, o)).collect(),
        }
    }

    pub(crate) fn get(&self, id: &Uuid) -> Option<&'a NetObject> {
        self.objects.get(id).copied()
    }

    /// Leaves of the given objects (union).
    pub(crate) fn leaves(&self, ids: &[Uuid]) -> Vec<Leaf> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for id in ids {
            self.collect(id, &mut out, &mut seen);
        }
        out
    }

    /// All object ids reachable from `ids` (the objects themselves and group members).
    pub(crate) fn closure(&self, ids: &[Uuid], seen: &mut HashSet<Uuid>) {
        let mut stack: Vec<Uuid> = ids.to_vec();
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            if let Some(NetObject {
                spec: NetObjectSpec::Group { members },
                ..
            }) = self.get(&id)
            {
                stack.extend(members.iter().copied());
            }
        }
    }

    fn collect(&self, id: &Uuid, out: &mut Vec<Leaf>, seen: &mut HashSet<Uuid>) {
        if !seen.insert(*id) {
            return;
        }
        let Some(obj) = self.get(id) else { return };
        match &obj.spec {
            NetObjectSpec::Group { members } => {
                for m in members {
                    self.collect(m, out, seen);
                }
            }
            spec => out.extend(leaf_of(spec)),
        }
    }
}

/// Compiled set of destinations.
#[derive(Clone, Debug, Default)]
pub(crate) struct DestSet {
    any: bool,
    exact: Vec<Box<str>>,
    suffixes: Vec<Box<str>>,
    nets: Vec<IpNet>,
    ranges: Vec<(IpAddr, IpAddr)>,
}

impl DestSet {
    pub(crate) fn from_leaves(leaves: impl IntoIterator<Item = Leaf>) -> Self {
        let mut s = DestSet::default();
        for l in leaves {
            match l {
                Leaf::Any => s.any = true,
                Leaf::Exact(n) => s.exact.push(n),
                Leaf::Suffix(n) => s.suffixes.push(n),
                Leaf::Net(n) => s.nets.push(n),
                Leaf::Range(a, b) => s.ranges.push((a, b)),
            }
        }
        s.exact.sort_unstable();
        s.exact.dedup();
        s.suffixes.sort_unstable();
        s.suffixes.dedup();
        s.nets.sort_unstable();
        s.nets.dedup();
        s
    }

    pub(crate) fn add_net(&mut self, net: IpNet) {
        self.nets.push(net);
    }

    pub(crate) fn add_name(&mut self, name: &str) {
        self.exact.push(name.into());
        self.exact.sort_unstable();
    }

    fn has_names(&self) -> bool {
        !self.exact.is_empty() || !self.suffixes.is_empty()
    }

    pub(crate) fn contains_ip(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(&ip))
            || self
                .ranges
                .iter()
                .any(|&(a, b)| a.is_ipv4() == ip.is_ipv4() && a <= ip && ip <= b)
    }

    pub(crate) fn has_ips(&self) -> bool {
        !self.nets.is_empty() || !self.ranges.is_empty()
    }

    /// Matches a flow destination: names against `host`, addresses against `ip`.
    pub(crate) fn matches(&self, host: &Host<'_>, ip: Option<IpAddr>) -> M {
        if self.any {
            return M::Yes;
        }
        if let Some(ip) = ip
            && self.contains_ip(ip)
        {
            return M::Yes;
        }
        match host {
            Host::Name(name) => {
                let name: &str = name;
                if self.exact.binary_search_by(|e| (**e).cmp(name)).is_ok()
                    || self
                        .suffixes
                        .iter()
                        .any(|s| name.len() > s.len() && name.ends_with(&**s))
                {
                    M::Yes
                } else {
                    M::No
                }
            }
            Host::Invalid if self.has_names() => M::Unsure,
            Host::IpLike if self.has_names() || self.has_ips() => M::Unsure,
            _ => M::No,
        }
    }
}

/// Normalises a request path: query and fragment removed, percent-decoding, `\` treated as
/// `/`, empty and `.` segments removed, `..` resolved (never above the root). `None` when the
/// path is malformed (not absolute, bad escape, NUL or control byte, invalid UTF-8).
pub(crate) fn normalize_path(raw: &str) -> Option<String> {
    let raw = raw.split(['?', '#']).next().unwrap_or("");
    let bytes = raw.as_bytes();
    if !matches!(bytes.first(), Some(b'/') | Some(b'\\')) {
        return None;
    }
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            let hex = |c: u8| (c as char).to_digit(16);
            let hi = bytes.get(i + 1).copied().and_then(hex)?;
            let lo = bytes.get(i + 2).copied().and_then(hex)?;
            decoded.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            decoded.push(b);
            i += 1;
        }
    }
    // A `%` left after one decoding pass (double encoding) is ambiguous: uncertain.
    if decoded.iter().any(|&b| b < 0x20 || b == 0x7f || b == b'%') {
        return None;
    }
    let s = String::from_utf8(decoded).ok()?;
    let mut segs: Vec<&str> = Vec::new();
    for seg in s.split(['/', '\\']) {
        // Path parameters (`/a;x`, `..;`) are dropped as servlet containers do.
        let seg = seg.split(';').next().unwrap_or("");
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    let mut out = String::with_capacity(s.len());
    for seg in &segs {
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() {
        out.push('/');
    }
    Some(out)
}

/// Segment-aware prefix: `/v1` covers `/v1` and `/v1/x`, not `/v1x`. Both normalised.
pub(crate) fn path_has_prefix(path: &str, prefix: &str) -> bool {
    prefix == "/"
        || path == prefix
        || (path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(
            normalize_path("/a/./b//c/../d?x=/..").as_deref(),
            Some("/a/b/d")
        );
        assert_eq!(normalize_path("/../../etc").as_deref(), Some("/etc"));
        assert_eq!(normalize_path("/%2e%2E/x").as_deref(), Some("/x"));
        assert_eq!(normalize_path("/").as_deref(), Some("/"));
        assert_eq!(normalize_path("/%"), None);
        assert_eq!(normalize_path("/%ff"), None);
        assert_eq!(normalize_path("x"), None);
        assert!(path_has_prefix("/v1/x", "/v1"));
        assert!(!path_has_prefix("/v1x", "/v1"));
    }

    #[test]
    fn three_valued_logic() {
        assert_eq!(M::Yes.and(M::Unsure), M::Unsure);
        assert_eq!(M::No.and(M::Unsure), M::No);
        assert_eq!(M::No.or(M::Unsure), M::Unsure);
        assert_eq!(M::Yes.or(M::No), M::Yes);
    }
}
