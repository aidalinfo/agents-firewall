//! Validation and normalization of names placed in certificates.

use std::net::IpAddr;

use crate::TlsError;

/// A validated subject for a leaf certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum LeafName {
    Dns(String),
    Ip(IpAddr),
}

impl LeafName {
    /// Cache key / canonical text form.
    pub(crate) fn key(&self) -> String {
        match self {
            LeafName::Dns(d) => d.clone(),
            LeafName::Ip(ip) => ip.to_string(),
        }
    }

    pub(crate) fn san(&self) -> Result<rcgen::SanType, TlsError> {
        Ok(match self {
            LeafName::Dns(d) => rcgen::SanType::DnsName(
                d.as_str()
                    .try_into()
                    .map_err(|_| TlsError::InvalidServerName(d.clone()))?,
            ),
            LeafName::Ip(ip) => rcgen::SanType::IpAddress(*ip),
        })
    }
}

/// Parses a server name as received in SNI, a Host header or a target address.
///
/// Accepts IPv4/IPv6 literals (optionally bracketed) and LDH DNS names
/// (letters, digits, hyphen, plus underscore which appears in real hostnames).
/// Rejects wildcards, empty labels, non-ASCII, and over-long names: a leaf is
/// only ever minted for one concrete host.
pub(crate) fn parse_leaf_name(input: &str) -> Result<LeafName, TlsError> {
    let bad = || TlsError::InvalidServerName(input.to_string());
    let trimmed = input
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(input);
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(LeafName::Ip(ip));
    }
    let name = input
        .strip_suffix('.')
        .unwrap_or(input)
        .to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 {
        return Err(bad());
    }
    for label in name.split('.') {
        let ok_len = !label.is_empty() && label.len() <= 63;
        let ok_chars = label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if !ok_len || !ok_chars || label.starts_with('-') || label.ends_with('-') {
            return Err(bad());
        }
    }
    // A name whose last label is all digits is either an IP literal (handled
    // above) or ambiguous (`1.2.3`, `10.0.0.256`): refuse it rather than mint a
    // DNS SAN that some resolvers would treat as an address.
    let last = name.rsplit('.').next().unwrap_or_default();
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    Ok(LeafName::Dns(name))
}

/// Gateway identifiers: 1..=128 chars of `[A-Za-z0-9._-]`.
pub(crate) fn valid_gateway_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_names() {
        assert_eq!(
            parse_leaf_name("A.Example.COM.").unwrap(),
            LeafName::Dns("a.example.com".into())
        );
        assert_eq!(
            parse_leaf_name("[::1]").unwrap(),
            LeafName::Ip("::1".parse().unwrap())
        );
        assert!(parse_leaf_name("localhost").is_ok());
        assert!(parse_leaf_name("_dmarc.example.com").is_ok());
        assert!(parse_leaf_name(".").is_err());
        assert!(parse_leaf_name("a.-b.c").is_err());
    }

    #[test]
    fn gateway_ids() {
        assert!(valid_gateway_id("0192f1c2-aaaa-7bbb-8ccc-0123456789ab"));
        assert!(!valid_gateway_id("gw:x"));
        assert!(!valid_gateway_id(""));
    }
}
