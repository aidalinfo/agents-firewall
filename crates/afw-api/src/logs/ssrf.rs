//! Outgoing alert requests must not reach internal services (SSRF): the target name is
//! resolved and every address checked, the request connects to a verified address only
//! (pinned resolution), redirects are never followed, and HTTPS is required — except for
//! hosts listed in `AFW_ALERT_ALLOWED_HOSTS` (comma-separated, exact names or IP literals).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// Addresses an alert channel may never reach unless its host is allowlisted.
pub fn forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return forbidden_v4(v4);
            }
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00 // ULA fc00::/7 (incl. fd00:ec2::254 metadata)
                || (seg[0] & 0xffc0) == 0xfe80 // link-local
                || (seg[0] & 0xffc0) == 0xfec0 // site-local (deprecated)
                || (seg[0] == 0x64 && seg[1] == 0xff9b) // NAT64 64:ff9b::/96
                || (seg[0] == 0x2002) // 6to4 (embeds an IPv4)
                || (seg[0] == 0x2001 && seg[1] == 0x0db8) // documentation
                || v6 == Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)
        }
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local() // 169.254/16, cloud metadata
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0 // 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmarking 198.18/15
        || o[0] >= 240 // reserved
}

/// Parsed `AFW_ALERT_ALLOWED_HOSTS`.
pub fn allowlist(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or("")
        .split(',')
        .map(|h| h.trim().trim_matches(['[', ']']).to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect()
}

/// A URL checked for sending.
#[derive(Debug, Clone)]
pub struct Checked {
    pub url: reqwest::Url,
    pub host: String,
    /// Verified address the request connects to.
    pub addr: SocketAddr,
    pub allowlisted: bool,
}

/// Static checks (scheme, host) without DNS.
pub fn check_static(url: &str, allow: &[String]) -> Result<(reqwest::Url, String, bool), String> {
    let u = reqwest::Url::parse(url).map_err(|_| "invalid URL".to_owned())?;
    let host = u
        .host_str()
        .ok_or_else(|| "URL without host".to_owned())?
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    if !u.username().is_empty() || u.password().is_some() {
        return Err("credentials in URL are not allowed".into());
    }
    let allowlisted = allow.contains(&host);
    match u.scheme() {
        "https" => {}
        "http" if allowlisted => {}
        "http" => return Err("https required (host not in AFW_ALERT_ALLOWED_HOSTS)".into()),
        _ => return Err("http(s) URL required".into()),
    }
    Ok((u, host, allowlisted))
}

/// Resolves and checks every address of the URL's host.
pub async fn check(url: &str, allow: &[String]) -> Result<Checked, String> {
    let (u, host, allowlisted) = check_static(url, allow)?;
    let port = u.port_or_known_default().unwrap_or(443);
    let addrs: Vec<SocketAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await
        .map_err(|_| format!("cannot resolve {host}: timeout"))?
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .collect(),
    };
    if addrs.is_empty() {
        return Err(format!("{host} has no address"));
    }
    if !allowlisted && let Some(bad) = addrs.iter().find(|a| forbidden_ip(a.ip())) {
        return Err(format!(
            "{host} resolves to a forbidden address {}",
            bad.ip()
        ));
    }
    Ok(Checked {
        url: u,
        host,
        addr: addrs[0],
        allowlisted,
    })
}

/// HTTP client bound to the verified address, without redirects.
pub fn client_for(c: &Checked) -> reqwest::Client {
    let mut b = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .no_proxy();
    if c.host.parse::<IpAddr>().is_err() {
        b = b.resolve(&c.host, c.addr);
    }
    b.build().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_addresses_are_forbidden() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00:ec2::254",
            "fc00::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
        ] {
            assert!(forbidden_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(!forbidden_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn checks_scheme_allowlist_and_resolution() {
        let allow = allowlist(Some(" 127.0.0.1 , Hooks.Local "));
        assert_eq!(allow, vec!["127.0.0.1", "hooks.local"]);
        assert!(
            check("http://1.1.1.1/x", &[]).await.is_err(),
            "https required"
        );
        assert!(check("https://1.1.1.1/x", &[]).await.is_ok());
        assert!(check("https://127.0.0.1/x", &[]).await.is_err());
        assert!(check("http://127.0.0.1:8080/x", &allow).await.is_ok());
        assert!(
            check("https://localhost/x", &[]).await.is_err(),
            "resolves to loopback"
        );
        assert!(check("https://u:p@1.1.1.1/x", &[]).await.is_err());
        assert!(check("ftp://1.1.1.1/x", &[]).await.is_err());
    }
}
