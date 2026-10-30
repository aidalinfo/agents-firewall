mod common;

use std::sync::Arc;

use afw_tls::GatewayCa;
use common::*;

#[tokio::test]
async fn leaf_for_dns_name_is_accepted_by_client_trusting_the_ca() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Arc::new(GatewayCa::load_or_create(dir.path(), "afw gw").unwrap());
    let out = handshake(
        ca.server_config(),
        client_trusting(&ca.ca_cert_pem()),
        "api.example.com",
    )
    .await;
    assert!(out.ok(), "{:?} / {:?}", out.client, out.server.err());
    let chain = out.server_chain.unwrap();
    let (_, leaf) = x509_parser::parse_x509_certificate(&chain[0]).unwrap();
    let v = leaf.validity();
    let lifetime = v.not_after.timestamp() - v.not_before.timestamp();
    assert_eq!(lifetime, 7 * 24 * 3600 + 3600, "7 days, backdated 1h");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(v.not_before.timestamp() <= now - 3500);
}

#[tokio::test]
async fn leaf_for_ip_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let ca = GatewayCa::load_or_create(dir.path(), "afw gw").unwrap();
    // No SNI is sent for IP addresses: use the target fallback.
    let server = ca.server_config_for_target("10.1.2.3", vec![b"http/1.1".to_vec()]);
    let out = handshake(server, client_trusting(&ca.ca_cert_pem()), "10.1.2.3").await;
    assert!(out.ok(), "{:?} / {:?}", out.client, out.server.err());

    let leaf = ca.leaf_for("2001:db8::1").unwrap();
    let (_, x) = x509_parser::parse_x509_certificate(&leaf.cert[0]).unwrap();
    let san = format!("{:?}", x.subject_alternative_name().unwrap().unwrap().value);
    assert!(san.contains("IPAddress"), "{san}");
}

#[tokio::test]
async fn sni_wins_over_target_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let ca = GatewayCa::load_or_create(dir.path(), "afw gw").unwrap();
    let server = ca.server_config_for_target("10.1.2.3", vec![]);
    let out = handshake(server, client_trusting(&ca.ca_cert_pem()), "named.example").await;
    assert!(out.ok());
}

#[test]
fn cache_returns_same_arc_and_normalizes_names() {
    let dir = tempfile::tempdir().unwrap();
    let ca = GatewayCa::load_or_create(dir.path(), "afw gw").unwrap();
    let a = ca.leaf_for("api.example.com").unwrap();
    let b = ca.leaf_for("api.example.com").unwrap();
    let c = ca.leaf_for("API.Example.com.").unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    assert!(Arc::ptr_eq(&a, &c));
    let d = ca.leaf_for("other.example.com").unwrap();
    assert!(!Arc::ptr_eq(&a, &d));
}

#[test]
fn cache_is_thread_safe() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Arc::new(GatewayCa::load_or_create(dir.path(), "afw gw").unwrap());
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let ca = ca.clone();
            std::thread::spawn(move || ca.leaf_for("race.example.com").unwrap())
        })
        .collect();
    let leaves: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for l in &leaves[1..] {
        assert!(Arc::ptr_eq(&leaves[0], l));
    }
}

#[tokio::test]
async fn reloaded_ca_keeps_identity_and_still_signs_valid_leaves() {
    let dir = tempfile::tempdir().unwrap();
    let first = GatewayCa::load_or_create(dir.path(), "afw gw").unwrap();
    let fp = first.fingerprint_sha256();
    let pem = first.ca_cert_pem();
    drop(first);
    let again = Arc::new(GatewayCa::load_or_create(dir.path(), "ignored").unwrap());
    assert_eq!(again.fingerprint_sha256(), fp);
    assert_eq!(again.ca_cert_pem(), pem);
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    let out = handshake(again.server_config(), client_trusting(&pem), "reload.example").await;
    assert!(out.ok(), "{:?}", out.client);
}

#[cfg(unix)]
#[test]
fn ca_files_have_expected_modes_and_extensions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let ca = GatewayCa::load_or_create(dir.path(), "afw gw").unwrap();
    let mode = |n: &str| {
        std::fs::metadata(dir.path().join(n)).unwrap().permissions().mode() & 0o777
    };
    assert_eq!(mode("ca.key"), 0o600);
    assert_eq!(mode("ca.crt"), 0o644);

    let der = rustls_pemfile::certs(&mut ca.ca_cert_pem().as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let (_, x) = x509_parser::parse_x509_certificate(&der).unwrap();
    assert!(x.basic_constraints().unwrap().unwrap().value.ca);
    assert!(x.key_usage().unwrap().unwrap().value.key_cert_sign());
    assert!(x.name_constraints().unwrap().is_none());
    let v = x.validity();
    let years = (v.not_after.timestamp() - v.not_before.timestamp()) / (365 * 24 * 3600);
    assert_eq!(years, 10);
    assert_eq!(
        x.subject().iter_common_name().next().unwrap().as_str().unwrap(),
        "afw gw"
    );
}

#[tokio::test]
async fn alpn_is_negotiated() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Arc::new(GatewayCa::load_or_create(dir.path(), "afw gw").unwrap());
    let cfg = ca.server_config();
    assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    let only = ca.server_config_for_alpn(vec![b"http/1.1".to_vec()]);
    assert_eq!(only.alpn_protocols, vec![b"http/1.1".to_vec()]);
}
