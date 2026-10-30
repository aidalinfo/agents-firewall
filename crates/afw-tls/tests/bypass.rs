//! Bypass tests: every way an attacker (or a misconfiguration) could get a
//! certificate accepted, an identity spoofed, or a weak key loaded must fail.

mod common;

use std::sync::Arc;

use afw_tls::{ConsolePki, GatewayCa, GatewayIdentity, peer_gateway_id, upstream_client_config};
use common::*;

fn alpn() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

#[tokio::test]
async fn leaf_is_rejected_by_a_standard_webpki_client() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Arc::new(GatewayCa::load_or_create(dir.path(), "afw test gateway").unwrap());
    let out = handshake(ca.server_config(), webpki_client(), "api.example.com").await;
    assert!(
        out.client.is_err(),
        "public PKI client must not accept a gateway leaf"
    );
}

#[tokio::test]
async fn leaf_is_rejected_by_a_client_trusting_another_gateway_ca() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ca_a = Arc::new(GatewayCa::load_or_create(a.path(), "gw a").unwrap());
    let ca_b = GatewayCa::load_or_create(b.path(), "gw b").unwrap();
    let out = handshake(
        ca_a.server_config(),
        client_trusting(&ca_b.ca_cert_pem()),
        "api.example.com",
    )
    .await;
    assert!(out.client.is_err());
}

#[cfg(unix)]
#[test]
fn ca_key_with_open_permissions_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    GatewayCa::load_or_create(dir.path(), "gw").unwrap();
    let key = dir.path().join("ca.key");
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    for mode in [0o644, 0o640, 0o604, 0o660] {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            GatewayCa::load_or_create(dir.path(), "gw").is_err(),
            "mode {mode:o} must be refused"
        );
    }
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(GatewayCa::load_or_create(dir.path(), "gw").is_ok());
}

#[cfg(unix)]
#[test]
fn console_ca_key_with_open_permissions_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    ConsolePki::load_or_create(dir.path()).unwrap();
    let key = dir.path().join("ca.key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ConsolePki::load_or_create(dir.path()).is_err());
}

#[cfg(unix)]
#[test]
fn gateway_identity_key_with_open_permissions_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let console_dir = tempfile::tempdir().unwrap();
    let gw_dir = tempfile::tempdir().unwrap();
    let pki = ConsolePki::load_or_create(console_dir.path()).unwrap();
    let csr = GatewayIdentity::generate(gw_dir.path()).unwrap();
    let cert = pki.sign_gateway_csr(&csr, "gw1", 30).unwrap();
    GatewayIdentity::store_cert(gw_dir.path(), &cert, &pki.ca_cert_pem()).unwrap();
    assert!(GatewayIdentity::client_config(gw_dir.path()).is_ok());
    let key = gw_dir.path().join("gateway.key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(GatewayIdentity::client_config(gw_dir.path()).is_err());
}

#[test]
fn half_present_ca_material_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    GatewayCa::load_or_create(dir.path(), "gw").unwrap();
    std::fs::remove_file(dir.path().join("ca.crt")).unwrap();
    // Must not silently mint a new CA over an orphaned key (or vice versa).
    assert!(GatewayCa::load_or_create(dir.path(), "gw").is_err());
}

#[test]
fn mismatched_ca_cert_and_key_are_refused() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    GatewayCa::load_or_create(a.path(), "gw").unwrap();
    GatewayCa::load_or_create(b.path(), "gw").unwrap();
    std::fs::copy(b.path().join("ca.crt"), a.path().join("ca.crt")).unwrap();
    assert!(GatewayCa::load_or_create(a.path(), "gw").is_err());
}

#[test]
fn invalid_server_names_get_no_leaf() {
    let dir = tempfile::tempdir().unwrap();
    let ca = GatewayCa::load_or_create(dir.path(), "gw").unwrap();
    for bad in [
        "",
        "*",
        "*.example.com",
        "exa mple.com",
        "example..com",
        "-bad.example.com",
        "bad\0.example.com",
        "évil.example.com",
        &"a".repeat(64),
        // M-4: all-numeric final label that is not a valid IP literal.
        "1.2.3",
        "999.1.1.1",
        "10.0.0.256",
        "example.123",
        "0x7f.1",
        &format!("{}.com", "a.".repeat(130)),
    ] {
        assert!(ca.leaf_for(bad).is_err(), "{bad:?} must be refused");
    }
}

#[tokio::test]
async fn client_certificate_from_another_ca_is_refused() {
    let console_dir = tempfile::tempdir().unwrap();
    let rogue_dir = tempfile::tempdir().unwrap();
    let gw_dir = tempfile::tempdir().unwrap();
    let console = ConsolePki::load_or_create(console_dir.path()).unwrap();
    let rogue = ConsolePki::load_or_create(rogue_dir.path()).unwrap();

    // The gateway gets a certificate signed by a rogue CA, but trusts the real
    // console CA for the server side.
    let csr = GatewayIdentity::generate(gw_dir.path()).unwrap();
    let cert = rogue.sign_gateway_csr(&csr, "gw1", 30).unwrap();
    GatewayIdentity::store_cert(gw_dir.path(), &cert, &console.ca_cert_pem()).unwrap();
    let client = GatewayIdentity::client_config(gw_dir.path()).unwrap();

    let server = console
        .server_config(&["console.local".to_string()])
        .unwrap();
    let out = handshake(server, client, "console.local").await;
    assert!(
        out.server.is_err(),
        "server must reject a foreign client cert"
    );
}

#[test]
fn csr_requesting_another_identity_gets_the_imposed_id() {
    let console_dir = tempfile::tempdir().unwrap();
    let console = ConsolePki::load_or_create(console_dir.path()).unwrap();

    // Hand-crafted CSR asking for CN gw:other, SANs and CA powers.
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["gw:other".to_string()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "gw:other");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    // Requested basicConstraints cA=TRUE (rcgen refuses is_ca in CSRs, so raw).
    params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
        &[2, 5, 29, 19],
        vec![0x30, 0x03, 0x01, 0x01, 0xff],
    )];
    let csr = params.serialize_request(&key).unwrap().pem().unwrap();

    let cert_pem = console.sign_gateway_csr(&csr, "gw-imposed", 30).unwrap();
    let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        peer_gateway_id(std::slice::from_ref(&der)).as_deref(),
        Some("gw-imposed")
    );

    let (_, x509) = x509_parser::parse_x509_certificate(&der).unwrap();
    let cns: Vec<_> = x509
        .subject()
        .iter_common_name()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(cns, vec!["gw:gw-imposed".to_string()]);
    let eku = x509.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.client_auth && !eku.server_auth);
    assert!(!x509.key_usage().unwrap().unwrap().value.key_cert_sign());
    let bc = x509.basic_constraints().unwrap();
    assert!(bc.map(|b| !b.value.ca).unwrap_or(true), "never a CA");
    let san = x509.subject_alternative_name().unwrap();
    if let Some(san) = san {
        for n in &san.value.general_names {
            assert!(
                !format!("{n:?}").contains("other"),
                "requested SAN leaked: {n:?}"
            );
        }
    }

    // And the key in the certificate is the CSR's key (so the requester can use it).
    assert_eq!(x509.public_key().raw, key.public_key_der().as_slice());
}

#[test]
fn invalid_gateway_ids_are_refused() {
    let console_dir = tempfile::tempdir().unwrap();
    let gw_dir = tempfile::tempdir().unwrap();
    let console = ConsolePki::load_or_create(console_dir.path()).unwrap();
    let csr = GatewayIdentity::generate(gw_dir.path()).unwrap();
    for bad in ["", "a,b", "gw:x", "a/b", "a b", "x\n", &"a".repeat(129)] {
        assert!(console.sign_gateway_csr(&csr, bad, 30).is_err(), "{bad:?}");
    }
    assert!(console.sign_gateway_csr(&csr, "gw1", 0).is_err());
}

#[test]
fn tampered_csr_is_refused() {
    let console_dir = tempfile::tempdir().unwrap();
    let gw_dir = tempfile::tempdir().unwrap();
    let console = ConsolePki::load_or_create(console_dir.path()).unwrap();
    let csr = GatewayIdentity::generate(gw_dir.path()).unwrap();
    let mut der = rustls_pemfile::csr(&mut csr.as_bytes())
        .unwrap()
        .unwrap()
        .as_ref()
        .to_vec();
    // Flip a bit in the signature (last byte).
    let n = der.len();
    der[n - 1] ^= 0x01;
    let pem = format!(
        "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
        base64_encode(&der)
    );
    assert!(console.sign_gateway_csr(&pem, "gw1", 30).is_err());
    assert!(console.sign_gateway_csr("not a csr", "gw1", 30).is_err());
}

#[test]
fn peer_gateway_id_ignores_non_gateway_certificates() {
    let dir = tempfile::tempdir().unwrap();
    let ca = GatewayCa::load_or_create(dir.path(), "gw").unwrap();
    let leaf = ca.leaf_for("gw.example.com").unwrap();
    assert_eq!(peer_gateway_id(&leaf.cert), None);
    assert_eq!(peer_gateway_id(&[]), None);
}

#[tokio::test]
async fn upstream_client_rejects_unknown_self_signed_certificate() {
    let client = upstream_client_config(&[], alpn()).unwrap();
    let out = handshake(self_signed_server("upstream.test"), client, "upstream.test").await;
    assert!(out.client.is_err());
}

#[tokio::test]
async fn upstream_client_rejects_name_mismatch_even_with_extra_root() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Arc::new(GatewayCa::load_or_create(dir.path(), "internal").unwrap());
    let client = upstream_client_config(&[ca.ca_cert_pem()], alpn()).unwrap();
    // Server presents a leaf for a.test but the client asks for b.test: the
    // resolver mints by SNI, so force a mismatch with a fixed-name config.
    let leaf = ca.leaf_for("a.test").unwrap();
    let server = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(leaf))),
    );
    let out = handshake(server, client, "b.test").await;
    assert!(out.client.is_err());
}

#[test]
fn upstream_client_refuses_garbage_extra_roots() {
    assert!(upstream_client_config(&["garbage".to_string()], alpn()).is_err());
}

#[derive(Debug)]
struct Fixed(Arc<rustls::sign::CertifiedKey>);
impl rustls::server::ResolvesServerCert for Fixed {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

// ---- Review fixes: ownership, directory and symlink hardening (I-1, I-2, M-1, M-2) ----

#[cfg(unix)]
fn is_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    // A file we just created is owned by our effective uid.
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::metadata(f.path()).unwrap().uid() == 0
}

#[cfg(unix)]
#[test]
fn key_owned_by_another_user_is_refused() {
    if !is_root() {
        eprintln!("skipped: chown needs root");
        return;
    }
    let console_dir = tempfile::tempdir().unwrap();
    let gw_dir = tempfile::tempdir().unwrap();
    let ca_dir = tempfile::tempdir().unwrap();
    GatewayCa::load_or_create(ca_dir.path(), "gw").unwrap();
    let pki = ConsolePki::load_or_create(console_dir.path()).unwrap();
    let csr = GatewayIdentity::generate(gw_dir.path()).unwrap();
    let cert = pki.sign_gateway_csr(&csr, "gw1", 30).unwrap();
    GatewayIdentity::store_cert(gw_dir.path(), &cert, &pki.ca_cert_pem()).unwrap();

    for key in [
        ca_dir.path().join("ca.key"),
        console_dir.path().join("ca.key"),
        gw_dir.path().join("gateway.key"),
    ] {
        std::os::unix::fs::chown(&key, Some(12345), Some(12345)).unwrap();
    }
    assert!(GatewayCa::load_or_create(ca_dir.path(), "gw").is_err());
    assert!(ConsolePki::load_or_create(console_dir.path()).is_err());
    assert!(GatewayIdentity::client_config(gw_dir.path()).is_err());
}

#[cfg(unix)]
#[test]
fn storage_dir_writable_by_group_or_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    GatewayCa::load_or_create(dir.path(), "gw").unwrap();
    for mode in [0o770, 0o707, 0o777, 0o720] {
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            GatewayCa::load_or_create(dir.path(), "gw").is_err(),
            "{mode:o}"
        );
        assert!(ConsolePki::load_or_create(dir.path()).is_err(), "{mode:o}");
        assert!(GatewayIdentity::generate(dir.path()).is_err(), "{mode:o}");
    }
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(GatewayCa::load_or_create(dir.path(), "gw").is_ok());
}

#[cfg(unix)]
#[test]
fn storage_dir_owned_by_another_user_is_refused() {
    if !is_root() {
        eprintln!("skipped: chown needs root");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::chown(dir.path(), Some(12345), Some(12345)).unwrap();
    assert!(GatewayCa::load_or_create(dir.path(), "gw").is_err());
}

#[cfg(unix)]
#[test]
fn created_storage_dir_is_0700() {
    use std::os::unix::fs::PermissionsExt;
    let parent = tempfile::tempdir().unwrap();
    for sub in ["gwca", "console", "identity"] {
        let d = parent.path().join(sub).join("nested");
        match sub {
            "gwca" => drop(GatewayCa::load_or_create(&d, "gw").unwrap()),
            "console" => drop(ConsolePki::load_or_create(&d).unwrap()),
            _ => drop(GatewayIdentity::generate(&d).unwrap()),
        }
        let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{sub}");
    }
}

#[cfg(unix)]
#[test]
fn symlinked_key_is_refused() {
    let real = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    GatewayCa::load_or_create(real.path(), "gw").unwrap();
    std::fs::copy(real.path().join("ca.crt"), dir.path().join("ca.crt")).unwrap();
    std::os::unix::fs::symlink(real.path().join("ca.key"), dir.path().join("ca.key")).unwrap();
    assert!(GatewayCa::load_or_create(dir.path(), "gw").is_err());
}

#[test]
fn interrupted_creation_is_recovered_from_complete_staging() {
    // Crash after the key was moved into place but before the certificate.
    let src = tempfile::tempdir().unwrap();
    let ca = GatewayCa::load_or_create(src.path(), "gw").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join(".ca-staging");
    std::fs::create_dir(&staging).unwrap();
    for f in ["ca.key", "ca.crt"] {
        std::fs::copy(src.path().join(f), staging.join(f)).unwrap();
    }
    std::fs::copy(src.path().join("ca.key"), dir.path().join("ca.key")).unwrap();
    let again = GatewayCa::load_or_create(dir.path(), "gw").unwrap();
    assert_eq!(again.fingerprint_sha256(), ca.fingerprint_sha256());
    assert!(!staging.exists());
}

#[test]
fn incomplete_staging_is_discarded() {
    // Crash while writing the staging pair: nothing was committed.
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join(".ca-staging");
    std::fs::create_dir(&staging).unwrap();
    std::fs::write(staging.join("ca.key"), "partial").unwrap();
    assert!(GatewayCa::load_or_create(dir.path(), "gw").is_ok());
    assert!(!staging.exists());
}

#[test]
fn staging_conflicting_with_committed_material_is_refused() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    GatewayCa::load_or_create(a.path(), "gw").unwrap();
    GatewayCa::load_or_create(b.path(), "gw").unwrap();
    let staging = a.path().join(".ca-staging");
    std::fs::create_dir(&staging).unwrap();
    for f in ["ca.key", "ca.crt"] {
        std::fs::copy(b.path().join(f), staging.join(f)).unwrap();
    }
    std::fs::remove_file(a.path().join("ca.crt")).unwrap();
    assert!(GatewayCa::load_or_create(a.path(), "gw").is_err());
}
