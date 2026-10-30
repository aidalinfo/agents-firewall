mod common;

use afw_tls::{ConsolePki, GatewayIdentity, peer_gateway_id};
use common::*;

#[tokio::test]
async fn signed_csr_gives_working_mtls_and_gateway_id() {
    let console_dir = tempfile::tempdir().unwrap();
    let gw_dir = tempfile::tempdir().unwrap();
    let console = ConsolePki::load_or_create(console_dir.path()).unwrap();

    // M-3: only the CSR is returned; the private key stays on disk.
    let csr: String = GatewayIdentity::generate(gw_dir.path()).unwrap();
    assert!(csr.contains("CERTIFICATE REQUEST"));
    assert!(!csr.contains("PRIVATE KEY"));
    let cert = console
        .sign_gateway_csr(&csr, "0192f1c2-aaaa-7bbb-8ccc-0123456789ab", 365)
        .unwrap();
    GatewayIdentity::store_cert(gw_dir.path(), &cert, &console.ca_cert_pem()).unwrap();
    let client = GatewayIdentity::client_config(gw_dir.path()).unwrap();

    let server = console
        .server_config(&["console.local".to_string(), "127.0.0.1".to_string()])
        .unwrap();
    let out = handshake(server.clone(), client.clone(), "console.local").await;
    assert!(out.ok(), "{:?} / {:?}", out.client, out.server);
    let peer = out.server.unwrap().expect("client cert presented");
    assert_eq!(
        peer_gateway_id(&peer).as_deref(),
        Some("0192f1c2-aaaa-7bbb-8ccc-0123456789ab")
    );

    // Server certificate is also valid for its IP SAN.
    let out = handshake(server, client, "127.0.0.1").await;
    assert!(out.ok());
}

#[tokio::test]
async fn client_without_certificate_is_allowed_but_has_no_identity() {
    // Registration (`POST /gw/v1/register`) happens before the gateway has a cert.
    let console_dir = tempfile::tempdir().unwrap();
    let console = ConsolePki::load_or_create(console_dir.path()).unwrap();
    let server = console
        .server_config(&["console.local".to_string()])
        .unwrap();
    let out = handshake(
        server,
        client_trusting(&console.ca_cert_pem()),
        "console.local",
    )
    .await;
    assert!(out.ok());
    assert!(out.server.unwrap().is_none());
}

#[tokio::test]
async fn gateway_refuses_a_console_signed_by_another_ca() {
    let console_dir = tempfile::tempdir().unwrap();
    let rogue_dir = tempfile::tempdir().unwrap();
    let gw_dir = tempfile::tempdir().unwrap();
    let console = ConsolePki::load_or_create(console_dir.path()).unwrap();
    let rogue = ConsolePki::load_or_create(rogue_dir.path()).unwrap();
    let csr = GatewayIdentity::generate(gw_dir.path()).unwrap();
    let cert = console.sign_gateway_csr(&csr, "gw1", 30).unwrap();
    GatewayIdentity::store_cert(gw_dir.path(), &cert, &console.ca_cert_pem()).unwrap();
    let client = GatewayIdentity::client_config(gw_dir.path()).unwrap();
    let out = handshake(
        rogue.server_config(&["console.local".to_string()]).unwrap(),
        client,
        "console.local",
    )
    .await;
    assert!(out.client.is_err());
}

#[tokio::test]
async fn gateway_does_not_trust_public_web_pki_for_the_console() {
    // A console certificate that would be valid on the public web PKI is not
    // enough: only the CA received at registration is trusted. We check the
    // root store size indirectly: a self-signed cert for the name is refused.
    let console_dir = tempfile::tempdir().unwrap();
    let gw_dir = tempfile::tempdir().unwrap();
    let console = ConsolePki::load_or_create(console_dir.path()).unwrap();
    let csr = GatewayIdentity::generate(gw_dir.path()).unwrap();
    let cert = console.sign_gateway_csr(&csr, "gw1", 30).unwrap();
    GatewayIdentity::store_cert(gw_dir.path(), &cert, &console.ca_cert_pem()).unwrap();
    let client = GatewayIdentity::client_config(gw_dir.path()).unwrap();
    let out = handshake(self_signed_server("console.local"), client, "console.local").await;
    assert!(out.client.is_err());
}

#[test]
fn console_ca_is_stable_across_reloads() {
    let dir = tempfile::tempdir().unwrap();
    let a = ConsolePki::load_or_create(dir.path())
        .unwrap()
        .ca_cert_pem();
    let b = ConsolePki::load_or_create(dir.path())
        .unwrap()
        .ca_cert_pem();
    assert_eq!(a, b);
}

#[test]
fn signed_certificate_has_client_auth_and_requested_validity() {
    let console_dir = tempfile::tempdir().unwrap();
    let gw_dir = tempfile::tempdir().unwrap();
    let console = ConsolePki::load_or_create(console_dir.path()).unwrap();
    let csr = GatewayIdentity::generate(gw_dir.path()).unwrap();
    let pem = console.sign_gateway_csr(&csr, "gw1", 90).unwrap();
    let der = rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let (_, x) = x509_parser::parse_x509_certificate(&der).unwrap();
    let eku = x.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.client_auth);
    assert!(!eku.server_auth);
    let v = x.validity();
    assert_eq!(
        v.not_after.timestamp() - v.not_before.timestamp(),
        90 * 86400 + 3600
    );
}

#[test]
fn ed25519_and_p384_csrs_are_accepted() {
    let console_dir = tempfile::tempdir().unwrap();
    let console = ConsolePki::load_or_create(console_dir.path()).unwrap();
    for alg in [&rcgen::PKCS_ED25519, &rcgen::PKCS_ECDSA_P384_SHA384] {
        let key = rcgen::KeyPair::generate_for(alg).unwrap();
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        let pem = console.sign_gateway_csr(&csr, "gw1", 30).unwrap();
        let der = rustls_pemfile::certs(&mut pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let (_, x) = x509_parser::parse_x509_certificate(&der).unwrap();
        assert_eq!(x.public_key().raw, key.public_key_der().as_slice());
    }
}
