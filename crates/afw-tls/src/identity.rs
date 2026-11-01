//! The gateway's mTLS identity towards the console.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::{ClientConfig, RootCertStore};

use crate::store::{prepare_dir, read_private_key, write_file};
use crate::{TlsError, certs_from_pem, crypto_provider, default_alpn};

/// Private key of the gateway (0600, never leaves the host).
pub const GATEWAY_KEY_FILE: &str = "gateway.key";
/// Client certificate issued by the console.
pub const GATEWAY_CERT_FILE: &str = "gateway.crt";
/// Console CA received at registration: the only trust anchor for the console.
pub const CONSOLE_CA_FILE: &str = "console-ca.crt";

/// File-backed gateway identity (`gateway.key`, `gateway.crt`, `console-ca.crt`).
pub struct GatewayIdentity;

impl GatewayIdentity {
    /// Generates a fresh ECDSA P-256 key, stores it in `<dir>/gateway.key`
    /// (0600, replacing any previous key) and returns the CSR (PEM). The
    /// private key is never returned. The CSR subject is informative only:
    /// the console imposes the identity.
    pub fn generate(dir: &Path) -> Result<String, TlsError> {
        prepare_dir(dir)?;
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "agents-firewall gateway");
        p.distinguished_name = dn;
        let csr = p.serialize_request(&key)?.pem()?;
        write_file(
            &dir.join(GATEWAY_KEY_FILE),
            key.serialize_pem().as_bytes(),
            0o600,
        )?;
        Ok(csr)
    }

    /// Stores the certificate and console CA received at registration, after
    /// checking that both parse and that the certificate matches the stored key.
    pub fn store_cert(dir: &Path, cert_pem: &str, ca_pem: &str) -> Result<(), TlsError> {
        prepare_dir(dir)?;
        let certs = certs_from_pem(cert_pem)?;
        certs_from_pem(ca_pem)?;
        let key = read_private_key(&dir.join(GATEWAY_KEY_FILE))?;
        let (_, x509) = x509_parser::parse_x509_certificate(&certs[0])
            .map_err(|e| TlsError::InvalidCertificate(e.to_string()))?;
        if x509.public_key().raw != key.public_key_der().as_slice() {
            return Err(TlsError::InconsistentStore {
                dir: dir.to_path_buf(),
                reason: format!("certificate does not match {GATEWAY_KEY_FILE}"),
            });
        }
        write_file(&dir.join(CONSOLE_CA_FILE), ca_pem.as_bytes(), 0o644)?;
        write_file(&dir.join(GATEWAY_CERT_FILE), cert_pem.as_bytes(), 0o644)?;
        Ok(())
    }

    /// mTLS client configuration towards the console: presents the gateway
    /// certificate and trusts **only** the stored console CA (no web PKI).
    pub fn client_config(dir: &Path) -> Result<Arc<ClientConfig>, TlsError> {
        prepare_dir(dir)?;
        let key = read_private_key(&dir.join(GATEWAY_KEY_FILE))?;
        let read = |name: &str| {
            let path = dir.join(name);
            fs::read_to_string(&path).map_err(|source| TlsError::Io { path, source })
        };
        let chain = certs_from_pem(&read(GATEWAY_CERT_FILE)?)?;
        let mut roots = RootCertStore::empty();
        for ca in certs_from_pem(&read(CONSOLE_CA_FILE)?)? {
            roots
                .add(ca)
                .map_err(|e| TlsError::InvalidCertificate(e.to_string()))?;
        }
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
        let mut cfg = ClientConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key_der)?;
        cfg.alpn_protocols = default_alpn();
        Ok(Arc::new(cfg))
    }
}
