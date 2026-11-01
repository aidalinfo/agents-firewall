//! Client configuration used by the gateway towards real upstream servers.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};

use crate::{TlsError, certs_from_pem, crypto_provider};

/// Client configuration for upstream connections made during inspection.
///
/// Trusts the Mozilla roots (webpki-roots) plus `extra_roots_pem` (each entry
/// a PEM bundle, e.g. an internal CA). Verification is the standard rustls
/// one: chain, validity dates, server name. There is no way to disable it.
/// An unparsable extra root is an error, never silently skipped.
pub fn upstream_client_config(
    extra_roots_pem: &[String],
    alpn: Vec<Vec<u8>>,
) -> Result<Arc<ClientConfig>, TlsError> {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for pem in extra_roots_pem {
        for cert in certs_from_pem(pem)? {
            roots
                .add(cert)
                .map_err(|e| TlsError::InvalidCertificate(e.to_string()))?;
        }
    }
    let mut cfg = ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn;
    Ok(Arc::new(cfg))
}
