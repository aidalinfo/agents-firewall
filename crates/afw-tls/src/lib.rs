//! TLS building blocks for agents-firewall.
//!
//! - [`GatewayCa`]: the per-gateway inspection authority. Its key never leaves
//!   the gateway host (ENF-02/ENF-03); it mints short-lived leaf certificates
//!   on the fly, keyed by SNI, for TLS inspection.
//! - [`upstream_client_config`]: the client side of inspection, with normal
//!   certificate verification (never accepts invalid certificates).
//! - [`ConsolePki`]: the console authority that signs gateway CSRs and serves
//!   the `/gw/v1` API over mutual TLS.
//! - [`GatewayIdentity`]: the gateway's own mTLS identity towards the console.
//!
//! The `ring` crypto provider is always passed explicitly to rustls builders;
//! no process-wide default provider is ever relied on (see ADR 0013).

mod console;
mod gateway_ca;
mod identity;
mod names;
mod store;
mod upstream;

use std::path::PathBuf;
use std::sync::Arc;

pub use console::{ConsolePki, peer_gateway_id};
pub use gateway_ca::{GatewayCa, LEAF_CACHE_CAPACITY};
pub use identity::GatewayIdentity;
pub use upstream::upstream_client_config;

/// Errors raised by this crate.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("i/o error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("insecure permissions on {path}: mode {mode:o} (too open for key material)")]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("refusing to use {path}: owned by uid {uid}, expected {expected}")]
    WrongOwner {
        path: PathBuf,
        uid: u32,
        expected: u32,
    },
    #[error("refusing to use {path}: not a regular file or directory, or a symbolic link")]
    NotARegularFile { path: PathBuf },
    #[error("inconsistent key material in {dir}: {reason}")]
    InconsistentStore { dir: PathBuf, reason: String },
    #[error("invalid server name {0:?}")]
    InvalidServerName(String),
    #[error("invalid gateway id {0:?}")]
    InvalidGatewayId(String),
    #[error("invalid validity: {0}")]
    InvalidValidity(String),
    #[error("invalid PEM: {0}")]
    InvalidPem(String),
    #[error("invalid certificate signing request: {0}")]
    InvalidCsr(String),
    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("client certificate verifier: {0}")]
    Verifier(String),
}

/// Default ALPN offered by inspection and API servers.
pub fn default_alpn() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

/// The crypto provider used everywhere in this crate: `ring`, explicitly.
pub fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Random positive serial number (16 bytes, MSB cleared) from the provider's CSPRNG.
pub(crate) fn random_serial() -> Result<rcgen::SerialNumber, TlsError> {
    let mut bytes = [0u8; 16];
    crypto_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| TlsError::Rustls(rustls::Error::FailedToGetRandomBytes))?;
    bytes[0] &= 0x7f;
    bytes[0] |= 0x01; // never zero / never a shorter encoding
    Ok(rcgen::SerialNumber::from_slice(&bytes))
}

/// Parses every certificate in a PEM bundle; fails on garbage or empty input.
pub(crate) fn certs_from_pem(
    pem: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, TlsError> {
    let certs = rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::InvalidPem(e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsError::InvalidPem("no certificate found".into()));
    }
    Ok(certs)
}

/// Builds a rustls `CertifiedKey` from a chain and an rcgen key pair.
pub(crate) fn certified_key(
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: &rcgen::KeyPair,
) -> Result<rustls::sign::CertifiedKey, TlsError> {
    let der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
    let signing = crypto_provider().key_provider.load_private_key(der)?;
    Ok(rustls::sign::CertifiedKey::new(chain, signing))
}

/// `now - 1h`, used as `not_before` to tolerate clock skew between hosts.
pub(crate) fn backdated_now() -> time::OffsetDateTime {
    // Truncate to whole seconds so that X.509 lifetimes are exact.
    let now = time::OffsetDateTime::now_utc();
    let now = now.replace_nanosecond(0).unwrap_or(now);
    now - time::Duration::hours(1)
}
