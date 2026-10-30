#![allow(unused_variables, clippy::missing_errors_doc)]
use std::path::Path;
use std::sync::Arc;
use rustls::pki_types::CertificateDer;
#[derive(Debug, thiserror::Error)]
pub enum TlsError { #[error("x")] X }
pub struct GatewayCa;
impl GatewayCa {
    pub fn load_or_create(dir: &Path, cn: &str) -> Result<Self, TlsError> { todo!() }
    pub fn ca_cert_pem(&self) -> String { todo!() }
    pub fn fingerprint_sha256(&self) -> String { todo!() }
    pub fn leaf_for(&self, n: &str) -> Result<Arc<rustls::sign::CertifiedKey>, TlsError> { todo!() }
    pub fn server_config(self: &Arc<Self>) -> Arc<rustls::ServerConfig> { todo!() }
    pub fn server_config_for_alpn(&self, a: Vec<Vec<u8>>) -> Arc<rustls::ServerConfig> { todo!() }
    pub fn server_config_for_target(&self, t: &str, a: Vec<Vec<u8>>) -> Arc<rustls::ServerConfig> { todo!() }
}
pub fn upstream_client_config(e: &[String], a: Vec<Vec<u8>>) -> Result<Arc<rustls::ClientConfig>, TlsError> { todo!() }
pub struct ConsolePki;
impl ConsolePki {
    pub fn load_or_create(dir: &Path) -> Result<Self, TlsError> { todo!() }
    pub fn ca_cert_pem(&self) -> String { todo!() }
    pub fn sign_gateway_csr(&self, c: &str, id: &str, d: u32) -> Result<String, TlsError> { todo!() }
    pub fn server_config(&self, n: &[String]) -> Result<Arc<rustls::ServerConfig>, TlsError> { todo!() }
}
pub fn peer_gateway_id(c: &[CertificateDer<'_>]) -> Option<String> { todo!() }
pub struct GatewayIdentity;
impl GatewayIdentity {
    pub fn generate(dir: &Path) -> Result<(String, String), TlsError> { todo!() }
    pub fn store_cert(dir: &Path, c: &str, ca: &str) -> Result<(), TlsError> { todo!() }
    pub fn client_config(dir: &Path) -> Result<Arc<rustls::ClientConfig>, TlsError> { todo!() }
}
