//! Console PKI: signs gateway CSRs and serves the `/gw/v1` API over mTLS.

use std::path::Path;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType, SubjectPublicKeyInfo,
};
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

use crate::names::{LeafName, parse_leaf_name, valid_gateway_id};
use crate::store::{CaMaterial, load_or_create_ca};
use crate::{TlsError, backdated_now, crypto_provider, default_alpn, random_serial};

/// Prefix of the subject CN of gateway client certificates.
pub const GATEWAY_CN_PREFIX: &str = "gw:";
/// Upper bound for gateway certificate validity.
pub const MAX_GATEWAY_CERT_DAYS: u32 = 825;
const CA_VALIDITY: time::Duration = time::Duration::days(3650);
const SERVER_CERT_VALIDITY: time::Duration = time::Duration::days(365);

/// The console's own certificate authority.
pub struct ConsolePki {
    ca: CaMaterial,
}

impl std::fmt::Debug for ConsolePki {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsolePki").finish_non_exhaustive()
    }
}

impl ConsolePki {
    /// Loads or creates `<dir>/ca.crt` (0644) + `<dir>/ca.key` (0600), with the
    /// same permission checks as [`crate::GatewayCa::load_or_create`].
    pub fn load_or_create(dir: &Path) -> Result<Self, TlsError> {
        let ca = load_or_create_ca(dir, || {
            let mut p = CertificateParams::default();
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "agents-firewall console CA");
            dn.push(DnType::OrganizationName, "agents-firewall");
            p.distinguished_name = dn;
            p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            p.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            p.not_before = backdated_now();
            p.not_after = p.not_before + CA_VALIDITY;
            p.serial_number = Some(random_serial()?);
            Ok(p)
        })?;
        Ok(ConsolePki { ca })
    }

    /// Console CA certificate (PEM), returned to gateways at registration.
    pub fn ca_cert_pem(&self) -> String {
        self.ca.cert_pem.clone()
    }

    /// Signs a gateway CSR. Only the CSR's public key is used (after checking
    /// the CSR self-signature); subject, SANs, extensions and CA flags it asks
    /// for are ignored. The certificate gets CN `gw:<gateway_id>`, a URI SAN
    /// `urn:afw:gw:<gateway_id>`, EKU clientAuth only, `cA=false`, and is valid
    /// `validity_days` (1..=825) from one hour ago.
    pub fn sign_gateway_csr(
        &self,
        csr_pem: &str,
        gateway_id: &str,
        validity_days: u32,
    ) -> Result<String, TlsError> {
        if !valid_gateway_id(gateway_id) {
            return Err(TlsError::InvalidGatewayId(gateway_id.to_string()));
        }
        if validity_days == 0 || validity_days > MAX_GATEWAY_CERT_DAYS {
            return Err(TlsError::InvalidValidity(format!(
                "{validity_days} days (allowed 1..={MAX_GATEWAY_CERT_DAYS})"
            )));
        }
        let public_key = csr_public_key(csr_pem)?;

        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            format!("{GATEWAY_CN_PREFIX}{gateway_id}"),
        );
        p.distinguished_name = dn;
        p.subject_alt_names = vec![SanType::URI(
            format!("urn:afw:gw:{gateway_id}")
                .try_into()
                .map_err(|_| TlsError::InvalidGatewayId(gateway_id.to_string()))?,
        )];
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.use_authority_key_identifier_extension = true;
        p.not_before = backdated_now();
        p.not_after =
            p.not_before + time::Duration::hours(1) + time::Duration::days(validity_days.into());
        p.serial_number = Some(random_serial()?);
        let cert = p.signed_by(&public_key, &self.ca.issuer, &self.ca.key)?;
        Ok(cert.pem())
    }

    /// Server configuration for the console API: server certificate for
    /// `server_names` (DNS names or IPs) signed by the console CA and minted in
    /// memory at each call (valid 1 year); client certificates are optional
    /// (registration happens without one) but, when presented, must chain to
    /// the console CA with EKU clientAuth. Use [`peer_gateway_id`] on the
    /// verified peer chain to authenticate `/gw/v1` calls.
    pub fn server_config(&self, server_names: &[String]) -> Result<Arc<ServerConfig>, TlsError> {
        let names = server_names
            .iter()
            .map(|n| parse_leaf_name(n))
            .collect::<Result<Vec<LeafName>, _>>()?;
        if names.is_empty() {
            return Err(TlsError::InvalidServerName(String::new()));
        }
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        let first = names[0].key();
        if first.len() <= 64 {
            dn.push(DnType::CommonName, first);
        }
        p.distinguished_name = dn;
        p.subject_alt_names = names.iter().map(LeafName::san).collect::<Result<_, _>>()?;
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        p.not_before = backdated_now();
        p.not_after = p.not_before + SERVER_CERT_VALIDITY;
        p.serial_number = Some(random_serial()?);
        let cert = p.signed_by(&key, &self.ca.issuer, &self.ca.key)?;
        let chain = vec![cert.der().clone(), self.ca.cert_der.clone()];
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());

        let mut roots = RootCertStore::empty();
        roots
            .add(self.ca.cert_der.clone())
            .map_err(|e| TlsError::InvalidCertificate(e.to_string()))?;
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), crypto_provider())
                .allow_unauthenticated()
                .build()
                .map_err(|e| TlsError::Verifier(e.to_string()))?;
        let mut cfg = ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key_der)?;
        cfg.alpn_protocols = default_alpn();
        Ok(Arc::new(cfg))
    }
}

/// Parses a PEM CSR, verifies its self-signature (proof of possession of the
/// private key) and returns only its public key. Everything else the CSR
/// requests (subject, extensions) is deliberately discarded, so unknown or
/// hostile extensions cannot influence the issued certificate.
fn csr_public_key(csr_pem: &str) -> Result<SubjectPublicKeyInfo, TlsError> {
    use x509_parser::certification_request::X509CertificationRequest;
    use x509_parser::prelude::FromDer;

    let der = match rustls_pemfile::csr(&mut csr_pem.as_bytes()) {
        Ok(Some(der)) => der,
        Ok(None) => return Err(TlsError::InvalidCsr("no CERTIFICATE REQUEST block".into())),
        Err(e) => return Err(TlsError::InvalidCsr(e.to_string())),
    };
    let (rest, csr) = X509CertificationRequest::from_der(der.as_ref())
        .map_err(|e| TlsError::InvalidCsr(e.to_string()))?;
    if !rest.is_empty() {
        return Err(TlsError::InvalidCsr("trailing bytes".into()));
    }
    csr.verify_signature()
        .map_err(|e| TlsError::InvalidCsr(format!("bad self-signature: {e}")))?;
    SubjectPublicKeyInfo::from_der(csr.certification_request_info.subject_pki.raw)
        .map_err(|e| TlsError::InvalidCsr(format!("unsupported public key: {e}")))
}

/// Extracts the gateway id from a peer certificate chain (leaf first).
///
/// Returns `Some(id)` only if the leaf subject has exactly one CN, of the form
/// `gw:<id>` with a valid id. **Only call this on a chain rustls has already
/// verified** against the console CA (e.g. `ServerConnection::peer_certificates`
/// with [`ConsolePki::server_config`]): this function does not verify anything.
pub fn peer_gateway_id(certs: &[CertificateDer<'_>]) -> Option<String> {
    let leaf = certs.first()?;
    let (_, x509) = x509_parser::parse_x509_certificate(leaf).ok()?;
    let mut cns = x509.subject().iter_common_name();
    let cn = cns.next()?.as_str().ok()?;
    if cns.next().is_some() {
        return None;
    }
    let id = cn.strip_prefix(GATEWAY_CN_PREFIX)?;
    valid_gateway_id(id).then(|| id.to_string())
}
