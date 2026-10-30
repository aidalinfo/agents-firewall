//! Per-gateway inspection authority and leaf minting.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};

use crate::names::{LeafName, parse_leaf_name};
use crate::store::{CaMaterial, load_or_create_ca};
use crate::{TlsError, backdated_now, certified_key, crypto_provider, default_alpn, random_serial};

/// Maximum number of leaf certificates kept in memory.
pub const LEAF_CACHE_CAPACITY: usize = 10_000;
/// Leaf lifetime after the 1 h backdating.
const LEAF_VALIDITY: time::Duration = time::Duration::days(7);
/// Cached leaves are re-minted after this age, well before they expire.
const LEAF_REFRESH_AFTER: Duration = Duration::from_secs(6 * 24 * 3600);
/// CA lifetime.
const CA_VALIDITY: time::Duration = time::Duration::days(3650);

/// The inspection authority of one gateway.
///
/// Cheap to clone (shared inner state). The private key stays in memory and
/// in `<dir>/ca.key` (0600); only the certificate is ever exported.
#[derive(Clone)]
pub struct GatewayCa {
    inner: Arc<Inner>,
}

struct Inner {
    ca: CaMaterial,
    fingerprint: String,
    cache: Mutex<LeafCache>,
}

impl std::fmt::Debug for GatewayCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayCa")
            .field("fingerprint_sha256", &self.inner.fingerprint)
            .finish_non_exhaustive()
    }
}

impl GatewayCa {
    /// Loads `<dir>/ca.crt` + `<dir>/ca.key`, or creates a new ECDSA P-256 CA
    /// (10 years, `cA=true, pathlen=0`, keyCertSign + cRLSign, no name
    /// constraints) named `common_name` when neither file exists.
    ///
    /// Refuses a key file readable or writable by group/others, a symlinked key,
    /// a certificate that does not match the key, and half-present material.
    pub fn load_or_create(dir: &Path, common_name: &str) -> Result<GatewayCa, TlsError> {
        let ca = load_or_create_ca(dir, || {
            let mut p = CertificateParams::default();
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, common_name);
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
        let fingerprint = hex::encode(Sha256::digest(ca.cert_der.as_ref()));
        Ok(GatewayCa {
            inner: Arc::new(Inner {
                ca,
                fingerprint,
                cache: Mutex::new(LeafCache::new(LEAF_CACHE_CAPACITY)),
            }),
        })
    }

    /// The CA certificate in PEM, to be installed in agents' trust stores.
    pub fn ca_cert_pem(&self) -> String {
        self.inner.ca.cert_pem.clone()
    }

    /// SHA-256 of the DER CA certificate, lowercase hex without separators.
    pub fn fingerprint_sha256(&self) -> String {
        self.inner.fingerprint.clone()
    }

    /// Returns a leaf certificate for `server_name` (DNS name or IP literal),
    /// minting it if needed. Valid 7 days, backdated 1 h; cached (LRU, at most
    /// [`LEAF_CACHE_CAPACITY`] entries). Names are lowercased and a trailing dot
    /// removed; wildcards and malformed names are refused.
    pub fn leaf_for(&self, server_name: &str) -> Result<Arc<CertifiedKey>, TlsError> {
        let name = parse_leaf_name(server_name)?;
        let key = name.key();
        if let Some(hit) = self.lock_cache().get(&key) {
            return Ok(hit);
        }
        // Mint outside the lock; on a race the first inserted leaf wins so all
        // callers share the same Arc.
        let minted = Arc::new(self.mint_leaf(&name)?);
        Ok(self.lock_cache().insert_or_get(key, minted))
    }

    /// Server configuration for TLS inspection: certificate chosen by SNI,
    /// ALPN `h2` then `http/1.1`.
    pub fn server_config(self: &Arc<Self>) -> Arc<ServerConfig> {
        self.server_config_for_alpn(default_alpn())
    }

    /// Same as [`server_config`](Self::server_config) with a custom ALPN list
    /// (for example the protocols the upstream actually agreed on).
    pub fn server_config_for_alpn(&self, alpn: Vec<Vec<u8>>) -> Arc<ServerConfig> {
        self.build_server_config(None, alpn)
    }

    /// Like [`server_config_for_alpn`](Self::server_config_for_alpn), but when
    /// the client sends no SNI (IP literal targets) the leaf is minted for
    /// `fallback_name` (typically the original destination IP). SNI, when
    /// present, always wins.
    pub fn server_config_for_target(
        &self,
        fallback_name: &str,
        alpn: Vec<Vec<u8>>,
    ) -> Arc<ServerConfig> {
        self.build_server_config(Some(fallback_name.to_string()), alpn)
    }

    fn build_server_config(
        &self,
        fallback: Option<String>,
        alpn: Vec<Vec<u8>>,
    ) -> Arc<ServerConfig> {
        let resolver = SniResolver {
            ca: self.clone(),
            fallback,
        };
        let mut cfg = ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the safe default protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        cfg.alpn_protocols = alpn;
        Arc::new(cfg)
    }

    fn lock_cache(&self) -> std::sync::MutexGuard<'_, LeafCache> {
        // A panic while holding the lock cannot leave the map logically broken
        // (single-step mutations), so recover from poisoning.
        self.inner
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn mint_leaf(&self, name: &LeafName) -> Result<CertifiedKey, TlsError> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        let text = name.key();
        if text.len() <= 64 {
            dn.push(DnType::CommonName, text);
        }
        p.distinguished_name = dn;
        p.subject_alt_names = vec![name.san()?];
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        p.not_before = backdated_now();
        p.not_after = p.not_before + time::Duration::hours(1) + LEAF_VALIDITY;
        p.serial_number = Some(random_serial()?);
        let ca = &self.inner.ca;
        let leaf = p.signed_by(&key, &ca.issuer, &ca.key)?;
        certified_key(vec![leaf.der().clone(), ca.cert_der.clone()], &key)
    }
}

/// Resolves the inspection certificate from the ClientHello SNI.
#[derive(Debug)]
struct SniResolver {
    ca: GatewayCa,
    fallback: Option<String>,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name().or(self.fallback.as_deref())?;
        // Any failure aborts the handshake: never fall back to another name.
        self.ca.leaf_for(name).ok()
    }
}

/// Bounded LRU map: `HashMap` for lookup, `BTreeMap<tick, key>` for recency.
struct LeafCache {
    capacity: usize,
    tick: u64,
    map: HashMap<String, Entry>,
    order: BTreeMap<u64, String>,
}

struct Entry {
    leaf: Arc<CertifiedKey>,
    tick: u64,
    minted: Instant,
}

impl LeafCache {
    fn new(capacity: usize) -> Self {
        LeafCache {
            capacity,
            tick: 0,
            map: HashMap::new(),
            order: BTreeMap::new(),
        }
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    fn get(&mut self, key: &str) -> Option<Arc<CertifiedKey>> {
        let tick = self.next_tick();
        let entry = self.map.get_mut(key)?;
        if entry.minted.elapsed() >= LEAF_REFRESH_AFTER {
            let old = entry.tick;
            self.map.remove(key);
            self.order.remove(&old);
            return None;
        }
        self.order.remove(&entry.tick);
        entry.tick = tick;
        self.order.insert(tick, key.to_string());
        Some(entry.leaf.clone())
    }

    fn insert_or_get(&mut self, key: String, leaf: Arc<CertifiedKey>) -> Arc<CertifiedKey> {
        if let Some(existing) = self.get(&key) {
            return existing;
        }
        while self.map.len() >= self.capacity {
            match self.order.pop_first() {
                Some((_, oldest)) => {
                    self.map.remove(&oldest);
                }
                None => break,
            }
        }
        let tick = self.next_tick();
        self.order.insert(tick, key.clone());
        self.map.insert(
            key,
            Entry {
                leaf: leaf.clone(),
                tick,
                minted: Instant::now(),
            },
        );
        leaf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_evicts_least_recently_used() {
        let dir = tempfile::tempdir().unwrap();
        let ca = GatewayCa::load_or_create(dir.path(), "t").unwrap();
        let leaf = ca.leaf_for("a.test").unwrap();
        let mut c = LeafCache::new(2);
        c.insert_or_get("a".into(), leaf.clone());
        c.insert_or_get("b".into(), leaf.clone());
        assert!(c.get("a").is_some()); // a is now most recent
        c.insert_or_get("c".into(), leaf.clone());
        assert!(c.get("b").is_none(), "b was least recently used");
        assert!(c.get("a").is_some());
        assert!(c.get("c").is_some());
        assert_eq!(c.map.len(), 2);
        assert_eq!(c.order.len(), 2);
    }
}
