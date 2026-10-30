//! Encryption at rest of captured contents (HTTP headers and bodies, pcap files), ADR 0006.
//!
//! `AFW_DATA_KEY` is a base64 32-byte master key. Each purpose uses its own key derived with
//! HKDF-SHA256 (RFC 5869); contents are sealed with AES-256-GCM, a random 96-bit nonce and the
//! record id as associated data, so a ciphertext moved to another record does not decrypt.
//! Envelope: `0x01 || nonce (12) || ciphertext || tag (16)`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const BLOCK: usize = 64;

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(data)
        .finalize();
    Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize()
        .into()
}

/// HKDF-SHA256 (RFC 5869), `len <= 255 * 32`.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    assert!(len <= 255 * 32, "HKDF output too long");
    let prk = hmac_sha256(salt, ikm);
    let mut okm = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while okm.len() < len {
        let mut msg = t.clone();
        msg.extend_from_slice(info);
        msg.push(counter);
        t = hmac_sha256(&prk, &msg).to_vec();
        okm.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    okm.truncate(len);
    okm
}

/// Constant-time equality of two byte strings.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("AFW_DATA_KEY must be base64 for exactly 32 bytes")]
    InvalidKey,
    #[error("cannot decrypt stored content")]
    Decrypt,
}

/// Purpose of a derived key (one key per kind of content).
#[derive(Clone, Copy, Debug)]
pub enum Purpose {
    HttpContent,
    Capture,
}

impl Purpose {
    fn info(self) -> &'static [u8] {
        match self {
            Self::HttpContent => b"afw-api/logs/http-content/v1",
            Self::Capture => b"afw-api/logs/capture/v1",
        }
    }
}

/// Seals and opens stored contents.
#[derive(Clone)]
pub struct DataCipher {
    http: Aes256Gcm,
    capture: Aes256Gcm,
}

impl std::fmt::Debug for DataCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataCipher(..)")
    }
}

impl DataCipher {
    /// Builds the cipher from the base64 master key (`AFW_DATA_KEY`).
    pub fn from_base64(key: &str) -> Result<Self, CryptoError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(key.trim())
            .map_err(|_| CryptoError::InvalidKey)?;
        if raw.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        let derive = |p: Purpose| {
            let k = hkdf_sha256(b"agents-firewall", &raw, p.info(), 32);
            Aes256Gcm::new_from_slice(&k).expect("32-byte key")
        };
        Ok(Self {
            http: derive(Purpose::HttpContent),
            capture: derive(Purpose::Capture),
        })
    }

    fn aead(&self, p: Purpose) -> &Aes256Gcm {
        match p {
            Purpose::HttpContent => &self.http,
            Purpose::Capture => &self.capture,
        }
    }

    /// Encrypts `plaintext` bound to `aad` (the record id).
    pub fn seal(&self, p: Purpose, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = self
            .aead(p)
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("AES-GCM encryption cannot fail for bounded inputs");
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        out.push(VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Decrypts an envelope produced by [`Self::seal`] with the same `aad`.
    pub fn open(&self, p: Purpose, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if sealed.len() < 1 + NONCE_LEN + 16 || sealed[0] != VERSION {
            return Err(CryptoError::Decrypt);
        }
        let (nonce, ct) = sealed[1..].split_at(NONCE_LEN);
        self.aead(p)
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
            .map_err(|_| CryptoError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> String {
        base64::engine::general_purpose::STANDARD.encode([7u8; 32])
    }

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_with_long_key_matches_rfc4231_case_6() {
        let key = [0xaau8; 131];
        assert_eq!(
            hex::encode(hmac_sha256(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn hkdf_matches_rfc5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        assert_eq!(
            hex::encode(hkdf_sha256(&salt, &ikm, &info, 42)),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn seal_open_round_trip_and_random_nonce() {
        let c = DataCipher::from_base64(&key()).unwrap();
        let a = c.seal(Purpose::HttpContent, b"id-1", b"secret body");
        let b = c.seal(Purpose::HttpContent, b"id-1", b"secret body");
        assert_ne!(a, b, "nonce must be random");
        assert!(!a.windows(11).any(|w| w == b"secret body"));
        assert_eq!(
            c.open(Purpose::HttpContent, b"id-1", &a).unwrap(),
            b"secret body"
        );
    }

    #[test]
    fn tampering_wrong_aad_wrong_purpose_or_key_is_refused() {
        let c = DataCipher::from_base64(&key()).unwrap();
        let mut a = c.seal(Purpose::HttpContent, b"id-1", b"secret body");
        assert_eq!(
            c.open(Purpose::HttpContent, b"id-2", &a),
            Err(CryptoError::Decrypt)
        );
        assert_eq!(
            c.open(Purpose::Capture, b"id-1", &a),
            Err(CryptoError::Decrypt)
        );
        let other =
            DataCipher::from_base64(&base64::engine::general_purpose::STANDARD.encode([8u8; 32]))
                .unwrap();
        assert_eq!(
            other.open(Purpose::HttpContent, b"id-1", &a),
            Err(CryptoError::Decrypt)
        );
        let last = a.len() - 1;
        a[last] ^= 1;
        assert_eq!(
            c.open(Purpose::HttpContent, b"id-1", &a),
            Err(CryptoError::Decrypt)
        );
        assert_eq!(
            c.open(Purpose::HttpContent, b"id-1", &[1, 2, 3]),
            Err(CryptoError::Decrypt)
        );
    }

    #[test]
    fn invalid_keys_are_rejected() {
        assert!(DataCipher::from_base64("not base64!").is_err());
        assert!(
            DataCipher::from_base64(&base64::engine::general_purpose::STANDARD.encode([1u8; 16]))
                .is_err()
        );
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
