//! Shared fixtures. Fake secrets are assembled with `concat!` so that the source never
//! contains a contiguous token that a secret scanner would flag.
#![allow(dead_code)]

use afw_dlp::{Finding, Scanner, ScannerOptions, builtin_classes};
use sha2::{Digest, Sha256};

pub const ANTHROPIC: &str = concat!(
    "sk-", "ant-", "api03-", "Xq7Lm2Pz9Rt4Vb8Nc1Kd6Hf3Jg5Ws0YeUa", "-", "T2oQiPu8MnBv4Cx"
);
pub const OPENAI: &str = concat!("sk-", "proj-", "Hn4Kq8Lz2Wx6Pv1Rt5Ym9Bc3", "Df7Gj0Ns4Qa8");
pub const GITHUB: &str = concat!("gh", "p_", "R8kz2LmQp4Xv7Tn9", "Wc1Bd5Hf3Jg6Ks0Y", "eUaP");
pub const GITLAB: &str = concat!("gl", "pat-", "Zx8Kq2Lm4Np6Rt", "9Vb1Wc3Y");
pub const AWS_KEY: &str = concat!("AK", "IA", "Q3EXAMPLE7ZK4M2P");
pub const AWS_SECRET: &str = concat!("wJalrXUtnFEMI/K7MDENG", "/bPxRfiCYzEXAMPLEKY");
pub const SLACK: &str = concat!("xo", "xb-", "1234567890-", "0987654321-", "AbCdEfGhIjKlMnOpQrStUvWx");
pub const JWT: &str = concat!(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ".",
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0", ".",
    "Qm9ndXNTaWduYXR1cmVGb3JUZXN0c09ubHk"
);
pub const PASSWORD: &str = "Xk9#mPq2$vLw8nRt";
pub const OPAQUE: &str = "f7Gh2Kq9Lm4Pz8Rt1Vb6Nc3Xw";

pub fn scanner() -> Scanner {
    Scanner::new(
        &builtin_classes(),
        ScannerOptions {
            internal_host_suffixes: vec![".internal".into(), ".corp.example".into()],
            ..ScannerOptions::default()
        },
    )
    .expect("builtin classes compile")
}

pub fn fp(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))[..12].to_string()
}

pub fn kinds(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.kind.as_str()).collect()
}

pub fn has(findings: &[Finding], kind: &str) -> bool {
    findings.iter().any(|f| f.kind == kind)
}

pub fn find<'a>(findings: &'a [Finding], kind: &str) -> &'a Finding {
    findings
        .iter()
        .find(|f| f.kind == kind)
        .unwrap_or_else(|| panic!("no `{kind}` finding in {findings:#?}"))
}

/// Deterministic xorshift64* PRNG (no external dependency).
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}
