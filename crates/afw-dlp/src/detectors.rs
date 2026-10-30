//! Built-in and custom detectors: a byte regex plus an optional validator.
//!
//! Patterns are written with Unicode disabled (`(?-u)`) so that they run on arbitrary bytes,
//! keywords are matched case-insensitively. Some shapes are inspired by gitleaks (MIT) and
//! Pipelock (Apache-2.0) rule sets; no pattern is copied verbatim (see ADR 0012).

use regex::bytes::{Regex, RegexBuilder};
use sha2::{Digest, Sha256};

use crate::DlpError;

/// Built-in detector identifiers, in the order of [`crate::builtin_classes`].
pub const BUILTIN_DETECTORS: &[&str] = &[
    "aws_access_key",
    "aws_secret_key",
    "github_token",
    "gitlab_token",
    "anthropic_key",
    "openai_key",
    "slack_token",
    "jwt",
    "private_key_pem",
    "password_in_url",
    "generic_secret_assignment",
    "bearer_token",
    "private_ip",
    "internal_hostname",
    "price_amount",
    "iban",
    "email",
    "credit_card",
];

/// Post-match validation applied to the value range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    None,
    AwsSecret,
    OpenAi,
    Generic,
    Iban,
    Luhn,
    Email,
    Ipv4,
    Hostname,
}

#[derive(Debug)]
pub(crate) struct Detector {
    pub kind: String,
    re: Regex,
    /// Capture group holding the value (`None`: the whole match).
    value_group: Option<usize>,
    key_group: Option<usize>,
    check: Check,
    /// Literal that every match contains, with the bytes a match may span before and after it:
    /// the full regex only runs in windows around the literal's occurrences.
    anchor: Option<Anchor>,
    /// The detector can match differently once JSON `\"` escapes are removed.
    pub quote_sensitive: bool,
}

#[derive(Debug)]
struct Anchor {
    re: Regex,
    before: usize,
    after: usize,
}

/// Separator class between a key and its value: `key=`, `"key": "`, multipart `name="key"\r\n\r\n`.
const ASSIGN: &str = r#"(?:["']?[ \t]*[:=][ \t]*["']?|"\r?\n\r?\n)"#;

fn builtin_pattern(id: &str) -> Option<(String, Check)> {
    let p = match id {
        "aws_access_key" => (
            r"(?-u)\b(?:AKIA|ASIA|ABIA|ACCA|AIDA|AROA|AIPA|ANPA|ANVA|AGPA)[A-Z0-9]{16}\b".into(),
            Check::None,
        ),
        "aws_secret_key" => (
            format!(
                r"(?i-u)aws[_.\- ]?(?:secret[_.\- ]?(?:access[_.\- ]?)?key|secret|sk){ASSIGN}(?P<v>[A-Za-z0-9/+]{{40}})"
            ),
            Check::AwsSecret,
        ),
        "github_token" => (
            r"(?i-u)\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b".into(),
            Check::None,
        ),
        "gitlab_token" => (r"(?i-u)\bglpat-[A-Za-z0-9_\-]{20,}".into(), Check::None),
        "anthropic_key" => (r"(?i-u)\bsk-ant-[A-Za-z0-9_\-]{20,}".into(), Check::None),
        "openai_key" => (
            r"(?i-u)\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}".into(),
            Check::OpenAi,
        ),
        "slack_token" => (
            r"(?i-u)\bxox[abposre]-[A-Za-z0-9\-]{10,}|https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]{20,}"
                .into(),
            Check::None,
        ),
        "jwt" => (
            r"(?-u)\beyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*".into(),
            Check::None,
        ),
        "private_key_pem" => (
            concat!(
                r"(?i-u)-----BEGIN[A-Z0-9 ]{0,30} PRIVATE KEY(?: BLOCK)?-----",
                r"(?:[A-Za-z0-9+/=\r\n\t :,]|\\[nrt])*",
                r"(?:-----END[A-Z0-9 ]{0,30} PRIVATE KEY(?: BLOCK)?-----)?"
            )
            .into(),
            Check::None,
        ),
        "password_in_url" => (
            r#"(?i-u)\b[a-z][a-z0-9+.\-]{1,15}://[^\s:/?#@"'<>]+:(?P<v>[^\s/@"'<>]+)@"#.into(),
            Check::None,
        ),
        "generic_secret_assignment" => (
            format!(
                concat!(
                    r"(?i-u)(?P<k>[a-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey",
                    r"|access[_\-]?key|auth[_\-]?key|private[_\-]?key|credentials?))",
                    r#"{}(?P<v>[^\s"'&,;<>{{}}\[\]()\\]{{12,}})"#
                ),
                ASSIGN
            ),
            Check::Generic,
        ),
        "bearer_token" => (
            r"(?i-u)\bbearer[ \t]+(?P<v>[A-Za-z0-9._~+/\-]{8,}=*)".into(),
            Check::None,
        ),
        "iban" => (
            r"(?i-u)\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b".into(),
            Check::Iban,
        ),
        "credit_card" => (r"(?-u)\b(?:[0-9][ \-]?){12,18}[0-9]\b".into(), Check::Luhn),
        "email" => (
            concat!(
                r"(?i-u)\b[a-z0-9._%+\-]+@[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?",
                r"(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,24}\b"
            )
            .into(),
            Check::Email,
        ),
        "private_ip" => (
            concat!(
                r"(?-u)\b(?:10(?:\.[0-9]{1,3}){3}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.[0-9]{1,3}){2}",
                r"|192\.168(?:\.[0-9]{1,3}){2})\b"
            )
            .into(),
            Check::Ipv4,
        ),
        "price_amount" => {
            let sep = r"(?:[ .,']|\xC2\xA0|\xE2\x80\xAF)";
            let num = format!(r"(?:[0-9]{{1,3}}(?:{sep}[0-9]{{3}})+|[0-9]+)(?:[.,][0-9]{{1,2}})?");
            let euro = r"(?:\xE2\x82\xAC|eur(?:os?)?\b)";
            (
                format!(
                    r"(?i-u)\xE2\x82\xAC[ ]?{num}|\b{num}(?:[ ]|\xC2\xA0|\xE2\x80\xAF)?{euro}|\beur[ ]?{num}"
                ),
                Check::None,
            )
        }
        _ => return None,
    };
    Some(p)
}

fn hostname_pattern(suffixes: &[String]) -> Option<String> {
    let alts: Vec<String> = suffixes
        .iter()
        .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .map(|s| regex::escape(&s))
        .collect();
    if alts.is_empty() {
        return None;
    }
    Some(format!(
        r"(?i-u)\b(?:[a-z0-9](?:[a-z0-9\-]{{0,61}}[a-z0-9])?\.)+(?:{})\b",
        alts.join("|")
    ))
}

fn compile(name: &str, pattern: &str) -> Result<Regex, DlpError> {
    RegexBuilder::new(pattern)
        .size_limit(4 << 20)
        .dfa_size_limit(8 << 20)
        .build()
        .map_err(|e| DlpError::InvalidPattern {
            name: name.to_string(),
            reason: e.to_string(),
        })
}

impl Detector {
    pub fn builtin(id: &str, internal_host_suffixes: &[String]) -> Result<Option<Self>, DlpError> {
        let (pattern, check) = if id == "internal_hostname" {
            match hostname_pattern(internal_host_suffixes) {
                Some(p) => (p, Check::Hostname),
                // No suffix configured: the detector exists but never matches.
                None => return Ok(None),
            }
        } else {
            builtin_pattern(id).ok_or_else(|| DlpError::UnknownDetector(id.to_string()))?
        };
        let mut det = Self::from_regex(id, compile(id, &pattern)?, check);
        det.quote_sensitive = matches!(
            id,
            "aws_secret_key" | "password_in_url" | "generic_secret_assignment"
        );
        det.anchor = match id {
            "price_amount" => Some(Anchor {
                re: compile(id, r"(?i-u)\xE2\x82\xAC|eur")?,
                before: 64,
                after: 64,
            }),
            "internal_hostname" => {
                let alts: Vec<String> = internal_host_suffixes
                    .iter()
                    .map(|s| regex::escape(s.trim().trim_start_matches('.')))
                    .filter(|s| !s.is_empty())
                    .collect();
                Some(Anchor {
                    re: compile(id, &format!("(?i-u){}", alts.join("|")))?,
                    before: 256,
                    after: 8,
                })
            }
            _ => None,
        };
        Ok(Some(det))
    }

    pub fn custom(name: &str, pattern: &str) -> Result<Self, DlpError> {
        if name.trim().is_empty() {
            return Err(DlpError::InvalidPattern {
                name: name.to_string(),
                reason: "empty detector name".into(),
            });
        }
        if pattern.len() > 4096 {
            return Err(DlpError::InvalidPattern {
                name: name.to_string(),
                reason: "pattern longer than 4096 bytes".into(),
            });
        }
        let re = compile(name, pattern)?;
        if re.is_match(b"") {
            return Err(DlpError::InvalidPattern {
                name: name.to_string(),
                reason: "pattern matches the empty string".into(),
            });
        }
        Ok(Self::from_regex(name, re, Check::None))
    }

    fn from_regex(kind: &str, re: Regex, check: Check) -> Self {
        let names: Vec<Option<&str>> = re.capture_names().collect();
        let idx = |n: &str| names.iter().position(|x| *x == Some(n));
        let value_group = idx("v").or_else(|| idx("value"));
        let key_group = idx("k");
        Self {
            kind: kind.to_string(),
            re,
            value_group,
            key_group,
            check,
            anchor: None,
            quote_sensitive: true,
        }
    }

    /// Value ranges found in `hay`.
    pub fn find(&self, hay: &[u8], out: &mut Vec<(usize, usize)>) {
        let Some(anchor) = &self.anchor else {
            return self.find_in(hay, 0, hay.len(), out);
        };
        let mut windows: Vec<(usize, usize)> = Vec::new();
        for m in anchor.re.find_iter(hay) {
            let s = m.start().saturating_sub(anchor.before);
            let e = (m.end() + anchor.after).min(hay.len());
            match windows.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => windows.push((s, e)),
            }
        }
        for (s, e) in windows {
            self.find_in(hay, s, e, out);
        }
    }

    /// Matches starting in `from..to`; `hay[..from]` still provides left context (`\b`).
    fn find_in(&self, hay: &[u8], from: usize, to: usize, out: &mut Vec<(usize, usize)>) {
        let h = &hay[..to];
        if self.value_group.is_none() && self.key_group.is_none() && from == 0 {
            for m in self.re.find_iter(h) {
                if m.start() < m.end() && self.validate(hay, m.start(), m.end(), None) {
                    out.push((m.start(), m.end()));
                }
            }
            return;
        }
        let mut at = from;
        while at <= to {
            let Some(caps) = self.re.captures_at(h, at) else {
                break;
            };
            let Some(m) = caps.get(0) else { break };
            at = if m.end() > m.start() {
                m.end()
            } else {
                m.end() + 1
            };
            let v = self.value_group.and_then(|g| caps.get(g)).unwrap_or(m);
            let key = self
                .key_group
                .and_then(|g| caps.get(g))
                .map(|k| k.as_bytes());
            if v.start() < v.end() && self.validate(hay, v.start(), v.end(), key) {
                out.push((v.start(), v.end()));
            }
        }
    }

    fn validate(&self, hay: &[u8], start: usize, end: usize, key: Option<&[u8]>) -> bool {
        let v = &hay[start..end];
        match self.check {
            Check::None => true,
            Check::AwsSecret => {
                !hay.get(end)
                    .is_some_and(|b| b.is_ascii_alphanumeric() || b"+/=".contains(b))
                    && entropy(v) >= 3.0
            }
            Check::OpenAi => {
                let lower = v.to_ascii_lowercase();
                let body = &v[3..];
                !lower.starts_with(b"sk-ant-")
                    && body.iter().any(u8::is_ascii_digit)
                    && body.iter().any(u8::is_ascii_alphabetic)
                    && entropy(body) >= 3.5
            }
            Check::Generic => {
                let key_ok = key.is_none_or(|k| !k.to_ascii_lowercase().starts_with(b"x-amz-"));
                key_ok && is_high_entropy_secret(v)
            }
            Check::Iban => iban_valid(v),
            Check::Luhn => card_valid(v),
            Check::Email => !preceded_by_url_userinfo(hay, start),
            Check::Ipv4 => {
                v.split(|b| *b == b'.').all(|o| {
                    std::str::from_utf8(o)
                        .ok()
                        .and_then(|s| s.parse::<u16>().ok())
                        .is_some_and(|n| n <= 255)
                }) && !continues_as_dotted(hay, end)
            }
            Check::Hostname => {
                !hay.get(end).is_some_and(|b| *b == b'-' || *b == b'_')
                    && !continues_as_dotted(hay, end)
            }
        }
    }
}

/// `value` is at least 12 bytes with Shannon entropy ≥ 3.5 bits per byte.
pub(crate) fn is_high_entropy_secret(value: &[u8]) -> bool {
    value.len() >= 12 && entropy(value) >= 3.5
}

/// Shannon entropy in bits per byte.
pub(crate) fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) / n;
            -p * p.log2()
        })
        .sum()
}

/// First 12 hex characters of the SHA-256 of `value`.
pub(crate) fn fingerprint(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    hex::encode(&digest[..6])
}

/// The match is followed by `.` and an alphanumeric byte (`10.0.0.1.5`, `a.internal.example.com`).
fn continues_as_dotted(hay: &[u8], end: usize) -> bool {
    hay.get(end) == Some(&b'.') && hay.get(end + 1).is_some_and(u8::is_ascii_alphanumeric)
}

/// `scheme://user:PASS@host`: the "email" `PASS@host` is URL userinfo, reported by `password_in_url`.
fn preceded_by_url_userinfo(hay: &[u8], start: usize) -> bool {
    if start == 0 || hay[start - 1] != b':' {
        return false;
    }
    let mut i = start - 1;
    let floor = start.saturating_sub(256);
    while i > floor {
        i -= 1;
        match hay[i] {
            b'/' => return i > 0 && hay[i - 1] == b'/',
            b if b.is_ascii_whitespace() || b == b'@' => return false,
            _ => {}
        }
    }
    false
}

fn iban_valid(v: &[u8]) -> bool {
    let s: Vec<u8> = v
        .iter()
        .filter(|b| **b != b' ')
        .map(u8::to_ascii_uppercase)
        .collect();
    if !(15..=34).contains(&s.len()) {
        return false;
    }
    let rearranged = s[4..].iter().chain(&s[..4]);
    let mut rem: u32 = 0;
    for b in rearranged {
        let d = match b {
            b'0'..=b'9' => u32::from(b - b'0'),
            b'A'..=b'Z' => u32::from(b - b'A') + 10,
            _ => return false,
        };
        rem = if d >= 10 {
            (rem * 100 + d) % 97
        } else {
            (rem * 10 + d) % 97
        };
    }
    rem == 1
}

fn card_valid(v: &[u8]) -> bool {
    let digits: Vec<u8> = v
        .iter()
        .filter(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect();
    if !(13..=19).contains(&digits.len()) || !matches!(digits[0], 2..=6) {
        return false;
    }
    // A run of one repeated digit (0000 0000 ...) is not a card.
    if digits.iter().all(|d| *d == digits[0]) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, d)| {
            let d = u32::from(*d);
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_compiles() {
        for id in BUILTIN_DETECTORS {
            let d = Detector::builtin(id, &[".internal".into()]).unwrap();
            assert!(d.is_some(), "{id}");
        }
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(b"aaaa"), 0.0);
        assert!((entropy(b"abcd") - 2.0).abs() < 1e-9);
    }

    #[test]
    fn luhn_and_iban() {
        assert!(card_valid(b"4111111111111111"));
        assert!(!card_valid(b"4111111111111112"));
        assert!(iban_valid(b"FR7630006000011234567890189"));
        assert!(!iban_valid(b"FR7630006000011234567890188"));
    }
}
