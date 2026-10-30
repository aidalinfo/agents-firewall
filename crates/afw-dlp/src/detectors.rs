//! Built-in and custom detectors: a byte regex plus an optional validator.
//!
//! Patterns are written with Unicode disabled (`(?-u)`) so that they run on arbitrary bytes,
//! keywords are matched case-insensitively. Some shapes are inspired by gitleaks (MIT) and
//! Pipelock (Apache-2.0) rule sets; no pattern is copied verbatim (see ADR 0012).

use std::sync::LazyLock;

use regex::bytes::{Captures, Regex, RegexBuilder};
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
    "session_cookie",
    "azure_sas_signature",
    "private_ip",
    "internal_hostname",
    "price_amount",
    "iban",
    "email",
    "credit_card",
];

/// Longest span masked for a PEM private key without its `-----END` marker.
pub(crate) const PEM_MAX: usize = 16 * 1024;

/// A detected value: `start..end` is the value, `ctx..end` the whole match (key included).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span {
    pub ctx: usize,
    pub start: usize,
    pub end: usize,
}

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
    Ip,
    Hostname,
}

/// How a detector finds its values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Finder {
    Regex,
    /// From `-----BEGIN … PRIVATE KEY-----` to the matching `-----END`, whatever is in between.
    Pem,
    /// High-entropy values of a `Cookie:` / `Set-Cookie:` line.
    Cookie,
}

#[derive(Debug)]
pub(crate) struct Detector {
    pub kind: String,
    re: Regex,
    /// Capture groups holding the value, first participating wins (none: the whole match).
    value_groups: Vec<usize>,
    key_group: Option<usize>,
    check: Check,
    finder: Finder,
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

static PEM_END: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i-u)-----END[A-Z0-9 ]{0,30} PRIVATE KEY(?: BLOCK)?-----").expect("static regex")
});

/// Separator class between a key and its value: `key=`, `"key": "`, multipart `name="key"\r\n\r\n`.
const ASSIGN: &str = r#"(?:["']?[ \t]*[:=][ \t]*["']?|"\r?\n\r?\n)"#;

/// Keys whose value is a password: lower thresholds (≥ 8 bytes, no entropy requirement).
const PASSWORD_KEYS: &[&[u8]] = &[b"password", b"passwd", b"passphrase", b"pwd", b"secret"];

fn builtin_pattern(id: &str) -> Option<(String, Check, Finder)> {
    use Finder::Regex as R;
    let p = match id {
        "aws_access_key" => (
            r"(?-u)\b(?:AKIA|ASIA|ABIA|ACCA|AIDA|AROA|AIPA|ANPA|ANVA|AGPA)[A-Z0-9]{16}\b".into(),
            Check::None,
            R,
        ),
        "aws_secret_key" => (
            format!(
                r"(?i-u)aws[_.\- ]?(?:secret[_.\- ]?(?:access[_.\- ]?)?key|secret|sk){ASSIGN}(?P<v>[A-Za-z0-9/+]{{40}})"
            ),
            Check::AwsSecret,
            R,
        ),
        "github_token" => (
            r"(?i-u)\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b".into(),
            Check::None,
            R,
        ),
        "gitlab_token" => (r"(?i-u)\bglpat-[A-Za-z0-9_\-]{20,}".into(), Check::None, R),
        "anthropic_key" => (r"(?i-u)\bsk-ant-[A-Za-z0-9_\-]{20,}".into(), Check::None, R),
        "openai_key" => (
            r"(?i-u)\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}".into(),
            Check::OpenAi,
            R,
        ),
        "slack_token" => (
            r"(?i-u)\bxox[abposre]-[A-Za-z0-9\-]{10,}|https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]{20,}"
                .into(),
            Check::None,
            R,
        ),
        "jwt" => (
            r"(?-u)\beyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*".into(),
            Check::None,
            R,
        ),
        "private_key_pem" => (
            r"(?i-u)-----BEGIN[A-Z0-9 ]{0,30} PRIVATE KEY(?: BLOCK)?-----".into(),
            Check::None,
            Finder::Pem,
        ),
        "password_in_url" => (
            r#"(?i-u)\b[a-z][a-z0-9+.\-]{1,15}://[^\s:/?#@"'<>]+:(?P<v>[^\s/@"'<>]+)@"#.into(),
            Check::None,
            R,
        ),
        "generic_secret_assignment" => (
            concat!(
                r"(?i-u)(?P<k>[a-z0-9_.\-]{0,64}(?:password|passwd|passphrase|pwd|secret|token|api[_\-]?key",
                r"|apikey|access[_\-]?key|auth[_\-]?key|private[_\-]?key|credentials?))",
                r#"(?:["']?[ \t]*[:=][ \t]*|"\r?\n\r?\n)"#,
                r#"(?:"(?P<dq>[^"\r\n]{1,256})"|'(?P<sq>[^'\r\n]{1,256})'|(?P<v>[^\s"'<>\\]{1,256}))"#
            )
            .into(),
            Check::Generic,
            R,
        ),
        "bearer_token" => (
            r"(?i-u)\bbearer[ \t]+(?P<v>[A-Za-z0-9._~+/\-]{8,}=*)".into(),
            Check::None,
            R,
        ),
        "session_cookie" => (
            r"(?i-u)\b(?:set-)?cookie[ \t]*:[ \t]*".into(),
            Check::None,
            Finder::Cookie,
        ),
        "azure_sas_signature" => (
            concat!(
                r"(?i-u)\b[a-z0-9\-]{1,63}\.(?:blob|file|queue|table|dfs)\.core\.windows\.net",
                r#"[^\s"'<>]*?[?&]sig=(?P<v>[A-Za-z0-9%+/=]{16,})"#
            )
            .into(),
            Check::None,
            R,
        ),
        "iban" => (
            r"(?i-u)\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b".into(),
            Check::Iban,
            R,
        ),
        "credit_card" => (
            r"(?-u)\b(?:[0-9][ \-.]?){12,18}[0-9]\b".into(),
            Check::Luhn,
            R,
        ),
        "email" => (
            concat!(
                r"(?i-u)\b[a-z0-9._%+\-]+@[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?",
                r"(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,24}\b"
            )
            .into(),
            Check::Email,
            R,
        ),
        "private_ip" => (
            concat!(
                r"(?-u)\b(?:10(?:\.[0-9]{1,3}){3}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.[0-9]{1,3}){2}",
                r"|192\.168(?:\.[0-9]{1,3}){2})\b",
                r"|(?i-u)\bf[cd][0-9a-f]{2}(?::[0-9a-f]{0,4}){2,7}"
            )
            .into(),
            Check::Ip,
            R,
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
                R,
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
        let (pattern, check, finder) = if id == "internal_hostname" {
            match hostname_pattern(internal_host_suffixes) {
                Some(p) => (p, Check::Hostname, Finder::Regex),
                // No suffix configured: the detector exists but never matches.
                None => return Ok(None),
            }
        } else {
            builtin_pattern(id).ok_or_else(|| DlpError::UnknownDetector(id.to_string()))?
        };
        let mut det = Self::from_regex(id, compile(id, &pattern)?, check);
        det.finder = finder;
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
        let value_groups = ["v", "dq", "sq", "value"]
            .iter()
            .filter_map(|n| idx(n))
            .collect();
        let key_group = idx("k");
        Self {
            kind: kind.to_string(),
            re,
            value_groups,
            key_group,
            check,
            finder: Finder::Regex,
            anchor: None,
            quote_sensitive: true,
        }
    }

    /// Values found in `hay`.
    pub fn find(&self, hay: &[u8], out: &mut Vec<Span>) {
        match self.finder {
            Finder::Pem => return self.find_pem(hay, out),
            Finder::Cookie => return self.find_cookies(hay, out),
            Finder::Regex => {}
        }
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
    fn find_in(&self, hay: &[u8], from: usize, to: usize, out: &mut Vec<Span>) {
        let h = &hay[..to];
        if self.value_groups.is_empty() && self.key_group.is_none() && from == 0 {
            for m in self.re.find_iter(h) {
                if m.start() < m.end()
                    && let Some((s, e)) = self.validate(hay, m.start(), m.end(), None, false)
                {
                    out.push(Span {
                        ctx: m.start(),
                        start: s,
                        end: e,
                    });
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
            let (v, quoted) = self.value_of(&caps).unwrap_or((m, false));
            let key = self
                .key_group
                .and_then(|g| caps.get(g))
                .map(|k| (k.start(), k.end()));
            if v.start() < v.end()
                && let Some((s, e)) = self.validate(hay, v.start(), v.end(), key, quoted)
            {
                out.push(Span {
                    ctx: m.start(),
                    start: s,
                    end: e,
                });
            }
        }
    }

    /// The participating value group, and whether it was quoted (`dq`/`sq`).
    fn value_of<'h>(&self, caps: &Captures<'h>) -> Option<(regex::bytes::Match<'h>, bool)> {
        self.value_groups.iter().find_map(|g| {
            caps.get(*g).map(|m| {
                let quoted = self
                    .re
                    .capture_names()
                    .nth(*g)
                    .flatten()
                    .is_some_and(|n| n == "dq" || n == "sq");
                (m, quoted)
            })
        })
    }

    fn find_pem(&self, hay: &[u8], out: &mut Vec<Span>) {
        let mut covered = 0;
        for m in self.re.find_iter(hay) {
            if m.start() < covered {
                continue;
            }
            let limit = (m.start() + PEM_MAX).min(hay.len());
            let end = PEM_END
                .find(&hay[m.end()..limit])
                .map_or(limit, |e| m.end() + e.end());
            out.push(Span {
                ctx: m.start(),
                start: m.start(),
                end,
            });
            covered = end;
        }
    }

    fn find_cookies(&self, hay: &[u8], out: &mut Vec<Span>) {
        let starts: Vec<(usize, usize)> = self
            .re
            .find_iter(hay)
            .map(|m| (m.start(), m.end()))
            .collect();
        for (i, &(ctx, line_start)) in starts.iter().enumerate() {
            let bound = starts
                .get(i + 1)
                .map_or(hay.len(), |n| n.0)
                .min(line_start + 8192);
            let line_end = hay[line_start..bound]
                .iter()
                .position(|b| *b == b'\r' || *b == b'\n')
                .map_or(bound, |p| line_start + p);
            let mut pos = line_start;
            for part in hay[line_start..line_end].split(|b| *b == b';') {
                let part_start = pos;
                pos += part.len() + 1;
                let Some(eq) = part.iter().position(|b| *b == b'=') else {
                    continue;
                };
                let (mut s, mut e) = (part_start + eq + 1, part_start + part.len());
                while s < e && matches!(hay[s], b' ' | b'"') {
                    s += 1;
                }
                while e > s && matches!(hay[e - 1], b' ' | b'"' | b'\t') {
                    e -= 1;
                }
                if is_high_entropy(&hay[s..e], 24) {
                    out.push(Span {
                        ctx,
                        start: s,
                        end: e,
                    });
                }
            }
        }
    }

    fn validate(
        &self,
        hay: &[u8],
        start: usize,
        end: usize,
        key: Option<(usize, usize)>,
        quoted: bool,
    ) -> Option<(usize, usize)> {
        let v = &hay[start..end];
        let ok = match self.check {
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
            Check::Generic => return generic_value(hay, start, end, key, quoted),
            Check::Iban => iban_valid(v),
            Check::Luhn => card_valid(v),
            Check::Email => !preceded_by_url_userinfo(hay, start),
            Check::Ip => ip_valid(hay, v, end),
            Check::Hostname => {
                !hay.get(end).is_some_and(|b| *b == b'-' || *b == b'_')
                    && !continues_as_dotted(hay, end)
            }
        };
        ok.then_some((start, end))
    }
}

/// Generic `key = value` rule. Password-like keys need ≥ 8 bytes; other keys (token, api key…)
/// ≥ 12 bytes, no whitespace and entropy ≥ 3.5. Placeholders and code are ignored.
fn generic_value(
    hay: &[u8],
    start: usize,
    mut end: usize,
    key: Option<(usize, usize)>,
    quoted: bool,
) -> Option<(usize, usize)> {
    let key_lower = key
        .map(|(s, e)| hay[s..e].to_ascii_lowercase())
        .unwrap_or_default();
    // SigV4/GCS signing parameters of a presigned URL (EF-72), only in a query string.
    if key.is_some_and(|(s, _)| s > 0 && matches!(hay[s - 1], b'?' | b'&'))
        && matches!(
            key_lower.as_slice(),
            b"x-amz-security-token"
                | b"x-amz-signature"
                | b"x-amz-credential"
                | b"x-goog-signature"
                | b"x-goog-credential"
        )
    {
        return None;
    }
    if !quoted {
        end = trim_unquoted(hay, start, end);
    }
    let v = &hay[start..end];
    if is_trivial(v, quoted) {
        return None;
    }
    let password_key = PASSWORD_KEYS.iter().any(|k| key_lower.ends_with(k));
    let ok = if password_key {
        v.len() >= 8
    } else {
        !v.iter().any(u8::is_ascii_whitespace) && is_high_entropy(v, 12)
    };
    ok.then_some((start, end))
}

/// An unquoted value ends before `&name=` / `;name=` / `,name=` (next parameter) and before
/// trailing separators or unbalanced closing brackets.
fn trim_unquoted(hay: &[u8], start: usize, end: usize) -> usize {
    let v = &hay[start..end];
    let mut cut = v.len();
    for (i, b) in v.iter().enumerate() {
        if matches!(b, b'&' | b';' | b',') {
            let rest = &v[i + 1..];
            let name_len = rest
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
                .count();
            if name_len > 0 && rest.get(name_len) == Some(&b'=') {
                cut = i;
                break;
            }
        }
    }
    let mut v = &v[..cut];
    loop {
        match v.last() {
            Some(b',' | b';') => v = &v[..v.len() - 1],
            Some(c @ (b')' | b']' | b'}')) => {
                let open = match c {
                    b')' => b'(',
                    b']' => b'[',
                    _ => b'{',
                };
                let opens = v.iter().filter(|x| **x == open).count();
                let closes = v.iter().filter(|x| *x == c).count();
                if closes > opens {
                    v = &v[..v.len() - 1];
                } else {
                    break;
                }
            }
            _ => break,
        }
    }
    start + v.len()
}

/// Placeholders, masks, variable references and code expressions.
fn is_trivial(v: &[u8], quoted: bool) -> bool {
    let lower = v.to_ascii_lowercase();
    let trimmed = lower.trim_ascii();
    if trimmed.is_empty() || trimmed.iter().all(|b| *b == trimmed[0]) {
        return true;
    }
    const WORDS: &[&[u8]] = &[
        b"changeme",
        b"change_me",
        b"password",
        b"passwd",
        b"secret",
        b"null",
        b"none",
        b"nil",
        b"undefined",
        b"true",
        b"false",
        b"redacted",
        b"<redacted>",
        b"[redacted]",
        b"hidden",
        b"example",
        b"placeholder",
        b"your_password",
        b"yourpassword",
        b"your-password",
        b"mypassword",
        b"notasecret",
        b"dummy",
        b"secret123",
        b"password123",
        b"xxxxxxxx",
    ];
    if WORDS.contains(&trimmed) {
        return true;
    }
    if trimmed
        .iter()
        .all(|b| matches!(b, b'*' | b'x' | b'.' | b'-' | b'#' | b'?' | b'<' | b'>'))
    {
        return true;
    }
    let first = trimmed[0];
    let last = trimmed[trimmed.len() - 1];
    if first == b'$'
        || trimmed.starts_with(b"{{")
        || trimmed.starts_with(b"%(")
        || (first == b'<' && last == b'>')
        || (first == b'[' && last == b']' && trimmed.windows(8).any(|w| w == b"redacted"))
    {
        return true;
    }
    !quoted && looks_like_code(v)
}

/// `getpass.getpass()`, `os.environ["X"]`, `process.env.DB_PASSWORD`, `config.db.password`.
fn looks_like_code(v: &[u8]) -> bool {
    let ident_len = |s: &[u8]| {
        if !s
            .first()
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        {
            return 0;
        }
        s.iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
            .count()
    };
    let mut i = 0;
    let mut segments = Vec::new();
    loop {
        let n = ident_len(&v[i..]);
        if n == 0 {
            return false;
        }
        segments.push(&v[i..i + n]);
        i += n;
        match v.get(i) {
            Some(b'.') => i += 1,
            Some(b'(' | b'[') => return true,
            None => break,
            Some(_) => return false,
        }
    }
    const ROOTS: &[&[u8]] = &[
        b"process",
        b"os",
        b"env",
        b"config",
        b"cfg",
        b"conf",
        b"settings",
        b"self",
        b"this",
        b"ctx",
        b"context",
        b"args",
        b"params",
        b"opts",
        b"options",
        b"request",
        b"req",
        b"vars",
        b"secrets",
        b"app",
        b"props",
        b"import",
    ];
    segments.len() > 1 && ROOTS.contains(&segments[0].to_ascii_lowercase().as_slice())
}

/// `value` is at least `min_len` bytes with Shannon entropy ≥ 3.5 bits per byte.
pub(crate) fn is_high_entropy(value: &[u8], min_len: usize) -> bool {
    value.len() >= min_len && entropy(value) >= 3.5
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

/// Private IPv4 (octets ≤ 255) or IPv6 unique local address (fc00::/7).
fn ip_valid(hay: &[u8], v: &[u8], end: usize) -> bool {
    if v.contains(&b':') {
        let next_ok = !hay
            .get(end)
            .is_some_and(|b| b.is_ascii_hexdigit() || *b == b':' || *b == b'.');
        return next_ok
            && std::str::from_utf8(v)
                .ok()
                .and_then(|s| s.parse::<std::net::Ipv6Addr>().ok())
                .is_some_and(|ip| ip.segments()[0] & 0xfe00 == 0xfc00);
    }
    v.split(|b| *b == b'.').all(|o| {
        std::str::from_utf8(o)
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .is_some_and(|n| n <= 255)
    }) && !continues_as_dotted(hay, end)
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

    #[test]
    fn code_and_placeholders() {
        assert!(looks_like_code(b"getpass.getpass()"));
        assert!(looks_like_code(b"process.env.DB_PASSWORD"));
        assert!(!looks_like_code(b"my.secret.pass"));
        assert!(is_trivial(b"${X}", false));
        assert!(!is_trivial(b"Summer2024!", false));
    }
}
