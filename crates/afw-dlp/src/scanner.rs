//! Buffer, header and URL scanning across decoded variants.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::bytes::Regex;

use crate::decode::{
    base64_variants, hex_variants, json_unescape, normalize_unicode, percent_decode,
    spaced_base64_variants, utf16_variants,
};
use crate::detectors::{Detector, Span, fingerprint};
use crate::stream::StreamScanner;
use crate::{ClassSpec, DataCategory, DetectorSpec, DlpError, Finding, ScannerOptions};

/// Decoding depth: the original buffer, its decoded variants, and their own decoded variants
/// (for example percent-encoded base64).
const MAX_DEPTH: u8 = 2;

/// SigV4 credential scope `X-Amz-Credential=<key id>/<yyyymmdd>/…` (presigned URL) or
/// `Credential=<key id>/<yyyymmdd>/…` (`Authorization` header): the access key id is a public
/// identifier there, not a secret (EF-72).
static SIGV4_CREDENTIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i-u)(?:x-amz-credential(?:=|%3D)|\bcredential=)A[KS]IA[A-Z0-9]{16}(?:/|%2F)[0-9]{8}(?:/|%2F)[A-Za-z0-9\-_%/]*")
        .expect("static regex")
});

/// SigV2 presigned URL: `AWSAccessKeyId=<key id>` with `Signature=` and `Expires=`.
static SIGV2_KEY_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u)[?&]AWSAccessKeyId=A[KS]IA[A-Z0-9]{16}").expect("static regex")
});

/// GCS V4 presigned URL credential (`service-account@project/…`): nothing in it is a secret.
static GCS_CREDENTIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i-u)[?&]x-goog-credential(?:=|%3D)[^&\s"'<>]*"#).expect("static regex")
});

#[derive(Debug, Clone)]
struct ClassMeta {
    id: String,
    name: String,
    category: DataCategory,
}

/// A raw detection: detector index, byte range in the scanned buffer, value fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hit {
    pub det: usize,
    pub start: usize,
    pub end: usize,
    pub fp: String,
    /// Start of the whole match (key included); retained by the stream while pending.
    pub ctx: usize,
}

/// Compiled set of data classes. Cheap to share (`&Scanner` is `Sync`).
#[derive(Debug)]
pub struct Scanner {
    opts: ScannerOptions,
    detectors: Vec<Detector>,
    /// For each detector, the indices of the classes that use it.
    bindings: Vec<Vec<usize>>,
    classes: Vec<ClassMeta>,
    aws_key_det: Option<usize>,
    bearer_det: Option<usize>,
}

impl Scanner {
    /// Compiles `classes`. Fails on an unknown built-in id or an invalid custom pattern.
    pub fn new(classes: &[ClassSpec], opts: ScannerOptions) -> Result<Scanner, DlpError> {
        if opts.max_pattern_len == 0 {
            return Err(DlpError::InvalidOptions(
                "max_pattern_len must be > 0".into(),
            ));
        }
        let mut detectors: Vec<Detector> = Vec::new();
        let mut bindings: Vec<Vec<usize>> = Vec::new();
        let mut by_key: HashMap<(bool, String, String), Option<usize>> = HashMap::new();
        let mut metas = Vec::with_capacity(classes.len());

        for (ci, class) in classes.iter().enumerate() {
            metas.push(ClassMeta {
                id: class.id.clone(),
                name: class.name.clone(),
                category: class.category,
            });
            for spec in &class.detectors {
                let key = match spec {
                    DetectorSpec::Builtin { id } => (true, id.clone(), String::new()),
                    DetectorSpec::Regex { name, pattern } => (false, name.clone(), pattern.clone()),
                };
                let idx = match by_key.get(&key) {
                    Some(idx) => *idx,
                    None => {
                        let det = match spec {
                            DetectorSpec::Builtin { id } => {
                                Detector::builtin(id, &opts.internal_host_suffixes)?
                            }
                            DetectorSpec::Regex { name, pattern } => {
                                Some(Detector::custom(name, pattern)?)
                            }
                        };
                        let idx = det.map(|d| {
                            detectors.push(d);
                            bindings.push(Vec::new());
                            detectors.len() - 1
                        });
                        by_key.insert(key, idx);
                        idx
                    }
                };
                if let Some(i) = idx
                    && !bindings[i].contains(&ci)
                {
                    bindings[i].push(ci);
                }
            }
        }
        let builtin_idx = |id: &str| {
            by_key
                .get(&(true, id.to_string(), String::new()))
                .copied()
                .flatten()
        };
        Ok(Scanner {
            aws_key_det: builtin_idx("aws_access_key"),
            bearer_det: builtin_idx("bearer_token"),
            opts,
            detectors,
            bindings,
            classes: metas,
        })
    }

    pub fn options(&self) -> &ScannerOptions {
        &self.opts
    }

    /// Scans a buffer and its decoded variants (base64, percent-encoding, JSON escapes).
    /// Ranges always refer to `data`.
    pub fn scan(&self, data: &[u8], location: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for h in self.hits(data) {
            self.push_findings(&h, 0, location, &mut out);
        }
        out
    }

    /// Scans request or response headers. Each finding's location is `header:<lowercase name>`
    /// and its range refers to the header value; a value found in a header name is reported
    /// with location `header_name:<lowercase name>` and a range in the trimmed name.
    pub fn scan_headers(&self, headers: &[(String, String)]) -> Vec<Finding> {
        let mut out = Vec::new();
        for (name, value) in headers {
            let name = name.trim();
            let lname = name.to_ascii_lowercase();
            // Scanning `name: value` lets `x-api-key: <opaque>` match the key/value detectors.
            let prefix = format!("{name}: ");
            let p = prefix.len();
            let mut text = prefix.into_bytes();
            text.extend_from_slice(value.as_bytes());
            let all = self.hits(&text);
            // A value smuggled in the header name itself (range relative to the name).
            let name_location = format!("header_name:{lname}");
            for h in all.iter().filter(|h| h.start < name.len()) {
                let in_name = Hit {
                    end: h.end.min(name.len()),
                    ..h.clone()
                };
                self.push_findings(&in_name, 0, &name_location, &mut out);
            }
            let mut hits: Vec<Hit> = all
                .into_iter()
                .filter(|h| h.end > p)
                .map(|h| Hit {
                    start: h.start.max(p) - p,
                    end: h.end - p,
                    ctx: h.ctx.max(p) - p,
                    ..h
                })
                .collect();
            if matches!(lname.as_str(), "authorization" | "proxy-authorization")
                && let Some(det) = self.bearer_det
                && !is_signing_scheme(value)
                && let Some((s, e)) = authorization_credential(value)
                && !hits.iter().any(|h| h.start <= s && h.end >= e)
            {
                hits.push(Hit {
                    det,
                    start: s,
                    end: e,
                    fp: fingerprint(&value.as_bytes()[s..e]),
                    ctx: s,
                });
            }
            let location = format!("header:{lname}");
            for h in hits {
                self.push_findings(&h, 0, &location, &mut out);
            }
        }
        out
    }

    /// Scans a URL (location `url`); percent-encoded query values are decoded.
    pub fn scan_url(&self, url: &str) -> Vec<Finding> {
        self.scan(url.as_bytes(), "url")
    }

    /// Starts an incremental scan of a continuous stream.
    pub fn stream(&self, location: &str) -> StreamScanner<'_> {
        StreamScanner::new(self, location)
    }

    /// Deduplicated hits, sorted by position.
    pub(crate) fn hits(&self, data: &[u8]) -> Vec<Hit> {
        let mut hits = Vec::new();
        self.scan_raw(data, 0, false, &mut hits);
        hits.sort_by(|a, b| (a.start, a.end, a.det).cmp(&(b.start, b.end, b.det)));
        hits.dedup_by(|a, b| a.det == b.det && a.start == b.start && a.end == b.end);
        hits
    }

    /// `quote_only`: `data` only differs from its parent by JSON quote/whitespace escapes, so
    /// only quote-sensitive detectors can find something new and no further decoding is needed.
    fn scan_raw(&self, data: &[u8], depth: u8, quote_only: bool, out: &mut Vec<Hit>) {
        let exclusions = self.exclusions(data);
        let mut spans: Vec<Span> = Vec::new();
        for (i, d) in self.detectors.iter().enumerate() {
            if quote_only && !d.quote_sensitive {
                continue;
            }
            spans.clear();
            d.find(data, &mut spans);
            for sp in &spans {
                let excluded = exclusions.iter().any(|(a, b, only)| {
                    sp.start >= *a && sp.end <= *b && only.is_none_or(|o| o == i)
                });
                if excluded {
                    continue;
                }
                out.push(Hit {
                    det: i,
                    start: sp.start,
                    end: sp.end,
                    fp: fingerprint(&data[sp.start..sp.end]),
                    ctx: sp.ctx,
                });
            }
        }
        if depth >= MAX_DEPTH || quote_only {
            return;
        }
        let mut variants = Vec::new();
        variants.extend(percent_decode(data).map(|v| (v, false)));
        variants.extend(json_unescape(data).map(|v| (v, !has_deep_json_escape(data))));
        variants.extend(normalize_unicode(data).map(|v| (v, false)));
        variants.extend(base64_variants(data).into_iter().map(|v| (v, false)));
        variants.extend(spaced_base64_variants(data).into_iter().map(|v| (v, false)));
        variants.extend(hex_variants(data).into_iter().map(|v| (v, false)));
        variants.extend(utf16_variants(data).into_iter().map(|v| (v, false)));
        let mut sub = Vec::new();
        for (v, quote_only) in variants {
            sub.clear();
            self.scan_raw(&v.data, depth + 1, quote_only, &mut sub);
            for h in sub.drain(..) {
                let (start, end) = v.map.range(h.start, h.end);
                let (ctx, _) = v.map.range(h.ctx, h.ctx);
                if start < end {
                    out.push(Hit {
                        start,
                        end,
                        ctx: ctx.min(start),
                        ..h
                    });
                }
            }
        }
    }

    /// Ranges of signed-URL parameters that are not secrets (EF-72), with the only detector
    /// they apply to (`None`: every detector).
    fn exclusions(&self, data: &[u8]) -> Vec<(usize, usize, Option<usize>)> {
        let mut ex = Vec::new();
        // The whole scope (`<key id>/<date>/<region>/<service>/aws4_request`), every detector.
        for m in SIGV4_CREDENTIAL.find_iter(data) {
            ex.push((m.start(), m.end(), None));
        }
        if let Some(aws) = self.aws_key_det
            && contains(data, b"Signature=")
            && contains(data, b"Expires=")
        {
            for m in SIGV2_KEY_ID.find_iter(data) {
                ex.push((m.start(), m.end(), Some(aws)));
            }
        }
        for m in GCS_CREDENTIAL.find_iter(data) {
            ex.push((m.start(), m.end(), None));
        }
        ex
    }

    /// One finding per class bound to the hit's detector; `offset` shifts the range.
    pub(crate) fn push_findings(
        &self,
        h: &Hit,
        offset: usize,
        location: &str,
        out: &mut Vec<Finding>,
    ) {
        let det = &self.detectors[h.det];
        for &ci in &self.bindings[h.det] {
            let c = &self.classes[ci];
            out.push(Finding {
                class_id: c.id.clone(),
                class_name: c.name.clone(),
                category: c.category,
                kind: det.kind.clone(),
                fingerprint: h.fp.clone(),
                start: offset + h.start,
                end: offset + h.end,
                location: location.to_string(),
            });
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// `Authorization: AWS4-HMAC-SHA256 Credential=…, Signature=…` (or GCS `GOOG4-…`): a request
/// signature, not a reusable credential.
fn is_signing_scheme(value: &str) -> bool {
    let v = value.trim_start().to_ascii_uppercase();
    v.starts_with("AWS4-") || v.starts_with("GOOG4-")
}

/// JSON escapes that can change what non key/value detectors see (`\uXXXX`, `\/`, `\\`).
fn has_deep_json_escape(data: &[u8]) -> bool {
    data.windows(2)
        .any(|w| w[0] == b'\\' && matches!(w[1], b'u' | b'/' | b'\\'))
}

/// Credential range in an `Authorization` value (`<scheme> <credential>`), at least 8 bytes.
fn authorization_credential(value: &str) -> Option<(usize, usize)> {
    let b = value.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    while i < b.len() && !b[i].is_ascii_whitespace() {
        i += 1;
    }
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    let mut end = b.len();
    while end > i && b[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (end >= i + 8).then_some((i, end))
}
