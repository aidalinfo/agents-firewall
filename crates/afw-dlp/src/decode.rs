//! Decoded variants of a buffer, with a position map back to the original bytes.

use std::sync::LazyLock;

use base64::Engine;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use regex::bytes::Regex;

/// A decoded copy of (part of) a buffer.
pub(crate) struct Variant {
    pub data: Vec<u8>,
    pub map: PosMap,
}

/// How positions in [`Variant::data`] map back to the parent buffer.
pub(crate) enum PosMap {
    /// Bytes are copied one to one except at the listed escapes (sorted by decoded offset).
    Escapes(Vec<Escape>),
    /// Every decoded position maps to this parent range (base64 and hex blobs).
    Whole(usize, usize),
    /// Decoded byte `i` is parent byte `base + i * stride` (UTF-16 to ASCII).
    Stride {
        base: usize,
        stride: usize,
        len: usize,
    },
}

/// `dec_len` decoded bytes at `dec` come from `orig_len` parent bytes at `orig`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Escape {
    dec: usize,
    dec_len: usize,
    orig: usize,
    orig_len: usize,
}

impl PosMap {
    pub fn range(&self, start: usize, end: usize) -> (usize, usize) {
        match self {
            PosMap::Escapes(e) => (map_pos(e, start), map_pos(e, end)),
            PosMap::Whole(s, e) => (*s, *e),
            PosMap::Stride { base, stride, len } => (
                (base + start * stride).min(*len),
                (base + end * stride).min(*len),
            ),
        }
    }
}

/// Parent offset of decoded position `i` (a position inside an escape maps to its start).
fn map_pos(escapes: &[Escape], i: usize) -> usize {
    let n = escapes.partition_point(|e| e.dec <= i);
    if n == 0 {
        return i;
    }
    let e = escapes[n - 1];
    if i < e.dec + e.dec_len {
        e.orig
    } else {
        e.orig + e.orig_len + (i - e.dec - e.dec_len)
    }
}

fn push_escape(
    escapes: &mut Vec<Escape>,
    dec: usize,
    dec_len: usize,
    orig: usize,
    orig_len: usize,
) {
    escapes.push(Escape {
        dec,
        dec_len,
        orig,
        orig_len,
    });
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decoding (`%XX`). `None` when there is nothing to decode.
pub(crate) fn percent_decode(data: &[u8]) -> Option<Variant> {
    let has_escape = data
        .windows(3)
        .any(|w| w[0] == b'%' && hex_val(w[1]).is_some() && hex_val(w[2]).is_some());
    if !has_escape {
        return None;
    }
    let mut out = Vec::with_capacity(data.len());
    let mut map = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'%'
            && let (Some(h), Some(l)) = (
                data.get(i + 1).copied().and_then(hex_val),
                data.get(i + 2).copied().and_then(hex_val),
            )
        {
            push_escape(&mut map, out.len(), 1, i, 3);
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(data[i]);
        i += 1;
    }
    Some(Variant {
        data: out,
        map: PosMap::Escapes(map),
    })
}

/// JSON string unescaping (`\"`, `\\`, `\/`, `\n`, `\uXXXX`...). `None` when no such escape exists.
pub(crate) fn json_unescape(data: &[u8]) -> Option<Variant> {
    let relevant = data.windows(2).any(|w| {
        w[0] == b'\\'
            && matches!(
                w[1],
                b'"' | b'\\' | b'/' | b'u' | b'n' | b'r' | b't' | b'b' | b'f'
            )
    });
    if !relevant {
        return None;
    }
    let mut out = Vec::with_capacity(data.len());
    let mut map = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\\'
            && let Some(&next) = data.get(i + 1)
        {
            let simple = match next {
                b'"' => Some(b'"'),
                b'\\' => Some(b'\\'),
                b'/' => Some(b'/'),
                b'n' => Some(b'\n'),
                b'r' => Some(b'\r'),
                b't' => Some(b'\t'),
                b'b' => Some(0x08),
                b'f' => Some(0x0c),
                _ => None,
            };
            if let Some(c) = simple {
                push_escape(&mut map, out.len(), 1, i, 2);
                out.push(c);
                i += 2;
                continue;
            }
            if next == b'u'
                && let Some(cp) = data.get(i + 2..i + 6).and_then(|h| {
                    h.iter()
                        .try_fold(0u32, |acc, b| hex_val(*b).map(|v| acc << 4 | u32::from(v)))
                })
                && let Some(ch) = char::from_u32(cp)
            {
                let mut buf = [0u8; 4];
                let encoded = ch.encode_utf8(&mut buf).as_bytes();
                push_escape(&mut map, out.len(), encoded.len(), i, 6);
                out.extend_from_slice(encoded);
                i += 6;
                continue;
            }
        }
        out.push(data[i]);
        i += 1;
    }
    Some(Variant {
        data: out,
        map: PosMap::Escapes(map),
    })
}

/// Base64 / base64url runs, possibly wrapped over several lines (MIME, PEM, `\n` in JSON).
static B64_RUN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?-u)(?:[A-Za-z0-9+/_\-]{16,}|[A-Za-z0-9+/]{4,}(?:\r?\n|\\r\\n|\\n)[A-Za-z0-9+/]{4,})",
        r"(?:(?:\r?\n|\\r\\n|\\n)[A-Za-z0-9+/_][A-Za-z0-9+/_\-]{3,})*={0,2}"
    ))
    .expect("static regex")
});

const LENIENT: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_decode_allow_trailing_bits(true)
    .with_decode_padding_mode(DecodePaddingMode::Indifferent);
const STD_LENIENT: GeneralPurpose = GeneralPurpose::new(&base64::alphabet::STANDARD, LENIENT);
const URL_LENIENT: GeneralPurpose = GeneralPurpose::new(&base64::alphabet::URL_SAFE, LENIENT);

/// Decoded variants for every plausible base64 run in `data`.
pub(crate) fn base64_variants(data: &[u8]) -> Vec<Variant> {
    let mut out = Vec::new();
    for m in B64_RUN.find_iter(data) {
        push_base64(m.as_bytes(), m.start(), m.end(), &mut out);
    }
    out
}

fn push_base64(run: &[u8], start: usize, end: usize, out: &mut Vec<Variant>) {
    let mut clean: Vec<u8> = Vec::with_capacity(run.len());
    let mut i = 0;
    while i < run.len() {
        match run[i] {
            b'\r' | b'\n' | b'=' | b' ' | b'\t' => i += 1,
            b'\\' => i += 2, // `\n` or `\r` escape
            b => {
                clean.push(b);
                i += 1;
            }
        }
    }
    let url = clean.iter().any(|b| *b == b'-' || *b == b'_');
    let std = clean.iter().any(|b| *b == b'+' || *b == b'/');
    if url && std {
        // Base64 glued to `-`/`_` separated words: try each standard segment.
        for seg in clean.split(|b| *b == b'-' || *b == b'_') {
            if seg.len() >= 16 {
                decode_into(seg, &STD_LENIENT, start, end, out);
            }
        }
        return;
    }
    decode_into(
        &clean,
        if url { &URL_LENIENT } else { &STD_LENIENT },
        start,
        end,
        out,
    );
}

/// Alignment 0 is always scanned, even if binary (detectors work on bytes). The run may also
/// start mid-token (`x` + base64): other alignments are kept when they decode to text.
fn decode_into(
    clean: &[u8],
    engine: &GeneralPurpose,
    start: usize,
    end: usize,
    out: &mut Vec<Variant>,
) {
    for skip in 0..4.min(clean.len()) {
        let mut s = &clean[skip..];
        if s.len() % 4 == 1 {
            s = &s[..s.len() - 1];
        }
        if s.len() < 12 {
            break;
        }
        if let Ok(d) = engine.decode(s)
            && (skip == 0 || plausible_text(&d))
        {
            let text = skip > 0 || plausible_text(&d);
            out.push(Variant {
                data: d,
                map: PosMap::Whole(start, end),
            });
            if text {
                return;
            }
        }
    }
}

/// Base64 split into equal groups by spaces (`QUJD REVG R0hJ`): groups of the same length
/// (a multiple of 4, the last one may be shorter), at least two groups and 16 characters.
pub(crate) fn spaced_base64_variants(data: &[u8]) -> Vec<Variant> {
    let is_b64 = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_');
    let mut tokens: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if is_b64(data[i]) {
            let s = i;
            while i < data.len() && is_b64(data[i]) {
                i += 1;
            }
            tokens.push((s, i));
        } else {
            i += 1;
        }
    }
    let mut out = Vec::new();
    let mut g = 0;
    while g < tokens.len() {
        let (s0, e0) = tokens[g];
        let width = e0 - s0;
        let mut last = g;
        if width >= 4 && width % 4 == 0 {
            while last + 1 < tokens.len() {
                let (ps, pe) = tokens[last];
                let (ns, ne) = tokens[last + 1];
                let gap = &data[pe..ns];
                let sep_ok = !gap.is_empty()
                    && gap.len() <= 2
                    && gap.iter().all(|b| matches!(b, b' ' | b'\t'));
                if !sep_ok || pe - ps != width || ne - ns > width {
                    break;
                }
                last += 1;
                if ne - ns < width {
                    break;
                }
            }
        }
        let total: usize = tokens[g..=last].iter().map(|(s, e)| e - s).sum();
        if last > g && total >= 16 {
            let (start, end) = (tokens[g].0, tokens[last].1);
            push_base64(&data[start..end], start, end, &mut out);
            g = last + 1;
        } else {
            g += 1;
        }
    }
    out
}

static HEX_RUN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)[0-9a-fA-F]{32,}").expect("static regex"));

/// Hex runs of at least 32 characters, decoded (both nibble alignments when odd).
pub(crate) fn hex_variants(data: &[u8]) -> Vec<Variant> {
    let mut out = Vec::new();
    for m in HEX_RUN.find_iter(data) {
        let run = m.as_bytes();
        let skips: &[usize] = if run.len() % 2 == 1 { &[0, 1] } else { &[0] };
        for &skip in skips {
            let d: Vec<u8> = run[skip..]
                .chunks_exact(2)
                .map(|p| hex_val(p[0]).unwrap_or(0) << 4 | hex_val(p[1]).unwrap_or(0))
                .collect();
            out.push(Variant {
                data: d,
                map: PosMap::Whole(m.start(), m.end()),
            });
        }
    }
    out
}

/// Fullwidth ASCII (U+FF01..U+FF5E) folded to ASCII; zero-width characters, word joiner, BOM
/// and soft hyphen removed. `None` when there is none.
pub(crate) fn normalize_unicode(data: &[u8]) -> Option<Variant> {
    let relevant = data
        .windows(2)
        .any(|w| matches!(w, [0xEF, 0xBB..=0xBD] | [0xE2, 0x80 | 0x81] | [0xC2, 0xAD]));
    if !relevant {
        return None;
    }
    let mut out = Vec::with_capacity(data.len());
    let mut map = Vec::new();
    let mut i = 0;
    let mut changed = false;
    while i < data.len() {
        let rest = &data[i..];
        let (replacement, len): (Option<u8>, usize) = match rest {
            [0xEF, 0xBC, c @ 0x81..=0xBF, ..] => (Some(c - 0x81 + 0x21), 3),
            [0xEF, 0xBD, c @ 0x80..=0x9E, ..] => (Some(c - 0x80 + 0x60), 3),
            [0xE2, 0x80, 0x8B..=0x8D, ..] | [0xE2, 0x81, 0xA0, ..] | [0xEF, 0xBB, 0xBF, ..] => {
                (None, 3)
            }
            [0xC2, 0xAD, ..] => (None, 2),
            _ => {
                out.push(data[i]);
                i += 1;
                continue;
            }
        };
        changed = true;
        push_escape(
            &mut map,
            out.len(),
            usize::from(replacement.is_some()),
            i,
            len,
        );
        out.extend(replacement);
        i += len;
    }
    changed.then_some(Variant {
        data: out,
        map: PosMap::Escapes(map),
    })
}

/// UTF-16 (LE or BE) text of mostly ASCII characters, narrowed to bytes.
pub(crate) fn utf16_variants(data: &[u8]) -> Vec<Variant> {
    let mut out = Vec::new();
    if data.len() < 16 {
        return out;
    }
    for zero_at in [1usize, 0] {
        let zeros = data
            .iter()
            .skip(zero_at)
            .step_by(2)
            .filter(|b| **b == 0)
            .count();
        let slots = (data.len() - zero_at).div_ceil(2);
        if zeros * 10 >= slots * 9 {
            let base = 1 - zero_at;
            out.push(Variant {
                data: data.iter().skip(base).step_by(2).copied().collect(),
                map: PosMap::Stride {
                    base,
                    stride: 2,
                    len: data.len(),
                },
            });
        }
    }
    out
}

/// Decoded bytes look like text.
fn plausible_text(d: &[u8]) -> bool {
    if d.len() < 8 {
        return false;
    }
    let printable = d
        .iter()
        .filter(|b| (0x20..0x7f).contains(*b) || matches!(b, b'\t' | b'\r' | b'\n'))
        .count();
    if printable * 10 >= d.len() * 9 {
        return true;
    }
    std::str::from_utf8(d).is_ok_and(|s| !s.chars().any(|c| c.is_control() && !c.is_whitespace()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_std(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    #[test]
    fn percent_map() {
        let v = percent_decode(b"a%41b").unwrap();
        assert_eq!(v.data, b"aAb");
        assert_eq!(v.map.range(1, 2), (1, 4));
        assert_eq!(v.map.range(0, 3), (0, 5));
    }

    #[test]
    fn json_map() {
        let v = json_unescape(br#"x\"y\u0041"#).unwrap();
        assert_eq!(v.data, b"x\"yA");
        assert_eq!(v.map.range(3, 4), (4, 10));
    }

    #[test]
    fn base64_alignment() {
        let enc = encode_std(b"hello secret world");
        let v = base64_variants(format!("zz{enc}").as_bytes());
        assert!(v.iter().any(|v| v.data == b"hello secret world"));
    }
}
