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
    /// Every decoded position maps to this parent range (base64 blobs).
    Whole(usize, usize),
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
    Regex::new(r"(?-u)[A-Za-z0-9+/_\-]{16,}(?:(?:\r?\n|\\r\\n|\\n)[A-Za-z0-9+/_\-]{4,})*={0,2}")
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
        if let Some(decoded) = decode_run(m.as_bytes()) {
            out.push(Variant {
                data: decoded,
                map: PosMap::Whole(m.start(), m.end()),
            });
        }
    }
    out
}

fn decode_run(run: &[u8]) -> Option<Vec<u8>> {
    let mut clean: Vec<u8> = Vec::with_capacity(run.len());
    let mut i = 0;
    while i < run.len() {
        match run[i] {
            b'\r' | b'\n' | b'=' => i += 1,
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
        return None;
    }
    let engine = if url { &URL_LENIENT } else { &STD_LENIENT };
    // The run may start mid-token (`x` + base64): try the four alignments.
    for skip in 0..4.min(clean.len()) {
        let mut s = &clean[skip..];
        if s.len() % 4 == 1 {
            s = &s[..s.len() - 1];
        }
        if s.len() < 12 {
            break;
        }
        if let Ok(d) = engine.decode(s)
            && plausible_text(&d)
        {
            return Some(d);
        }
    }
    None
}

/// Decoded bytes look like text (so they are worth scanning).
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
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].data, b"hello secret world");
    }
}
