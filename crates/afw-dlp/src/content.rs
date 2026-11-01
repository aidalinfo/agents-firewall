//! `Content-Encoding` decoding before scanning, bounded against decompression bombs.

use std::io::Read;

use crate::DlpError;

/// Undoes an HTTP `Content-Encoding` (`gzip`, `x-gzip`, `deflate` (zlib or raw), `br`,
/// `identity` or empty), applying a comma-separated list in reverse order. The output (and
/// every intermediate stage) is limited to `max_out` bytes: beyond it, [`DlpError::TooLarge`]
/// is returned without inflating further.
pub fn decode_content(encoding: &str, data: &[u8], max_out: usize) -> Result<Vec<u8>, DlpError> {
    let codings: Vec<String> = encoding
        .split(',')
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty() && c != "identity")
        .collect();
    if codings.is_empty() {
        if data.len() > max_out {
            return Err(DlpError::TooLarge { max: max_out });
        }
        return Ok(data.to_vec());
    }
    let mut cur = data.to_vec();
    for coding in codings.iter().rev() {
        cur = decode_one(coding, &cur, max_out)?;
    }
    Ok(cur)
}

fn decode_one(coding: &str, data: &[u8], max_out: usize) -> Result<Vec<u8>, DlpError> {
    match coding {
        "gzip" | "x-gzip" => read_bounded(flate2::read::MultiGzDecoder::new(data), max_out),
        "deflate" => {
            // RFC 9110 says zlib, but raw deflate is common in the wild.
            match read_bounded(flate2::read::ZlibDecoder::new(data), max_out) {
                Err(DlpError::Decode(_)) => {
                    read_bounded(flate2::read::DeflateDecoder::new(data), max_out)
                }
                other => other,
            }
        }
        "br" => read_bounded(brotli::Decompressor::new(data, 4096), max_out),
        other => Err(DlpError::UnsupportedEncoding(other.to_string())),
    }
}

fn read_bounded(reader: impl Read, max_out: usize) -> Result<Vec<u8>, DlpError> {
    let mut out = Vec::new();
    let limit = u64::try_from(max_out).unwrap_or(u64::MAX).saturating_add(1);
    reader
        .take(limit)
        .read_to_end(&mut out)
        .map_err(|e| DlpError::Decode(e.to_string()))?;
    if out.len() > max_out {
        return Err(DlpError::TooLarge { max: max_out });
    }
    Ok(out)
}
