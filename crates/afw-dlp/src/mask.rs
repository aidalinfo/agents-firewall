//! Masking of detected values: `[<CATEGORY>:<kind>:<fingerprint>]`.

use crate::{DataCategory, Finding};

fn label(f: &Finding) -> String {
    let cat = match f.category {
        DataCategory::Secret => "SECRET",
        DataCategory::Infra => "INFRA",
        DataCategory::Commercial => "COMMERCIAL",
        DataCategory::Personal => "PERSONAL",
        DataCategory::Custom => "CUSTOM",
    };
    format!("[{cat}:{}:{}]", f.kind, f.fingerprint)
}

/// Replaces each finding's range in `data` by its label. Overlapping findings are merged into
/// one replacement (labelled by the one that starts first, the longest on a tie). Findings out
/// of range are ignored.
pub fn mask_bytes(data: &[u8], findings: &[Finding]) -> Vec<u8> {
    let mut fs: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.start < f.end && f.end <= data.len())
        .collect();
    fs.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut out = Vec::with_capacity(data.len());
    let mut pos = 0;
    let mut i = 0;
    while i < fs.len() {
        let first = fs[i];
        let mut end = first.end;
        let mut j = i + 1;
        while j < fs.len() && fs[j].start < end {
            end = end.max(fs[j].end);
            j += 1;
        }
        out.extend_from_slice(&data[pos..first.start]);
        out.extend_from_slice(label(first).as_bytes());
        pos = end;
        i = j;
    }
    out.extend_from_slice(&data[pos..]);
    out
}

/// [`mask_bytes`] on text. A range that splits a UTF-8 sequence yields U+FFFD.
pub fn mask(text: &str, findings: &[Finding]) -> String {
    match String::from_utf8(mask_bytes(text.as_bytes(), findings)) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}
