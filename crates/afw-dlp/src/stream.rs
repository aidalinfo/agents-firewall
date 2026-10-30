//! Incremental scanning of a continuous stream with a sliding window.

use crate::Finding;
use crate::scanner::{Hit, Scanner};

/// Upper bound of the bytes kept between two chunks to finish a token or a pending detection
/// (base64 blob, PEM block). Beyond it, only `max_pattern_len` bytes of overlap are kept.
const MAX_RETAIN: usize = 16 * 1024;

/// Incremental scanner for a continuous stream (request body, SSE, WebSocket).
///
/// Each [`feed`](Self::feed) scans the retained tail of the previous chunks plus the new chunk.
/// A detection that touches the end of the buffer may still grow, so it is reported later.
/// Findings carry absolute offsets in the stream and each value is reported once.
#[derive(Debug)]
pub struct StreamScanner<'a> {
    scanner: &'a Scanner,
    location: String,
    buf: Vec<u8>,
    /// Absolute stream offset of `buf[0]`.
    offset: usize,
    /// Already reported hits, in absolute offsets.
    reported: Vec<Hit>,
}

impl<'a> StreamScanner<'a> {
    pub(crate) fn new(scanner: &'a Scanner, location: &str) -> Self {
        Self {
            scanner,
            location: location.to_string(),
            buf: Vec::new(),
            offset: 0,
            reported: Vec::new(),
        }
    }

    /// Scans the next chunk; returns the findings that are complete so far.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Finding> {
        self.buf.extend_from_slice(chunk);
        let len = self.buf.len();
        let mut out = Vec::new();
        let mut pending: Option<usize> = None;
        for h in self.scanner.hits(&self.buf) {
            if h.end == len {
                pending = Some(pending.map_or(h.start, |p| p.min(h.start)));
                continue;
            }
            self.report(h, &mut out);
        }
        self.trim(pending);
        out
    }

    /// Stub.
    pub fn safe_len(&self) -> u64 {
        u64::MAX
    }

    /// Ends the stream; returns the findings still pending.
    pub fn finish(mut self) -> Vec<Finding> {
        let mut out = Vec::new();
        for h in self.scanner.hits(&self.buf) {
            self.report(h, &mut out);
        }
        out
    }

    fn report(&mut self, h: Hit, out: &mut Vec<Finding>) {
        let abs = Hit {
            start: self.offset + h.start,
            end: self.offset + h.end,
            ..h
        };
        let seen = self.reported.iter().any(|r| {
            r.det == abs.det
                && ((r.start == abs.start && r.end == abs.end)
                    || (r.fp == abs.fp && r.start < abs.end && abs.start < r.end))
        });
        if seen {
            return;
        }
        self.scanner.push_findings(&abs, 0, &self.location, out);
        self.reported.push(abs);
    }

    fn trim(&mut self, pending: Option<usize>) {
        let len = self.buf.len();
        let overlap = self.scanner.options().max_pattern_len;
        let floor = len.saturating_sub(MAX_RETAIN.max(overlap));
        let mut keep = len.saturating_sub(overlap);
        if let Some(p) = pending {
            keep = keep.min(p);
        }
        // Do not cut a token in two: it would lose its left context (word boundary, base64
        // alignment, `key=` prefix).
        while keep > floor && is_token_byte(self.buf[keep - 1]) {
            keep -= 1;
        }
        let keep = keep.max(floor);
        if keep > 0 {
            self.buf.drain(..keep);
            self.offset += keep;
        }
        let offset = self.offset;
        self.reported.retain(|r| r.end > offset);
    }
}

fn is_token_byte(b: u8) -> bool {
    !b.is_ascii_whitespace() && b != b'"' && b != b'\''
}
