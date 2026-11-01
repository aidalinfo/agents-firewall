//! Incremental scanning of a continuous stream with a sliding window.

use crate::Finding;
use crate::detectors::PEM_MAX;
use crate::scanner::{Hit, Scanner};

/// Upper bound of the bytes kept between two scans to finish a pending detection (PEM block)
/// or an open base64 run. Otherwise only `max_pattern_len` bytes of overlap are kept.
const MAX_RETAIN: usize = PEM_MAX + 1024;

/// Incremental scanner for a continuous stream (request body, SSE, WebSocket).
///
/// Findings carry absolute offsets in the stream and each value is reported once.
///
/// # Contract with the relaying gateway
///
/// - Bytes are relayed only up to [`safe_len`](Self::safe_len): nothing before that offset can
///   be part of a detection reported later. Bytes after it are held back.
/// - A finding returned by [`feed`](Self::feed) always starts at or after the `safe_len()`
///   observed before that call, so held-back bytes can still be cut or masked.
/// - At [`finish`](Self::finish), the held-back rest is relayed only if `finish` (and the
///   policy applied to earlier findings) allows it.
///
/// # Cost
///
/// Each scan covers the retained tail plus the bytes received since the last scan. Small
/// chunks are accumulated until they amount to a quarter of the buffer, so the total work stays
/// linear in the stream length (at most ~5 scans per byte), whatever the chunk size.
#[derive(Debug)]
pub struct StreamScanner<'a> {
    scanner: &'a Scanner,
    location: String,
    buf: Vec<u8>,
    /// Absolute stream offset of `buf[0]`.
    offset: usize,
    /// Bytes at the end of `buf` not scanned yet.
    unscanned: usize,
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
            unscanned: 0,
            reported: Vec::new(),
        }
    }

    /// Adds the next chunk; returns the findings known to be complete so far. A detection that
    /// touches the end of the received data may still grow: it is reported by a later call.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Finding> {
        self.buf.extend_from_slice(chunk);
        self.unscanned += chunk.len();
        let mut out = Vec::new();
        if self.unscanned == 0 || self.unscanned * 4 < self.buf.len() {
            return out;
        }
        self.unscanned = 0;
        let len = self.buf.len();
        let mut pending: Option<usize> = None;
        for h in self.scanner.hits(&self.buf) {
            if h.end == len {
                pending = Some(pending.map_or(h.ctx, |p| p.min(h.ctx)));
                continue;
            }
            self.report(h, &mut out);
        }
        self.trim(pending);
        out
    }

    /// Number of stream bytes that can be relayed: no later finding starts before it.
    pub fn safe_len(&self) -> u64 {
        self.offset as u64
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
            ctx: self.offset + h.ctx,
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

    /// Keeps `max_pattern_len` bytes, extended back to a pending detection or to the start of
    /// an open base64 run (kept 4-aligned), never more than `MAX_RETAIN`.
    fn trim(&mut self, pending: Option<usize>) {
        let len = self.buf.len();
        let overlap = self.scanner.options().max_pattern_len;
        let floor = len.saturating_sub(MAX_RETAIN.max(overlap));
        let mut keep = len.saturating_sub(overlap);
        if let Some(p) = pending {
            keep = keep.min(p.max(floor));
        }
        let run_start = len
            - self
                .buf
                .iter()
                .rev()
                .take_while(|b| is_base64_byte(**b))
                .count();
        if run_start < keep {
            let mut k = run_start.max(floor);
            // Stay aligned on base64 quanta from the start of the run.
            k += (4 - (k - run_start) % 4) % 4;
            keep = keep.min(k);
        }
        if keep > 0 {
            self.buf.drain(..keep);
            self.offset += keep;
        }
        let offset = self.offset;
        self.reported.retain(|r| r.end > offset);
    }
}

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
}
