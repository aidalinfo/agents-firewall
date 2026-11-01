//! Minimal Server-Sent Events parser (`GET /logs/stream`).

/// One dispatched SSE message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseMessage {
    /// `event:` field (`message` when absent).
    pub event: String,
    /// `data:` lines joined with `\n`.
    pub data: String,
}

/// Incremental parser: feed it chunks, get complete messages back.
#[derive(Debug, Default)]
pub struct SseParser {
    buf: String,
    event: Option<String>,
    data: Vec<String>,
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds a chunk and returns the messages completed by it.
    pub fn push(&mut self, chunk: &str) -> Vec<SseMessage> {
        self.buf.push_str(chunk);
        let mut out = Vec::new();
        while let Some(pos) = self.buf.find('\n') {
            let mut line: String = self.buf.drain(..=pos).collect();
            line.pop(); // '\n'
            if line.ends_with('\r') {
                line.pop();
            }
            self.line(&line, &mut out);
        }
        out
    }

    fn line(&mut self, line: &str, out: &mut Vec<SseMessage>) {
        if line.is_empty() {
            if !self.data.is_empty() {
                out.push(SseMessage {
                    event: self.event.take().unwrap_or_else(|| "message".into()),
                    data: self.data.join("\n"),
                });
            }
            self.event = None;
            self.data.clear();
            return;
        }
        if line.starts_with(':') {
            return; // comment / keep-alive
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        match field {
            "event" => self.event = Some(value.to_string()),
            "data" => self.data.push(value.to_string()),
            _ => {} // id, retry: not needed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_events_split_across_chunks() {
        let mut p = SseParser::new();
        assert!(p.push(": keep-alive\n\nevent: fl").is_empty());
        let got = p.push("ow\r\ndata: {\"a\":1}\r\n\r\ndata: x\ndata: y\n\n");
        assert_eq!(
            got,
            vec![
                SseMessage {
                    event: "flow".into(),
                    data: "{\"a\":1}".into()
                },
                SseMessage {
                    event: "message".into(),
                    data: "x\ny".into()
                }
            ]
        );
    }
}
