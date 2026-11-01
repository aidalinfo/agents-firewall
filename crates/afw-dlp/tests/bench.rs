//! Throughput measurement. Run with:
//! `scripts/cargo.sh test --release -p afw-dlp --test bench -- --ignored --nocapture`

mod common;

use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;

/// ~10 MB of LLM-API-like JSON traffic: escaped prose and code, a few base64 blobs and secrets.
fn corpus() -> Vec<u8> {
    let mut rng = Rng(42);
    let words = [
        "the",
        "agent",
        "calls",
        "function",
        "return",
        "value",
        "config",
        "deploy",
        "server",
        "error",
        "request",
        "context",
        "message",
        "assistant",
        "tool_use",
        "result",
        "kubernetes",
        "pod",
        "let",
        "fn",
        "impl",
        "struct",
        "self",
        "match",
        "Some(x)",
        "=>",
        "{",
        "}",
        "\\n",
        "\\\"",
    ];
    let blob = STANDARD.encode((0..3000).map(|i| (i * 7 % 251) as u8).collect::<Vec<u8>>());
    let mut out = String::with_capacity(10 << 20);
    let mut n = 0usize;
    while out.len() < 10 << 20 {
        out.push_str("{\"role\":\"user\",\"content\":\"");
        for _ in 0..400 {
            out.push_str(words[rng.below(words.len())]);
            out.push(' ');
        }
        n += 1;
        match n % 50 {
            0 => out.push_str(&format!("key={GITHUB} ")),
            10 => out.push_str(&format!("data:image/png;base64,{blob} ")),
            20 => out.push_str("id 123e4567-e89b-12d3-a456-426614174000 sha 9fceb02d0ae598e95dc970b74767f19372d61af8 "),
            _ => {}
        }
        out.push_str("\"},\n");
    }
    out.into_bytes()
}

#[test]
#[ignore = "throughput measurement, run explicitly in release mode"]
fn throughput_10mb() {
    let data = corpus();
    let s = scanner();
    let mb = data.len() as f64 / (1024.0 * 1024.0);

    let t = Instant::now();
    let found = s.scan(&data, "body");
    let dt = t.elapsed().as_secs_f64();
    println!(
        "scan:   {mb:.1} MiB in {dt:.3} s = {:.1} MiB/s ({} findings)",
        mb / dt,
        found.len()
    );

    let t = Instant::now();
    let mut st = s.stream("body");
    let mut streamed = 0;
    for c in data.chunks(64 * 1024) {
        streamed += st.feed(c).len();
    }
    streamed += st.finish().len();
    let dt = t.elapsed().as_secs_f64();
    println!(
        "stream: {mb:.1} MiB in {dt:.3} s = {:.1} MiB/s (64 KiB chunks, {streamed} findings)",
        mb / dt
    );
    assert!(found.iter().filter(|f| f.kind == "github_token").count() > 0);
}
