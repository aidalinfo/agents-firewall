//! Cases from the independent review of PR #7 (bypasses, false positives, DoS, gateway contract).

mod common;

use std::time::{Duration, Instant};

use afw_dlp::{DlpError, Finding, decode_content, mask};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use common::*;

fn scan(s: &str) -> Vec<Finding> {
    scanner().scan(s.as_bytes(), "body")
}

fn assert_anthropic(label: &str, s: &str) {
    let f = scan(s);
    let a = f.iter().find(|f| f.kind == "anthropic_key");
    assert!(a.is_some(), "[{label}] not detected: {:?}", kinds(&f));
    assert_eq!(a.unwrap().fingerprint, fp(ANTHROPIC), "[{label}]");
}

// ---- 5. encodings -------------------------------------------------------------------------

#[test]
fn encodings_detected() {
    let a = ANTHROPIC;
    assert_anthropic("b64 nopad", &format!("x {} y", STANDARD_NO_PAD.encode(a)));
    assert_anthropic(
        "b64url nopad",
        &format!("x {} y", URL_SAFE_NO_PAD.encode(a)),
    );
    let hexs: String = a.bytes().map(|b| format!("{b:02x}")).collect();
    assert_anthropic("hex", &format!("x {hexs} y"));
    assert_anthropic("hex upper", &format!("x {} y", hexs.to_uppercase()));
    let dbl: String = a.bytes().map(|b| format!("%25{b:02X}")).collect();
    assert_anthropic("double pct", &format!("q={dbl}"));
    let fw: String = a
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                char::from_u32(c as u32 + 0xFEE0).unwrap()
            } else {
                c
            }
        })
        .collect();
    assert_anthropic("fullwidth", &format!("x {fw} y"));
    let zw: String = a.chars().flat_map(|c| [c, '\u{200b}']).collect();
    assert_anthropic("zero-width", &format!("x {zw} y"));
    let mut bin = a.as_bytes().to_vec();
    let mut r = Rng(7);
    for _ in 0..64 {
        bin.push((r.next_u64() & 0xff) as u8);
    }
    assert_anthropic(
        "b64(secret+64 random bytes)",
        &format!("x {} y", STANDARD.encode(&bin)),
    );
    let mut bin2: Vec<u8> = (0..37).map(|_| (r.next_u64() & 0xff) as u8).collect();
    bin2.extend_from_slice(a.as_bytes());
    assert_anthropic(
        "b64(random+secret)",
        &format!("x {} y", STANDARD.encode(&bin2)),
    );
    let utf16: Vec<u8> = a.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    assert_anthropic("b64(utf16le)", &format!("x {} y", STANDARD.encode(&utf16)));
    let spaced = STANDARD
        .encode(a)
        .as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    assert_anthropic("b64 with spaces", &format!("x {spaced} y"));
    let lines = STANDARD
        .encode(a)
        .as_bytes()
        .chunks(12)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert_anthropic("b64 short lines", &format!("x\n{lines}\ny"));
    let json_u: String = a.chars().map(|c| format!("\\u{:04x}", c as u32)).collect();
    assert_anthropic("json \\u full", &format!("\"{json_u}\""));
    let b2 = STANDARD.encode(STANDARD.encode(a));
    assert_anthropic("b64^2", &format!("x {b2} y"));
}

#[test]
fn documented_encoding_limits_do_not_panic() {
    // Triple nesting and one-char spacing are documented limits (ADR 0012): no panic, no claim.
    let a = ANTHROPIC;
    let b3 = STANDARD.encode(STANDARD.encode(STANDARD.encode(a)));
    let _ = scan(&format!("x {b3} y"));
    let tri: String = a.bytes().map(|b| format!("%2525{b:02X}")).collect();
    let _ = scan(&format!("q={tri}"));
    let spaced: String = a.chars().flat_map(|c| [c, ' ']).collect();
    let _ = scan(&format!("x {spaced} y"));
}

#[test]
fn hex_hashes_are_not_secrets() {
    let f = scan(
        "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 and 9fceb02d0ae598e95dc970b74767f19372d61af8",
    );
    assert!(f.is_empty(), "{f:#?}");
}

// ---- 2. PEM ---------------------------------------------------------------------------------

#[test]
fn pem_masks_everything_up_to_end_marker() {
    let cases = [
        (
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,3F1A2B\n\nMIIEowIBAAKCAQEAsecretbodyAAAA\nBBBBCCCCDDDD\n-----END RSA PRIVATE KEY-----",
            &["Proc-Type", "DEK-Info", "secretbody", "BBBBCCCC"][..],
        ),
        (
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nComment: https://x.y/z-k\nVersion: 1\n\nlQOYBGSecretBodyMaterial\nZZZZ\n-----END PGP PRIVATE KEY BLOCK-----",
            &["Comment", "SecretBody", "ZZZZ"][..],
        ),
        (
            "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n#comment-x\nkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n-----END PRIVATE KEY-----",
            &["MIIEvQ", "comment", "kqhkiG9w0"][..],
        ),
    ];
    for (pem, fragments) in cases {
        let text = format!("before\n{pem}\nafter");
        let found = scan(&text);
        let masked = mask(&text, &found);
        for frag in fragments {
            assert!(!masked.contains(frag), "{frag} survived:\n{masked}");
        }
        assert!(
            masked.starts_with("before\n[SECRET:private_key_pem:"),
            "{masked}"
        );
        assert!(masked.ends_with("]\nafter"), "{masked}");
    }
}

#[test]
fn pem_without_end_is_masked_up_to_16_kib() {
    let body = "QUJD\n".repeat(5000); // 25 000 bytes, no END
    let text = format!("-----BEGIN PRIVATE KEY-----\n{body}");
    let f = find(&scan(&text), "private_key_pem").clone();
    assert_eq!(f.start, 0);
    assert!(f.end >= 16 * 1024 && f.end <= 16 * 1024 + 64, "{}", f.end);
}

// ---- 4. generic assignments -----------------------------------------------------------------

#[test]
fn explicit_password_keys_have_lower_thresholds() {
    for (text, value) in [
        ("password=Summer2024!", "Summer2024!"),
        ("password=Password1234", "Password1234"),
        (
            "{\"password\": \"correct horse battery staple\"}",
            "correct horse battery staple",
        ),
        ("password=Ab3dE;fG7hI9jK2lM", "Ab3dE;fG7hI9jK2lM"),
        ("db_password=Q9w&E7r!T5y#U3i", "Q9w&E7r!T5y#U3i"),
        ("client_secret: 'k8s-Zq1!x7Lm'", "k8s-Zq1!x7Lm"),
        ("PWD=hunter2hunter2", "hunter2hunter2"),
        ("x-amz-api-key=Zk8pL2wQ9zXr4Tn7", "Zk8pL2wQ9zXr4Tn7"),
    ] {
        let f = scan(text);
        let g = f.iter().find(|f| f.kind == "generic_secret_assignment");
        let g = g.unwrap_or_else(|| panic!("not detected in {text:?}: {f:#?}"));
        assert_eq!(&text[g.start..g.end], value, "{text}");
    }
}

#[test]
fn query_separators_still_end_unquoted_values() {
    let url = "https://h.example.com/?password=Summer2024!&page=2;lang=fr";
    let f = scanner().scan_url(url);
    let g = find(&f, "generic_secret_assignment");
    assert_eq!(&url[g.start..g.end], "Summer2024!");
}

#[test]
fn trivial_password_values_are_ignored() {
    for text in [
        "password=***",
        "password=********",
        "password=<redacted>",
        "password=${DB_PASSWORD}",
        "password: {{ vault_password }}",
        "password=changeme",
        "password=password",
        "password=xxxxxxxxxx",
        "\"password\": null",
        "password = getpass.getpass()",
        "password = os.environ[\"DB_PASSWORD\"]",
        "password=process.env.DB_PASSWORD",
        "secret=$SECRET_VALUE",
        "token=short",
    ] {
        let f = scan(text);
        assert!(!has(&f, "generic_secret_assignment"), "{text}: {f:#?}");
    }
}

// ---- 7. presigned URLs / SAS ---------------------------------------------------------------

#[test]
fn presigned_urls_v2_and_gcs_are_not_secrets() {
    let ak = AWS_KEY;
    let v2 = format!(
        "https://b.s3.amazonaws.com/o?AWSAccessKeyId={ak}&Expires=1700000000&Signature=vjbyPxybdZaNmGa%2ByT272YEAiv4%3D"
    );
    assert!(
        scanner().scan_url(&v2).is_empty(),
        "{:#?}",
        scanner().scan_url(&v2)
    );
    let gcs = "https://storage.googleapis.com/b/o?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=sa%40proj.iam.gserviceaccount.com%2F20261030%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20261030T000000Z&X-Goog-Expires=900&X-Goog-SignedHeaders=host&X-Goog-Signature=a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    assert!(
        scanner().scan_url(gcs).is_empty(),
        "{:#?}",
        scanner().scan_url(gcs)
    );
    // Without the SigV2 companions the key id is still reported.
    assert!(has(
        &scanner().scan_url(&format!("https://x.example.com/?AWSAccessKeyId={ak}")),
        "aws_access_key"
    ));
}

#[test]
fn azure_sas_signature_is_detected() {
    let url = "https://acct.blob.core.windows.net/c/b?sv=2022-11-02&ss=b&srt=o&sp=r&se=2026-11-01&sig=Zk8pL2wQ9zXr4Tn7aB3cD5eF7gH9iJ1kL3mN5oP7qR8%3D";
    let f = scanner().scan_url(url);
    let s = find(&f, "azure_sas_signature");
    assert_eq!(
        &url[s.start..s.end],
        "Zk8pL2wQ9zXr4Tn7aB3cD5eF7gH9iJ1kL3mN5oP7qR8%3D"
    );
}

#[test]
fn sigv4_authorization_header_is_not_a_secret() {
    let headers = vec![
        (
            "Authorization".to_string(),
            format!(
                "AWS4-HMAC-SHA256 Credential={AWS_KEY}/20261030/eu-west-3/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
            ),
        ),
        ("X-Amz-Date".to_string(), "20261030T120000Z".to_string()),
    ];
    let f = scanner().scan_headers(&headers);
    assert!(f.is_empty(), "{f:#?}");
}

// ---- minors -------------------------------------------------------------------------------

#[test]
fn session_cookie_ipv6_and_dotted_card() {
    let f = scan("Cookie: theme=dark; sessionid=9f8e7d6c5b4a39281706f5e4d3c2b1a0");
    let c = find(&f, "session_cookie");
    assert_eq!(c.end - c.start, 32);
    let f = scanner().scan_headers(&[("Cookie".into(), "sid=Zk8pL2wQ9zXr4Tn7aB3cD5eF7gH9".into())]);
    assert!(has(&f, "session_cookie"), "{f:#?}");
    assert!(!has(
        &scan("Cookie: theme=dark; lang=fr-FR"),
        "session_cookie"
    ));
    assert!(has(&scan("host fd12:3456:789a::1 up"), "private_ip"));
    assert!(has(&scan("host FC00:0:0:1::5 up"), "private_ip"));
    assert!(!has(&scan("addr 2001:db8::1 and fe80::1"), "private_ip"));
    assert!(has(&scan("4111.1111.1111.1111"), "credit_card"));
    assert!(has(&scan("4111-1111-1111-1111"), "credit_card"));
    assert!(has(&scan("FR76 3000 6000 0112 3456 7890 189"), "iban"));
}

// ---- 6. content decoding ------------------------------------------------------------------

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

#[test]
fn decode_content_gzip_deflate_br_identity() {
    use std::io::Write;
    let plain = format!("{{\"k\":\"{ANTHROPIC}\"}}").repeat(10);
    assert_eq!(
        decode_content("gzip", &gzip(plain.as_bytes()), 1 << 20).unwrap(),
        plain.as_bytes()
    );
    assert_eq!(
        decode_content("x-gzip", &gzip(plain.as_bytes()), 1 << 20).unwrap(),
        plain.as_bytes()
    );
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(plain.as_bytes()).unwrap();
    assert_eq!(
        decode_content("deflate", &z.finish().unwrap(), 1 << 20).unwrap(),
        plain.as_bytes()
    );
    let mut d = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    d.write_all(plain.as_bytes()).unwrap();
    assert_eq!(
        decode_content("Deflate", &d.finish().unwrap(), 1 << 20).unwrap(),
        plain.as_bytes(),
        "raw deflate"
    );
    let mut br = Vec::new();
    {
        let mut w = brotli::CompressorWriter::new(&mut br, 4096, 5, 22);
        w.write_all(plain.as_bytes()).unwrap();
    }
    assert_eq!(
        decode_content("br", &br, 1 << 20).unwrap(),
        plain.as_bytes()
    );
    assert_eq!(decode_content("identity", b"abc", 10).unwrap(), b"abc");
    assert_eq!(decode_content("", b"abc", 10).unwrap(), b"abc");
    // Stacked encodings are undone in reverse order.
    let stacked = gzip(&gzip(plain.as_bytes()));
    assert_eq!(
        decode_content("gzip, gzip", &stacked, 1 << 20).unwrap(),
        plain.as_bytes()
    );
    let decoded = decode_content("gzip", &gzip(plain.as_bytes()), 1 << 20).unwrap();
    assert!(has(&scanner().scan(&decoded, "body"), "anthropic_key"));
}

#[test]
fn decode_content_bounds_and_errors() {
    let bomb = gzip(&vec![0u8; 50 << 20]);
    assert!(bomb.len() < 100 << 10);
    let t = Instant::now();
    assert!(matches!(
        decode_content("gzip", &bomb, 1 << 20),
        Err(DlpError::TooLarge { .. })
    ));
    assert!(t.elapsed() < Duration::from_secs(5));
    assert!(matches!(
        decode_content("identity", b"abcdef", 3),
        Err(DlpError::TooLarge { .. })
    ));
    assert!(matches!(
        decode_content("gzip", b"not gzip", 1 << 20),
        Err(DlpError::Decode(_))
    ));
    assert!(matches!(
        decode_content("compress", b"x", 10),
        Err(DlpError::UnsupportedEncoding(_))
    ));
}

// ---- 1 & 3. streaming DoS and safe_len ------------------------------------------------------

fn release_or(debug: u64, release: u64) -> Duration {
    Duration::from_millis(if cfg!(debug_assertions) {
        debug
    } else {
        release
    })
}

#[test]
fn stream_small_chunks_without_whitespace_is_linear() {
    let s = scanner();
    for (data, label) in [
        (b"a".repeat(1 << 20), "a*"),
        (b"QUFB".repeat(1 << 18), "base64*"),
    ] {
        let t = Instant::now();
        let mut st = s.stream("body");
        for c in data.chunks(16) {
            let _ = st.feed(c);
        }
        let _ = st.finish();
        let dt = t.elapsed();
        assert!(
            dt < release_or(15_000, 500),
            "{label}: 1 MiB in 16-byte chunks took {dt:?}"
        );
    }
}

#[test]
fn safe_len_never_lets_a_secret_through() {
    let s = scanner();
    let mut rng = Rng(0xDEC0DE);
    let secrets = [
        ANTHROPIC.to_string(),
        GITHUB.to_string(),
        format!("password={PASSWORD}"),
        STANDARD.encode(GITLAB),
    ];
    for round in 0..60 {
        let mut data = String::new();
        while data.len() < 6000 {
            if rng.below(6) == 0 {
                data.push_str(&secrets[rng.below(secrets.len())]);
            } else {
                for _ in 0..rng.below(40) {
                    data.push((b'a' + rng.below(26) as u8) as char);
                }
            }
            if rng.below(3) == 0 {
                data.push(' ');
            }
        }
        let bytes = data.as_bytes();
        let full = s.scan(bytes, "body");
        let mut st = s.stream("body");
        let mut pos = 0;
        let mut safe = 0u64;
        let mut reported: Vec<Finding> = Vec::new();
        while pos < bytes.len() {
            let n = 1 + rng.below(if round % 2 == 0 { 20 } else { 900 });
            let end = (pos + n).min(bytes.len());
            for f in st.feed(&bytes[pos..end]) {
                assert!(
                    f.start as u64 >= safe,
                    "finding {f:?} starts before already relayed {safe}"
                );
                reported.push(f);
            }
            let now = st.safe_len();
            assert!(
                now >= safe && now <= end as u64,
                "safe_len {now} (prev {safe}, fed {end})"
            );
            safe = now;
            pos = end;
        }
        for f in st.finish() {
            assert!(
                f.start as u64 >= safe,
                "finding {f:?} at finish starts before relayed {safe}"
            );
            reported.push(f);
        }
        // Every secret of the full scan is reported by the stream.
        for f in full
            .iter()
            .filter(|f| f.category == afw_dlp::DataCategory::Secret)
        {
            assert!(
                reported
                    .iter()
                    .any(|r| r.kind == f.kind && r.fingerprint == f.fingerprint),
                "round {round}: {f:?} missed by stream"
            );
        }
    }
}

#[test]
fn feed_ending_with_complete_secret_holds_it_back() {
    let s = scanner();
    let mut st = s.stream("body");
    let data = format!("{{\"k\":\"x\"}} token {ANTHROPIC}");
    let f1 = st.feed(data.as_bytes());
    assert!(f1.iter().all(|f| f.kind != "anthropic_key"));
    assert!(st.safe_len() <= data.find(ANTHROPIC).unwrap() as u64);
    assert!(has(&st.finish(), "anthropic_key"));
}

// ---- adversarial inputs ---------------------------------------------------------------------

fn adversarial(size: usize) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("a*", vec![b'a'; size]),
        ("password repeated", b"password".repeat(size / 8)),
        ("password= repeated", b"password=".repeat(size / 9)),
        ("'password'=\"", b"password\":\"".repeat(size / 11)),
        ("eyJ.", b"eyJaaaaa.".repeat(size / 9)),
        ("eyJ chain", b"eyJaaaaa.eyJaaaaa.".repeat(size / 18)),
        ("digits", b"4".repeat(size)),
        ("digits spaced", b"4 ".repeat(size / 2)),
        ("digits dotted", b"4.".repeat(size / 2)),
        (
            "FR76 groups",
            b"FR76 "
                .iter()
                .chain(b"ABCD ".repeat(size / 5).iter())
                .copied()
                .collect(),
        ),
        ("dots ip", b"10.".repeat(size / 3)),
        ("fd ipv6", b"fd00:".repeat(size / 5)),
        ("a.internal", b"a.".repeat(size / 2)),
        ("internal x", b"a.internal ".repeat(size / 11)),
        ("eur", b"1 000 ".repeat(size / 6)),
        ("eur anchor", b"1 000 eur ".repeat(size / 10)),
        ("percent", b"%41".repeat(size / 3)),
        ("json \\u", b"\\u0041".repeat(size / 6)),
        ("json \\\"", b"\\\"".repeat(size / 2)),
        (
            "b64 text",
            STANDARD
                .encode(b"hello world ".repeat(size / 16))
                .into_bytes(),
        ),
        (
            "b64 lines",
            STANDARD
                .encode(b"hello world ".repeat(size / 16))
                .as_bytes()
                .chunks(76)
                .collect::<Vec<_>>()
                .join(&b"\n"[..]),
        ),
        (
            "b64 spaced",
            STANDARD
                .encode(b"hello world ".repeat(size / 16))
                .as_bytes()
                .chunks(8)
                .collect::<Vec<_>>()
                .join(&b" "[..]),
        ),
        (
            "b64 short runs",
            b"QUFBQUFBQUFBQUFBQUFBQQ== ".repeat(size / 25),
        ),
        ("hex", b"0123456789abcdef".repeat(size / 16)),
        ("pem open", {
            let mut v = b"-----BEGIN PRIVATE KEY-----".to_vec();
            v.extend(b"A".repeat(size));
            v
        }),
        (
            "pem open repeated",
            b"-----BEGIN PRIVATE KEY-----AAAA".repeat(size / 31),
        ),
        ("email @", b"a@".repeat(size / 2)),
        ("email local", {
            let mut v = b"a".repeat(size);
            v.extend(b"@x");
            v
        }),
        ("url userinfo", b"ab://x:".repeat(size / 7)),
        ("sk-", b"sk-".repeat(size / 3)),
        ("bearer", b"bearer ".repeat(size / 7)),
        ("cookie", b"Cookie: a=b;".repeat(size / 12)),
        ("cookie semis", {
            let mut v = b"Cookie: ".to_vec();
            v.extend(b"a=b;".repeat(size / 4));
            v
        }),
        ("key-ish chars", b"a_a-a.a".repeat(size / 7)),
        (
            "key=low entropy",
            b"api_key=aaaaaaaaaaaa ".repeat(size / 21),
        ),
        ("x-amz-credential", b"X-Amz-Credential=".repeat(size / 17)),
        (
            "blob.core sig",
            b"x.blob.core.windows.net/?".repeat(size / 25),
        ),
        ("fullwidth", "Ａ".repeat(size / 3).into_bytes()),
        ("zero width", "a\u{200b}".repeat(size / 4).into_bytes()),
        ("utf16", b"a\0".repeat(size / 2)),
    ]
}

#[test]
fn adversarial_inputs_scan_in_bounded_time() {
    let s = scanner();
    for (label, data) in adversarial(256 << 10) {
        let t = Instant::now();
        let _ = s.scan(&data, "body");
        let dt = t.elapsed();
        assert!(dt < release_or(20_000, 500), "{label}: 256 KiB took {dt:?}");
    }
}

#[test]
#[ignore = "release-mode timing on 4 MiB inputs"]
fn adversarial_inputs_4mib_release() {
    let s = scanner();
    for (label, data) in adversarial(4 << 20) {
        let t = Instant::now();
        let _ = s.scan(&data, "body");
        let dt = t.elapsed();
        println!("{label:24} {:>8} B {dt:?}", data.len());
        assert!(dt < Duration::from_secs(3), "{label}: 4 MiB took {dt:?}");
    }
}
