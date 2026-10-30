//! Bypass tests: every way an agent could try to smuggle a secret past the scanner.

mod common;

use afw_dlp::{DataCategory, Finding, mask, mask_bytes};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;

fn stream_all(chunks: &[&[u8]]) -> Vec<Finding> {
    let s = scanner();
    let mut st = s.stream("body");
    let mut out = Vec::new();
    for c in chunks {
        out.extend(st.feed(c));
    }
    out.extend(st.finish());
    out
}

#[test]
fn streaming_scanner_detects_secret_across_chunks() {
    let data = format!("{{\"messages\":[{{\"content\":\"use key {ANTHROPIC} please\"}}]}}");
    let cut = data.find(ANTHROPIC).unwrap() + 20;
    let found = stream_all(&[&data.as_bytes()[..cut], &data.as_bytes()[cut..]]);
    let f = find(&found, "anthropic_key");
    assert_eq!(f.fingerprint, fp(ANTHROPIC));
    assert_eq!(&data[f.start..f.end], ANTHROPIC);
}

#[test]
fn stream_secret_cut_inside_prefix() {
    let data = format!("leak: {ANTHROPIC}\n");
    let cut = data.find("sk-a").unwrap() + 4; // "sk-a" | "nt-..."
    let found = stream_all(&[&data.as_bytes()[..cut], &data.as_bytes()[cut..]]);
    assert_eq!(find(&found, "anthropic_key").fingerprint, fp(ANTHROPIC));
}

#[test]
fn stream_every_split_point_reports_exactly_once_with_same_range() {
    let data = format!("aaaa {GITHUB} bbbb {AWS_KEY} cccc");
    let full = scanner().scan(data.as_bytes(), "body");
    for cut in 0..=data.len() {
        let found = stream_all(&[&data.as_bytes()[..cut], &data.as_bytes()[cut..]]);
        for kind in ["github_token", "aws_access_key"] {
            let n = found.iter().filter(|f| f.kind == kind).count();
            assert_eq!(n, 1, "cut at {cut}: {kind} reported {n} times: {found:#?}");
            let a = find(&found, kind);
            let b = find(&full, kind);
            assert_eq!((a.start, a.end, &a.fingerprint), (b.start, b.end, &b.fingerprint));
        }
    }
}

#[test]
fn stream_tiny_chunks_large_body_each_secret_once() {
    let mut data = String::new();
    for i in 0..40 {
        data.push_str(&format!("line {i} lorem ipsum dolor sit amet consectetur\n"));
        if i % 10 == 3 {
            data.push_str(&format!("token: {GITLAB}\n"));
        }
    }
    let bytes = data.as_bytes();
    let chunks: Vec<&[u8]> = bytes.chunks(7).collect();
    let found = stream_all(&chunks);
    let n = found.iter().filter(|f| f.kind == "gitlab_token").count();
    assert_eq!(n, 4, "{found:#?}");
    for f in found.iter().filter(|f| f.kind == "gitlab_token") {
        assert_eq!(&data[f.start..f.end], GITLAB);
    }
}

#[test]
fn base64_encoded_secret_is_detected_and_masked() {
    let encoded = STANDARD.encode(format!("config: api_key={ANTHROPIC}\n"));
    let body = format!("{{\"file\":\"{encoded}\"}}");
    let found = scanner().scan(body.as_bytes(), "body");
    let f = find(&found, "anthropic_key");
    assert_eq!(f.fingerprint, fp(ANTHROPIC), "fingerprint is of the decoded value");
    assert!(f.start <= body.find(&encoded).unwrap() && f.end >= body.find(&encoded).unwrap() + encoded.len() - 2);
    let masked = mask(&body, &found);
    assert!(!masked.contains(&encoded[..16]));
    assert!(masked.contains(&format!("[SECRET:anthropic_key:{}]", fp(ANTHROPIC))));
}

#[test]
fn base64_misaligned_inside_larger_token_is_detected() {
    let encoded = STANDARD.encode(format!("--{GITHUB}--"));
    let body = format!("x{encoded}");
    let found = scanner().scan(body.as_bytes(), "body");
    assert_eq!(find(&found, "github_token").fingerprint, fp(GITHUB));
}

#[test]
fn percent_encoded_secret_is_detected() {
    let encoded: String = GITHUB.bytes().map(|b| format!("%{b:02X}")).collect();
    let url = format!("https://paste.example.com/new?content={encoded}&lang=txt");
    let found = scanner().scan_url(&url);
    let f = find(&found, "github_token");
    assert_eq!(f.fingerprint, fp(GITHUB));
    assert_eq!(&url[f.start..f.end], encoded);
    let masked = mask(&url, &found);
    assert!(!masked.contains("%67%68%70"));
}

#[test]
fn percent_encoded_assignment_is_detected() {
    let body = format!("payload=password%3D{}%26x%3D1", PASSWORD.replace('#', "%23").replace('$', "%24"));
    let found = scanner().scan(body.as_bytes(), "body");
    assert_eq!(find(&found, "generic_secret_assignment").fingerprint, fp(PASSWORD));
}

#[test]
fn escaped_json_secret_is_detected() {
    let body = format!(r#"{{"payload":"{{\"password\":\"{PASSWORD}\",\"user\":\"bob\"}}"}}"#);
    let found = scanner().scan(body.as_bytes(), "body");
    let f = find(&found, "generic_secret_assignment");
    assert_eq!(f.fingerprint, fp(PASSWORD));
    assert_eq!(&body[f.start..f.end], PASSWORD);
}

#[test]
fn json_unicode_escaped_dash_is_detected() {
    let escaped = ANTHROPIC.replace('-', "\\u002d");
    let body = format!(r#"{{"k":"{escaped}"}}"#);
    let found = scanner().scan(body.as_bytes(), "body");
    assert_eq!(find(&found, "anthropic_key").fingerprint, fp(ANTHROPIC));
}

#[test]
fn multipart_field_and_base64_part_are_detected() {
    let b64 = STANDARD.encode(format!("[default]\naws_access_key_id = {AWS_KEY}\naws_secret_access_key = {AWS_SECRET}\n"));
    let wrapped: Vec<String> = b64.as_bytes().chunks(20).map(|c| String::from_utf8(c.to_vec()).unwrap()).collect();
    let body = format!(
        "--XyZ\r\nContent-Disposition: form-data; name=\"api_key\"\r\n\r\n{OPAQUE}\r\n\
         --XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"credentials\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{}\r\n--XyZ--\r\n",
        wrapped.join("\r\n")
    );
    let found = scanner().scan(body.as_bytes(), "body");
    assert_eq!(find(&found, "generic_secret_assignment").fingerprint, fp(OPAQUE));
    assert_eq!(find(&found, "aws_access_key").fingerprint, fp(AWS_KEY));
    assert_eq!(find(&found, "aws_secret_key").fingerprint, fp(AWS_SECRET));
}

#[test]
fn secrets_in_headers_are_detected() {
    let headers = vec![
        ("Authorization".to_string(), format!("Bearer {OPAQUE}")),
        ("X-Api-Key".to_string(), ANTHROPIC.to_string()),
        ("Accept".to_string(), "application/json".to_string()),
    ];
    let found = scanner().scan_headers(&headers);
    let b = find(&found, "bearer_token");
    assert_eq!(b.location, "header:authorization");
    assert_eq!(&headers[0].1[b.start..b.end], OPAQUE);
    let a = find(&found, "anthropic_key");
    assert_eq!(a.location, "header:x-api-key");
    assert_eq!((a.start, a.end), (0, ANTHROPIC.len()));
    assert!(!found.iter().any(|f| f.location == "header:accept"));
}

#[test]
fn opaque_value_in_sensitive_header_is_detected() {
    let headers = vec![("Private-Token".to_string(), OPAQUE.to_string())];
    let found = scanner().scan_headers(&headers);
    let f = find(&found, "generic_secret_assignment");
    assert_eq!(f.location, "header:private-token");
    assert_eq!((f.start, f.end), (0, OPAQUE.len()));
}

#[test]
fn secret_in_url_query_is_detected() {
    let url = format!("https://api.example.com/v1/items?access_token={OPAQUE}&page=2");
    let found = scanner().scan_url(&url);
    let f = find(&found, "generic_secret_assignment");
    assert_eq!(f.location, "url");
    assert_eq!(&url[f.start..f.end], OPAQUE);

    let url = format!("https://x.example.com/?k={GITHUB}");
    assert!(has(&scanner().scan_url(&url), "github_token"));
}

#[test]
fn uppercase_keywords_and_prefixes_are_detected() {
    let body = format!("PASSWORD={PASSWORD}\nAUTHORIZATION: BEARER {OPAQUE}\n{}\n", ANTHROPIC.to_uppercase());
    let found = scanner().scan(body.as_bytes(), "body");
    assert!(has(&found, "generic_secret_assignment"), "{found:#?}");
    assert!(has(&found, "bearer_token"), "{found:#?}");
    assert!(has(&found, "anthropic_key"), "{found:#?}");
}

#[test]
fn same_secret_twice_gives_same_fingerprint() {
    let body = format!("a={GITHUB} b={GITHUB}");
    let found = scanner().scan(body.as_bytes(), "body");
    let gh: Vec<&Finding> = found.iter().filter(|f| f.kind == "github_token").collect();
    assert_eq!(gh.len(), 2);
    assert_eq!(gh[0].fingerprint, gh[1].fingerprint);
    assert_eq!(gh[0].fingerprint, fp(GITHUB));
    assert_eq!(gh[0].fingerprint.len(), 12);
    let again = scanner().scan(GITHUB.as_bytes(), "url");
    assert_eq!(find(&again, "github_token").fingerprint, gh[0].fingerprint);
}

#[test]
fn masking_leaves_no_fragment_of_any_secret() {
    let secrets = [ANTHROPIC, OPENAI, GITHUB, GITLAB, AWS_KEY, SLACK, JWT, PASSWORD, OPAQUE];
    let body = format!(
        "a {ANTHROPIC} b {OPENAI} c {GITHUB} d {GITLAB} e {AWS_KEY}\n\
         aws_secret_access_key={AWS_SECRET}\n{SLACK} {JWT}\npassword={PASSWORD} \
         https://bob:{OPAQUE}@db.example.com/x\n\
         b64 {}\n",
        STANDARD.encode(GITHUB)
    );
    let found = scanner().scan(body.as_bytes(), "body");
    let masked = mask(&body, &found);
    for s in secrets.iter().chain([&AWS_SECRET]) {
        for w in s.as_bytes().windows(8) {
            let w = std::str::from_utf8(w).unwrap();
            assert!(!masked.contains(w), "fragment {w:?} of {s} survived:\n{masked}");
        }
    }
    assert!(!masked.contains(&STANDARD.encode(GITHUB)[..12]));
    assert!(masked.contains(&format!("[SECRET:aws_access_key:{}]", fp(AWS_KEY))));
    assert_eq!(mask_bytes(body.as_bytes(), &found), masked.as_bytes());
}

#[test]
fn random_non_utf8_input_never_panics() {
    let s = scanner();
    let fragments: [&[u8]; 10] = [
        b"sk-ant-", b"password=", b"%", b"%4", b"\\u00", b"\\\"", b"==", b"-----BEGIN PRIVATE KEY-----",
        b"https://u:p@", b"\xe2\x82\xac",
    ];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..400 {
        let len = rng.below(3000);
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            if rng.below(8) == 0 {
                data.extend_from_slice(fragments[rng.below(fragments.len())]);
            } else if rng.below(3) == 0 {
                data.push(b"ABCxyz0129+/=_-"[rng.below(15)]);
            } else {
                data.push(rng.next_u64() as u8);
            }
        }
        let found = s.scan(&data, "body");
        for f in &found {
            assert!(f.start < f.end && f.end <= data.len(), "{f:?}");
        }
        let masked = mask_bytes(&data, &found);
        assert!(masked.len() <= data.len() + 64 * found.len());

        let mut st = s.stream("body");
        let mut pos = 0;
        let mut streamed = Vec::new();
        while pos < data.len() {
            let n = 1 + rng.below(700);
            let end = (pos + n).min(data.len());
            streamed.extend(st.feed(&data[pos..end]));
            pos = end;
        }
        streamed.extend(st.finish());
        for f in &streamed {
            assert!(f.start < f.end && f.end <= data.len(), "{f:?}");
        }
        let _ = s.scan_url(&String::from_utf8_lossy(&data));
    }
}

#[test]
fn no_false_positive_on_uuid_and_git_sha() {
    let body = "{\"id\":\"123e4567-e89b-12d3-a456-426614174000\",\
                \"commit\":\"9fceb02d0ae598e95dc970b74767f19372d61af8\",\
                \"request_id\":\"c56a4180-65aa-42ec-a945-5fd21dec0538\"}\n\
                commit 9fceb02d0ae598e95dc970b74767f19372d61af8\nMerge: 1d6b2a4 3f9e0c1";
    let found = scanner().scan(body.as_bytes(), "body");
    assert!(found.is_empty(), "{found:#?}");
}

const PRESIGNED: &str = concat!(
    "https://my-bucket.s3.eu-west-3.amazonaws.com/uploads/report.pdf",
    "?X-Amz-Algorithm=AWS4-HMAC-SHA256",
    "&X-Amz-Credential=", "AK", "IA", "Q3EXAMPLE7ZK4M2P", "%2F20261030%2Feu-west-3%2Fs3%2Faws4_request",
    "&X-Amz-Date=20261030T120000Z&X-Amz-Expires=3600",
    "&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEJr%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMyJHMEUCIQD",
    "x9mLq2Vt7Zk4Pw8Rn1Hb6Jc3Ys0Ga5Fd8Kt2Lm9Qp4Wv7Xz1Bn6Cr3Ej0Hu5Ik8Ol2Ma9Pq4Rs7Tt1Uv6Wx3Yz0",
    "&X-Amz-SignedHeaders=host",
    "&X-Amz-Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
);

#[test]
fn presigned_s3_url_is_not_a_secret_ef72() {
    let found = scanner().scan_url(PRESIGNED);
    assert!(found.is_empty(), "{found:#?}");
    let body = format!("{{\"upload_url\":\"{PRESIGNED}\"}}");
    let found = scanner().scan(body.as_bytes(), "body");
    assert!(!found.iter().any(|f| f.category == DataCategory::Secret), "{found:#?}");
    let found = scanner().scan(PRESIGNED.replace("%2F", "/").as_bytes(), "body");
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn presigned_s3_url_does_not_hide_other_secrets() {
    let url = format!("{PRESIGNED}&note={GITHUB}");
    let found = scanner().scan_url(&url);
    assert_eq!(kinds(&found), vec!["github_token"]);
    let url = format!("{PRESIGNED}&password={PASSWORD}");
    assert!(has(&scanner().scan_url(&url), "generic_secret_assignment"));
}
