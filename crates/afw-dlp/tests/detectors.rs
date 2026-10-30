//! One positive and one negative case per built-in detector, classes, serde and errors.

mod common;

use afw_dlp::{
    ClassSpec, DataCategory, DetectorSpec, DlpError, Scanner, ScannerOptions, builtin_classes, mask,
};
use common::*;

fn kinds_in(text: &str) -> Vec<String> {
    let mut k: Vec<String> = scanner()
        .scan(text.as_bytes(), "body")
        .into_iter()
        .map(|f| f.kind)
        .collect();
    k.sort();
    k.dedup();
    k
}

fn detects(text: &str, kind: &str) -> bool {
    kinds_in(text).iter().any(|k| k == kind)
}

#[test]
fn fixture_shapes() {
    assert_eq!(AWS_KEY.len(), 20);
    assert_eq!(AWS_SECRET.len(), 40);
    assert_eq!(GITHUB.len(), 40);
}

#[test]
fn positives() {
    let cases: Vec<(String, &str)> = vec![
        (format!("key {AWS_KEY} end"), "aws_access_key"),
        (format!("aws_secret_access_key = \"{AWS_SECRET}\""), "aws_secret_key"),
        (format!("AWS_SECRET_KEY: {AWS_SECRET}"), "aws_secret_key"),
        (format!("t={GITHUB}"), "github_token"),
        (concat!("x ", "gh", "s_", "Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7Qr9St1Uv3Wx5Y").to_string(), "github_token"),
        (concat!("x ", "github", "_pat_", "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123").to_string(), "github_token"),
        (format!("glab {GITLAB}"), "gitlab_token"),
        (format!("k {ANTHROPIC}"), "anthropic_key"),
        (format!("k {OPENAI}"), "openai_key"),
        (concat!("k ", "sk-", "Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7Qr9St1Uv3Wx5Yz7Ab3Cd5Ef7").to_string(), "openai_key"),
        (format!("slack {SLACK}"), "slack_token"),
        (format!("jwt {JWT}"), "jwt"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn\n-----END RSA PRIVATE KEY-----".to_string(), "private_key_pem"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\\nb3BlbnNzaC1rZXktdjEAAAAA\\n-----END OPENSSH PRIVATE KEY-----".to_string(), "private_key_pem"),
        (format!("postgres://app:{PASSWORD}@db:5432/x"), "password_in_url"),
        (format!("secret: \"{OPAQUE}\""), "generic_secret_assignment"),
        (format!("\"api_key\": \"{OPAQUE}\""), "generic_secret_assignment"),
        (format!("DB_PASSWD={PASSWORD}"), "generic_secret_assignment"),
        (format!("Authorization: Bearer {OPAQUE}"), "bearer_token"),
        ("IBAN FR76 3000 6000 0112 3456 7890 189".to_string(), "iban"),
        ("iban=DE89370400440532013000".to_string(), "iban"),
        ("card 4111 1111 1111 1111 exp".to_string(), "credit_card"),
        ("card 5500-0000-0000-0004".to_string(), "credit_card"),
        ("mail alice.martin@example.org now".to_string(), "email"),
        ("host 10.12.0.5 up".to_string(), "private_ip"),
        ("db 192.168.1.20:5432".to_string(), "private_ip"),
        ("ip 172.20.3.4".to_string(), "private_ip"),
        ("ssh build-01.internal".to_string(), "internal_hostname"),
        ("api.billing.corp.example/v1".to_string(), "internal_hostname"),
        ("total 1 250,00 € HT".to_string(), "price_amount"),
        ("price: €99.90".to_string(), "price_amount"),
        ("budget 15000 EUR".to_string(), "price_amount"),
        ("Montant : 3 400 euros".to_string(), "price_amount"),
    ];
    for (text, kind) in cases {
        assert!(
            detects(&text, kind),
            "`{kind}` not detected in {text:?}: {:?}",
            kinds_in(&text)
        );
    }
}

#[test]
fn negatives() {
    let cases: Vec<(&str, &str)> = vec![
        ("AKIA is a prefix, AKIASHORT", "aws_access_key"),
        ("aws_secret_access_key = short", "aws_secret_key"),
        ("ghp_short", "github_token"),
        ("glpat-short", "gitlab_token"),
        ("sk-ant-short", "anthropic_key"),
        ("task-abcdefghijklmnopqrstuvwxyz", "openai_key"),
        ("risk-assessment-for-the-project-2026", "openai_key"),
        ("xoxb-", "slack_token"),
        ("eyJhbGciOi.not-a-jwt", "jwt"),
        (
            "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq\n-----END PUBLIC KEY-----",
            "private_key_pem",
        ),
        ("https://example.com:8443/path@foo", "password_in_url"),
        ("https://user@example.com/", "password_in_url"),
        ("password=changeme", "generic_secret_assignment"),
        ("password=aaaaaaaaaaaaaaaaaaaa", "generic_secret_assignment"),
        ("token=${GITHUB_TOKEN}", "generic_secret_assignment"),
        ("the bearer of bad news", "bearer_token"),
        ("FR76 3000 6000 0112 3456 7890 188", "iban"),
        ("card 4111 1111 1111 1112", "credit_card"),
        ("order 1234567890123", "credit_card"),
        ("not an email: user@localhost", "email"),
        ("version 10.2.3 and 8.8.8.8 and 300.1.1.1", "private_ip"),
        ("10.0.0.256", "private_ip"),
        (
            "www.internal-tools.com and example.internal.example.com",
            "internal_hostname",
        ),
        ("page 1250 of 3000", "price_amount"),
    ];
    for (text, kind) in cases {
        assert!(
            !detects(text, kind),
            "`{kind}` falsely detected in {text:?}"
        );
    }
}

#[test]
fn builtin_classes_cover_the_four_defaults() {
    let classes = builtin_classes();
    let ids: Vec<(&str, DataCategory)> = classes
        .iter()
        .map(|c| (c.id.as_str(), c.category))
        .collect();
    assert_eq!(
        ids,
        vec![
            ("secrets", DataCategory::Secret),
            ("inventaire-infra", DataCategory::Infra),
            ("commercial", DataCategory::Commercial),
            ("donnees-personnelles", DataCategory::Personal),
        ]
    );
    let mut all: Vec<String> = classes
        .iter()
        .flat_map(|c| c.detectors.iter())
        .map(|d| match d {
            DetectorSpec::Builtin { id } => id.clone(),
            DetectorSpec::Regex { name, .. } => name.clone(),
        })
        .collect();
    all.sort();
    let mut expected: Vec<String> = afw_dlp::BUILTIN_DETECTORS
        .iter()
        .map(|s| s.to_string())
        .collect();
    expected.sort();
    assert_eq!(all, expected);
}

#[test]
fn finding_carries_class_metadata() {
    let found = scanner().scan(format!("{GITHUB} alice@example.org").as_bytes(), "body");
    let gh = find(&found, "github_token");
    assert_eq!(
        (gh.class_id.as_str(), gh.class_name.as_str()),
        ("secrets", "Secrets")
    );
    assert_eq!(gh.category, DataCategory::Secret);
    assert_eq!(gh.location, "body");
    assert_eq!(find(&found, "email").category, DataCategory::Personal);
}

#[test]
fn custom_regex_class() {
    let classes = vec![ClassSpec {
        id: "0b9a6f0e-2f7e-4d55-9c2b-1d2c3e4f5a6b".into(),
        name: "Projets".into(),
        category: DataCategory::Custom,
        detectors: vec![DetectorSpec::Regex {
            name: "project_code".into(),
            pattern: r"PRJ-\d{4}".into(),
        }],
    }];
    let s = Scanner::new(&classes, ScannerOptions::default()).unwrap();
    let found = s.scan(b"see PRJ-2041 and PRJ-12", "body");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].kind, "project_code");
    assert_eq!(
        mask("see PRJ-2041", &s.scan(b"see PRJ-2041", "body")),
        format!("see [CUSTOM:project_code:{}]", fp("PRJ-2041"))
    );
}

#[test]
fn same_value_in_two_classes_yields_one_finding_per_class() {
    let mut classes = builtin_classes();
    classes.push(ClassSpec {
        id: "cles-cloud".into(),
        name: "Clés cloud".into(),
        category: DataCategory::Custom,
        detectors: vec![DetectorSpec::Builtin {
            id: "aws_access_key".into(),
        }],
    });
    let s = Scanner::new(&classes, ScannerOptions::default()).unwrap();
    let found = s.scan(AWS_KEY.as_bytes(), "body");
    let mut ids: Vec<&str> = found.iter().map(|f| f.class_id.as_str()).collect();
    ids.sort();
    assert_eq!(ids, vec!["cles-cloud", "secrets"]);
}

#[test]
fn errors() {
    let bad = |d: DetectorSpec| {
        Scanner::new(
            &[ClassSpec {
                id: "x".into(),
                name: "x".into(),
                category: DataCategory::Custom,
                detectors: vec![d],
            }],
            ScannerOptions::default(),
        )
        .unwrap_err()
    };
    assert_eq!(
        bad(DetectorSpec::Builtin { id: "nope".into() }),
        DlpError::UnknownDetector("nope".into())
    );
    assert!(matches!(
        bad(DetectorSpec::Regex {
            name: "r".into(),
            pattern: "(".into()
        }),
        DlpError::InvalidPattern { .. }
    ));
    assert!(matches!(
        bad(DetectorSpec::Regex {
            name: "empty".into(),
            pattern: "a*".into()
        }),
        DlpError::InvalidPattern { .. }
    ));
    let err = Scanner::new(
        &[],
        ScannerOptions {
            max_pattern_len: 0,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(matches!(err, DlpError::InvalidOptions(_)));
}

#[test]
fn serde_formats() {
    let c: ClassSpec = serde_json::from_str(
        r#"{"id":"secrets","name":"Secrets","category":"secret","detectors":[
            {"type":"builtin","id":"jwt"},{"type":"regex","name":"n","pattern":"x+"}]}"#,
    )
    .unwrap();
    assert_eq!(c.category, DataCategory::Secret);
    assert_eq!(
        c.detectors[1],
        DetectorSpec::Regex {
            name: "n".into(),
            pattern: "x+".into()
        }
    );
    assert_eq!(
        serde_json::to_string(&DataCategory::Personal).unwrap(),
        "\"personal\""
    );
    let f = &scanner().scan(GITHUB.as_bytes(), "body")[0];
    let back: afw_dlp::Finding = serde_json::from_str(&serde_json::to_string(f).unwrap()).unwrap();
    assert_eq!(&back, f);
}

#[test]
fn mask_labels_and_overlaps() {
    let text = format!("Authorization: Bearer {JWT}");
    let found = scanner().scan(text.as_bytes(), "body");
    let masked = mask(&text, &found);
    assert!(
        masked.starts_with("Authorization: Bearer [SECRET:"),
        "{masked}"
    );
    assert_eq!(
        masked.matches("[SECRET:").count(),
        1,
        "overlapping findings merge: {masked}"
    );
    assert_eq!(mask("nothing", &[]), "nothing");
}

#[test]
fn mask_ignores_out_of_range_findings() {
    let mut f = scanner().scan(GITHUB.as_bytes(), "body");
    f[0].end = 10_000;
    assert_eq!(mask("short", &f), "short");
}
