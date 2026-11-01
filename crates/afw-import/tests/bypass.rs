//! Bypass tests of the importer: a translated policy must never be weaker than the egress-guard
//! file it comes from (except the documented EF-72 correction), and never fail open.

mod common;

use afw_core::events::Verdict;
use afw_core::policy::{Action, Layer, NetObjectSpec};
use afw_dlp::{ClassSpec, DataCategory as DlpCategory, DetectorSpec, Scanner, ScannerOptions};
use afw_import::import;
use common::*;

#[test]
fn log_rule_never_accepts_content_a_deny_rule_refuses() {
    // infra → trusted is "log" (accept), secrets → trusted is "deny": a body carrying both must
    // be refused whatever the rule order in the file.
    let plan = import_enforced(EXAMPLE);
    let policy = compile(&plan);
    let secrets = class_id(&plan, "secrets");
    let infra = class_id(&plan, "infra_inventory");
    assert_eq!(
        verdict(&policy, "graph.microsoft.com", 443, vec![infra, secrets]).0,
        Verdict::Deny
    );
    assert_eq!(
        verdict(&policy, "graph.microsoft.com", 443, vec![secrets, infra]).0,
        Verdict::Deny
    );
}

#[test]
fn log_to_any_does_not_open_unlisted_destinations() {
    let yaml = "data_classes:\n  commercial:\n    patterns: ['QUOTE-\\d{6}']\ndestinations:\n  allow:\n    - { host: api.example.com, tier: t }\nmatrix:\n  commercial: { any: log }\n";
    let plan = import_enforced(yaml);
    let policy = compile(&plan);
    let c = class_id(&plan, "commercial");
    assert_eq!(
        verdict(&policy, "exfil.example.net", 443, vec![c]).0,
        Verdict::Deny
    );
    assert_eq!(
        verdict(&policy, "api.example.com", 443, vec![c]).0,
        Verdict::Allow
    );
    // No accept rule without destination.
    assert!(
        plan.rules
            .iter()
            .all(|r| r.action == Action::Deny || !r.destinations.is_empty())
    );
}

#[test]
fn deny_to_any_covers_every_listed_destination() {
    let yaml = "data_classes:\n  secrets:\n    patterns: ['exk_[a-z0-9]{32}']\ndestinations:\n  allow:\n    - { host: api.example.com, tier: t }\nmatrix:\n  secrets: { any: deny }\n";
    let plan = import_enforced(yaml);
    let policy = compile(&plan);
    let s = class_id(&plan, "secrets");
    assert_eq!(
        verdict(&policy, "api.example.com", 443, vec![s]).0,
        Verdict::Deny
    );
}

#[test]
fn ported_entry_is_not_accepted_on_another_port() {
    let plan = import_enforced(EXAMPLE);
    let policy = compile(&plan);
    assert_eq!(
        verdict(&policy, "smtp.partner.example", 587, vec![]).0,
        Verdict::Allow
    );
    assert_eq!(
        verdict(&policy, "smtp.partner.example", 443, vec![]).0,
        Verdict::Deny
    );
    // The "log" content rule to the partner tier keeps the port restriction too.
    let commercial = class_id(&plan, "commercial");
    assert_eq!(
        verdict(&policy, "smtp.partner.example", 25, vec![commercial]).0,
        Verdict::Deny
    );
    assert_eq!(
        verdict(&policy, "smtp.partner.example", 587, vec![commercial]).0,
        Verdict::Allow
    );
}

#[test]
fn denied_host_wins_over_allowed_wildcard() {
    let yaml = "destinations:\n  allow:\n    - { host: '*.example.com', tier: t }\n  deny:\n    - paste.example.com\n";
    let plan = import_enforced(yaml);
    let policy = compile(&plan);
    assert_eq!(
        verdict(&policy, "paste.example.com", 443, vec![]).0,
        Verdict::Deny
    );
    assert_eq!(
        verdict(&policy, "api.example.com", 443, vec![]).0,
        Verdict::Allow
    );
    // The deny list lives in the baseline (not overridable by zone rules), scoped to the zone.
    let deny = plan
        .rules
        .iter()
        .find(|r| r.layer == Layer::Baseline)
        .unwrap();
    assert_eq!(deny.action, Action::Deny);
    assert_eq!(deny.sources, vec![plan.zone.id]);
}

#[test]
fn same_host_allowed_and_denied_is_denied() {
    let yaml = "destinations:\n  allow:\n    - { host: x.example.com, tier: t }\n  deny:\n    - X.example.com\n";
    let plan = import_enforced(yaml);
    let policy = compile(&plan);
    assert_eq!(
        verdict(&policy, "x.example.com", 443, vec![]).0,
        Verdict::Deny
    );
}

#[test]
fn global_wildcard_is_never_any() {
    let yaml =
        "destinations:\n  allow:\n    - { host: '*', tier: t }\n    - { host: '*.*', tier: t }\n";
    let plan = import_enforced(yaml);
    assert!(!plan.objects.iter().any(|o| o.spec == NetObjectSpec::Any
        || matches!(&o.spec, NetObjectSpec::Domain { pattern } if pattern.contains("*.*"))));
    assert!(plan.rules.iter().all(|r| r.action == Action::Deny));
    let policy = compile(&plan);
    assert_eq!(
        verdict(&policy, "anything.example.net", 443, vec![]).0,
        Verdict::Deny
    );
}

#[test]
fn default_allow_does_not_disable_default_deny() {
    let yaml =
        "destinations:\n  default: allow\n  allow:\n    - { host: api.example.com, tier: t }\n";
    let plan = import_enforced(yaml);
    assert!(
        plan.report
            .warnings
            .iter()
            .any(|w| w.path == "destinations.default")
    );
    let policy = compile(&plan);
    assert_eq!(
        verdict(&policy, "other.example.net", 443, vec![]).0,
        Verdict::Deny
    );
}

#[test]
fn unknown_matrix_decision_is_strictest() {
    let yaml = "data_classes:\n  secrets:\n    patterns: ['exk_[a-z0-9]{32}']\ndestinations:\n  allow:\n    - { host: api.example.com, tier: t }\nmatrix:\n  secrets: { t: allwo }\n";
    let plan = import_enforced(yaml);
    let policy = compile(&plan);
    let s = class_id(&plan, "secrets");
    assert_eq!(
        verdict(&policy, "api.example.com", 443, vec![s]).0,
        Verdict::Deny
    );
    assert!(
        plan.report
            .warnings
            .iter()
            .any(|w| w.message.contains("allwo"))
    );
}

#[test]
fn llm_tier_defined_by_category_only_is_exempt_but_reported() {
    let yaml = "tiers:\n  ai: { category: llm_provider }\ndata_classes:\n  secrets:\n    patterns: ['exk_[a-z0-9]{32}']\ndestinations:\n  allow:\n    - { host: api.llm.example, tier: ai }\nmatrix:\n  secrets: { ai: deny }\n";
    let plan = import_enforced(yaml);
    assert!(
        plan.report
            .warnings
            .iter()
            .any(|w| w.message.contains("EF-25"))
    );
}

// ---- EF-72: presigned S3 uploads ------------------------------------------------------------

const PRESIGNED: &str = concat!(
    "https://my-bucket.s3.eu-west-3.amazonaws.com/uploads/report.pdf",
    "?X-Amz-Algorithm=AWS4-HMAC-SHA256",
    "&X-Amz-Credential=",
    "AK",
    "IA",
    "Q3EXAMPLE7ZK4M2P",
    "%2F20261030%2Feu-west-3%2Fs3%2Faws4_request",
    "&X-Amz-Date=20261030T120000Z&X-Amz-Expires=3600",
    "&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEJr%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMyJHMEUCIQD",
    "x9mLq2Vt7Zk4Pw8Rn1Hb6Jc3Ys0Ga5Fd8Kt2Lm9Qp4Wv7Xz1Bn6Cr3Ej0Hu5Ik8Ol2Ma9Pq4Rs7Tt1Uv6Wx3Yz0",
    "&X-Amz-SignedHeaders=host",
    "&X-Amz-Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
);

fn scanner_for(plan: &afw_import::ImportPlan) -> Scanner {
    let classes: Vec<ClassSpec> = plan
        .data_classes
        .iter()
        .map(|c| ClassSpec {
            id: c.id.to_string(),
            name: c.name.clone(),
            category: match c.category {
                afw_core::policy::DataCategory::Secret => DlpCategory::Secret,
                afw_core::policy::DataCategory::Infra => DlpCategory::Infra,
                afw_core::policy::DataCategory::Commercial => DlpCategory::Commercial,
                afw_core::policy::DataCategory::Personal => DlpCategory::Personal,
                afw_core::policy::DataCategory::Custom => DlpCategory::Custom,
            },
            detectors: c
                .detectors
                .iter()
                .map(|d| match d {
                    afw_core::policy::Detector::Builtin { id } => {
                        DetectorSpec::Builtin { id: id.clone() }
                    }
                    afw_core::policy::Detector::Regex { name, pattern } => DetectorSpec::Regex {
                        name: name.clone(),
                        pattern: pattern.clone(),
                    },
                })
                .collect(),
        })
        .collect();
    Scanner::new(&classes, ScannerOptions::default()).expect("imported classes compile in afw-dlp")
}

#[test]
fn presigned_s3_upload_is_not_blocked_ef72() {
    let plan = import_enforced(EXAMPLE);
    let scanner = scanner_for(&plan);
    assert!(
        scanner.scan_url(PRESIGNED).is_empty(),
        "{:#?}",
        scanner.scan_url(PRESIGNED)
    );
    let body = format!("{{\"upload_url\":\"{PRESIGNED}\"}}");
    let found = scanner.scan(body.as_bytes(), "body");
    assert!(found.is_empty(), "{found:#?}");
    let decoded = PRESIGNED.replace("%2F", "/");
    assert!(scanner.scan(decoded.as_bytes(), "body").is_empty());
    // So the upload to the trusted S3 tier is allowed (no data class detected).
    let policy = compile(&plan);
    assert_eq!(
        verdict(&policy, "my-bucket.s3.eu-west-3.amazonaws.com", 443, vec![]).0,
        Verdict::Allow
    );
}

#[test]
fn presigned_correction_does_not_hide_real_secrets() {
    let plan = import_enforced(EXAMPLE);
    let scanner = scanner_for(&plan);
    let gh = concat!("gh", "p_", "Zk8pL2wQ9zXr4Tn7aB3cD5eF7gH9iJ1kL3mN");
    let url = format!("{PRESIGNED}&note={gh}");
    assert!(!scanner.scan_url(&url).is_empty());
    let key = concat!("AK", "IA", "Q3EXAMPLE7ZK4M2P");
    let body = format!("aws_access_key_id = {key}");
    assert!(
        !scanner.scan(body.as_bytes(), "body").is_empty(),
        "a bare access key is still a secret"
    );
    let custom = format!("token exk_{}", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");
    assert!(!scanner.scan(custom.as_bytes(), "body").is_empty());
}

#[test]
fn every_imported_class_ignores_presigned_urls() {
    // Whatever the class (not only "secrets"), a pattern that catches a presigned URL is dropped.
    let yaml = "data_classes:\n  infra:\n    category: infra\n    patterns:\n      - { name: hex64, regex: '[0-9a-f]{64}' }\n      - { name: ip, regex: '\\b10\\.\\d+\\.\\d+\\.\\d+\\b' }\n";
    let plan = import(yaml, &opts("z")).unwrap();
    let scanner = scanner_for(&plan);
    assert!(scanner.scan_url(PRESIGNED).is_empty());
    assert_eq!(plan.data_classes[0].detectors.len(), 1);
}
