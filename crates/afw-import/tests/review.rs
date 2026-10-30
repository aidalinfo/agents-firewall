//! Non-regression tests from the review of PR #14: an import never widens access. Every case
//! asserts a `Verdict::Deny` on the flow the faulty translation would have let through.

mod common;

use std::net::IpAddr;

use afw_core::events::Verdict;
use afw_core::policy::{Action, L4Proto, Layer, PolicyDocument, Rule, Track, Zone, ZoneMode};
use afw_engine::{CompiledPolicy, FlowContext};
use afw_import::{ImportError, ImportOptions, ImportPlan, import};
use chrono::Utc;
use common::*;
use uuid::Uuid;

fn verdict_ip(policy: &CompiledPolicy, ip: &str) -> Verdict {
    let ctx = FlowContext {
        agent_ip: AGENT_IP.parse().unwrap(),
        dst_ip: Some(ip.parse::<IpAddr>().unwrap()),
        dst_ip_trusted: true,
        dst_port: 443,
        l4: L4Proto::Tcp,
        app: None,
        host: None,
        method: None,
        path: None,
        data_classes: vec![],
        now: Utc::now(),
    };
    policy.evaluate(&ctx).verdict
}

const SECRETS: &str = "data_classes:\n  secrets:\n    patterns: ['exk_[a-z0-9]{32}']\n";

fn enforce_zone(name: &str) -> Zone {
    Zone {
        id: Uuid::new_v4(),
        name: name.into(),
        comment: String::new(),
        mode: ZoneMode::Enforce,
        delegated_to_mcp: false,
    }
}

/// Compiles `plan` merged into `existing` (agent in the plan's zone).
fn compile_with(plan: &ImportPlan, existing: &PolicyDocument) -> CompiledPolicy {
    let mut doc = plan.merged_into(existing);
    doc.agents.push(afw_core::policy::Agent {
        id: Uuid::new_v4(),
        name: "bot".into(),
        zone_id: plan.zone.id,
        kind: afw_core::policy::AgentKind::DockerCompose,
        gateway_id: None,
        addresses: vec![AGENT_IP.parse().unwrap()],
        labels: Default::default(),
        hermes: true,
        mcp_admin: false,
    });
    CompiledPolicy::compile(&afw_core::InstalledPolicy::new(1, "t", doc), Utc::now()).unwrap()
}

#[test]
fn c1_declared_tier_named_other_is_a_real_tier() {
    for name in ["other", "others", "unknown", "unlisted"] {
        let yaml = format!(
            "tiers:\n  {name}: {{}}\n{SECRETS}destinations:\n  allow:\n    - {{ host: x.example.com, tier: {name} }}\nmatrix:\n  secrets: {{ {name}: deny }}\n"
        );
        let plan = import_enforced(&yaml);
        let policy = compile(&plan);
        let s = class_id(&plan, "secrets");
        assert_eq!(
            verdict(&policy, "x.example.com", 443, vec![s]).0,
            Verdict::Deny,
            "tier {name}"
        );
    }
}

#[test]
fn c2_ports_emptied_by_cleanup_are_not_opened() {
    let yaml = "destinations:\n  allow:\n    - { host: smtp.example.com, tier: t, ports: [0] }\n";
    let plan = import_enforced(yaml);
    assert!(
        plan.report
            .unsupported
            .iter()
            .any(|u| u.path == "destinations.allow[0]")
    );
    let policy = compile(&plan);
    assert_eq!(
        verdict(&policy, "smtp.example.com", 443, vec![]).0,
        Verdict::Deny
    );
}

#[test]
fn c3_zero_and_overly_broad_prefixes() {
    let yaml = "destinations:\n  allow:\n    - { host: 0.0.0.0/0, tier: t }\n    - { host: '::/0', tier: t }\n    - { host: 16.0.0.0/4, tier: t }\n    - { host: '2000::/3', tier: t }\n    - { host: 198.51.100.0/24, tier: t }\n  deny:\n    - 0.0.0.0/0\n";
    let plan = import_enforced(yaml);
    for p in [
        "destinations.allow[0]",
        "destinations.allow[1]",
        "destinations.allow[2]",
        "destinations.allow[3]",
        "destinations.deny[0]",
    ] {
        assert!(
            plan.report.unsupported.iter().any(|u| u.path == p),
            "{p}: {:#?}",
            plan.report
        );
    }
    let policy = compile(&plan);
    assert_eq!(verdict_ip(&policy, "1.2.3.4"), Verdict::Deny);
    assert_eq!(verdict_ip(&policy, "17.1.2.3"), Verdict::Deny);
    assert_eq!(verdict_ip(&policy, "2001:db8::1"), Verdict::Deny);
    assert_eq!(verdict_ip(&policy, "198.51.100.7"), Verdict::Allow);
}

#[test]
fn i1_existing_zone_is_never_downgraded() {
    let zone = enforce_zone("assistant");
    let existing = PolicyDocument {
        zones: vec![zone.clone()],
        ..Default::default()
    };
    let mut o = ImportOptions::new("assistant");
    o.existing = Some(&existing);
    let plan = import(EXAMPLE, &o).unwrap();
    assert_eq!(plan.zone.mode, ZoneMode::Enforce);
    let policy = compile_with(&plan, &existing);
    assert_eq!(
        verdict(&policy, "unknown.example.net", 443, vec![]).0,
        Verdict::Deny
    );
}

#[test]
fn i2_tier_names_are_case_insensitive_and_lost_denies_are_blocking() {
    let yaml = format!(
        "tiers:\n  Trusted: {{}}\n{SECRETS}destinations:\n  allow:\n    - {{ host: x.example.com, tier: trusted }}\nmatrix:\n  secrets: {{ TRUSTED: deny }}\n"
    );
    let plan = import_enforced(&yaml);
    assert!(plan.is_safe(), "{:#?}", plan.report.blocking);
    let policy = compile(&plan);
    let s = class_id(&plan, "secrets");
    assert_eq!(
        verdict(&policy, "x.example.com", 443, vec![s]).0,
        Verdict::Deny
    );

    // A deny that cannot be converted is blocking.
    let yaml = format!(
        "{SECRETS}destinations:\n  allow:\n    - {{ host: x.example.com, tier: t }}\nmatrix:\n  secrets: {{ nowhere: deny, t: allow }}\n  ghost: {{ t: gate }}\n"
    );
    let plan = import_enforced(&yaml);
    assert!(!plan.is_safe());
    let paths: Vec<&str> = plan
        .report
        .blocking
        .iter()
        .map(|b| b.path.as_str())
        .collect();
    assert!(paths.contains(&"matrix.secrets.nowhere"), "{paths:?}");
    assert!(paths.contains(&"matrix.ghost.t"), "{paths:?}");
    assert!(plan.report.to_markdown().contains("Bloquant"));
    assert!(import_example().is_safe());
}

#[test]
fn i3_existing_rule_with_same_name_but_different_content_is_not_reused() {
    let zone = enforce_zone("assistant");
    let yaml = format!(
        "{SECRETS}destinations:\n  allow:\n    - {{ host: x.example.com, tier: t }}\nmatrix:\n  secrets: {{ t: deny }}\n"
    );
    // First import gives the rule names.
    let first = {
        let existing = PolicyDocument {
            zones: vec![zone.clone()],
            ..Default::default()
        };
        let mut o = ImportOptions::new("assistant");
        o.existing = Some(&existing);
        import(&yaml, &o).unwrap()
    };
    let deny_name = first
        .rules
        .iter()
        .find(|r| r.action == Action::Deny)
        .unwrap()
        .name
        .clone();
    let decoy = Rule {
        id: Uuid::new_v4(),
        name: deny_name.clone(),
        layer: Layer::Zone { zone_id: zone.id },
        section: None,
        position: 500,
        sources: vec![zone.id],
        destinations: vec![],
        services: vec![],
        data_classes: vec![],
        action: Action::Deny,
        track: Track::Detailed,
        expires_at: None,
        comment: String::new(),
        enabled: false,
    };
    let existing = PolicyDocument {
        zones: vec![zone.clone()],
        rules: vec![decoy],
        ..Default::default()
    };
    let mut o = ImportOptions::new("assistant");
    o.existing = Some(&existing);
    let plan = import(&yaml, &o).unwrap();
    let new = plan
        .rules
        .iter()
        .find(|r| r.action == Action::Deny && r.layer != Layer::Baseline)
        .expect("a new deny rule is created");
    assert_ne!(new.name, deny_name);
    assert!(
        plan.report
            .warnings
            .iter()
            .any(|w| w.message.contains(&deny_name))
    );
    let policy = compile_with(&plan, &existing);
    let s = class_id(&plan, "secrets");
    assert_eq!(
        verdict(&policy, "x.example.com", 443, vec![s]).0,
        Verdict::Deny
    );
}

#[test]
fn i4_size_depth_and_pattern_limits() {
    let big = format!("# {}\n", "x".repeat(1024 * 1024));
    assert!(matches!(
        import(&big, &opts("z")),
        Err(ImportError::Limit(_))
    ));
    let deep = format!("a: {}{}\n", "[".repeat(200), "]".repeat(200));
    assert!(matches!(
        import(&deep, &opts("z")),
        Err(ImportError::Limit(_))
    ));
    let many: String = (0..201)
        .map(|i| format!("      - 'p{i}x[0-9]{{8}}'\n"))
        .collect();
    let yaml = format!("data_classes:\n  c:\n    patterns:\n{many}");
    assert!(matches!(
        import(&yaml, &opts("z")),
        Err(ImportError::Limit(_))
    ));
    let long = format!(
        "data_classes:\n  c:\n    patterns:\n      - 'ok_[0-9]{{8}}'\n      - '{}'\n",
        "a".repeat(600)
    );
    let plan = import(&long, &opts("z")).unwrap();
    assert!(
        plan.report
            .unsupported
            .iter()
            .any(|u| u.path == "data_classes.c.patterns[1]")
    );
    assert_eq!(plan.data_classes[0].detectors.len(), 1);
}

#[test]
fn i5_nested_quantifiers_in_action_patterns_are_rejected() {
    let yaml = format!(
        "action_classes:\n  irreversible:\n    decision: gate\n    tools: [x]\n    patterns:\n      - '(a+)+$'\n      - '(?:\\w*)*z'\n      - '(ab+)*'\n      - '{}'\n      - '\\brm\\s+-rf\\b'\n",
        "b".repeat(600)
    );
    let plan = import(&yaml, &opts("z")).unwrap();
    assert_eq!(
        plan.intent_policy.action_classes[0].patterns,
        vec![r"\brm\s+-rf\b".to_string()]
    );
    assert_eq!(plan.report.unsupported.len(), 4, "{:#?}", plan.report);
}

#[test]
fn m1_denied_wildcard_covers_apex() {
    let yaml = "destinations:\n  allow:\n    - { host: 'paste.example', tier: t }\n  deny:\n    - '*.paste.example'\n";
    let plan = import_enforced(yaml);
    let policy = compile(&plan);
    assert_eq!(
        verdict(&policy, "paste.example", 443, vec![]).0,
        Verdict::Deny
    );
    assert_eq!(
        verdict(&policy, "a.paste.example", 443, vec![]).0,
        Verdict::Deny
    );
}

fn accept_all(zone: &Zone, position: u32) -> Rule {
    Rule {
        id: Uuid::new_v4(),
        name: "legacy accept all".into(),
        layer: Layer::Zone { zone_id: zone.id },
        section: None,
        position,
        sources: vec![zone.id],
        destinations: vec![],
        services: vec![],
        data_classes: vec![],
        action: Action::Accept,
        track: Track::Detailed,
        expires_at: None,
        comment: String::new(),
        enabled: true,
    }
}

#[test]
fn m2_imported_rules_go_before_existing_rules() {
    let zone = enforce_zone("assistant");
    let yaml = format!(
        "{SECRETS}destinations:\n  allow:\n    - {{ host: x.example.com, tier: t }}\nmatrix:\n  secrets: {{ t: deny }}\n"
    );
    let existing = PolicyDocument {
        zones: vec![zone.clone()],
        rules: vec![accept_all(&zone, 100)],
        ..Default::default()
    };
    let mut o = ImportOptions::new("assistant");
    o.existing = Some(&existing);
    let plan = import(&yaml, &o).unwrap();
    assert!(plan.rules.iter().all(|r| r.position < 100));
    let policy = compile_with(&plan, &existing);
    let s = class_id(&plan, "secrets");
    assert_eq!(
        verdict(&policy, "x.example.com", 443, vec![s]).0,
        Verdict::Deny
    );

    // No room before position 1: shadowing is reported.
    let existing = PolicyDocument {
        zones: vec![zone.clone()],
        rules: vec![accept_all(&zone, 1)],
        ..Default::default()
    };
    let mut o = ImportOptions::new("assistant");
    o.existing = Some(&existing);
    let plan = import(&yaml, &o).unwrap();
    assert!(
        plan.report
            .warnings
            .iter()
            .any(|w| w.message.contains("masqu")),
        "{:#?}",
        plan.report.warnings
    );
}

#[test]
fn policy_fragment_and_intent_note() {
    let plan = import_example();
    let f = plan.to_policy_fragment();
    assert!(f.agents.is_empty());
    assert_eq!(f.settings, Default::default());
    assert_eq!(f.zones, vec![plan.zone.clone()]);
    assert_eq!(f.objects.len(), plan.objects.len());
    assert_eq!(f.rules.len(), plan.rules.len());
    assert_eq!(f.data_classes.len(), plan.data_classes.len());
    assert!(
        plan.report
            .warnings
            .iter()
            .any(|w| w.message.contains("PUT /intent-policy"))
    );
}
