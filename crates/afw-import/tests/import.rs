//! Behaviour of the egress-guard importer (lot L10, EF-70, EF-71, EF-72).

mod common;

use afw_core::api::IntentDecision;
use afw_core::events::Verdict;
use afw_core::policy::{
    Action, DataCategory, DestCategory, Detector, Layer, NetObject, NetObjectSpec, PolicyDocument,
    Zone, ZoneMode,
};
use afw_import::{ImportError, ImportOptions, SessionChange, import};
use common::*;
use uuid::Uuid;

fn object<'a>(plan: &'a afw_import::ImportPlan, name: &str) -> &'a NetObject {
    plan.objects
        .iter()
        .find(|o| o.name == name)
        .unwrap_or_else(|| panic!("object {name} not in plan"))
}

fn has_warning(plan: &afw_import::ImportPlan, needle: &str) -> bool {
    plan.report
        .warnings
        .iter()
        .any(|w| w.path.contains(needle) || w.message.contains(needle))
}

#[test]
fn full_example_counts() {
    let plan = import_example();
    // 10 allowed + 3 denied hosts (+ the apex of the denied `*.ngrok.io`), 5 tier groups +
    // 1 denied group.
    let leaves = plan
        .objects
        .iter()
        .filter(|o| !matches!(o.spec, NetObjectSpec::Group { .. }))
        .count();
    let groups = plan.objects.len() - leaves;
    assert_eq!((leaves, groups), (14, 6), "{:#?}", plan.objects);
    // One TCP/587 service for the partner SMTP host.
    assert_eq!(plan.services.len(), 1);
    assert_eq!(plan.services[0].ports[0].start, 587);
    assert_eq!(plan.data_classes.len(), 3);
    let baseline = plan
        .rules
        .iter()
        .filter(|r| r.layer == Layer::Baseline)
        .count();
    let zone = plan.rules.len() - baseline;
    // Baseline: denied hosts. Zone: 5 matrix deny + 3 matrix log + 6 tier accepts.
    assert_eq!((baseline, zone), (1, 14), "{:#?}", plan.rules);
    assert_eq!(plan.intent_policy.action_classes.len(), 4);
    assert!(plan.report.unsupported.iter().any(|u| u.path == "senders"));
    // Every rule is enabled, sourced from the imported zone and compiles.
    assert!(
        plan.rules
            .iter()
            .all(|r| r.enabled && r.sources == vec![plan.zone.id])
    );
    compile(&plan);
}

#[test]
fn zone_is_observe_by_default_ef71() {
    let plan = import_example();
    assert_eq!(plan.zone.name, "assistant");
    assert_eq!(plan.zone.mode, ZoneMode::Observe);
    assert_eq!(ImportOptions::new("x").zone_mode, ZoneMode::Observe);
    let policy = compile(&plan);
    // In observe mode a would-be denial passes, marked observed.
    let d = policy.evaluate(&afw_engine::FlowContext {
        agent_ip: AGENT_IP.parse().unwrap(),
        dst_ip: Some("203.0.113.10".parse().unwrap()),
        dst_ip_trusted: true,
        dst_port: 443,
        l4: afw_core::policy::L4Proto::Tcp,
        app: None,
        host: Some("unknown.example.net".into()),
        method: None,
        path: None,
        data_classes: vec![],
        now: chrono::Utc::now(),
    });
    assert_eq!(d.verdict, Verdict::Allow);
    assert!(d.observed);
}

#[test]
fn wildcard_domains() {
    let plan = import_example();
    let o = object(&plan, "*.wikipedia.org");
    assert_eq!(
        o.spec,
        NetObjectSpec::Domain {
            pattern: "*.wikipedia.org".into()
        }
    );
    // The apex is not covered: reported so the operator can add it.
    assert!(has_warning(&plan, "*.wikipedia.org"));
    let policy = compile(&import_enforced(EXAMPLE));
    assert_eq!(
        verdict(&policy, "fr.wikipedia.org", 443, vec![]).0,
        Verdict::Allow
    );
    assert_eq!(
        verdict(&policy, "wikipedia.org", 443, vec![]).0,
        Verdict::Deny
    );
    assert_eq!(
        verdict(&policy, "evilwikipedia.org", 443, vec![]).0,
        Verdict::Deny
    );
    // Upper case and trailing dot are normalised; invalid wildcards are not converted.
    let yaml = "destinations:\n  allow:\n    - { host: 'API.Example.COM.', tier: t }\n    - { host: 'api.*.example.com', tier: t }\n    - { host: '*', tier: t }\n";
    let plan = import(yaml, &opts("z")).unwrap();
    assert!(plan.objects.iter().any(|o| o.spec
        == NetObjectSpec::Domain {
            pattern: "api.example.com".into()
        }));
    assert_eq!(plan.report.unsupported.len(), 2, "{:#?}", plan.report);
}

#[test]
fn destination_tiers_become_groups_with_categories() {
    let plan = import_example();
    let llm = object(&plan, "egress-guard/assistant/llm");
    assert_eq!(llm.category, Some(DestCategory::LlmProvider));
    let NetObjectSpec::Group { members } = &llm.spec else {
        panic!("tier is a group")
    };
    assert_eq!(members.len(), 2);
    assert_eq!(
        object(&plan, "egress-guard/assistant/internal").category,
        Some(DestCategory::Internal)
    );
    assert_eq!(
        object(&plan, "egress-guard/assistant/public").category,
        None
    );
    // Leaf objects carry their tier category too.
    assert_eq!(
        object(&plan, "api.openai.com").category,
        Some(DestCategory::LlmProvider)
    );

    let policy = compile(&import_enforced(EXAMPLE));
    assert_eq!(
        verdict(&policy, "graph.microsoft.com", 443, vec![]).0,
        Verdict::Allow
    );
    assert_eq!(
        verdict(&policy, "smtp.partner.example", 587, vec![]).0,
        Verdict::Allow
    );
    assert_eq!(
        verdict(&policy, "pastebin.com", 443, vec![]).0,
        Verdict::Deny
    );
    // Default deny: an unlisted host hits the implicit cleanup.
    let (v, rule) = verdict(&policy, "unknown.example.net", 443, vec![]);
    assert_eq!(v, Verdict::Deny);
    assert!(!rule.contains("egress-guard"), "{rule}");
}

#[test]
fn matrix_becomes_content_rules() {
    let plan = import_enforced(EXAMPLE);
    let secrets = class_id(&plan, "secrets");
    let infra = class_id(&plan, "infra_inventory");
    let commercial = class_id(&plan, "commercial");

    // Content rules carry their data class; deny/gate rules come before log rules, which come
    // before plain destination accepts.
    let zone_rules: Vec<_> = {
        let mut r: Vec<_> = plan
            .rules
            .iter()
            .filter(|r| r.layer != Layer::Baseline)
            .collect();
        r.sort_by_key(|r| r.position);
        r
    };
    let kinds: Vec<(Action, bool)> = zone_rules
        .iter()
        .map(|r| (r.action, r.data_classes.is_empty()))
        .collect();
    let first_plain_accept = kinds.iter().position(|k| k.1).unwrap();
    assert!(kinds[..5].iter().all(|k| *k == (Action::Deny, false)));
    assert!(
        kinds[5..first_plain_accept]
            .iter()
            .all(|k| *k == (Action::Accept, false))
    );
    assert!(
        kinds[first_plain_accept..]
            .iter()
            .all(|k| *k == (Action::Accept, true))
    );

    let policy = compile(&plan);
    // deny
    assert_eq!(
        verdict(&policy, "graph.microsoft.com", 443, vec![secrets]).0,
        Verdict::Deny
    );
    // gate → deny at the gateway (no approval queue in V1)
    assert_eq!(
        verdict(&policy, "git.corp.example", 443, vec![secrets]).0,
        Verdict::Deny
    );
    assert_eq!(
        verdict(&policy, "api.partner.example", 443, vec![infra]).0,
        Verdict::Deny
    );
    // log → accepted, attributed to a dedicated rule
    let (v, rule) = verdict(&policy, "graph.microsoft.com", 443, vec![infra]);
    assert_eq!(v, Verdict::Allow);
    assert!(rule.contains("log"), "{rule}");
    // allow → plain tier accept
    assert_eq!(
        verdict(&policy, "graph.microsoft.com", 443, vec![commercial]).0,
        Verdict::Allow
    );
    // LLM providers are exempt from data-class blocking (EF-25).
    assert_eq!(
        verdict(&policy, "api.anthropic.com", 443, vec![secrets]).0,
        Verdict::Allow
    );
    // gate is reported as an approximation.
    assert!(has_warning(&plan, "gate"));
}

#[test]
fn data_class_categories_and_detectors() {
    let plan = import_example();
    let get = |n: &str| plan.data_classes.iter().find(|c| c.name == n).unwrap();
    assert_eq!(get("secrets").category, DataCategory::Secret);
    assert_eq!(get("infra_inventory").category, DataCategory::Infra);
    assert_eq!(get("commercial").category, DataCategory::Commercial);
    let secrets = get("secrets");
    // Built-in afw-dlp secret detectors replace the regex class...
    assert!(secrets.detectors.contains(&Detector::Builtin {
        id: "aws_access_key".into()
    }));
    // ...custom patterns that do not match presigned URLs are kept...
    assert!(
        secrets
            .detectors
            .iter()
            .any(|d| matches!(d, Detector::Regex { name, .. } if name == "example_api_key"))
    );
    // ...and the ones that caught presigned uploads are dropped (EF-72).
    assert!(!secrets.detectors.iter().any(
        |d| matches!(d, Detector::Regex { name, .. } if name == "aws_signature" || name == "aws_access_key")
    ));
    assert!(has_warning(&plan, "EF-72"));
    assert_eq!(get("commercial").detectors.len(), 2);
}

#[test]
fn action_classes_become_intent_policy() {
    let plan = import_example();
    let ip = &plan.intent_policy;
    assert_eq!(ip.version, 1);
    let ids: Vec<&str> = ip.action_classes.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "irreversible",
            "access",
            "infra_destructive",
            "paid_generation"
        ]
    );
    let infra = &ip.action_classes[2];
    assert_eq!(infra.name, "Infrastructure destructive");
    assert_eq!(infra.decision, IntentDecision::Gate);
    assert_eq!(infra.tools, ["terminal", "shell", "coolify_*"]);
    assert_eq!(infra.patterns.len(), 3);
    assert_eq!(ip.action_classes[3].decision, IntentDecision::Log);
    // Serialises to the ADR 0015 format.
    let json = serde_json::to_value(ip).unwrap();
    assert!(json["action_classes"][0]["decision"] == "gate");

    // Synonyms and unknown decisions; missing standard classes are reported.
    let yaml = "action_classes:\n  Paid-Generation:\n    decision: ask\n  weird:\n    decision: maybe\n    tools: [x]\n";
    let plan = import(yaml, &opts("z")).unwrap();
    let ac = &plan.intent_policy.action_classes;
    assert_eq!(ac[0].id, "paid_generation");
    assert_eq!(ac[0].decision, IntentDecision::Gate);
    assert_eq!(ac[1].decision, IntentDecision::Deny);
    assert!(has_warning(&plan, "maybe"));
    assert!(has_warning(&plan, "irreversible"));
}

#[test]
fn unknown_fields_are_warnings() {
    let yaml = r#"
version: 2
colour: blue
destinations:
  default: deny
  allow:
    - host: api.example.com
      tier: t
      ttl: 30
data_classes:
  secrets:
    severity: high
    patterns:
      - { name: k, regex: 'exk_[a-z0-9]{32}', flags: i }
matrix:
  secrets: { t: deny }
action_classes:
  irreversible: { decision: gate, tools: [delete_*], owner: ops }
tiers:
  t: { trust: 3 }
"#;
    let plan = import(yaml, &opts("z")).unwrap();
    for path in [
        "colour",
        "destinations.allow[0].ttl",
        "data_classes.secrets.severity",
        "data_classes.secrets.patterns[0].flags",
        "action_classes.irreversible.owner",
        "tiers.t.trust",
    ] {
        assert!(
            plan.report.warnings.iter().any(|w| w.path == path),
            "missing warning for {path}: {:#?}",
            plan.report.warnings
        );
    }
}

#[test]
fn invalid_yaml_is_a_clear_error() {
    let err = import("destinations: [\n  allow: {", &opts("z")).unwrap_err();
    assert!(matches!(err, ImportError::Yaml(_)), "{err:?}");
    assert!(err.to_string().contains("line"), "{err}");

    let err = import("- just\n- a list\n", &opts("z")).unwrap_err();
    assert!(matches!(err, ImportError::Invalid { .. }), "{err:?}");

    let err = import("destinations:\n  allow: 42\n", &opts("z")).unwrap_err();
    assert!(err.to_string().contains("destinations"), "{err}");

    let err = import("data_classes:\n  s:\n    patterns: 7\n", &opts("z")).unwrap_err();
    assert!(err.to_string().contains("data_classes.s"), "{err}");

    let err = import("version: 2\n", &opts("  ")).unwrap_err();
    assert!(matches!(err, ImportError::Options(_)), "{err:?}");
}

#[test]
fn invalid_regex_is_unsupported_not_silent() {
    let yaml = "data_classes:\n  commercial:\n    patterns:\n      - { name: ok, regex: 'QUOTE-\\d{6}' }\n      - { name: bad, regex: '(?<=x)y' }\n";
    let plan = import(yaml, &opts("z")).unwrap();
    assert_eq!(plan.data_classes[0].detectors.len(), 1);
    assert!(
        plan.report
            .unsupported
            .iter()
            .any(|u| u.path == "data_classes.commercial.patterns[1]")
    );
}

#[test]
fn reuses_existing_objects_and_zone() {
    let existing_obj = NetObject {
        id: Uuid::new_v4(),
        name: "Microsoft Graph".into(),
        comment: String::new(),
        category: None,
        spec: NetObjectSpec::Domain {
            pattern: "Graph.Microsoft.com".into(),
        },
    };
    let zone = Zone {
        id: Uuid::new_v4(),
        name: "assistant".into(),
        comment: String::new(),
        mode: ZoneMode::Enforce,
        delegated_to_mcp: false,
    };
    let existing = PolicyDocument {
        objects: vec![existing_obj.clone()],
        zones: vec![zone.clone()],
        ..Default::default()
    };
    let mut o = opts("assistant");
    o.existing = Some(&existing);
    let plan = import(EXAMPLE, &o).unwrap();
    // Same domain: not recreated, referenced by its id.
    assert!(!plan.objects.iter().any(|o| o.name == "graph.microsoft.com"));
    let NetObjectSpec::Group { members } = &object(&plan, "egress-guard/assistant/trusted").spec
    else {
        panic!()
    };
    assert!(members.contains(&existing_obj.id));
    // Existing zone reused (same id): an import never downgrades it (review I1).
    assert_eq!(plan.zone.id, zone.id);
    assert_eq!(plan.zone.mode, ZoneMode::Enforce);
    assert_eq!(plan.zone_change, afw_import::ZoneChange::Unchanged);
    let changes = plan.to_session_changes();
    assert!(!changes.iter().any(|c| matches!(
        c,
        SessionChange::UpdateZone(_) | SessionChange::CreateZone(_)
    )));
    assert!(has_warning(&plan, "downgrade"));
    // Explicit downgrade switches it to observe.
    let mut o = opts("assistant");
    o.existing = Some(&existing);
    o.downgrade = true;
    let down = import(EXAMPLE, &o).unwrap();
    assert_eq!(down.zone.mode, ZoneMode::Observe);
    assert!(
        down.to_session_changes()
            .iter()
            .any(|c| matches!(c, SessionChange::UpdateZone(z) if z.id == zone.id))
    );
    // Re-importing the merged result creates nothing new for the same objects.
    let merged = plan.merged_into(&existing);
    let mut o = opts("assistant");
    o.existing = Some(&merged);
    let again = import(EXAMPLE, &o).unwrap();
    assert!(again.objects.is_empty(), "{:#?}", again.objects);
    assert!(again.rules.is_empty(), "{:#?}", again.rules);
    assert!(again.to_session_changes().is_empty());
    assert!(again.data_classes.is_empty());
    assert!(again.services.is_empty());
}

#[test]
fn session_changes_are_ordered_by_dependency() {
    let plan = import_example();
    let changes = plan.to_session_changes();
    let total =
        plan.objects.len() + plan.services.len() + plan.data_classes.len() + 1 + plan.rules.len();
    assert_eq!(changes.len(), total);
    let pos = |pred: &dyn Fn(&SessionChange) -> bool| changes.iter().position(pred).unwrap();
    let first_group = pos(
        &|c| matches!(c, SessionChange::CreateObject(o) if matches!(o.spec, NetObjectSpec::Group{..})),
    );
    let last_leaf = changes
        .iter()
        .rposition(|c| {
            matches!(c, SessionChange::CreateObject(o) if !matches!(o.spec, NetObjectSpec::Group{..}))
        })
        .unwrap();
    assert!(last_leaf < first_group);
    let zone = pos(&|c| matches!(c, SessionChange::CreateZone(_)));
    let first_rule = pos(&|c| matches!(c, SessionChange::CreateRule(_)));
    assert!(first_group < zone && zone < first_rule);
    let (method, path) = changes[first_rule].endpoint();
    assert_eq!((method, path), ("POST", "/rules".to_string()));
    let json = serde_json::to_value(&changes[0]).unwrap();
    assert!(json.get("op").is_some(), "{json}");
}

#[test]
fn markdown_report() {
    let plan = import_example();
    let md = plan.report.to_markdown();
    assert!(md.starts_with("# Rapport d'import egress-guard"));
    for needle in [
        "## Converti",
        "## Avertissements",
        "## Non converti",
        "observe",
        "EF-72",
        "senders",
    ] {
        assert!(md.contains(needle), "missing {needle}:\n{md}");
    }
}
