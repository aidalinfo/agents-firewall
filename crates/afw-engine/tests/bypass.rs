//! Bypass tests: every way a flow could slip past the policy. Written before the engine.

mod common;

use afw_core::events::Verdict;
use afw_core::policy::*;
use afw_engine::{CompileError, CompiledPolicy, DecisionLayer, Implicit};
use common::*;

const A: &str = "10.1.0.2";

fn allow_only(pattern: &str) -> afw_engine::CompiledPolicy {
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let d = b.domain(pattern);
    b.rule("allow", Layer::Zone { zone_id: z }, 1, &[d], Action::Accept);
    b.compile()
}

fn verdict(p: &afw_engine::CompiledPolicy, host: &str) -> Verdict {
    p.evaluate(&ctx(A, Some(host), Some("203.0.113.10"), 443)).verdict
}

#[test]
fn wildcard_domain_matching_edge_cases() {
    let p = allow_only("*.example.com");
    assert_eq!(verdict(&p, "a.example.com"), Verdict::Allow);
    assert_eq!(verdict(&p, "a.b.example.com"), Verdict::Allow);
    assert_eq!(verdict(&p, "API.Example.com."), Verdict::Allow);
    assert_eq!(verdict(&p, "example.com"), Verdict::Deny);
    assert_eq!(verdict(&p, "evil-example.com"), Verdict::Deny);
    assert_eq!(verdict(&p, "evilexample.com"), Verdict::Deny);
    assert_eq!(verdict(&p, "example.com.evil.net"), Verdict::Deny);
    assert_eq!(verdict(&p, "a.example.com.evil.net"), Verdict::Deny);
    assert_eq!(verdict(&p, ".example.com"), Verdict::Deny);
    assert_eq!(verdict(&p, "a..example.com"), Verdict::Deny);
    assert_eq!(verdict(&p, "*.example.com"), Verdict::Deny);
    assert_eq!(verdict(&p, "a.example.com.."), Verdict::Deny);
    assert_eq!(verdict(&p, "\u{0430}.example.com"), Verdict::Deny); // Cyrillic a: not ASCII
    assert_eq!(verdict(&p, ""), Verdict::Deny);

    let p = allow_only("Example.COM.");
    assert_eq!(verdict(&p, "example.com"), Verdict::Allow);
    assert_eq!(verdict(&p, "API.Example.com."), Verdict::Deny);
    assert_eq!(verdict(&p, "EXAMPLE.com."), Verdict::Allow);
    assert_eq!(verdict(&p, "a.example.com"), Verdict::Deny);
    assert_eq!(verdict(&p, "example.com.evil.net"), Verdict::Deny);
}

#[test]
fn domain_object_does_not_match_by_ip_and_ip_literal_host_is_an_address() {
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let meta = b.obj(
        "meta",
        NetObjectSpec::Host {
            ip: ip("169.254.169.254"),
        },
    );
    let any = b.obj("any", NetObjectSpec::Any);
    b.rule("no-meta", Layer::Baseline, 1, &[meta], Action::Deny);
    b.rule("all", Layer::Zone { zone_id: z }, 1, &[any], Action::Accept);
    let p = b.compile();
    // Explicit proxy: host is an IP literal and dst_ip is not resolved yet.
    let d = p.evaluate(&ctx(A, Some("169.254.169.254"), None, 80));
    assert_eq!(d.verdict, Verdict::Deny);
    let d = p.evaluate(&ctx(A, Some("[::ffff:169.254.169.254]"), None, 80));
    assert_eq!(d.verdict, Verdict::Deny, "IPv4-mapped IPv6 literal");
    let d = p.evaluate(&ctx(A, None, Some("::ffff:169.254.169.254"), 80));
    assert_eq!(d.verdict, Verdict::Deny, "IPv4-mapped IPv6 address");
}

#[test]
fn baseline_wins_over_zone_accept_all() {
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let bad = b.domain("*.pastebin.com");
    b.rule("deny-paste", Layer::Baseline, 5, &[bad], Action::Deny);
    b.rule("all", Layer::Zone { zone_id: z }, 1, &[], Action::Accept);
    let p = b.compile();
    let d = p.evaluate(&ctx(A, Some("x.pastebin.com"), Some("203.0.113.5"), 443));
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.layer, DecisionLayer::Baseline);
    assert_eq!(d.rule_number, Some(1));
    let d = p.evaluate(&ctx(A, Some("ok.com"), Some("203.0.113.5"), 443));
    assert_eq!(d.verdict, Verdict::Allow);
    assert_eq!(d.layer, DecisionLayer::Zone);
}

#[test]
fn http_path_normalization_cannot_escape_prefix() {
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let d = b.domain("api.example.com");
    let s = b.svc(
        L4Proto::Tcp,
        &[(443, 443)],
        Some(AppMatch {
            proto: AppProto::Https,
            methods: vec!["get".into()],
            path_prefixes: vec!["/v1/public".into()],
        }),
    );
    b.rule("pub", Layer::Zone { zone_id: z }, 1, &[d], Action::Accept)
        .services = vec![s];
    let p = b.compile();
    let h = "api.example.com";
    assert_eq!(p.evaluate(&http(A, h, "GET", "/v1/public/x")).verdict, Verdict::Allow);
    assert_eq!(p.evaluate(&http(A, h, "get", "/v1/public")).verdict, Verdict::Allow);
    assert_eq!(p.evaluate(&http(A, h, "GET", "/v1/public?q=1")).verdict, Verdict::Allow);
    for bad in [
        "/v1/public/../admin",
        "/v1/public/%2e%2e/admin",
        "/v1/public/%2E%2E/admin",
        "/v1/public/..%2fadmin",
        "/v1/public%2f..%2f..%2fadmin",
        "/v1/public/./../admin",
        "/v1/publicity",
        "/v1/public\\..\\admin",
        "//v1/public/../../admin",
        "/v1/public/%zz",
        "/v1/public/%00",
        "v1/public/x",
        "/V1/public/x",
    ] {
        assert_eq!(
            p.evaluate(&http(A, h, "GET", bad)).verdict,
            Verdict::Deny,
            "path {bad:?} must not match the prefix"
        );
    }
    assert_eq!(p.evaluate(&http(A, h, "POST", "/v1/public/x")).verdict, Verdict::Deny);
    assert_eq!(p.evaluate(&http(A, h, "GET ", "/v1/public/x")).verdict, Verdict::Deny);
    // `//` and `/./` collapse: still inside the prefix.
    assert_eq!(p.evaluate(&http(A, h, "GET", "/v1//public/./x")).verdict, Verdict::Allow);
}

#[test]
fn deny_on_path_cannot_be_dodged_by_encoding() {
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let d = b.domain("api.example.com");
    let admin = b.svc(
        L4Proto::Tcp,
        &[],
        Some(AppMatch {
            proto: AppProto::Https,
            methods: vec![],
            path_prefixes: vec!["/admin".into()],
        }),
    );
    b.rule("no-admin", Layer::Zone { zone_id: z }, 1, &[d], Action::Deny)
        .services = vec![admin];
    b.rule("rest", Layer::Zone { zone_id: z }, 2, &[d], Action::Accept);
    let p = b.compile();
    let h = "api.example.com";
    for bad in [
        "/admin",
        "/admin/users",
        "//admin",
        "/x/../admin",
        "/%61dmin",
        "/x/%2e%2e/admin/",
        "/./admin",
        "/admin/%zz",
        "/admin%00",
    ] {
        assert_eq!(
            p.evaluate(&http(A, h, "DELETE", bad)).verdict,
            Verdict::Deny,
            "path {bad:?} must hit the deny rule"
        );
    }
    assert_eq!(p.evaluate(&http(A, h, "GET", "/administrator")).verdict, Verdict::Allow);
    // A malformed path cannot satisfy an accept rule's prefix but does satisfy a deny rule's.
    assert_eq!(p.evaluate(&http(A, h, "GET", "/%zz")).verdict, Verdict::Deny);
}

#[test]
fn unknown_agent_is_denied_even_with_accept_all() {
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Observe);
    b.agent("bot", z, A);
    b.rule("all", Layer::Baseline, 1, &[], Action::Accept);
    let p = b.compile();
    let d = p.evaluate(&ctx("10.9.9.9", Some("example.com"), Some("203.0.113.1"), 443));
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.implicit, Some(Implicit::UnknownAgent));
    assert!(!d.observed);
    assert_eq!(d.agent_id, None);
}

#[test]
fn deny_all_policy_denies_everything() {
    let p = CompiledPolicy::deny_all();
    let d = p.evaluate(&ctx(A, Some("example.com"), Some("10.0.0.5"), 443));
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.implicit, Some(Implicit::NoPolicy));
    assert_eq!(p.revision(), None);
    assert!(p.resolve_agent(ip(A)).is_none());
    assert_eq!(d.deny_message("example.com"), "blocked by agents-firewall: example.com not allowed for unknown (rule no-policy)");
}

#[test]
fn cloud_metadata_stays_denied_in_observe_mode() {
    let mut b = B::new();
    let z = b.zone("lab", ZoneMode::Observe);
    b.agent("bot", z, A);
    let meta = b.obj_cat(
        "metadata",
        NetObjectSpec::Network {
            cidr: "169.254.169.254/32".parse().unwrap(),
        },
        Some(DestCategory::CloudMetadata),
    );
    b.rule("no-meta", Layer::Baseline, 1, &[meta], Action::Deny);
    let p = b.compile();
    let d = p.evaluate(&ctx(A, None, Some("169.254.169.254"), 80));
    assert_eq!(d.verdict, Verdict::Deny);
    assert!(!d.observed);
    // Observe mode still allows other denials.
    let d = p.evaluate(&ctx(A, Some("example.org"), Some("203.0.113.9"), 443));
    assert_eq!(d.verdict, Verdict::Allow);
    assert!(d.observed);
    assert_eq!(d.implicit, Some(Implicit::Cleanup));
}

#[test]
fn well_known_metadata_address_stays_denied_in_observe_without_any_rule() {
    let mut b = B::new();
    let z = b.zone("lab", ZoneMode::Observe);
    b.agent("bot", z, A);
    let p = b.compile();
    for dst in ["169.254.169.254", "fd00:ec2::254"] {
        let d = p.evaluate(&ctx(A, None, Some(dst), 80));
        assert_eq!(d.verdict, Verdict::Deny, "{dst}");
    }
    let d = p.evaluate(&ctx(A, Some("metadata.google.internal."), None, 80));
    assert_eq!(d.verdict, Verdict::Deny);
}

#[test]
fn tampered_policy_does_not_compile() {
    let b = B::new();
    let mut inst = b.installed();
    inst.revision += 1;
    assert!(matches!(
        CompiledPolicy::compile(&inst, now()),
        Err(CompileError::Integrity(_))
    ));
}

#[test]
fn zone_rule_must_have_its_zone_as_source() {
    let mut b = B::new();
    let z = b.zone("a", ZoneMode::Enforce);
    let z2 = b.zone("b", ZoneMode::Enforce);
    b.rule("r", Layer::Zone { zone_id: z }, 1, &[], Action::Accept).sources = vec![];
    assert!(matches!(
        CompiledPolicy::compile(&b.installed(), now()),
        Err(CompileError::ZoneRuleSource { .. })
    ));
    b.doc.rules[0].sources = vec![z2];
    assert!(matches!(
        CompiledPolicy::compile(&b.installed(), now()),
        Err(CompileError::ZoneRuleSource { .. })
    ));
    b.doc.rules[0].sources = vec![z];
    assert!(CompiledPolicy::compile(&b.installed(), now()).is_ok());
}

#[test]
fn group_cycle_and_dangling_references_are_rejected() {
    let mut b = B::new();
    let g1 = b.obj("g1", NetObjectSpec::Group { members: vec![] });
    let g2 = b.obj("g2", NetObjectSpec::Group { members: vec![g1] });
    b.doc.objects[0].spec = NetObjectSpec::Group { members: vec![g2] };
    assert!(matches!(
        CompiledPolicy::compile(&b.installed(), now()),
        Err(CompileError::GroupCycle(_))
    ));

    let mut b = B::new();
    b.rule("r", Layer::Baseline, 1, &[uuid::Uuid::new_v4()], Action::Deny);
    assert!(matches!(
        CompiledPolicy::compile(&b.installed(), now()),
        Err(CompileError::UnknownReference { .. })
    ));

    let mut b = B::new();
    b.agent("orphan", uuid::Uuid::new_v4(), A);
    assert!(matches!(
        CompiledPolicy::compile(&b.installed(), now()),
        Err(CompileError::UnknownZone { .. })
    ));
}

#[test]
fn ambiguous_agent_address_is_rejected() {
    let mut b = B::new();
    let z = b.zone("a", ZoneMode::Enforce);
    b.agent("one", z, A);
    b.agent("two", z, A);
    assert!(matches!(
        CompiledPolicy::compile(&b.installed(), now()),
        Err(CompileError::DuplicateAgentAddress(_))
    ));
}

#[test]
fn invalid_domain_pattern_is_rejected() {
    for bad in ["*", "a.*.com", "*example.com", "ex ample.com", "", "bücher.de", "a..b"] {
        let mut b = B::new();
        b.domain(bad);
        assert!(
            matches!(
                CompiledPolicy::compile(&b.installed(), now()),
                Err(CompileError::InvalidDomain { .. })
            ),
            "{bad:?}"
        );
    }
}

#[test]
fn llm_exemption_does_not_exempt_destination_rules() {
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let llm = b.obj_cat(
        "anthropic",
        NetObjectSpec::Domain {
            pattern: "api.anthropic.com".into(),
        },
        Some(DestCategory::LlmProvider),
    );
    let secret = b.class("secret");
    b.rule("no-secret", Layer::Baseline, 1, &[], Action::Deny).data_classes = vec![secret];
    b.rule("no-llm-here", Layer::Zone { zone_id: z }, 1, &[llm], Action::Deny);
    let p = b.compile();
    let mut c = ctx(A, Some("api.anthropic.com"), Some("203.0.113.7"), 443);
    c.data_classes = vec![secret];
    let d = p.evaluate(&c);
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rule_name, "no-llm-here");
    assert!(d.llm_provider);
}
