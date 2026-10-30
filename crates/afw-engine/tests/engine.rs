//! Behaviour tests of the engine: evaluation order, matching, flags, verification, where-used.

mod common;

use std::time::Instant;

use afw_core::api::VerifyFinding;
use afw_core::events::Verdict;
use afw_core::policy::*;
use afw_engine::{
    CompiledPolicy, DecisionLayer, Implicit, TraceOutcome, VerifyWarning, verify, verify_warnings,
    where_used,
};
use chrono::Duration;
use common::*;
use uuid::Uuid;

const A: &str = "10.1.0.2";
const OTHER: &str = "10.1.0.3";

fn base() -> (B, Uuid) {
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("daniel-bot", z, A);
    (b, z)
}

#[test]
fn first_match_wins_in_position_order() {
    let (mut b, z) = base();
    let d = b.domain("api.example.com");
    // Inserted out of order: position decides, not insertion order.
    b.rule("second", Layer::Zone { zone_id: z }, 20, &[d], Action::Deny);
    b.rule(
        "first",
        Layer::Zone { zone_id: z },
        10,
        &[d],
        Action::Accept,
    );
    let p = b.compile();
    let dec = p.evaluate(&ctx(A, Some("api.example.com"), Some("203.0.113.1"), 443));
    assert_eq!(dec.verdict, Verdict::Allow);
    assert_eq!(dec.rule_name, "first");
    assert_eq!(dec.rule_number, Some(1));
    assert_eq!(dec.agent_name.as_deref(), Some("daniel-bot"));
    assert_eq!(dec.zone_name.as_deref(), Some("prod"));
    assert_eq!(dec.track, Track::Log);
    assert_eq!(p.revision(), Some(7));
}

#[test]
fn cleanup_denies_and_message_is_exact() {
    let (mut b, z) = base();
    let d = b.domain("api.example.com");
    b.rule("deny-it", Layer::Zone { zone_id: z }, 1, &[d], Action::Deny);
    let p = b.compile();
    let dec = p.evaluate(&ctx(A, Some("api.example.com"), Some("203.0.113.1"), 443));
    assert_eq!(dec.verdict, Verdict::Deny);
    assert_eq!(
        dec.deny_message("api.example.com"),
        "blocked by agents-firewall: api.example.com not allowed for daniel-bot (rule 1)"
    );
    let r = dec.to_ref();
    assert_eq!(r.rule_number, Some(1));
    assert_eq!(r.revision, Some(7));
    assert_eq!(r.layer, "zone");

    let dec = p.evaluate(&ctx(A, Some("other.com"), Some("203.0.113.2"), 443));
    assert_eq!(dec.verdict, Verdict::Deny);
    assert_eq!(dec.implicit, Some(Implicit::Cleanup));
    assert_eq!(dec.layer, DecisionLayer::Implicit);
    assert_eq!(dec.rule_id, None);
    assert_eq!(
        dec.deny_message("other.com"),
        "blocked by agents-firewall: other.com not allowed for daniel-bot (rule default-deny)"
    );
    assert_eq!(dec.to_ref().layer, "implicit");

    let dec = p.evaluate(&ctx("10.7.7.7", Some("x.com"), None, 443));
    assert_eq!(
        dec.deny_message("x.com"),
        "blocked by agents-firewall: x.com not allowed for unknown (rule unknown-agent)"
    );
}

#[test]
fn expired_and_disabled_rules_are_ignored() {
    let (mut b, z) = base();
    let d = b.domain("api.example.com");
    b.rule(
        "expired",
        Layer::Zone { zone_id: z },
        1,
        &[d],
        Action::Accept,
    )
    .expires_at = Some(now() - Duration::hours(1));
    b.rule(
        "disabled",
        Layer::Zone { zone_id: z },
        2,
        &[d],
        Action::Accept,
    )
    .enabled = false;
    b.rule(
        "future",
        Layer::Zone { zone_id: z },
        3,
        &[d],
        Action::Accept,
    )
    .expires_at = Some(now() + Duration::hours(1));
    let p = b.compile();
    let mut c = ctx(A, Some("api.example.com"), Some("203.0.113.1"), 443);
    let dec = p.evaluate(&c);
    assert_eq!(dec.rule_name, "future");
    assert_eq!(dec.rule_number, Some(3));
    let outcomes: Vec<_> = dec.trace.iter().map(|s| s.outcome).collect();
    assert_eq!(
        outcomes,
        vec![
            TraceOutcome::Expired,
            TraceOutcome::Disabled,
            TraceOutcome::Matched
        ]
    );
    // The rule expires while the policy is active.
    c.now = now() + Duration::hours(2);
    assert_eq!(p.evaluate(&c).implicit, Some(Implicit::Cleanup));
}

#[test]
fn cidr_and_range_ipv4_ipv6() {
    let (mut b, z) = base();
    let net4 = b.obj(
        "n4",
        NetObjectSpec::Network {
            cidr: "198.51.100.0/24".parse().unwrap(),
        },
    );
    let net6 = b.obj(
        "n6",
        NetObjectSpec::Network {
            cidr: "2001:db8::/32".parse().unwrap(),
        },
    );
    let r4 = b.obj(
        "r4",
        NetObjectSpec::Range {
            start: ip("203.0.113.10"),
            end: ip("203.0.113.20"),
        },
    );
    let r6 = b.obj(
        "r6",
        NetObjectSpec::Range {
            start: ip("2001:db9::1"),
            end: ip("2001:db9::ff"),
        },
    );
    let h = b.obj(
        "h",
        NetObjectSpec::Host {
            ip: ip("192.0.2.1"),
        },
    );
    b.rule(
        "ok",
        Layer::Zone { zone_id: z },
        1,
        &[net4, net6, r4, r6, h],
        Action::Accept,
    );
    let p = b.compile();
    let v = |dst: &str| p.evaluate(&ctx(A, None, Some(dst), 443)).verdict;
    for ok in [
        "198.51.100.0",
        "198.51.100.255",
        "2001:db8::1",
        "2001:db8:ffff::1",
        "203.0.113.10",
        "203.0.113.20",
        "2001:db9::1",
        "2001:db9::ff",
        "192.0.2.1",
    ] {
        assert_eq!(v(ok), Verdict::Allow, "{ok}");
    }
    for ko in [
        "198.51.101.0",
        "2001:db7::1",
        "203.0.113.9",
        "203.0.113.21",
        "2001:db9::100",
        "192.0.2.2",
        "::",
    ] {
        assert_eq!(v(ko), Verdict::Deny, "{ko}");
    }
    // A host name alone does not match address objects.
    assert_eq!(
        p.evaluate(&ctx(A, Some("example.com"), None, 443)).verdict,
        Verdict::Deny
    );
}

#[test]
fn services_match_protocol_and_ports() {
    let (mut b, z) = base();
    let ssh = b.svc(L4Proto::Tcp, &[(22, 22), (2200, 2299)], None);
    let dns = b.svc(L4Proto::Udp, &[(53, 53)], None);
    b.rule("ok", Layer::Zone { zone_id: z }, 1, &[], Action::Accept)
        .services = vec![ssh, dns];
    let p = b.compile();
    let mut c = ctx(A, None, Some("203.0.113.1"), 22);
    assert_eq!(p.evaluate(&c).verdict, Verdict::Allow);
    c.dst_port = 2250;
    assert_eq!(p.evaluate(&c).verdict, Verdict::Allow);
    c.dst_port = 2300;
    assert_eq!(p.evaluate(&c).verdict, Verdict::Deny);
    c.dst_port = 53;
    assert_eq!(p.evaluate(&c).verdict, Verdict::Deny);
    c.l4 = L4Proto::Udp;
    assert_eq!(p.evaluate(&c).verdict, Verdict::Allow);
}

#[test]
fn observe_mode_turns_denials_into_observed_allows() {
    let mut b = B::new();
    let z = b.zone("lab", ZoneMode::Observe);
    b.agent("bot", z, A);
    let d = b.domain("blocked.com");
    b.rule("no", Layer::Zone { zone_id: z }, 1, &[d], Action::Deny);
    let p = b.compile();
    let dec = p.evaluate(&ctx(A, Some("blocked.com"), Some("203.0.113.1"), 443));
    assert_eq!(dec.verdict, Verdict::Allow);
    assert!(dec.observed);
    assert_eq!(dec.rule_name, "no");
    assert!(dec.to_ref().reason.contains("observe"));
}

#[test]
fn llm_provider_skips_data_class_rules_and_sets_flag() {
    let (mut b, z) = base();
    let llm = b.obj_cat(
        "llm",
        NetObjectSpec::Group { members: vec![] },
        Some(DestCategory::LlmProvider),
    );
    let anthropic = b.domain("api.anthropic.com");
    let openai = b.domain("*.openai.com");
    b.doc.objects[0].spec = NetObjectSpec::Group {
        members: vec![anthropic, openai],
    };
    let secret = b.class("secret");
    b.rule("no-secret", Layer::Baseline, 1, &[], Action::Deny)
        .data_classes = vec![secret];
    b.rule("all", Layer::Zone { zone_id: z }, 1, &[], Action::Accept);
    let p = b.compile();
    assert!(p.is_llm_provider(Some("API.openai.com."), None));
    assert!(!p.is_llm_provider(Some("openai.com"), None));
    let _ = llm;

    let mut c = ctx(A, Some("api.anthropic.com"), Some("203.0.113.7"), 443);
    c.data_classes = vec![secret];
    let dec = p.evaluate(&c);
    assert_eq!(dec.verdict, Verdict::Allow);
    assert!(dec.llm_provider);
    assert!(
        dec.trace
            .iter()
            .any(|s| s.outcome == TraceOutcome::LlmExempt)
    );

    let mut c = ctx(A, Some("paste.example.net"), Some("203.0.113.8"), 443);
    c.data_classes = vec![secret];
    let dec = p.evaluate(&c);
    assert_eq!(dec.verdict, Verdict::Deny);
    assert_eq!(dec.rule_name, "no-secret");
    assert!(!dec.llm_provider);
    // Without detected classes the content rule does not match.
    c.data_classes.clear();
    assert_eq!(p.evaluate(&c).verdict, Verdict::Allow);
    assert_eq!(p.data_class_specs().len(), 1);
}

#[test]
fn internal_flows_are_monitored_and_allowed_by_default() {
    let (mut b, z) = base();
    b.agent("peer", z, OTHER);
    let p = b.compile();
    let dec = p.evaluate(&ctx(A, None, Some("192.168.1.10"), 5432));
    assert_eq!(dec.verdict, Verdict::Allow);
    assert_eq!(dec.implicit, Some(Implicit::InternalMonitor));
    assert_eq!(dec.track, Track::Detailed);
    assert!(dec.internal);
    // Another agent counts as internal even outside internal_networks.
    let mut b2 = B::new();
    let z2 = b2.zone("prod", ZoneMode::Enforce);
    b2.agent("a", z2, "100.64.0.2");
    b2.agent("b", z2, "100.64.0.3");
    let p2 = b2.compile();
    let dec = p2.evaluate(&ctx("100.64.0.2", None, Some("100.64.0.3"), 80));
    assert_eq!(dec.implicit, Some(Implicit::InternalMonitor));
    let dec = p2.evaluate(&ctx("100.64.0.2", None, Some("100.64.0.9"), 80));
    assert_eq!(dec.implicit, Some(Implicit::Cleanup));
    assert!(p2.resolve_agent(ip("100.64.0.3")).is_some());
}

#[test]
fn zone_rule_can_deny_internal_flow() {
    let (mut b, z) = base();
    let db = b.obj(
        "db",
        NetObjectSpec::Host {
            ip: ip("192.168.1.10"),
        },
    );
    let pg = b.svc(L4Proto::Tcp, &[(5432, 5432)], None);
    b.rule("no-db", Layer::Zone { zone_id: z }, 1, &[db], Action::Deny)
        .services = vec![pg];
    let p = b.compile();
    let dec = p.evaluate(&ctx(A, None, Some("192.168.1.10"), 5432));
    assert_eq!(dec.verdict, Verdict::Deny);
    assert!(dec.internal);
    assert_eq!(dec.rule_name, "no-db");
}

#[test]
fn nested_groups_resolve() {
    let (mut b, z) = base();
    let a = b.domain("a.com");
    let inner = b.obj("inner", NetObjectSpec::Group { members: vec![a] });
    let net = b.obj(
        "net",
        NetObjectSpec::Network {
            cidr: "198.51.100.0/24".parse().unwrap(),
        },
    );
    let outer = b.obj(
        "outer",
        NetObjectSpec::Group {
            members: vec![inner, net, inner],
        },
    );
    b.rule(
        "ok",
        Layer::Zone { zone_id: z },
        1,
        &[outer],
        Action::Accept,
    );
    let p = b.compile();
    assert_eq!(
        p.evaluate(&ctx(A, Some("a.com"), None, 443)).verdict,
        Verdict::Allow
    );
    assert_eq!(
        p.evaluate(&ctx(A, None, Some("198.51.100.4"), 443)).verdict,
        Verdict::Allow
    );
    assert_eq!(
        p.evaluate(&ctx(A, Some("b.com"), None, 443)).verdict,
        Verdict::Deny
    );
}

#[test]
fn inspection_rules_first_match_default_inspect() {
    let (mut b, z) = base();
    let pinned = b.domain("pinned.example.com");
    let all = b.obj("any", NetObjectSpec::Any);
    b.doc.inspection_rules.push(InspectionRule {
        id: Uuid::new_v4(),
        name: "bypass-pinned".into(),
        position: 2,
        zones: vec![z],
        destinations: vec![pinned],
        action: InspectionAction::Bypass,
    });
    b.doc.inspection_rules.push(InspectionRule {
        id: Uuid::new_v4(),
        name: "inspect-first".into(),
        position: 1,
        zones: vec![Uuid::new_v4()],
        destinations: vec![all],
        action: InspectionAction::Inspect,
    });
    // Unknown zone id in an inspection rule is a dangling reference.
    assert!(CompiledPolicy::compile(&b.installed(), now()).is_err());
    b.doc.inspection_rules[1].zones = vec![z];
    b.doc.inspection_rules[1].destinations = vec![pinned];
    b.doc.inspection_rules[1].position = 3;
    let p = b.compile();
    assert!(
        !p.evaluate(&ctx(A, Some("pinned.example.com"), None, 443))
            .inspect_tls
    );
    assert!(
        p.evaluate(&ctx(A, Some("other.example.com"), None, 443))
            .inspect_tls
    );
}

#[test]
fn trace_lists_examined_rules() {
    let (mut b, z) = base();
    let d = b.domain("a.com");
    let s = b.svc(L4Proto::Udp, &[], None);
    let c = b.class("secret");
    b.rule("base", Layer::Baseline, 1, &[d], Action::Deny)
        .services = vec![s];
    b.rule("cls", Layer::Zone { zone_id: z }, 1, &[], Action::Deny)
        .data_classes = vec![c];
    b.rule("dst", Layer::Zone { zone_id: z }, 2, &[d], Action::Accept);
    let p = b.compile();
    let dec = p.evaluate(&ctx(A, Some("b.com"), None, 443));
    let outcomes: Vec<_> = dec.trace.iter().map(|s| (s.layer, s.outcome)).collect();
    assert_eq!(
        outcomes,
        vec![
            (DecisionLayer::Baseline, TraceOutcome::DestinationMismatch),
            (DecisionLayer::Zone, TraceOutcome::DataClassMismatch),
            (DecisionLayer::Zone, TraceOutcome::DestinationMismatch),
        ]
    );
    let dec = p.evaluate(&ctx(A, Some("a.com"), None, 443));
    assert_eq!(dec.trace[0].outcome, TraceOutcome::ServiceMismatch);
    assert_eq!(dec.trace.last().unwrap().outcome, TraceOutcome::Matched);
    assert_eq!(dec.trace.last().unwrap().rule_number, Some(3));
}

#[test]
fn baseline_sources_restrict_zones() {
    let (mut b, z) = base();
    let other = b.zone("other", ZoneMode::Enforce);
    b.rule("only-other", Layer::Baseline, 1, &[], Action::Deny)
        .sources = vec![other];
    b.rule("all", Layer::Zone { zone_id: z }, 1, &[], Action::Accept);
    let p = b.compile();
    let dec = p.evaluate(&ctx(A, Some("x.com"), None, 443));
    assert_eq!(dec.verdict, Verdict::Allow);
    assert_eq!(dec.trace[0].outcome, TraceOutcome::SourceMismatch);
}

// ------------------------------------------------------------------------------- verify

#[test]
fn verify_finds_shadowed_rule() {
    let (mut b, z) = base();
    let wide = b.domain("*.example.com");
    let narrow = b.domain("api.example.com");
    let https = b.svc(L4Proto::Tcp, &[(443, 443)], None);
    let r1 = b
        .rule(
            "wide",
            Layer::Zone { zone_id: z },
            1,
            &[wide],
            Action::Accept,
        )
        .id;
    let r2 = {
        let r = b.rule(
            "narrow",
            Layer::Zone { zone_id: z },
            2,
            &[narrow],
            Action::Deny,
        );
        r.services = vec![https];
        r.id
    };
    let f = verify(&b.doc, now());
    assert!(
        f.contains(&VerifyFinding::Shadowed { rule: r2, by: r1 }),
        "{f:?}"
    );
}

#[test]
fn verify_no_false_shadow_with_content_condition_or_narrower_service() {
    let (mut b, z) = base();
    let wide = b.domain("*.example.com");
    let narrow = b.domain("api.example.com");
    let secret = b.class("secret");
    let https = b.svc(L4Proto::Tcp, &[(443, 443)], None);
    b.rule(
        "content",
        Layer::Zone { zone_id: z },
        1,
        &[wide],
        Action::Deny,
    )
    .data_classes = vec![secret];
    b.rule("svc", Layer::Zone { zone_id: z }, 2, &[wide], Action::Deny)
        .services = vec![https];
    b.rule(
        "narrow",
        Layer::Zone { zone_id: z },
        3,
        &[narrow],
        Action::Accept,
    );
    // Different layer never shadows.
    b.rule("base-exact", Layer::Baseline, 1, &[], Action::Deny)
        .data_classes = vec![secret];
    let f = verify(&b.doc, now());
    assert!(
        !f.iter()
            .any(|x| matches!(x, VerifyFinding::Shadowed { .. })),
        "{f:?}"
    );
}

#[test]
fn verify_reports_unused_and_expired_and_warnings() {
    let (mut b, z) = base();
    let used = b.domain("used.com");
    let unused = b.domain("unused.com");
    let member = b.domain("member.com");
    let group = b.obj(
        "g",
        NetObjectSpec::Group {
            members: vec![member],
        },
    );
    let unused_svc = b.svc(L4Proto::Tcp, &[], None);
    let unused_cls = b.class("c");
    let empty = b.zone("empty", ZoneMode::Enforce);
    let _ = empty;
    let exp = b.rule(
        "old",
        Layer::Zone { zone_id: z },
        1,
        &[used, group],
        Action::Accept,
    );
    exp.expires_at = Some(now() - Duration::days(1));
    let exp = exp.id;
    let f = verify(&b.doc, now());
    assert!(f.contains(&VerifyFinding::Expired { rule: exp }));
    assert!(f.contains(&VerifyFinding::UnusedObject { id: unused }));
    assert!(f.contains(&VerifyFinding::UnusedObject { id: unused_svc }));
    assert!(f.contains(&VerifyFinding::UnusedObject { id: unused_cls }));
    assert!(!f.contains(&VerifyFinding::UnusedObject { id: used }));
    assert!(!f.contains(&VerifyFinding::UnusedObject { id: member }));

    let w = verify_warnings(&b.doc);
    assert!(w.contains(&VerifyWarning::ZoneWithoutAgent { zone: empty }));
    assert!(w.contains(&VerifyWarning::NoCloudMetadataBaselineRule));

    let meta = b.obj_cat(
        "meta",
        NetObjectSpec::Host {
            ip: ip("169.254.169.254"),
        },
        Some(DestCategory::CloudMetadata),
    );
    b.rule("no-meta", Layer::Baseline, 1, &[meta], Action::Deny);
    assert!(!verify_warnings(&b.doc).contains(&VerifyWarning::NoCloudMetadataBaselineRule));
}

#[test]
fn where_used_reports_direct_and_group_usage() {
    let (mut b, z) = base();
    let leaf = b.domain("leaf.com");
    let g = b.obj(
        "g",
        NetObjectSpec::Group {
            members: vec![leaf],
        },
    );
    let outer = b.obj("outer", NetObjectSpec::Group { members: vec![g] });
    let direct = b
        .rule(
            "direct",
            Layer::Zone { zone_id: z },
            1,
            &[leaf],
            Action::Accept,
        )
        .id;
    let via = b
        .rule(
            "via",
            Layer::Zone { zone_id: z },
            2,
            &[outer],
            Action::Accept,
        )
        .id;
    let insp = Uuid::new_v4();
    b.doc.inspection_rules.push(InspectionRule {
        id: insp,
        name: "i".into(),
        position: 1,
        zones: vec![],
        destinations: vec![g],
        action: InspectionAction::Bypass,
    });
    let u = where_used(&b.doc, leaf);
    let ids: Vec<_> = u.iter().map(|x| x.id).collect();
    assert!(ids.contains(&direct));
    assert!(ids.contains(&via));
    assert!(ids.contains(&insp));
    assert!(ids.contains(&g));
    assert!(ids.contains(&outer));
    let via_usage = u.iter().find(|x| x.id == via).unwrap();
    assert_eq!(via_usage.via, Some(outer));
    assert_eq!(u.iter().find(|x| x.id == direct).unwrap().via, None);
    assert_eq!(via_usage.to_ref().kind, afw_core::api::ResourceKind::Rule);
    assert!(where_used(&b.doc, Uuid::new_v4()).is_empty());
}

#[test]
fn verify_and_where_used_survive_group_cycles() {
    let mut b = B::new();
    let g1 = b.obj("g1", NetObjectSpec::Group { members: vec![] });
    let g2 = b.obj("g2", NetObjectSpec::Group { members: vec![g1] });
    b.doc.objects[0].spec = NetObjectSpec::Group { members: vec![g2] };
    b.rule("r", Layer::Baseline, 1, &[g1], Action::Deny);
    let _ = verify(&b.doc, now());
    let _ = where_used(&b.doc, g1);
}

// ------------------------------------------------------------------------------- bench

#[test]
#[ignore = "benchmark: run with --ignored --nocapture"]
fn bench_2000_rules_10000_objects() {
    let mut b = B::new();
    let mut zones = vec![];
    for i in 0..10 {
        let z = b.zone(&format!("z{i}"), ZoneMode::Enforce);
        b.agent(&format!("a{i}"), z, &format!("10.2.0.{}", i + 1));
        zones.push(z);
    }
    let mut objs = vec![];
    for i in 0..10_000u32 {
        let id = if i % 2 == 0 {
            b.domain(&format!("h{i}.example{}.com", i % 97))
        } else {
            b.obj(
                "n",
                NetObjectSpec::Host {
                    ip: std::net::IpAddr::from([198, 18, (i >> 8) as u8, i as u8]),
                },
            )
        };
        objs.push(id);
    }
    let https = b.svc(L4Proto::Tcp, &[(443, 443)], None);
    for i in 0..2000usize {
        let layer = if i < 200 {
            Layer::Baseline
        } else {
            Layer::Zone {
                zone_id: zones[i % 10],
            }
        };
        let dsts = objs[(i * 5) % 10_000..(i * 5) % 10_000 + 5].to_vec();
        b.rule(&format!("r{i}"), layer, i as u32, &dsts, Action::Accept)
            .services = vec![https];
    }
    let p = b.compile();
    let c = ctx(
        "10.2.0.1",
        Some("nomatch.example.org"),
        Some("203.0.113.1"),
        443,
    );
    let mut samples = Vec::with_capacity(20_000);
    for _ in 0..20_000 {
        let t = Instant::now();
        let d = p.evaluate(&c);
        samples.push(t.elapsed().as_nanos() as u64);
        assert_eq!(d.verdict, Verdict::Deny);
    }
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2] as f64 / 1000.0;
    let p99 = samples[samples.len() * 99 / 100] as f64 / 1000.0;
    println!(
        "evaluate (worst case, no match, 2000 rules / 10000 objects): p50 = {p50:.1} µs, p99 = {p99:.1} µs"
    );
}

// ------------------------------------------------------------------------------- review follow-ups

#[test]
fn trusted_destination_ip_grants_address_accepts() {
    let (mut b, z) = base();
    let n = b.obj(
        "partner",
        NetObjectSpec::Network {
            cidr: "203.0.113.0/24".parse().unwrap(),
        },
    );
    b.rule(
        "partner",
        Layer::Zone { zone_id: z },
        1,
        &[n],
        Action::Accept,
    );
    let p = b.compile();
    let mut c = ctx(A, Some("api.partner.example"), Some("203.0.113.7"), 443);
    assert_eq!(p.evaluate(&c).verdict, Verdict::Deny);
    c.dst_ip_trusted = true;
    assert_eq!(p.evaluate(&c).verdict, Verdict::Allow);
    // Internal monitor only on a trusted address.
    let mut c = ctx(A, Some("db.internal.example"), Some("10.9.9.9"), 5432);
    assert_eq!(p.evaluate(&c).implicit, Some(Implicit::Cleanup));
    c.dst_ip_trusted = true;
    assert_eq!(p.evaluate(&c).implicit, Some(Implicit::InternalMonitor));
}

#[test]
fn deny_by_address_applies_even_when_untrusted() {
    let (mut b, z) = base();
    let n = b.obj(
        "bad",
        NetObjectSpec::Network {
            cidr: "198.51.100.0/24".parse().unwrap(),
        },
    );
    b.rule("bad", Layer::Zone { zone_id: z }, 1, &[n], Action::Deny);
    b.rule("all", Layer::Zone { zone_id: z }, 2, &[], Action::Accept);
    let p = b.compile();
    let c = ctx(A, Some("good.example"), Some("198.51.100.9"), 443);
    assert_eq!(p.evaluate(&c).rule_name, "bad");
}

#[test]
fn metadata_needs_an_explicit_accept() {
    let (mut b, z) = base();
    let meta = b.obj_cat(
        "meta",
        NetObjectSpec::Host {
            ip: ip("169.254.169.254"),
        },
        Some(DestCategory::CloudMetadata),
    );
    b.rule("all", Layer::Zone { zone_id: z }, 1, &[], Action::Accept);
    let p = b.compile();
    let d = p.evaluate(&ctx(A, None, Some("169.254.169.254"), 80));
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.trace[0].outcome, TraceOutcome::MetadataProtected);
    b.rule(
        "meta-ok",
        Layer::Zone { zone_id: z },
        0,
        &[meta],
        Action::Accept,
    );
    let p = b.compile();
    assert_eq!(
        p.evaluate(&ctx(A, None, Some("169.254.169.254"), 80))
            .verdict,
        Verdict::Allow
    );
}

#[test]
fn needs_l7_at_connection_stage() {
    let (mut b, z) = base();
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
    b.rule(
        "no-admin",
        Layer::Zone { zone_id: z },
        1,
        &[d],
        Action::Deny,
    )
    .services = vec![admin];
    b.rule("rest", Layer::Zone { zone_id: z }, 2, &[d], Action::Accept);
    let p = b.compile();
    let mut c = ctx(A, Some("api.example.com"), None, 443);
    c.app = Some(AppProto::Https);
    let dec = p.evaluate(&c);
    assert_eq!(dec.verdict, Verdict::Allow);
    assert!(
        dec.needs_l7,
        "the deny on /admin must be checked per request"
    );
    assert_eq!(dec.trace[0].outcome, TraceOutcome::NeedsL7);
    assert!(dec.to_ref().reason.contains("L7"));

    // TLS not inspected: requests will never be seen, the deny-by-path applies to the connection.
    b.doc.inspection_rules.push(InspectionRule {
        id: Uuid::new_v4(),
        name: "bypass".into(),
        position: 1,
        zones: vec![],
        destinations: vec![d],
        action: InspectionAction::Bypass,
    });
    let p = b.compile();
    let mut c = ctx(A, Some("api.example.com"), None, 443);
    c.app = Some(AppProto::Https);
    let dec = p.evaluate(&c);
    assert_eq!(dec.verdict, Verdict::Deny);
    assert!(!dec.needs_l7);
}

#[test]
fn verify_empty_group_is_not_shadowed() {
    let (mut b, z) = base();
    let empty = b.obj("empty", NetObjectSpec::Group { members: vec![] });
    let a = b.domain("a.com");
    b.rule("a", Layer::Zone { zone_id: z }, 1, &[a], Action::Accept);
    b.rule("e", Layer::Zone { zone_id: z }, 2, &[empty], Action::Accept);
    assert!(
        !verify(&b.doc, now())
            .iter()
            .any(|f| matches!(f, VerifyFinding::Shadowed { .. }))
    );
}

#[test]
fn content_rules_apply_flags_uninspectable_flows() {
    let (mut b, z) = base();
    let api = b.domain("api.example.com");
    let other = b.domain("other.example.com");
    let llm = b.obj_cat(
        "llm",
        NetObjectSpec::Domain { pattern: "llm.example.com".into() },
        Some(DestCategory::LlmProvider),
    );
    let secrets = b.class("secrets");
    b.rule("no secrets to api", Layer::Baseline, 1, &[api], Action::Deny).data_classes = vec![secrets];
    b.rule("all", Layer::Zone { zone_id: z }, 1, &[], Action::Accept);
    let p = b.compile();

    // Raw TCP to api: accepted, but a deny-by-content rule above could apply and the content
    // will never be seen.
    let dec = p.evaluate(&ctx(A, Some("api.example.com"), None, 22));
    assert_eq!(dec.verdict, Verdict::Allow);
    assert!(dec.content_rules_apply);
    // Other destination: the content rule cannot target it.
    let dec = p.evaluate(&ctx(A, Some("other.example.com"), None, 22));
    assert!(!dec.content_rules_apply);
    let _ = other;
    // LLM provider: data-class rules are skipped (EF-25).
    b.rule("no secrets anywhere", Layer::Baseline, 2, &[], Action::Deny).data_classes = vec![secrets];
    let p = b.compile();
    let dec = p.evaluate(&ctx(A, Some("llm.example.com"), None, 22));
    assert!(!dec.content_rules_apply);
    let _ = llm;
    // Request stage with content already analysed: not set.
    let mut c = http(A, "other.example.com", "POST", "/x");
    c.data_classes = vec![];
    let dec = p.evaluate(&c);
    assert!(!dec.content_rules_apply);
    // A deny-by-content rule BELOW the deciding rule does not count.
    let (mut b, z) = base();
    let api = b.domain("api.example.com");
    let secrets = b.class("secrets");
    b.rule("allow api", Layer::Baseline, 1, &[api], Action::Accept);
    b.rule("no secrets", Layer::Zone { zone_id: z }, 1, &[], Action::Deny).data_classes = vec![secrets];
    let p = b.compile();
    assert!(!p.evaluate(&ctx(A, Some("api.example.com"), None, 22)).content_rules_apply);
}
