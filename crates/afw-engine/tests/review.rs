//! Independent review tests of PR #10. Each `rv_*` test asserts the safe behaviour.
mod common;
use afw_core::events::Verdict;
use afw_core::policy::*;
use afw_engine::Implicit;
use common::*;

const A: &str = "10.0.0.2";

fn path_policy(action_admin: Action) -> (afw_engine::CompiledPolicy, &'static str) {
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let d = b.domain("api.example.com");
    let s = b.svc(
        L4Proto::Tcp,
        &[],
        Some(AppMatch {
            proto: AppProto::Https,
            methods: vec![],
            path_prefixes: vec![if action_admin == Action::Deny {
                "/admin".into()
            } else {
                "/public".into()
            }],
        }),
    );
    b.rule("r1", Layer::Zone { zone_id: z }, 1, &[d], action_admin)
        .services = vec![s];
    if action_admin == Action::Deny {
        b.rule("rest", Layer::Zone { zone_id: z }, 2, &[d], Action::Accept);
    }
    (b.compile(), "api.example.com")
}

// 1. `;` path parameters / matrix params dodge a Deny on /admin (Tomcat, Spring, Jetty strip `;...`).
#[test]
fn rv_semicolon_dodges_deny_path() {
    let (p, h) = path_policy(Action::Deny);
    for bad in ["/admin;x", "/admin;/users", "/x/..;/admin"] {
        assert_eq!(
            p.evaluate(&http(A, h, "GET", bad)).verdict,
            Verdict::Deny,
            "{bad}"
        );
    }
}

// 2. `..;` escapes an Accept prefix on Tomcat-like back ends.
#[test]
fn rv_dotdot_semicolon_escapes_accept_prefix() {
    let (p, h) = path_policy(Action::Accept);
    assert_eq!(
        p.evaluate(&http(A, h, "GET", "/public/..;/admin")).verdict,
        Verdict::Deny
    );
}

// 3. Double encoding escapes an Accept prefix on a back end that decodes twice.
#[test]
fn rv_double_encoding_escapes_accept_prefix() {
    let (p, h) = path_policy(Action::Accept);
    assert_eq!(
        p.evaluate(&http(A, h, "GET", "/public/%252e%252e/admin"))
            .verdict,
        Verdict::Deny
    );
}

// 4. Numeric host forms (inet_aton) are names for the engine: a baseline Deny on the
//    metadata IP does not apply when dst_ip is not yet known.
#[test]
fn rv_numeric_host_forms_are_not_names() {
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let md = b.obj_cat(
        "md",
        NetObjectSpec::Host {
            ip: ip("169.254.169.254"),
        },
        Some(DestCategory::CloudMetadata),
    );
    b.rule("no-md", Layer::Baseline, 1, &[md], Action::Deny);
    b.rule("all", Layer::Zone { zone_id: z }, 1, &[], Action::Accept);
    let p = b.compile();
    for h in [
        "2852039166",
        "0xa9fea9fe",
        "0251.0376.0251.0376",
        "169.254.43518",
        "0xa9.0xfe.0xa9.0xfe",
    ] {
        assert_eq!(
            p.evaluate(&ctx(A, Some(h), None, 80)).verdict,
            Verdict::Deny,
            "{h}"
        );
    }
}

// 5. Transparent mode: agent connects to an internal IP but announces an Internet SNI/Host.
//    The gateway connects upstream to the NAME (plan L6) => implicit internal allow reaches the Internet.
#[test]
fn rv_internal_ip_with_external_name_is_not_internal_monitor() {
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let p = b.compile();
    let d = p.evaluate(&ctx(
        A,
        Some("exfil.attacker.example"),
        Some("10.9.9.9"),
        443,
    ));
    assert_eq!(d.verdict, Verdict::Deny, "implicit={:?}", d.implicit);
}

// 6. Same with an explicit Accept on an IP object: SNI is ignored when the IP matches.
#[test]
fn rv_accept_on_ip_object_does_not_cover_foreign_name() {
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
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
    assert_eq!(
        p.evaluate(&ctx(
            A,
            Some("exfil.attacker.example"),
            Some("203.0.113.7"),
            443
        ))
        .verdict,
        Verdict::Deny
    );
}

// 7. Explicit Accept on a DOMAIN whose DNS (attacker-controlled) points at the metadata IP.
#[test]
fn rv_accept_domain_resolving_to_metadata_ip() {
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let d = b.domain("*.attacker.example");
    b.rule("ok", Layer::Zone { zone_id: z }, 1, &[d], Action::Accept);
    let p = b.compile();
    assert_eq!(
        p.evaluate(&ctx(
            A,
            Some("md.attacker.example"),
            Some("169.254.169.254"),
            80
        ))
        .verdict,
        Verdict::Deny
    );
}

// 8. Other well-known metadata/credential endpoints in observe mode.
#[test]
fn rv_other_metadata_endpoints_in_observe() {
    let mut b = B::new();
    let z = b.zone("obs", ZoneMode::Observe);
    b.agent("bot", z, A);
    let p = b.compile();
    for dst in ["169.254.170.2", "100.100.100.200", "169.254.169.253"] {
        let d = p.evaluate(&ctx(A, None, Some(dst), 80));
        assert_eq!(d.verdict, Verdict::Deny, "{dst} observed={}", d.observed);
    }
}

// 9. NAT64 / IPv4-compatible forms of the metadata address.
#[test]
fn rv_metadata_v6_embeddings() {
    let mut b = B::new();
    let z = b.zone("obs", ZoneMode::Observe);
    b.agent("bot", z, A);
    let p = b.compile();
    for dst in [
        "::ffff:169.254.169.254",
        "64:ff9b::a9fe:a9fe",
        "::a9fe:a9fe",
    ] {
        assert_eq!(
            p.evaluate(&ctx(A, None, Some(dst), 80)).verdict,
            Verdict::Deny,
            "{dst}"
        );
    }
}

// 10. Network object written as IPv4-mapped IPv6 never matches (flow IPs are canonicalised).
#[test]
fn rv_mapped_network_object_matches() {
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let n = b.obj(
        "bad",
        NetObjectSpec::Network {
            cidr: "::ffff:198.51.100.0/120".parse().unwrap(),
        },
    );
    b.rule("deny", Layer::Zone { zone_id: z }, 1, &[n], Action::Deny);
    b.rule("all", Layer::Zone { zone_id: z }, 2, &[], Action::Accept);
    let p = b.compile();
    assert_eq!(
        p.evaluate(&ctx(A, None, Some("198.51.100.7"), 80)).verdict,
        Verdict::Deny
    );
}

// 11. Accept with a path prefix cannot be reached at the connection stage (no method/path yet):
//     the CONNECT / ClientHello evaluation is a plain Cleanup with no "needs L7" signal.
#[test]
fn rv_accept_with_path_at_connect_stage() {
    let (p, h) = path_policy(Action::Accept);
    let mut c = ctx(A, Some(h), Some("203.0.113.10"), 443);
    c.app = Some(AppProto::Https);
    let d = p.evaluate(&c);
    println!("connect-stage decision: {:?} {:?}", d.verdict, d.implicit);
    assert!(
        !(d.verdict == Verdict::Deny && d.implicit == Some(Implicit::Cleanup)),
        "connect stage denied: an accept-by-path rule can never be used"
    );
}

// --- sanity checks expected to pass
#[test]
fn rv_sanity() {
    let (p, h) = path_policy(Action::Deny);
    // Case-sensitive paths: documented choice (ADR 0016, limits).
    println!(
        "/ADMIN: {:?}",
        p.evaluate(&http(A, h, "GET", "/ADMIN")).verdict
    );
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let d = b.domain("*.example.com");
    b.rule("deny", Layer::Zone { zone_id: z }, 1, &[d], Action::Deny);
    b.rule("all", Layer::Zone { zone_id: z }, 2, &[], Action::Accept);
    let p = b.compile();
    let long = format!("{}.example.com", "a.".repeat(200));
    for h in [
        "X.EXAMPLE.COM.",
        "x.example.com..",
        "x..example.com",
        "xn--80ak6aa92e.example.com",
        "x.example.com:443",
        "x.ex\u{0430}mple.com",
        &long,
        "x.example.com\0",
        " x.example.com",
    ] {
        assert_eq!(
            p.evaluate(&ctx(A, Some(h), None, 443)).verdict,
            Verdict::Deny,
            "{h:?}"
        );
    }
    // IPv6 zone id
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let n = b.obj(
        "ll",
        NetObjectSpec::Network {
            cidr: "fe80::/10".parse().unwrap(),
        },
    );
    b.rule("deny", Layer::Zone { zone_id: z }, 1, &[n], Action::Deny);
    b.rule("all", Layer::Zone { zone_id: z }, 2, &[], Action::Accept);
    let p = b.compile();
    println!(
        "zone1 {:?}",
        p.evaluate(&ctx(A, Some("[fe80::1%25eth0]"), None, 443))
            .verdict
    );
    println!(
        "zone2 {:?}",
        p.evaluate(&ctx(A, Some("fe80::1%eth0"), None, 443)).verdict
    );
    // ports at bounds
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let s = b.svc(L4Proto::Tcp, &[(1000, 2000), (65535, 65535)], None);
    b.rule("a", Layer::Zone { zone_id: z }, 1, &[], Action::Accept)
        .services = vec![s];
    let p = b.compile();
    for (port, v) in [
        (999, Verdict::Deny),
        (1000, Verdict::Allow),
        (2000, Verdict::Allow),
        (2001, Verdict::Deny),
        (65535, Verdict::Allow),
        (0, Verdict::Deny),
    ] {
        assert_eq!(
            p.evaluate(&ctx(A, None, Some("203.0.113.1"), port)).verdict,
            v,
            "{port}"
        );
    }
    // range bounds
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let r = b.obj(
        "r",
        NetObjectSpec::Range {
            start: ip("198.51.100.10"),
            end: ip("198.51.100.20"),
        },
    );
    let c = b.obj(
        "c",
        NetObjectSpec::Network {
            cidr: "2001:db8::/127".parse().unwrap(),
        },
    );
    b.rule("a", Layer::Zone { zone_id: z }, 1, &[r, c], Action::Accept);
    let p = b.compile();
    for (d, v) in [
        ("198.51.100.9", Verdict::Deny),
        ("198.51.100.10", Verdict::Allow),
        ("198.51.100.20", Verdict::Allow),
        ("198.51.100.21", Verdict::Deny),
        ("2001:db8::1", Verdict::Allow),
        ("2001:db8::2", Verdict::Deny),
        ("::ffff:198.51.100.15", Verdict::Allow),
    ] {
        assert_eq!(p.evaluate(&ctx(A, None, Some(d), 443)).verdict, v, "{d}");
    }
    // unknown agent via mapped form still resolves; unknown agent denied in observe zone
    assert_eq!(
        p.evaluate(&ctx("::ffff:10.0.0.2", None, Some("198.51.100.15"), 443))
            .verdict,
        Verdict::Allow
    );
    assert_eq!(
        p.evaluate(&ctx("10.0.0.3", None, Some("198.51.100.15"), 443))
            .verdict,
        Verdict::Deny
    );
    // expiry to the second
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    b.rule("a", Layer::Zone { zone_id: z }, 1, &[], Action::Accept)
        .expires_at = Some(now() + chrono::Duration::seconds(1));
    let p = b.compile();
    let mut c = ctx(A, None, Some("203.0.113.1"), 443);
    assert_eq!(p.evaluate(&c).verdict, Verdict::Allow);
    c.now = now() + chrono::Duration::milliseconds(999);
    assert_eq!(p.evaluate(&c).verdict, Verdict::Allow);
    c.now = now() + chrono::Duration::seconds(1);
    assert_eq!(p.evaluate(&c).verdict, Verdict::Deny);
    // zone accept cannot beat baseline deny, even in a baseline-sources-restricted case
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    let d = b.domain("evil.example");
    b.rule("bd", Layer::Baseline, 5, &[d], Action::Deny);
    b.rule("za", Layer::Zone { zone_id: z }, 0, &[d], Action::Accept);
    let p = b.compile();
    assert_eq!(
        p.evaluate(&ctx(A, Some("EVIL.example."), None, 443))
            .verdict,
        Verdict::Deny
    );
    // agent internal: other agent address is internal
    let mut b = B::new();
    let z = b.zone("prod", ZoneMode::Enforce);
    b.agent("bot", z, A);
    b.agent("db", z, "198.51.100.50");
    let p = b.compile();
    let d = p.evaluate(&ctx(A, None, Some("198.51.100.50"), 5432));
    assert_eq!(d.implicit, Some(Implicit::InternalMonitor));
}
