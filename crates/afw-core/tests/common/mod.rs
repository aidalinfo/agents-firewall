#![allow(dead_code)]
//! Sample values covering every variant, shared by the afw-core tests.

use std::collections::BTreeMap;

use afw_core::events::*;
use afw_core::policy::*;
use chrono::{TimeZone, Utc};
use uuid::Uuid;

pub fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

pub fn at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 30, 12, 0, 0).unwrap()
}

pub fn rule(n: u128, layer: Layer, position: u32) -> Rule {
    Rule {
        id: id(n),
        name: format!("rule-{n}"),
        layer,
        section: Some("web".into()),
        position,
        sources: vec![],
        destinations: vec![id(100)],
        services: vec![id(200)],
        data_classes: vec![],
        action: Action::Accept,
        track: Track::default(),
        expires_at: None,
        comment: String::new(),
        enabled: true,
    }
}

pub fn document() -> PolicyDocument {
    let zone_a = Zone {
        id: id(10),
        name: "internes".into(),
        comment: "".into(),
        mode: ZoneMode::Enforce,
        delegated_to_mcp: false,
    };
    let zone_b = Zone {
        id: id(11),
        name: "clients".into(),
        comment: "observe first".into(),
        mode: ZoneMode::Observe,
        delegated_to_mcp: true,
    };
    let mut deny = rule(3, Layer::Zone { zone_id: id(10) }, 1);
    deny.action = Action::Deny;
    deny.track = Track::Capture;
    deny.data_classes = vec![id(300)];
    deny.expires_at = Some(at());
    PolicyDocument {
        objects: vec![
            NetObject {
                id: id(100),
                name: "anthropic".into(),
                comment: "".into(),
                category: Some(DestCategory::LlmProvider),
                spec: NetObjectSpec::Domain {
                    pattern: "*.anthropic.com".into(),
                },
            },
            NetObject {
                id: id(101),
                name: "metadata".into(),
                comment: "".into(),
                category: Some(DestCategory::CloudMetadata),
                spec: NetObjectSpec::Host {
                    ip: "169.254.169.254".parse().unwrap(),
                },
            },
            NetObject {
                id: id(102),
                name: "lan".into(),
                comment: "".into(),
                category: Some(DestCategory::Internal),
                spec: NetObjectSpec::Network {
                    cidr: "10.0.0.0/8".parse().unwrap(),
                },
            },
            NetObject {
                id: id(103),
                name: "range".into(),
                comment: "".into(),
                category: None,
                spec: NetObjectSpec::Range {
                    start: "192.0.2.1".parse().unwrap(),
                    end: "192.0.2.9".parse().unwrap(),
                },
            },
            NetObject {
                id: id(104),
                name: "group".into(),
                comment: "".into(),
                category: None,
                spec: NetObjectSpec::Group {
                    members: vec![id(100), id(101)],
                },
            },
            NetObject {
                id: id(105),
                name: "any".into(),
                comment: "".into(),
                category: None,
                spec: NetObjectSpec::Any,
            },
        ],
        services: vec![Service {
            id: id(200),
            name: "https-api".into(),
            comment: "".into(),
            protocol: L4Proto::Tcp,
            ports: vec![PortRange {
                start: 443,
                end: 443,
            }],
            app: Some(AppMatch {
                proto: AppProto::Https,
                methods: vec!["GET".into(), "POST".into()],
                path_prefixes: vec!["/v1/".into()],
            }),
        }],
        data_classes: vec![DataClass {
            id: id(300),
            name: "secrets".into(),
            comment: "".into(),
            category: DataCategory::Secret,
            detectors: vec![
                Detector::Builtin {
                    id: "aws_access_key".into(),
                },
                Detector::Regex {
                    name: "internal".into(),
                    pattern: "corp-[0-9]+".into(),
                },
            ],
        }],
        zones: vec![zone_b, zone_a],
        agents: vec![Agent {
            id: id(20),
            name: "daniel-bot".into(),
            zone_id: id(10),
            kind: AgentKind::DockerCompose,
            gateway_id: Some(id(30)),
            addresses: vec!["172.30.0.10".parse().unwrap()],
            labels: BTreeMap::from([("team".into(), "ops".into())]),
            hermes: true,
            mcp_admin: false,
        }],
        rules: vec![
            rule(1, Layer::Baseline, 2),
            rule(2, Layer::Baseline, 1),
            deny,
            rule(4, Layer::Zone { zone_id: id(11) }, 1),
        ],
        inspection_rules: vec![InspectionRule {
            id: id(400),
            name: "pinning".into(),
            position: 1,
            zones: vec![],
            destinations: vec![id(100)],
            action: InspectionAction::Bypass,
        }],
        settings: PolicySettings::default(),
    }
}

pub fn decision() -> DecisionRef {
    DecisionRef {
        rule_id: Some(id(1)),
        rule_number: Some(1),
        rule_name: "rule-1".into(),
        revision: Some(3),
        layer: "baseline".into(),
        reason: "matched".into(),
    }
}

pub fn flow() -> FlowEvent {
    FlowEvent {
        id: id(500),
        gateway_id: id(30),
        agent_id: Some(id(20)),
        zone_id: Some(id(10)),
        src: "172.30.0.10:40000".parse().unwrap(),
        dst: "[2001:db8::1]:443".parse().unwrap(),
        protocol: L4Proto::Tcp,
        app: Some(AppProto::Https),
        domain: Some("api.anthropic.com".into()),
        sni: Some("api.anthropic.com".into()),
        bytes_out: 10,
        bytes_in: 20,
        started_at: at(),
        ended_at: Some(at()),
        verdict: Verdict::Deny,
        decision: decision(),
        internal: false,
        llm_provider: true,
        tls_inspected: true,
        data_classes: vec!["secrets".into()],
        observed: false,
    }
}

pub fn http() -> HttpEvent {
    let body = Body {
        encoding: BodyEncoding::Utf8,
        data: "token=[SECRET:aws_access_key:3f9a1c2b7d10]".into(),
        size: 42,
        truncated: false,
        sha256: "00".repeat(32),
    };
    HttpEvent {
        id: id(600),
        flow_id: id(500),
        gateway_id: id(30),
        agent_id: Some(id(20)),
        at: at(),
        method: "POST".into(),
        url: "https://api.anthropic.com/v1/messages".into(),
        host: "api.anthropic.com".into(),
        request_headers: vec![("content-type".into(), "application/json".into())],
        request_body: Some(body.clone()),
        status: Some(200),
        response_headers: vec![],
        response_body: Some(Body {
            encoding: BodyEncoding::Base64,
            ..body
        }),
        findings: vec![Finding {
            class: "secrets".into(),
            category: DataCategory::Secret,
            kind: "aws_access_key".into(),
            fingerprint: "3f9a1c2b7d10".into(),
            location: "request.body".into(),
        }],
        admin_action: Some(AdminAction {
            system: AdminSystem::Kubernetes,
            action: "delete".into(),
            resource: "pods/x".into(),
        }),
        websocket: false,
    }
}

pub fn alert() -> AlertEvent {
    AlertEvent {
        id: id(700),
        at: at(),
        kind: AlertKind::CloudMetadata,
        severity: Severity::Critical,
        agent_id: Some(id(20)),
        summary: "metadata access".into(),
        details: serde_json::json!({"dst": "169.254.169.254"}),
    }
}

pub fn gateway_events() -> Vec<GatewayEvent> {
    vec![
        GatewayEvent::Flow(flow()),
        GatewayEvent::Dns(DnsEvent {
            id: id(800),
            gateway_id: id(30),
            agent_id: Some(id(20)),
            zone_id: Some(id(10)),
            at: at(),
            qname: "api.anthropic.com".into(),
            qtype: "AAAA".into(),
            answers: vec!["2001:db8::1".into()],
            verdict: Verdict::Allow,
            decision: decision(),
        }),
        GatewayEvent::Http(http()),
        GatewayEvent::Alert(alert()),
        GatewayEvent::RuleHits {
            hits: vec![RuleHit {
                rule_id: id(1),
                revision: 3,
                hits: 12,
                last_hit_at: at(),
            }],
        },
    ]
}

pub fn tool_call() -> ToolCallEvent {
    ToolCallEvent {
        id: id(900),
        agent: "daniel-bot".into(),
        conversation_id: "conv-1".into(),
        tool: "web_fetch".into(),
        args_summary: "url=https://example.com".into(),
        started_at: at(),
        ended_at: None,
        status: Some("ok".into()),
    }
}

pub fn actor() -> Actor {
    Actor {
        kind: ActorKind::Human,
        id: "killian".into(),
        name: "Killian".into(),
    }
}

pub fn audit_entry(seq: i64, prev_hash: &str) -> AuditEntry {
    let mut e = AuditEntry {
        seq,
        at: at(),
        actor: actor(),
        interface: Interface::Ui,
        session_id: Some(id(1000)),
        action: "rule.create".into(),
        target: format!("rule:{seq}"),
        diff: serde_json::json!({"after": {"name": "x", "position": seq}}),
        prev_hash: prev_hash.into(),
        hash: String::new(),
    };
    e.hash = afw_core::audit::audit_hash(prev_hash, &e);
    e
}
