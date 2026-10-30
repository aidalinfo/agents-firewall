mod common;

use std::fmt::Debug;

use afw_core::api::*;
use afw_core::audit::{ChainError, GENESIS_HASH, audit_hash, verify_chain};
use afw_core::events::*;
use afw_core::policy::*;
use afw_core::protocol::*;
use afw_core::{InstalledPolicy, PolicyIntegrityError, canonical_json, sha256_hex};
use common::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;

fn roundtrip<T: Serialize + DeserializeOwned + PartialEq + Debug>(value: &T) {
    let text = serde_json::to_string(value).unwrap();
    let back: T = serde_json::from_str(&text).unwrap();
    assert_eq!(&back, value, "round trip of {text}");
}

#[test]
fn policy_types_round_trip() {
    let doc = document();
    roundtrip(&doc);
    for o in &doc.objects {
        roundtrip(o);
    }
    for r in &doc.rules {
        roundtrip(r);
    }
    roundtrip(&doc.services[0]);
    roundtrip(&doc.data_classes[0]);
    roundtrip(&doc.zones[0]);
    roundtrip(&doc.agents[0]);
    roundtrip(&doc.inspection_rules[0]);
    roundtrip(&doc.settings);
    roundtrip(&InstalledPolicy::new(7, "killian", doc));
}

#[test]
fn event_types_round_trip() {
    for e in gateway_events() {
        roundtrip(&e);
    }
    roundtrip(&tool_call());
    roundtrip(&audit_entry(1, GENESIS_HASH));
    roundtrip(&EventBatch {
        batch_id: id(42),
        events: gateway_events(),
    });
}

#[test]
fn protocol_types_round_trip() {
    roundtrip(&RegisterRequest {
        token: "t".into(),
        name: "gw".into(),
        hostname: "h".into(),
        csr_pem: "-----BEGIN".into(),
    });
    roundtrip(&RegisterResponse {
        gateway_id: id(30),
        cert_pem: "c".into(),
        ca_pem: "a".into(),
    });
    roundtrip(&PolicyQuery { have: Some(3) });
    roundtrip(&PolicyAck {
        revision: 3,
        ok: false,
        error: Some("bad".into()),
    });
    roundtrip(&Heartbeat {
        version: "0.1.0".into(),
        revision: None,
        stats: GatewayStats::default(),
        ca_fingerprint: "ab".into(),
    });
    roundtrip(&HeartbeatResponse {
        commands: vec![
            GatewayCommand::StartCapture {
                capture_id: id(1),
                agent_id: id(20),
                duration_secs: 60,
            },
            GatewayCommand::Reinstall,
            GatewayCommand::SelfTest,
        ],
    });
}

#[test]
fn api_types_round_trip() {
    let doc = document();
    let rref = ResourceRef {
        kind: ResourceKind::Rule,
        id: id(1),
        name: "r".into(),
    };
    roundtrip(&Page {
        items: vec![flow()],
        next_cursor: Some("c".into()),
    });
    roundtrip(&Problem {
        kind: "about:blank".into(),
        title: "Not Found".into(),
        status: 404,
        detail: None,
        instance: None,
    });
    roundtrip(&WhereUsed {
        references: vec![rref.clone()],
    });
    roundtrip(&MoveRuleRequest {
        position: 2,
        layer: Some(Layer::Zone { zone_id: id(10) }),
        section: None,
    });
    roundtrip(&Session {
        id: id(1),
        owner: actor(),
        interface: Interface::Mcp,
        state: SessionState::Open,
        opened_at: at(),
        closed_at: None,
        locks: vec![rref.clone()],
        changes: 1,
        approval_id: None,
        name: Some("s".into()),
        pending_install: Some(2),
    });
    roundtrip(&OpenSessionRequest { name: None });
    roundtrip(&PublishRequest {
        comment: "c".into(),
    });
    roundtrip(&AllowFromLogRequest {
        flow_id: id(500),
        destination: AllowDestination::Wildcard,
        expires_in_days: Some(7),
        track: Some(Track::Log),
    });
    let view = RuleView {
        rule: doc.rules[0].clone(),
        number: 1,
        hits: 3,
        last_hit_at: Some(at()),
        expired: false,
        locked_by: Some(actor()),
        pending_change: Some(ChangeOp::Update),
    };
    roundtrip(&AllowFromLogResponse {
        rule: view.clone(),
        created_object: Some(doc.objects[0].clone()),
        changes: vec![SessionChange {
            op: ChangeOp::Create,
            resource: rref.clone(),
            after: Some(serde_json::json!({"a": 1})),
        }],
    });
    roundtrip(&Rulebase {
        baseline: BaselineLayerView {
            sections: vec![RuleSection {
                name: None,
                rules: vec![view.clone()],
            }],
        },
        zones: vec![ZoneLayerView {
            zone: doc.zones[0].clone(),
            mode: doc.zones[0].mode,
            sections: vec![],
            cleanup_number: 2,
        }],
    });
    let revision = Revision {
        number: 3,
        published_at: at(),
        published_by: actor(),
        interface: Interface::Ui,
        session_id: Some(id(1)),
        comment: "c".into(),
        sha256: "00".into(),
    };
    roundtrip(&revision);
    roundtrip(&RevisionDetail {
        revision,
        document: doc.clone(),
    });
    roundtrip(&RevisionDiff {
        from: 2,
        to: 3,
        changes: vec![Change {
            kind: ChangeKind::Modified,
            resource: rref,
            before: Some(json!({"a": 1})),
            after: None,
        }],
    });
    roundtrip(&VerifyReport {
        revision: Some(3),
        findings: vec![
            VerifyFinding::Shadowed {
                rule: id(2),
                by: id(1),
            },
            VerifyFinding::UnusedObject { id: id(105) },
            VerifyFinding::Expired { rule: id(3) },
        ],
    });
    roundtrip(&InstallRequest {
        revision: 3,
        gateways: vec![id(30)],
    });
    roundtrip(&InstallResult {
        installs: vec![Install {
            id: id(1),
            revision: 3,
            gateway_id: id(30),
            requested_at: at(),
            requested_by: actor(),
            state: InstallState::Failed,
            acked_at: Some(at()),
            error: Some("x".into()),
        }],
    });
    let gateway = Gateway {
        id: id(30),
        name: "gw".into(),
        hostname: "h".into(),
        status: GatewayStatus::Online,
        version: Some("0.1.0".into()),
        desired_revision: Some(3),
        active_revision: Some(2),
        last_seen_at: Some(at()),
        registered_at: at(),
        ca_fingerprint: None,
        stats: Some(GatewayStats::default()),
    };
    roundtrip(&gateway);
    roundtrip(&CreateRegistrationToken { name: None });
    roundtrip(&RegistrationToken {
        token: "t".into(),
        expires_at: at(),
    });
    roundtrip(&FlowQuery {
        verdict: Some(Verdict::Deny),
        limit: Some(10),
        ..Default::default()
    });
    roundtrip(&FlowDetail {
        flow: flow(),
        http: vec![http()],
        tool_call: Some(tool_call()),
        correlation: Some(Correlation {
            tool_call_id: id(900),
            conversation_id: "conv-1".into(),
            confidence: Confidence::Probable,
        }),
        trace: vec![TraceStep {
            rule_id: Some(id(5)),
            rule_number: Some(3),
            rule_label: "3 · web".into(),
            layer: "zone".into(),
            outcome: TraceOutcome::NotMatched,
            reason: "destination".into(),
        }],
        agent_message: Some("blocked by agents-firewall: x not allowed for y (rule 3)".into()),
        allow_proposal: Some(AllowProposal {
            zone_id: id(2),
            zone_name: Some("bots".into()),
            destinations: vec![ProposedDestination {
                kind: ProposedDestinationKind::Exact,
                label: "x".into(),
                spec: Some(NetObjectSpec::Domain {
                    pattern: "x".into(),
                }),
                object_id: None,
            }],
            service: ProposedService {
                label: "tcp/443".into(),
                service_id: None,
                protocol: L4Proto::Tcp,
                port: 443,
            },
            rule_number: Some(4),
        }),
    });
    roundtrip(&FlowListItem {
        flow: flow(),
        agent_name: Some("bot".into()),
        zone_name: None,
        rule_label: "default-deny".into(),
        tool: None,
        conversation_id: None,
        correlation_confidence: Some(Confidence::Certain),
    });
    roundtrip(&FlowStats {
        bucket: StatsBucket::FiveMinutes,
        from: at(),
        to: at(),
        points: vec![FlowStatsPoint {
            at: at(),
            allow: 1,
            deny: 2,
            observed: 3,
        }],
        total: 6,
        allow: 1,
        deny: 2,
        observed: 3,
    });
    roundtrip(&ToolCallBatch {
        events: vec![tool_call()],
    });
    roundtrip(&CaptureRequest {
        agent_id: id(20),
        duration_secs: 30,
    });
    roundtrip(&Capture {
        id: id(1),
        agent_id: id(20),
        gateway_id: id(30),
        requested_at: at(),
        requested_by: actor(),
        duration_secs: 30,
        state: CaptureState::Running,
        size: None,
        error: None,
    });
    roundtrip(&Alert {
        event: alert(),
        gateway_id: Some(id(30)),
        acknowledged: false,
        acknowledged_by: None,
    });
    roundtrip(&AlertChannel {
        id: id(1),
        name: "teams".into(),
        kind: AlertChannelKind::Teams,
        url: "https://x".into(),
        min_severity: Severity::Warning,
        enabled: true,
    });
    roundtrip(&AgentOverview {
        agent: doc.agents[0].clone(),
        zone: doc.zones[0].clone(),
        gateway: Some(gateway),
        last_seen_at: None,
        flows_24h: 1,
        denied_24h: 1,
        bytes_out_24h: 1,
        bytes_in_24h: 1,
        top_destinations: vec![DestinationStat {
            destination: "api.anthropic.com".into(),
            flows: 1,
            denied: 0,
            bytes_out: 1,
            bytes_in: 1,
            last_seen_at: at(),
        }],
        recent_denied: vec![flow()],
        recent_tool_calls: vec![tool_call()],
        alerts: vec![alert()],
    });
    roundtrip(&InternalMap {
        nodes: vec![MapNode {
            id: "10.0.0.5".into(),
            label: "db".into(),
            kind: MapNodeKind::Internal,
            agent_id: None,
            zone_id: None,
            address: Some("10.0.0.5".into()),
        }],
        edges: vec![MapEdge {
            source: id(20).to_string(),
            target: "10.0.0.5".into(),
            protocol: L4Proto::Tcp,
            port: 5432,
            app: Some(AppProto::Other),
            flows: 1,
            bytes: 2,
            alerts: 0,
            first_seen_at: at(),
            last_seen_at: at(),
            new: true,
        }],
    });
    roundtrip(&AuditVerifyResult {
        ok: true,
        checked: 3,
        broken_at: None,
        head_seq: Some(3),
        head_hash: Some("ab".into()),
    });
    roundtrip(&Approval {
        id: id(1),
        session_id: id(2),
        requested_by: actor(),
        requested_at: at(),
        summary: "s".into(),
        reason: "r".into(),
        status: ApprovalStatus::Pending,
        decided_by: None,
        decided_at: None,
        comment: None,
    });
    roundtrip(&ApprovalDecision {
        approve: true,
        comment: None,
    });
    let token = ApiToken {
        id: id(1),
        name: "ci".into(),
        role: Role::McpAgent,
        agent_id: Some(id(20)),
        created_at: at(),
        created_by: actor(),
        expires_at: None,
        last_used_at: None,
    };
    roundtrip(&token);
    roundtrip(&CreateApiToken {
        name: "ci".into(),
        role: Role::Viewer,
        agent_id: None,
        expires_at: None,
    });
    roundtrip(&CreatedApiToken {
        token,
        secret: "s".into(),
    });
    roundtrip(&Me {
        actor: actor(),
        email: None,
        role: Role::Auditor,
        agent_id: None,
        writable_zones: Some(vec![id(11)]),
    });
    roundtrip(&IntentPolicy {
        version: 3,
        action_classes: vec![ActionClass {
            id: "irreversible".into(),
            name: "Irreversible".into(),
            tools: vec!["*delete*".into()],
            patterns: vec![],
            decision: IntentDecision::Deny,
        }],
    });
    roundtrip(&EnrollmentRequest {
        name: "bot".into(),
        zone_id: id(10),
        kind: AgentKind::Coolify,
        gateway_id: id(30),
        hermes: true,
    });
    roundtrip(&Enrollment {
        agent: doc.agents[0].clone(),
        session_id: id(1),
        plugin_token: Some("p".into()),
    });
}

#[test]
fn wire_format_is_snake_case_and_tagged() {
    let o = &document().objects;
    assert_eq!(
        serde_json::to_value(&o[0]).unwrap()["spec"],
        json!({"type": "domain", "pattern": "*.anthropic.com"})
    );
    assert_eq!(
        serde_json::to_value(&o[0]).unwrap()["category"],
        json!("llm_provider")
    );
    assert_eq!(
        serde_json::to_value(Layer::Zone { zone_id: id(10) }).unwrap(),
        json!({"type": "zone", "zone_id": id(10)})
    );
    assert_eq!(
        serde_json::to_value(Layer::Baseline).unwrap(),
        json!({"type": "baseline"})
    );
    assert_eq!(
        serde_json::to_value(Role::McpAgent).unwrap(),
        json!("mcp_agent")
    );
    assert_eq!(
        serde_json::to_value(GatewayCommand::SelfTest).unwrap(),
        json!({"type": "self_test"})
    );
    let ev = serde_json::to_value(&gateway_events()[0]).unwrap();
    assert_eq!(ev["type"], "flow");
    assert_eq!(ev["verdict"], "deny");
    let hits = serde_json::to_value(&gateway_events()[4]).unwrap();
    assert_eq!(hits["type"], "rule_hits");
    assert!(hits["hits"].is_array());
    let problem = serde_json::to_value(Problem {
        kind: "about:blank".into(),
        title: "t".into(),
        status: 400,
        detail: None,
        instance: None,
    })
    .unwrap();
    assert_eq!(problem["type"], "about:blank");
}

#[test]
fn defaults_match_the_plan() {
    assert_eq!(Track::default(), Track::Detailed);
    assert_eq!(InspectionAction::default(), InspectionAction::Inspect);
    let s = PolicySettings::default();
    let nets: Vec<String> = s.internal_networks.iter().map(|n| n.to_string()).collect();
    assert_eq!(
        nets,
        ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
    );
    assert_eq!(s.max_buffered_body, 1024 * 1024);
    assert_eq!(s.max_stored_body, 256 * 1024);
    assert_eq!(
        s.retention_days,
        Retention {
            flows: 30,
            http: 14,
            captures: 7
        }
    );
    // A rule without `track` defaults to Detailed.
    let mut v = serde_json::to_value(rule(1, Layer::Baseline, 1)).unwrap();
    v.as_object_mut().unwrap().remove("track");
    let r: Rule = serde_json::from_value(v).unwrap();
    assert_eq!(r.track, Track::Detailed);
}

#[test]
fn rule_numbers_are_global_ranks() {
    // Baseline: rule 2 (pos 1), rule 1 (pos 2); zones sorted by name: "clients" (rule 4)
    // before "internes" (rule 3).
    let numbers = document().rule_numbers();
    assert_eq!(numbers[&id(2)], 1);
    assert_eq!(numbers[&id(1)], 2);
    assert_eq!(numbers[&id(4)], 3);
    assert_eq!(numbers[&id(3)], 4);
    assert_eq!(numbers.len(), 4);
}

#[test]
fn canonical_json_sorts_keys_without_spaces() {
    let v = json!({"b": [1, {"z": null, "a": "é\"x"}], "a": true, "c": 1.5});
    assert_eq!(
        canonical_json(&v),
        r#"{"a":true,"b":[1,{"a":"é\"x","z":null}],"c":1.5}"#
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn audit_hash_is_stable() {
    let e = audit_entry(1, GENESIS_HASH);
    // Independent of the current `hash` value.
    let mut other = e.clone();
    other.hash = "garbage".into();
    assert_eq!(audit_hash(GENESIS_HASH, &other), e.hash);
    // Frozen value: changing it breaks every existing audit chain.
    let mut v = serde_json::to_value(&e).unwrap();
    v.as_object_mut().unwrap().remove("hash");
    let expected = sha256_hex(format!("{GENESIS_HASH}{}", canonical_json(&v)).as_bytes());
    assert_eq!(e.hash, expected);
    assert_eq!(
        e.hash,
        "9659d851ecf52cf5f0eeaea1dcc9a9cc1dfa3272e097c9d759fcea3c3e3351b1"
    );
}

#[test]
fn verify_chain_detects_tampering() {
    let e1 = audit_entry(1, GENESIS_HASH);
    let e2 = audit_entry(2, &e1.hash);
    let e3 = audit_entry(3, &e2.hash);
    let chain = vec![e1, e2, e3];
    assert_eq!(verify_chain(&chain), Ok(()));
    assert_eq!(verify_chain(&[]), Ok(()));

    let mut modified = chain.clone();
    modified[1].action = "rule.delete".into();
    assert_eq!(verify_chain(&modified), Err(ChainError { seq: 2 }));

    let mut removed = chain.clone();
    removed.remove(1);
    assert_eq!(verify_chain(&removed), Err(ChainError { seq: 3 }));

    // Re-hashing a modified entry still breaks the link to the next one.
    let mut rehashed = chain.clone();
    rehashed[1].target = "rule:other".into();
    rehashed[1].hash = audit_hash(&rehashed[1].prev_hash, &rehashed[1]);
    assert_eq!(verify_chain(&rehashed), Err(ChainError { seq: 3 }));
}

#[test]
fn installed_policy_rejects_wrong_fingerprint_and_unknown_format() {
    let p = InstalledPolicy::new(3, "killian", document());
    assert_eq!(p.format, 1);
    assert_eq!(p.sha256.len(), 64);
    assert_eq!(p.verify(), Ok(()));
    // Survives a JSON round trip (key order independent).
    let back: InstalledPolicy = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
    assert_eq!(back.verify(), Ok(()));

    let mut tampered = p.clone();
    tampered.document.rules[0].action = Action::Accept;
    tampered.document.rules[2].action = Action::Accept;
    assert!(matches!(
        tampered.verify(),
        Err(PolicyIntegrityError::FingerprintMismatch { .. })
    ));

    let mut bad_sha = p.clone();
    bad_sha.sha256 = "0".repeat(64);
    assert!(matches!(
        bad_sha.verify(),
        Err(PolicyIntegrityError::FingerprintMismatch { .. })
    ));

    let mut future = p;
    future.format = 2;
    assert_eq!(future.verify(), Err(PolicyIntegrityError::UnknownFormat(2)));
}

#[test]
fn unknown_fields_are_rejected_on_policy_and_write_dtos() {
    // Typo `destination` instead of `destinations` must not silently mean "any".
    let mut v = serde_json::to_value(rule(1, Layer::Baseline, 1)).unwrap();
    let dests = v.as_object_mut().unwrap().remove("destinations").unwrap();
    v["destination"] = dests;
    assert!(serde_json::from_value::<Rule>(v).is_err());

    let spec = json!({"type": "domain", "pattern": "a.com", "patern": "b.com"});
    assert!(serde_json::from_value::<NetObjectSpec>(spec).is_err());
    let layer = json!({"type": "zone", "zone_id": id(1), "zone": id(2)});
    assert!(serde_json::from_value::<Layer>(layer).is_err());

    let mut doc = serde_json::to_value(document()).unwrap();
    doc["rule"] = json!([]);
    assert!(serde_json::from_value::<PolicyDocument>(doc).is_err());

    let install = json!({"revision": 3, "gateway": [id(30)]});
    assert!(serde_json::from_value::<InstallRequest>(install).is_err());
    let token =
        json!({"name": "x", "role": "admin", "agent_id": null, "expires_at": null, "scope": "all"});
    assert!(serde_json::from_value::<CreateApiToken>(token).is_err());
}

#[test]
fn rollback_flag_is_covered_by_the_fingerprint() {
    let p = InstalledPolicy::new(5, "killian", document());
    assert!(!p.rollback);
    let r = InstalledPolicy::new(3, "killian", document()).as_rollback();
    assert!(r.rollback);
    assert_eq!(r.verify(), Ok(()));
    // Same document, different fingerprint when only the flag differs.
    assert_ne!(
        r.sha256,
        InstalledPolicy::new(3, "killian", document()).sha256
    );

    let mut forged = InstalledPolicy::new(3, "killian", document());
    forged.rollback = true;
    assert!(matches!(
        forged.verify(),
        Err(PolicyIntegrityError::FingerprintMismatch { .. })
    ));
    let mut renumbered = p.clone();
    renumbered.revision = 9;
    assert!(matches!(
        renumbered.verify(),
        Err(PolicyIntegrityError::FingerprintMismatch { .. })
    ));
}

#[test]
fn gateway_refuses_older_revision_unless_rollback() {
    let older = InstalledPolicy::new(3, "k", document());
    let same = InstalledPolicy::new(5, "k", document());
    let newer = InstalledPolicy::new(6, "k", document());
    let rollback = InstalledPolicy::new(3, "k", document()).as_rollback();
    assert!(older.may_replace(None));
    assert!(!older.may_replace(Some(5)));
    assert!(same.may_replace(Some(5)));
    assert!(newer.may_replace(Some(5)));
    assert!(rollback.may_replace(Some(5)));
}

#[test]
fn intent_policy_matches_the_hermes_plugin_format() {
    // Format consumed by integrations/hermes (ADR 0015).
    let wire = json!({
        "version": 4,
        "action_classes": [
            {"id": "infra_destructive", "name": "Infra", "tools": ["terminal"],
             "patterns": ["(?i)kubectl\\s+delete"], "decision": "gate"},
            {"id": "paid_generation", "name": "Paid", "tools": [], "patterns": [], "decision": "log"}
        ]
    });
    let p: IntentPolicy = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(p.action_classes[0].decision, IntentDecision::Gate);
    assert_eq!(serde_json::to_value(&p).unwrap(), wire);
}
