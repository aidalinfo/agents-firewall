#![allow(dead_code)]

use std::net::IpAddr;

use afw_core::InstalledPolicy;
use afw_core::events::Verdict;
use afw_core::policy::{Agent, AgentKind, L4Proto, PolicyDocument, ZoneMode};
use afw_engine::{CompiledPolicy, FlowContext};
use afw_import::{ImportOptions, ImportPlan, import};
use chrono::Utc;
use uuid::Uuid;

pub const EXAMPLE: &str = include_str!("../../../../examples/egress-guard/guardrails.example.yaml");

pub const AGENT_IP: &str = "10.200.0.5";

pub fn opts(zone: &str) -> ImportOptions<'static> {
    ImportOptions::new(zone)
}

pub fn import_example() -> ImportPlan {
    import(EXAMPLE, &opts("assistant")).expect("example imports")
}

pub fn import_enforced(yaml: &str) -> ImportPlan {
    let mut o = opts("assistant");
    o.zone_mode = ZoneMode::Enforce;
    import(yaml, &o).expect("imports")
}

/// Compiles the plan merged into an empty document, with one agent in the imported zone.
pub fn compile(plan: &ImportPlan) -> CompiledPolicy {
    let mut doc = plan.merged_into(&PolicyDocument::default());
    doc.agents.push(Agent {
        id: Uuid::new_v4(),
        name: "bot".into(),
        zone_id: plan.zone.id,
        kind: AgentKind::DockerCompose,
        gateway_id: None,
        addresses: vec![AGENT_IP.parse().unwrap()],
        labels: Default::default(),
        hermes: true,
        mcp_admin: false,
    });
    let installed = InstalledPolicy::new(1, "test", doc);
    CompiledPolicy::compile(&installed, Utc::now()).expect("imported plan compiles")
}

pub fn class_id(plan: &ImportPlan, name: &str) -> Uuid {
    plan.data_classes
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("data class {name} not in plan"))
        .id
}

/// Evaluates an HTTPS flow to `host:port` (public address) carrying `classes`.
pub fn verdict(
    policy: &CompiledPolicy,
    host: &str,
    port: u16,
    classes: Vec<Uuid>,
) -> (Verdict, String) {
    let ctx = FlowContext {
        agent_ip: AGENT_IP.parse().unwrap(),
        dst_ip: Some("203.0.113.10".parse::<IpAddr>().unwrap()),
        dst_ip_trusted: true,
        dst_port: port,
        l4: L4Proto::Tcp,
        app: None,
        host: Some(host.into()),
        method: None,
        path: None,
        data_classes: classes,
        now: Utc::now(),
    };
    let d = policy.evaluate(&ctx);
    (d.verdict, d.rule_name)
}
