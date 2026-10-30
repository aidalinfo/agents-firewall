//! Test helpers: a small policy builder.
#![allow(dead_code)]

use std::net::IpAddr;

use afw_core::InstalledPolicy;
use afw_core::policy::*;
use afw_engine::{CompiledPolicy, FlowContext};
use chrono::{DateTime, TimeZone, Utc};
use uuid::Uuid;

pub fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 30, 12, 0, 0).unwrap()
}

pub fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[derive(Default)]
pub struct B {
    pub doc: PolicyDocument,
}

impl B {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn zone(&mut self, name: &str, mode: ZoneMode) -> Uuid {
        let id = Uuid::new_v4();
        self.doc.zones.push(Zone {
            id,
            name: name.into(),
            comment: String::new(),
            mode,
            delegated_to_mcp: false,
        });
        id
    }

    pub fn agent(&mut self, name: &str, zone_id: Uuid, addr: &str) -> Uuid {
        let id = Uuid::new_v4();
        self.doc.agents.push(Agent {
            id,
            name: name.into(),
            zone_id,
            kind: AgentKind::Container,
            gateway_id: None,
            addresses: vec![ip(addr)],
            labels: Default::default(),
            hermes: false,
            mcp_admin: false,
        });
        id
    }

    pub fn obj(&mut self, name: &str, spec: NetObjectSpec) -> Uuid {
        self.obj_cat(name, spec, None)
    }

    pub fn obj_cat(&mut self, name: &str, spec: NetObjectSpec, cat: Option<DestCategory>) -> Uuid {
        let id = Uuid::new_v4();
        self.doc.objects.push(NetObject {
            id,
            name: name.into(),
            comment: String::new(),
            category: cat,
            spec,
        });
        id
    }

    pub fn domain(&mut self, pattern: &str) -> Uuid {
        self.obj(
            pattern,
            NetObjectSpec::Domain {
                pattern: pattern.into(),
            },
        )
    }

    pub fn svc(&mut self, protocol: L4Proto, ports: &[(u16, u16)], app: Option<AppMatch>) -> Uuid {
        let id = Uuid::new_v4();
        self.doc.services.push(Service {
            id,
            name: format!("svc-{id}"),
            comment: String::new(),
            protocol,
            ports: ports
                .iter()
                .map(|&(start, end)| PortRange { start, end })
                .collect(),
            app,
        });
        id
    }

    pub fn class(&mut self, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        self.doc.data_classes.push(DataClass {
            id,
            name: name.into(),
            comment: String::new(),
            category: DataCategory::Secret,
            detectors: vec![Detector::Builtin {
                id: "aws_access_key".into(),
            }],
        });
        id
    }

    /// Adds a rule and returns a mutable reference to tweak it.
    pub fn rule(
        &mut self,
        name: &str,
        layer: Layer,
        position: u32,
        destinations: &[Uuid],
        action: Action,
    ) -> &mut Rule {
        let sources = match layer {
            Layer::Baseline => vec![],
            Layer::Zone { zone_id } => vec![zone_id],
        };
        self.doc.rules.push(Rule {
            id: Uuid::new_v4(),
            name: name.into(),
            layer,
            section: None,
            position,
            sources,
            destinations: destinations.to_vec(),
            services: vec![],
            data_classes: vec![],
            action,
            track: Track::Log,
            expires_at: None,
            comment: String::new(),
            enabled: true,
        });
        self.doc.rules.last_mut().unwrap()
    }

    pub fn installed(&self) -> InstalledPolicy {
        InstalledPolicy::new(7, "test", self.doc.clone())
    }

    pub fn compile(&self) -> CompiledPolicy {
        CompiledPolicy::compile(&self.installed(), now()).expect("policy compiles")
    }
}

pub fn ctx(agent: &str, host: Option<&str>, dst: Option<&str>, port: u16) -> FlowContext {
    FlowContext {
        agent_ip: ip(agent),
        dst_ip: dst.map(ip),
        dst_port: port,
        l4: L4Proto::Tcp,
        app: None,
        host: host.map(str::to_owned),
        method: None,
        path: None,
        data_classes: vec![],
        now: now(),
    }
}

pub fn http(agent: &str, host: &str, method: &str, path: &str) -> FlowContext {
    FlowContext {
        app: Some(AppProto::Https),
        method: Some(method.into()),
        path: Some(path.into()),
        ..ctx(agent, Some(host), Some("203.0.113.10"), 443)
    }
}
