//! Minimal stand-in for `afw-engine` (lot L5), with the frozen public API of plan §4 L5.
//!
//! It exists only so that the gateway can be built and tested while L5 is developed in
//! parallel; it is replaced by `afw_engine` (see `engine.rs`) as soon as L5 is merged. It
//! implements the fixed evaluation order (baseline, zone, internal monitor, cleanup), observe
//! mode, the LLM exemption, inspection rules and unknown-agent denial, without the
//! optimisations nor the pre-install verification of the real engine.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use afw_core::InstalledPolicy;
use afw_core::events::{DecisionRef, Verdict};
use afw_core::policy::{
    Action, Agent, AppProto, DataClass, DestCategory, InspectionAction, L4Proto, Layer,
    NetObjectSpec, PolicyDocument, Rule, Service, Track, ZoneMode,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub struct FlowContext {
    pub agent_ip: IpAddr,
    pub dst_ip: Option<IpAddr>,
    pub dst_port: u16,
    pub l4: L4Proto,
    pub app: Option<AppProto>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub data_classes: Vec<Uuid>,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionLayer {
    Baseline,
    Zone,
    Implicit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Implicit {
    InternalMonitor,
    Cleanup,
    UnknownAgent,
    NoPolicy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TraceStep {
    pub rule_id: Uuid,
    pub matched: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub verdict: Verdict,
    pub agent_id: Option<Uuid>,
    pub agent_name: Option<String>,
    pub zone_id: Option<Uuid>,
    pub zone_name: Option<String>,
    pub rule_id: Option<Uuid>,
    pub rule_number: Option<u32>,
    pub rule_name: String,
    pub layer: DecisionLayer,
    pub implicit: Option<Implicit>,
    pub track: Track,
    pub inspect_tls: bool,
    pub observed: bool,
    pub llm_provider: bool,
    pub internal: bool,
    pub trace: Vec<TraceStep>,
    /// Shim-only: revision carried into `to_ref` (the real engine knows it too).
    revision: Option<u64>,
}

impl Decision {
    pub fn to_ref(&self) -> DecisionRef {
        DecisionRef {
            rule_id: self.rule_id,
            rule_number: self.rule_number,
            rule_name: self.rule_name.clone(),
            revision: self.revision,
            layer: match self.layer {
                DecisionLayer::Baseline => "baseline",
                DecisionLayer::Zone => "zone",
                DecisionLayer::Implicit => "implicit",
            }
            .to_string(),
            reason: match self.implicit {
                Some(Implicit::InternalMonitor) => "internal-monitor",
                Some(Implicit::Cleanup) => "default-deny",
                Some(Implicit::UnknownAgent) => "unknown-agent",
                Some(Implicit::NoPolicy) => "no-policy",
                None => "rule",
            }
            .to_string(),
        }
    }

    /// EF-21 message: `blocked by agents-firewall: <destination> not allowed for <agent> (rule <n>)`.
    pub fn deny_message(&self, destination: &str) -> String {
        let agent = self.agent_name.clone().unwrap_or_else(|| "unknown-agent".into());
        let rule = match (self.rule_number, self.implicit) {
            (Some(n), _) => n.to_string(),
            (None, Some(Implicit::UnknownAgent)) => "unknown-agent".into(),
            (None, Some(Implicit::NoPolicy)) => "no-policy".into(),
            _ => "default-deny".into(),
        };
        format!("blocked by agents-firewall: {destination} not allowed for {agent} (rule {rule})")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("policy integrity: {0}")]
    Integrity(#[from] afw_core::PolicyIntegrityError),
    #[error("invalid policy: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    doc: Option<PolicyDocument>,
    revision: Option<u64>,
    numbers: HashMap<Uuid, u32>,
}

impl CompiledPolicy {
    pub fn compile(policy: &InstalledPolicy, _now: DateTime<Utc>) -> Result<Self, CompileError> {
        policy.verify()?;
        let doc = &policy.document;
        let zones: HashSet<Uuid> = doc.zones.iter().map(|z| z.id).collect();
        for a in &doc.agents {
            if !zones.contains(&a.zone_id) {
                return Err(CompileError::Invalid(format!("agent {} in unknown zone", a.name)));
            }
        }
        for r in &doc.rules {
            if let Layer::Zone { zone_id } = r.layer
                && r.sources != vec![zone_id]
            {
                return Err(CompileError::Invalid(format!(
                    "zone rule {} must have its zone as only source",
                    r.name
                )));
            }
        }
        Ok(Self {
            numbers: doc.rule_numbers().into_iter().collect(),
            doc: Some(doc.clone()),
            revision: Some(policy.revision),
        })
    }

    pub fn deny_all() -> Self {
        Self {
            doc: None,
            revision: None,
            numbers: HashMap::new(),
        }
    }

    pub fn revision(&self) -> Option<u64> {
        self.revision
    }

    pub fn data_class_specs(&self) -> &[DataClass] {
        self.doc.as_ref().map(|d| d.data_classes.as_slice()).unwrap_or(&[])
    }

    pub fn resolve_agent(&self, ip: IpAddr) -> Option<&Agent> {
        self.doc.as_ref()?.agents.iter().find(|a| a.addresses.contains(&ip))
    }

    pub fn is_llm_provider(&self, host: Option<&str>, ip: Option<IpAddr>) -> bool {
        let Some(doc) = &self.doc else { return false };
        doc.objects.iter().any(|o| {
            o.category == Some(DestCategory::LlmProvider) && self.object_matches(doc, o.id, host, ip, 0)
        })
    }

    fn category_of(&self, doc: &PolicyDocument, cat: DestCategory, host: Option<&str>, ip: Option<IpAddr>) -> bool {
        doc.objects
            .iter()
            .any(|o| o.category == Some(cat) && self.object_matches(doc, o.id, host, ip, 0))
    }

    fn base(&self, verdict: Verdict) -> Decision {
        Decision {
            verdict,
            agent_id: None,
            agent_name: None,
            zone_id: None,
            zone_name: None,
            rule_id: None,
            rule_number: None,
            rule_name: String::new(),
            layer: DecisionLayer::Implicit,
            implicit: None,
            track: Track::Detailed,
            inspect_tls: true,
            observed: false,
            llm_provider: false,
            internal: false,
            trace: Vec::new(),
            revision: self.revision,
        }
    }

    pub fn evaluate(&self, ctx: &FlowContext) -> Decision {
        let Some(doc) = &self.doc else {
            let mut d = self.base(Verdict::Deny);
            d.implicit = Some(Implicit::NoPolicy);
            d.rule_name = "no-policy".into();
            return d;
        };
        let Some(agent) = self.resolve_agent(ctx.agent_ip) else {
            let mut d = self.base(Verdict::Deny);
            d.implicit = Some(Implicit::UnknownAgent);
            d.rule_name = "unknown-agent".into();
            return d;
        };
        let zone = doc.zones.iter().find(|z| z.id == agent.zone_id);
        let host = ctx.host.as_deref();
        let llm = self.category_of(doc, DestCategory::LlmProvider, host, ctx.dst_ip);
        let metadata = self.category_of(doc, DestCategory::CloudMetadata, host, ctx.dst_ip);
        let internal = ctx.dst_ip.is_some_and(|ip| {
            doc.settings.internal_networks.iter().any(|n| n.contains(&ip))
                || doc.agents.iter().any(|a| a.id != agent.id && a.addresses.contains(&ip))
        });
        let mut d = self.base(Verdict::Deny);
        d.agent_id = Some(agent.id);
        d.agent_name = Some(agent.name.clone());
        d.zone_id = Some(agent.zone_id);
        d.zone_name = zone.map(|z| z.name.clone());
        d.llm_provider = llm;
        d.internal = internal;
        d.inspect_tls = self.inspect(doc, agent.zone_id, host, ctx.dst_ip);

        let mut ordered: Vec<&Rule> = doc
            .rules
            .iter()
            .filter(|r| match r.layer {
                Layer::Baseline => r.sources.is_empty() || r.sources.contains(&agent.zone_id),
                Layer::Zone { zone_id } => zone_id == agent.zone_id,
            })
            .collect();
        ordered.sort_by_key(|r| (matches!(r.layer, Layer::Zone { .. }), r.position));
        let mut matched: Option<&Rule> = None;
        for r in ordered {
            let ok = self.rule_matches(doc, r, ctx, llm);
            d.trace.push(TraceStep {
                rule_id: r.id,
                matched: ok,
                reason: if ok { "match".into() } else { "no match".into() },
            });
            if ok {
                matched = Some(r);
                break;
            }
        }
        match matched {
            Some(r) => {
                d.verdict = match r.action {
                    Action::Accept => Verdict::Allow,
                    Action::Deny => Verdict::Deny,
                };
                d.rule_id = Some(r.id);
                d.rule_number = self.numbers.get(&r.id).copied();
                d.rule_name = r.name.clone();
                d.layer = match r.layer {
                    Layer::Baseline => DecisionLayer::Baseline,
                    Layer::Zone { .. } => DecisionLayer::Zone,
                };
                d.track = r.track;
            }
            None if internal => {
                d.verdict = Verdict::Allow;
                d.implicit = Some(Implicit::InternalMonitor);
                d.rule_name = "internal-monitor".into();
            }
            None => {
                d.implicit = Some(Implicit::Cleanup);
                d.rule_name = "default-deny".into();
            }
        }
        if d.verdict == Verdict::Deny
            && zone.is_some_and(|z| z.mode == ZoneMode::Observe)
            && !metadata
        {
            d.verdict = Verdict::Allow;
            d.observed = true;
        }
        d
    }

    fn inspect(&self, doc: &PolicyDocument, zone: Uuid, host: Option<&str>, ip: Option<IpAddr>) -> bool {
        let mut rules: Vec<_> = doc.inspection_rules.iter().collect();
        rules.sort_by_key(|r| r.position);
        for r in rules {
            let z = r.zones.is_empty() || r.zones.contains(&zone);
            let dst = r.destinations.is_empty()
                || r.destinations.iter().any(|o| self.object_matches(doc, *o, host, ip, 0));
            if z && dst {
                return r.action == InspectionAction::Inspect;
            }
        }
        true
    }

    fn rule_matches(&self, doc: &PolicyDocument, r: &Rule, ctx: &FlowContext, llm: bool) -> bool {
        if !r.enabled || r.expires_at.is_some_and(|e| e <= ctx.now) {
            return false;
        }
        if !r.data_classes.is_empty()
            && (llm || !r.data_classes.iter().any(|c| ctx.data_classes.contains(c)))
        {
            return false;
        }
        let host = ctx.host.as_deref();
        if !r.destinations.is_empty()
            && !r.destinations.iter().any(|o| self.object_matches(doc, *o, host, ctx.dst_ip, 0))
        {
            return false;
        }
        if !r.services.is_empty()
            && !r.services.iter().any(|s| {
                doc.services.iter().find(|x| x.id == *s).is_some_and(|s| service_matches(s, ctx))
            })
        {
            return false;
        }
        true
    }

    fn object_matches(&self, doc: &PolicyDocument, id: Uuid, host: Option<&str>, ip: Option<IpAddr>, depth: u32) -> bool {
        if depth > 16 {
            return false;
        }
        let Some(o) = doc.objects.iter().find(|o| o.id == id) else { return false };
        match &o.spec {
            NetObjectSpec::Any => true,
            NetObjectSpec::Domain { pattern } => host.is_some_and(|h| domain_matches(pattern, h)),
            NetObjectSpec::Host { ip: x } => ip == Some(*x),
            NetObjectSpec::Network { cidr } => ip.is_some_and(|i| cidr.contains(&i)),
            NetObjectSpec::Range { start, end } => ip.is_some_and(|i| match (start, end, i) {
                (IpAddr::V4(s), IpAddr::V4(e), IpAddr::V4(i)) => *s <= i && i <= *e,
                (IpAddr::V6(s), IpAddr::V6(e), IpAddr::V6(i)) => *s <= i && i <= *e,
                _ => false,
            }),
            NetObjectSpec::Group { members } => members
                .iter()
                .any(|m| self.object_matches(doc, *m, host, ip, depth + 1)),
        }
    }
}

fn service_matches(s: &Service, ctx: &FlowContext) -> bool {
    if s.protocol != L4Proto::Any && ctx.l4 != L4Proto::Any && s.protocol != ctx.l4 {
        return false;
    }
    if !s.ports.is_empty() && !s.ports.iter().any(|p| p.start <= ctx.dst_port && ctx.dst_port <= p.end) {
        return false;
    }
    if let Some(app) = &s.app {
        if let Some(m) = &ctx.method
            && !app.methods.is_empty()
            && !app.methods.iter().any(|x| x.eq_ignore_ascii_case(m))
        {
            return false;
        }
        if let Some(p) = &ctx.path
            && !app.path_prefixes.is_empty()
            && !app.path_prefixes.iter().any(|x| p.starts_with(x.as_str()))
        {
            return false;
        }
    }
    true
}

pub(crate) fn domain_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim_end_matches('.').to_ascii_lowercase();
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    match p.strip_prefix("*.") {
        Some(suffix) => h.len() > suffix.len() + 1 && h.ends_with(&format!(".{suffix}")),
        None => p == h,
    }
}
