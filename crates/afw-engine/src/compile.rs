//! Policy compilation and flow evaluation.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use afw_core::events::Verdict;
use afw_core::installed::PolicyIntegrityError;
use afw_core::policy::{
    Action, AppProto, DataClass, DestCategory, InspectionAction, L4Proto, Layer, NetObjectSpec,
    PolicyDocument, Service, Track, ZoneMode,
};
use afw_core::{InstalledPolicy, policy::Agent};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use uuid::Uuid;

use crate::matching::{
    DestSet, Host, M, Resolver, canon_ip, classify_host, leaf_of, normalize_path, path_has_prefix,
};
use crate::{Decision, DecisionLayer, FlowContext, Implicit, TraceOutcome, TraceStep};

/// Why a policy cannot be compiled. A gateway treats any error as "no valid policy".
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CompileError {
    #[error(transparent)]
    Integrity(#[from] PolicyIntegrityError),
    #[error("duplicate id {0}")]
    DuplicateId(Uuid),
    #[error("{from} references unknown or wrong-kind resource {to}")]
    UnknownReference { from: Uuid, to: Uuid },
    #[error("{id} references unknown zone {zone}")]
    UnknownZone { id: Uuid, zone: Uuid },
    #[error("zone rule {rule} must have exactly its own zone as source")]
    ZoneRuleSource { rule: Uuid },
    #[error("object group cycle through {0}")]
    GroupCycle(Uuid),
    #[error("object {object}: invalid domain pattern {pattern:?}")]
    InvalidDomain { object: Uuid, pattern: String },
    #[error("object {object}: invalid address range")]
    InvalidRange { object: Uuid },
    #[error("service {service}: {reason}")]
    InvalidService { service: Uuid, reason: String },
    #[error("address {0} belongs to more than one agent")]
    DuplicateAgentAddress(IpAddr),
}

/// Well-known cloud metadata endpoints, always treated as `CloudMetadata` (ADR 0016).
const BUILTIN_METADATA_NETS: [&str; 2] = ["169.254.169.254/32", "fd00:ec2::254/128"];
const BUILTIN_METADATA_NAMES: [&str; 2] = ["metadata.google.internal", "metadata.goog"];

#[derive(Debug, Clone)]
struct CService {
    protocol: L4Proto,
    ports: Vec<(u16, u16)>,
    app: Option<CApp>,
}

#[derive(Debug, Clone)]
struct CApp {
    proto: AppProto,
    methods: Vec<String>,
    prefixes: Vec<String>,
}

#[derive(Debug, Clone)]
struct CRule {
    id: Uuid,
    number: u32,
    name: String,
    layer: DecisionLayer,
    /// Baseline only: zones; empty = all zones.
    sources: Vec<Uuid>,
    /// `None` = any destination.
    dest: Option<DestSet>,
    /// Indexes into `Inner::services`; empty = any service.
    services: Vec<usize>,
    data_classes: Vec<Uuid>,
    action: Action,
    track: Track,
    expires_at: Option<DateTime<Utc>>,
    enabled: bool,
}

#[derive(Debug, Clone)]
struct CInspection {
    zones: Vec<Uuid>,
    dest: Option<DestSet>,
    action: InspectionAction,
}

#[derive(Debug, Clone)]
struct CZone {
    name: String,
    mode: ZoneMode,
    rules: Vec<CRule>,
}

#[derive(Debug, Clone)]
struct Inner {
    revision: u64,
    agents: Vec<Agent>,
    agent_by_ip: HashMap<IpAddr, usize>,
    zones: HashMap<Uuid, CZone>,
    baseline: Vec<CRule>,
    services: Vec<CService>,
    inspection: Vec<CInspection>,
    data_classes: Vec<DataClass>,
    internal_networks: Vec<IpNet>,
    llm: DestSet,
    metadata: DestSet,
    internal_objects: DestSet,
}

/// A policy ready for evaluation. Cheap to share behind an `Arc`.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    inner: Option<Inner>,
}

/// Flow information normalised once per evaluation.
struct Flow<'a> {
    host: Host<'a>,
    ip: Option<IpAddr>,
    path: Option<Option<String>>,
}

impl CompiledPolicy {
    /// Policy used when no valid policy is available: every flow is denied (`NoPolicy`).
    pub fn deny_all() -> CompiledPolicy {
        CompiledPolicy { inner: None }
    }

    /// Verifies the fingerprint and compiles. Rule expiry is checked at evaluation time against
    /// [`FlowContext::now`]; `_now` is accepted for API stability.
    pub fn compile(
        policy: &InstalledPolicy,
        _now: DateTime<Utc>,
    ) -> Result<CompiledPolicy, CompileError> {
        policy.verify()?;
        let doc = &policy.document;
        check_unique_ids(doc)?;
        let resolver = Resolver::new(&doc.objects);
        check_objects(doc, &resolver)?;

        let zone_ids: HashSet<Uuid> = doc.zones.iter().map(|z| z.id).collect();
        let service_idx: HashMap<Uuid, usize> = doc
            .services
            .iter()
            .enumerate()
            .map(|(i, s)| (s.id, i))
            .collect();
        let class_ids: HashSet<Uuid> = doc.data_classes.iter().map(|c| c.id).collect();
        let services = doc
            .services
            .iter()
            .map(compile_service)
            .collect::<Result<Vec<_>, _>>()?;

        // Agents.
        let mut agent_by_ip = HashMap::new();
        for (i, a) in doc.agents.iter().enumerate() {
            if !zone_ids.contains(&a.zone_id) {
                return Err(CompileError::UnknownZone {
                    id: a.id,
                    zone: a.zone_id,
                });
            }
            for ip in &a.addresses {
                let ip = canon_ip(*ip);
                if agent_by_ip.insert(ip, i).is_some_and(|prev| prev != i) {
                    return Err(CompileError::DuplicateAgentAddress(ip));
                }
            }
        }

        // Rules.
        let numbers = doc.rule_numbers();
        let dest_of = |from: Uuid, ids: &[Uuid]| -> Result<Option<DestSet>, CompileError> {
            for id in ids {
                if resolver.get(id).is_none() {
                    return Err(CompileError::UnknownReference { from, to: *id });
                }
            }
            Ok((!ids.is_empty()).then(|| DestSet::from_leaves(resolver.leaves(ids))))
        };
        let mut zones: HashMap<Uuid, CZone> = doc
            .zones
            .iter()
            .map(|z| {
                (
                    z.id,
                    CZone {
                        name: z.name.clone(),
                        mode: z.mode,
                        rules: Vec::new(),
                    },
                )
            })
            .collect();
        let mut baseline = Vec::new();
        for r in &doc.rules {
            let layer = match r.layer {
                Layer::Baseline => {
                    for s in &r.sources {
                        if !zone_ids.contains(s) {
                            return Err(CompileError::UnknownReference { from: r.id, to: *s });
                        }
                    }
                    DecisionLayer::Baseline
                }
                Layer::Zone { zone_id } => {
                    if !zone_ids.contains(&zone_id) {
                        return Err(CompileError::UnknownZone {
                            id: r.id,
                            zone: zone_id,
                        });
                    }
                    if r.sources.is_empty() || r.sources.iter().any(|s| *s != zone_id) {
                        return Err(CompileError::ZoneRuleSource { rule: r.id });
                    }
                    DecisionLayer::Zone
                }
            };
            let mut svc = Vec::with_capacity(r.services.len());
            for s in &r.services {
                svc.push(
                    *service_idx
                        .get(s)
                        .ok_or(CompileError::UnknownReference { from: r.id, to: *s })?,
                );
            }
            for c in &r.data_classes {
                if !class_ids.contains(c) {
                    return Err(CompileError::UnknownReference { from: r.id, to: *c });
                }
            }
            let rule = CRule {
                id: r.id,
                number: numbers[&r.id],
                name: r.name.clone(),
                layer,
                sources: if layer == DecisionLayer::Baseline {
                    r.sources.clone()
                } else {
                    Vec::new()
                },
                dest: dest_of(r.id, &r.destinations)?,
                services: svc,
                data_classes: r.data_classes.clone(),
                action: r.action,
                track: r.track,
                expires_at: r.expires_at,
                enabled: r.enabled,
            };
            match r.layer {
                Layer::Baseline => baseline.push(rule),
                Layer::Zone { zone_id } => zones
                    .get_mut(&zone_id)
                    .expect("zone checked above")
                    .rules
                    .push(rule),
            }
        }
        baseline.sort_by_key(|r| r.number);
        for z in zones.values_mut() {
            z.rules.sort_by_key(|r| r.number);
        }

        // Inspection rules.
        let mut insp: Vec<_> = doc.inspection_rules.iter().collect();
        insp.sort_by_key(|r| (r.position, r.id));
        let mut inspection = Vec::with_capacity(insp.len());
        for r in insp {
            for z in &r.zones {
                if !zone_ids.contains(z) {
                    return Err(CompileError::UnknownReference { from: r.id, to: *z });
                }
            }
            inspection.push(CInspection {
                zones: r.zones.clone(),
                dest: dest_of(r.id, &r.destinations)?,
                action: r.action,
            });
        }

        // Categories.
        let category = |cat: DestCategory| {
            let ids: Vec<Uuid> = doc
                .objects
                .iter()
                .filter(|o| o.category == Some(cat))
                .map(|o| o.id)
                .collect();
            DestSet::from_leaves(resolver.leaves(&ids))
        };
        let mut metadata = category(DestCategory::CloudMetadata);
        for n in BUILTIN_METADATA_NETS {
            metadata.add_net(n.parse().expect("valid built-in CIDR"));
        }
        for n in BUILTIN_METADATA_NAMES {
            metadata.add_name(n);
        }

        Ok(CompiledPolicy {
            inner: Some(Inner {
                revision: policy.revision,
                agents: doc.agents.clone(),
                agent_by_ip,
                zones,
                baseline,
                services,
                inspection,
                data_classes: doc.data_classes.clone(),
                internal_networks: doc.settings.internal_networks.clone(),
                llm: category(DestCategory::LlmProvider),
                metadata,
                internal_objects: category(DestCategory::Internal),
            }),
        })
    }

    /// Policy revision; `None` for [`Self::deny_all`].
    pub fn revision(&self) -> Option<u64> {
        self.inner.as_ref().map(|i| i.revision)
    }

    /// Agent owning a source address.
    pub fn resolve_agent(&self, ip: IpAddr) -> Option<&Agent> {
        let inner = self.inner.as_ref()?;
        inner
            .agent_by_ip
            .get(&canon_ip(ip))
            .map(|&i| &inner.agents[i])
    }

    /// Whether the destination belongs to an object of category `LlmProvider` (EF-25).
    pub fn is_llm_provider(&self, host: Option<&str>, ip: Option<IpAddr>) -> bool {
        let Some(inner) = &self.inner else {
            return false;
        };
        let flow = Flow::new(host, ip, None);
        inner.llm.matches(&flow.host, flow.ip) == M::Yes
    }

    /// Data classes of the policy (to configure `afw-dlp` on the gateway).
    pub fn data_class_specs(&self) -> &[DataClass] {
        self.inner
            .as_ref()
            .map(|i| i.data_classes.as_slice())
            .unwrap_or(&[])
    }

    /// Decides a flow. Never panics; anything unknown denies.
    pub fn evaluate(&self, ctx: &FlowContext) -> Decision {
        let Some(inner) = &self.inner else {
            return implicit(Implicit::NoPolicy, None, Vec::new());
        };
        inner.evaluate(ctx)
    }
}

impl<'a> Flow<'a> {
    fn new(host: Option<&'a str>, dst_ip: Option<IpAddr>, path: Option<&str>) -> Self {
        let host = host.map(classify_host).unwrap_or(Host::Absent);
        let ip = dst_ip.map(canon_ip).or(match host {
            Host::Ip(ip) => Some(ip),
            _ => None,
        });
        Flow {
            host,
            ip,
            path: path.map(normalize_path),
        }
    }
}

fn implicit(kind: Implicit, revision: Option<u64>, trace: Vec<TraceStep>) -> Decision {
    Decision {
        verdict: if kind == Implicit::InternalMonitor {
            Verdict::Allow
        } else {
            Verdict::Deny
        },
        agent_id: None,
        agent_name: None,
        zone_id: None,
        zone_name: None,
        rule_id: None,
        rule_number: None,
        rule_name: kind.rule_name().to_owned(),
        layer: DecisionLayer::Implicit,
        implicit: Some(kind),
        track: Track::Detailed,
        inspect_tls: true,
        observed: false,
        llm_provider: false,
        internal: false,
        revision,
        trace,
    }
}

impl Inner {
    fn evaluate(&self, ctx: &FlowContext) -> Decision {
        let flow = Flow::new(ctx.host.as_deref(), ctx.dst_ip, ctx.path.as_deref());
        let llm = self.llm.matches(&flow.host, flow.ip) == M::Yes;
        // Cloud metadata (or possibly so): never implicitly allowed, even in observe mode.
        let metadata = self.metadata.matches(&flow.host, flow.ip) != M::No;
        let internal = flow.ip.is_some_and(|ip| {
            self.internal_networks.iter().any(|n| n.contains(&ip))
                || self.agent_by_ip.contains_key(&ip)
        }) || self.internal_objects.matches(&flow.host, flow.ip) == M::Yes;

        let Some(&agent_idx) = self.agent_by_ip.get(&canon_ip(ctx.agent_ip)) else {
            let mut d = implicit(Implicit::UnknownAgent, Some(self.revision), Vec::new());
            d.llm_provider = llm;
            d.internal = internal;
            return d;
        };
        let agent = &self.agents[agent_idx];
        let zone = &self.zones[&agent.zone_id];

        let mut trace = Vec::with_capacity(self.baseline.len() + zone.rules.len());
        let matched = self.baseline.iter().chain(zone.rules.iter()).find(|rule| {
            let outcome = self.check(rule, agent.zone_id, ctx, &flow, llm);
            trace.push(TraceStep {
                rule_id: rule.id,
                rule_number: Some(rule.number),
                layer: rule.layer,
                outcome,
            });
            outcome == TraceOutcome::Matched
        });

        let mut d = match matched {
            Some(rule) => Decision {
                verdict: match rule.action {
                    Action::Accept => Verdict::Allow,
                    Action::Deny => Verdict::Deny,
                },
                agent_id: None,
                agent_name: None,
                zone_id: None,
                zone_name: None,
                rule_id: Some(rule.id),
                rule_number: Some(rule.number),
                rule_name: rule.name.clone(),
                layer: rule.layer,
                implicit: None,
                track: rule.track,
                inspect_tls: true,
                observed: false,
                llm_provider: false,
                internal: false,
                revision: Some(self.revision),
                trace,
            },
            None if internal && !metadata => {
                implicit(Implicit::InternalMonitor, Some(self.revision), trace)
            }
            None => implicit(Implicit::Cleanup, Some(self.revision), trace),
        };
        d.agent_id = Some(agent.id);
        d.agent_name = Some(agent.name.clone());
        d.zone_id = Some(agent.zone_id);
        d.zone_name = Some(zone.name.clone());
        d.llm_provider = llm;
        d.internal = internal;
        d.inspect_tls = self.inspect_tls(agent.zone_id, &flow);

        // EF-12: observe mode never lets cloud metadata through (ADR 0005).
        if d.verdict == Verdict::Deny && zone.mode == ZoneMode::Observe && !metadata {
            d.verdict = Verdict::Allow;
            d.observed = true;
        }
        d
    }

    fn check(
        &self,
        rule: &CRule,
        zone_id: Uuid,
        ctx: &FlowContext,
        flow: &Flow<'_>,
        llm: bool,
    ) -> TraceOutcome {
        if !rule.enabled {
            return TraceOutcome::Disabled;
        }
        if rule.expires_at.is_some_and(|e| e <= ctx.now) {
            return TraceOutcome::Expired;
        }
        if !rule.sources.is_empty() && !rule.sources.contains(&zone_id) {
            return TraceOutcome::SourceMismatch;
        }
        if !rule.data_classes.is_empty() {
            if llm {
                return TraceOutcome::LlmExempt;
            }
            if !rule
                .data_classes
                .iter()
                .any(|c| ctx.data_classes.contains(c))
            {
                return TraceOutcome::DataClassMismatch;
            }
        }
        let dest = rule
            .dest
            .as_ref()
            .map_or(M::Yes, |d| d.matches(&flow.host, flow.ip));
        if dest == M::No {
            return TraceOutcome::DestinationMismatch;
        }
        let svc = if rule.services.is_empty() {
            M::Yes
        } else {
            rule.services.iter().fold(M::No, |acc, &i| {
                acc.or(service_matches(&self.services[i], ctx, flow))
            })
        };
        if svc == M::No {
            return TraceOutcome::ServiceMismatch;
        }
        match dest.and(svc) {
            M::Yes => TraceOutcome::Matched,
            // Malformed host or path: only a deny rule may apply (fail closed).
            _ if rule.action == Action::Deny => TraceOutcome::Matched,
            _ => TraceOutcome::Indeterminate,
        }
    }

    fn inspect_tls(&self, zone_id: Uuid, flow: &Flow<'_>) -> bool {
        self.inspection
            .iter()
            .find(|r| {
                (r.zones.is_empty() || r.zones.contains(&zone_id))
                    && r.dest
                        .as_ref()
                        .is_none_or(|d| d.matches(&flow.host, flow.ip) == M::Yes)
            })
            .is_none_or(|r| r.action == InspectionAction::Inspect)
    }
}

fn service_matches(s: &CService, ctx: &FlowContext, flow: &Flow<'_>) -> M {
    if s.protocol != L4Proto::Any && s.protocol != ctx.l4 {
        return M::No;
    }
    if !s.ports.is_empty()
        && !s
            .ports
            .iter()
            .any(|&(a, b)| a <= ctx.dst_port && ctx.dst_port <= b)
    {
        return M::No;
    }
    let Some(app) = &s.app else { return M::Yes };
    if ctx.app != Some(app.proto) {
        return M::No;
    }
    if !app.methods.is_empty() {
        let Some(m) = &ctx.method else { return M::No };
        if !app.methods.iter().any(|x| x.eq_ignore_ascii_case(m)) {
            return M::No;
        }
    }
    if app.prefixes.is_empty() {
        return M::Yes;
    }
    match &flow.path {
        None => M::No,
        Some(None) => M::Unsure,
        Some(Some(p)) if app.prefixes.iter().any(|pre| path_has_prefix(p, pre)) => M::Yes,
        Some(Some(_)) => M::No,
    }
}

fn compile_service(s: &Service) -> Result<CService, CompileError> {
    let invalid = |reason: &str| CompileError::InvalidService {
        service: s.id,
        reason: reason.to_owned(),
    };
    if s.ports.iter().any(|p| p.start > p.end) {
        return Err(invalid("port range start is greater than its end"));
    }
    let app = match &s.app {
        None => None,
        Some(a) => {
            let http = matches!(a.proto, AppProto::Http | AppProto::Https);
            if !http && (!a.methods.is_empty() || !a.path_prefixes.is_empty()) {
                return Err(invalid(
                    "methods and path prefixes apply to http/https only",
                ));
            }
            if a.methods
                .iter()
                .any(|m| m.is_empty() || !m.bytes().all(|c| c.is_ascii_alphabetic()))
            {
                return Err(invalid("invalid HTTP method"));
            }
            let prefixes = a
                .path_prefixes
                .iter()
                .map(|p| normalize_path(p).ok_or_else(|| invalid("invalid path prefix")))
                .collect::<Result<Vec<_>, _>>()?;
            Some(CApp {
                proto: a.proto,
                methods: a.methods.clone(),
                prefixes,
            })
        }
    };
    Ok(CService {
        protocol: s.protocol,
        ports: s.ports.iter().map(|p| (p.start, p.end)).collect(),
        app,
    })
}

fn check_unique_ids(doc: &PolicyDocument) -> Result<(), CompileError> {
    let mut seen = HashSet::new();
    let ids = doc
        .objects
        .iter()
        .map(|o| o.id)
        .chain(doc.services.iter().map(|s| s.id))
        .chain(doc.data_classes.iter().map(|c| c.id))
        .chain(doc.zones.iter().map(|z| z.id))
        .chain(doc.agents.iter().map(|a| a.id))
        .chain(doc.rules.iter().map(|r| r.id))
        .chain(doc.inspection_rules.iter().map(|r| r.id));
    for id in ids {
        if !seen.insert(id) {
            return Err(CompileError::DuplicateId(id));
        }
    }
    Ok(())
}

/// Validates object specs, group members and the absence of group cycles.
fn check_objects(doc: &PolicyDocument, resolver: &Resolver<'_>) -> Result<(), CompileError> {
    for o in &doc.objects {
        match &o.spec {
            NetObjectSpec::Group { members } => {
                for m in members {
                    if resolver.get(m).is_none() {
                        return Err(CompileError::UnknownReference { from: o.id, to: *m });
                    }
                }
            }
            NetObjectSpec::Domain { pattern } => {
                if leaf_of(&o.spec).is_none() {
                    return Err(CompileError::InvalidDomain {
                        object: o.id,
                        pattern: pattern.clone(),
                    });
                }
            }
            NetObjectSpec::Range { .. } => {
                if leaf_of(&o.spec).is_none() {
                    return Err(CompileError::InvalidRange { object: o.id });
                }
            }
            _ => {}
        }
    }
    // Cycle detection: iterative DFS with colours (0 = new, 1 = on stack, 2 = done).
    let mut colour: HashMap<Uuid, u8> = HashMap::new();
    for o in &doc.objects {
        if colour.get(&o.id).copied().unwrap_or(0) != 0 {
            continue;
        }
        let mut stack: Vec<(Uuid, usize)> = vec![(o.id, 0)];
        colour.insert(o.id, 1);
        while let Some((id, next)) = stack.pop() {
            let members: &[Uuid] = match resolver.get(&id).map(|o| &o.spec) {
                Some(NetObjectSpec::Group { members }) => members,
                _ => &[],
            };
            if let Some(m) = members.get(next) {
                stack.push((id, next + 1));
                match colour.get(m).copied().unwrap_or(0) {
                    1 => return Err(CompileError::GroupCycle(*m)),
                    0 => {
                        colour.insert(*m, 1);
                        stack.push((*m, 0));
                    }
                    _ => {}
                }
            } else {
                colour.insert(id, 2);
            }
        }
    }
    Ok(())
}
