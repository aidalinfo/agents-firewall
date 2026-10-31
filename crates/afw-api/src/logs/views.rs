//! Views computed by the API for the console (which has no business logic): flow labels,
//! message received by the agent, "Allow" proposal, agent overview, internal map, rule
//! counters.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use afw_core::api::{
    AgentOverview, AllowProposal, InternalMap, MapEdge, MapNode, MapNodeKind, MapPeriod,
    ProposedDestination, ProposedDestinationKind, ProposedService, Role, TraceOutcome, TraceStep,
};
use afw_core::events::{DecisionRef, DenyMode, FlowEvent, Verdict};
use afw_core::policy::{
    Action, AppProto, Layer, NetObject, NetObjectSpec, PolicyDocument, Rule, Track,
};
use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use super::alerts;
use super::store::{LogStore, enum_str, flow_destination};
use crate::AppState;
use crate::auth::Principal;
use crate::error::ApiError;

/// Rules examined for `flow`, recomputed by compiling revision `revision` of the policy
/// (`doc`) and re-evaluating the flow. The recorded destination address is the one the gateway
/// really connected to, hence `dst_ip_trusted`. Method and path come from the first HTTP
/// exchange, if any.
pub fn trace(
    flow: &FlowEvent,
    doc: &PolicyDocument,
    revision: u64,
    first_http: Option<&afw_core::events::HttpEvent>,
) -> Vec<TraceStep> {
    use afw_engine::{CompiledPolicy, FlowContext, TraceOutcome as E};
    let installed = afw_core::InstalledPolicy::new(revision, "trace", doc.clone());
    let compiled = match CompiledPolicy::compile(&installed, flow.started_at) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(revision, error = %e, "cannot compile the flow's revision for its trace");
            return Vec::new();
        }
    };
    let path = first_http.and_then(|h| {
        reqwest::Url::parse(&h.url).ok().map(|u| match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_owned(),
        })
    });
    let ctx = FlowContext {
        agent_ip: flow.src.ip(),
        dst_ip: Some(flow.dst.ip()),
        dst_ip_trusted: true,
        dst_port: flow.dst.port(),
        l4: flow.protocol,
        app: flow.app,
        host: flow.domain.clone().or_else(|| flow.sni.clone()),
        method: first_http.map(|h| h.method.clone()),
        path,
        data_classes: doc
            .data_classes
            .iter()
            .filter(|c| flow.data_classes.contains(&c.name))
            .map(|c| c.id)
            .collect(),
        now: flow.started_at,
    };
    let decision = compiled.evaluate(&ctx);
    let mut steps: Vec<TraceStep> = decision
        .trace
        .iter()
        .map(|s| {
            let name = doc
                .rules
                .iter()
                .find(|r| r.id == s.rule_id)
                .map_or_else(String::new, |r| r.name.clone());
            let (outcome, reason) = match s.outcome {
                E::Matched => (TraceOutcome::Matched, "matched"),
                E::Disabled => (TraceOutcome::Skipped, "rule disabled"),
                E::Expired => (TraceOutcome::Skipped, "rule expired"),
                E::SourceMismatch => (TraceOutcome::NotMatched, "source zone does not match"),
                E::LlmExempt => (
                    TraceOutcome::Skipped,
                    "data-class rule skipped for an LLM provider",
                ),
                E::DataClassMismatch => (TraceOutcome::NotMatched, "no listed data class detected"),
                E::DestinationMismatch => (TraceOutcome::NotMatched, "destination does not match"),
                E::ServiceMismatch => (TraceOutcome::NotMatched, "service does not match"),
                E::Indeterminate => (TraceOutcome::NotMatched, "host or path malformed"),
                E::MetadataProtected => (
                    TraceOutcome::NotMatched,
                    "cloud metadata destination not named by the rule",
                ),
                E::NeedsL7 => (
                    TraceOutcome::NotMatched,
                    "depends on the HTTP method or path",
                ),
            };
            TraceStep {
                rule_id: Some(s.rule_id),
                rule_number: s.rule_number,
                rule_label: match s.rule_number {
                    Some(n) => format!("{n} · {name}"),
                    None => name,
                },
                layer: s.layer.as_str().to_owned(),
                outcome,
                reason: reason.to_owned(),
            }
        })
        .collect();
    if let Some(i) = decision.implicit {
        steps.push(TraceStep {
            rule_id: None,
            rule_number: None,
            rule_label: i.rule_name().to_owned(),
            layer: "implicit".to_owned(),
            outcome: TraceOutcome::Matched,
            reason: decision.to_ref().reason,
        });
    }
    steps
}

/// `12 · name`, `socle · name` (baseline without number) or `default-deny`.
pub fn rule_label(d: &DecisionRef, verdict: Verdict) -> String {
    match (d.rule_number, d.layer.as_str()) {
        (Some(n), _) => format!("{n} · {}", d.rule_name),
        (None, "baseline") => format!("socle · {}", d.rule_name),
        (None, "implicit") if verdict == Verdict::Deny => "default-deny".to_owned(),
        (None, _) if !d.rule_name.is_empty() => d.rule_name.clone(),
        (None, _) if verdict == Verdict::Deny => "default-deny".to_owned(),
        (None, _) => "implicit".to_owned(),
    }
}

pub fn agent_name(doc: Option<&PolicyDocument>, agent: Option<Uuid>) -> Option<String> {
    let agent = agent?;
    doc?.agents
        .iter()
        .find(|a| a.id == agent)
        .map(|a| a.name.clone())
}

pub fn zone_name(doc: Option<&PolicyDocument>, zone: Option<Uuid>) -> Option<String> {
    let zone = zone?;
    doc?.zones
        .iter()
        .find(|z| z.id == zone)
        .map(|z| z.name.clone())
}

/// Exact HTTP denial text received by the agent (EF-21, frozen format of the plan §1):
/// `blocked by agents-firewall: <destination> not allowed for <agent> (rule <n>)`. Only for
/// denied HTTP exchanges the gateway could answer (plain HTTP or inspected HTTPS); other denials
/// are a refused connection.
pub fn agent_message(flow: &FlowEvent, agent: Option<&str>) -> Option<String> {
    if flow.verdict != Verdict::Deny {
        return None;
    }
    // The gateway says how it refused; older events are judged on the application.
    let http = match flow.deny_mode {
        Some(mode) => mode == DenyMode::Http403,
        None => match flow.app {
            Some(AppProto::Http) => true,
            Some(AppProto::Https) => flow.tls_inspected,
            _ => false,
        },
    };
    if !http {
        return None;
    }
    let agent = agent
        .map(str::to_owned)
        .or_else(|| flow.agent_id.map(|a| a.to_string()))
        .unwrap_or_else(|| flow.src.ip().to_string());
    let rule = match flow.decision.rule_number {
        Some(n) => n.to_string(),
        None if !flow.decision.rule_name.is_empty() => flow.decision.rule_name.clone(),
        None => "default-deny".to_owned(),
    };
    Some(format!(
        "blocked by agents-firewall: {} not allowed for {agent} (rule {rule})",
        flow_destination(flow)
    ))
}

fn object_matches(
    doc: &PolicyDocument,
    obj: &NetObject,
    domain: Option<&str>,
    ip: IpAddr,
    depth: u8,
) -> bool {
    match &obj.spec {
        NetObjectSpec::Domain { pattern } => {
            let Some(d) = domain else { return false };
            let p = pattern.trim_end_matches('.').to_ascii_lowercase();
            match p.strip_prefix("*.") {
                Some(suffix) => d.ends_with(&format!(".{suffix}")),
                None => d == p,
            }
        }
        NetObjectSpec::Host { ip: h } => *h == ip,
        NetObjectSpec::Network { cidr } => cidr.contains(&ip),
        NetObjectSpec::Range { start, end } => *start <= ip && ip <= *end,
        NetObjectSpec::Group { members } => {
            depth < 8
                && members.iter().any(|m| {
                    doc.objects
                        .iter()
                        .find(|o| o.id == *m)
                        .is_some_and(|o| object_matches(doc, o, domain, ip, depth + 1))
                })
        }
        NetObjectSpec::Any => false,
    }
}

/// Proposal behind the "Allow" button (denied or observed flows of a known zone).
pub fn allow_proposal(flow: &FlowEvent, doc: Option<&PolicyDocument>) -> Option<AllowProposal> {
    if flow.verdict != Verdict::Deny && !flow.observed {
        return None;
    }
    let zone_id = flow.zone_id?;
    let ip = flow.dst.ip();
    let domain = flow
        .domain
        .as_deref()
        .or(flow.sni.as_deref())
        .map(|d| d.trim_end_matches('.').to_ascii_lowercase());
    let mut destinations = Vec::new();
    match &domain {
        Some(d) => {
            destinations.push(ProposedDestination {
                kind: ProposedDestinationKind::Exact,
                label: d.clone(),
                spec: Some(NetObjectSpec::Domain { pattern: d.clone() }),
                object_id: None,
            });
            // Wildcard on the parent, never on a top-level domain (`*.com`).
            if let Some((_, parent)) = d.split_once('.')
                && parent.contains('.')
            {
                let pattern = format!("*.{parent}");
                destinations.push(ProposedDestination {
                    kind: ProposedDestinationKind::Wildcard,
                    label: pattern.clone(),
                    spec: Some(NetObjectSpec::Domain { pattern }),
                    object_id: None,
                });
            }
        }
        None => destinations.push(ProposedDestination {
            kind: ProposedDestinationKind::Exact,
            label: ip.to_string(),
            spec: Some(NetObjectSpec::Host { ip }),
            object_id: None,
        }),
    }
    let port = flow.dst.port();
    let mut service = ProposedService {
        label: format!("{}/{port}", enum_str(&flow.protocol)),
        service_id: None,
        protocol: flow.protocol,
        port,
    };
    let mut rule_number = None;
    if let Some(doc) = doc {
        for o in &doc.objects {
            if object_matches(doc, o, domain.as_deref(), ip, 0) {
                destinations.push(ProposedDestination {
                    kind: ProposedDestinationKind::Existing,
                    label: o.name.clone(),
                    spec: None,
                    object_id: Some(o.id),
                });
            }
        }
        // Most specific existing service: same protocol, port listed, fewest ports.
        if let Some(s) = doc
            .services
            .iter()
            .filter(|s| s.protocol == flow.protocol)
            .filter(|s| s.ports.iter().any(|r| r.start <= port && port <= r.end))
            .min_by_key(|s| {
                s.ports
                    .iter()
                    .map(|r| u32::from(r.end - r.start) + 1)
                    .sum::<u32>()
            })
        {
            service.label = s.name.clone();
            service.service_id = Some(s.id);
        }
        // Number of a rule inserted at the top of the zone layer.
        let mut hypo = doc.clone();
        hypo.rules.push(Rule {
            id: Uuid::nil(),
            name: String::new(),
            layer: Layer::Zone { zone_id },
            section: None,
            position: 0,
            sources: vec![zone_id],
            destinations: vec![],
            services: vec![],
            data_classes: vec![],
            action: Action::Accept,
            track: Track::Detailed,
            expires_at: None,
            comment: String::new(),
            enabled: true,
        });
        rule_number = hypo.rule_numbers().get(&Uuid::nil()).copied();
    }
    Some(AllowProposal {
        zone_id,
        zone_name: zone_name(doc, Some(zone_id)),
        destinations,
        service,
        rule_number,
    })
}

/// Rule hit counters: `rule id -> (hits, last hit)` over every gateway and revision (lot L7a).
pub async fn rule_stats(
    pool: &PgPool,
) -> Result<HashMap<Uuid, (u64, Option<DateTime<Utc>>)>, ApiError> {
    let rows: Vec<(Uuid, i64, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT rule_id, COALESCE(sum(hits), 0)::bigint, max(last_hit_at) FROM rule_hits \
         GROUP BY rule_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, h, at)| (id, (u64::try_from(h).unwrap_or(0), at)))
        .collect())
}

/// `GET /agents/{id}/overview` (EF-43).
pub async fn agent_overview(
    p: Principal,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentOverview>, ApiError> {
    p.require(Role::Viewer)?;
    let doc = state
        .logs
        .load_policy(None)
        .await
        .ok_or(ApiError::NotFound)?;
    let agent = doc
        .agents
        .iter()
        .find(|a| a.id == id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    let zone = doc
        .zones
        .iter()
        .find(|z| z.id == agent.zone_id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    let store = state.logs.store()?;
    let now = Utc::now();
    let day = store.agent_activity(id, now - Duration::hours(24)).await?;
    let last = store.recent_flows(id, None, 1).await?;
    Ok(Json(AgentOverview {
        agent,
        zone,
        // TODO(L7c): gateway view (`gateways` table of the gateways module).
        gateway: None,
        last_seen_at: last.first().map(|f| f.started_at),
        flows_24h: day.flows,
        denied_24h: day.denied,
        bytes_out_24h: day.bytes_out,
        bytes_in_24h: day.bytes_in,
        top_destinations: store
            .top_destinations(id, now - Duration::days(7), 10)
            .await?,
        recent_denied: store.recent_flows(id, Some(Verdict::Deny), 20).await?,
        recent_tool_calls: store.recent_tool_calls(id, 20).await?,
        alerts: alerts::recent_for_agent(&state, id, 20).await?,
    }))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct MapQuery {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub zone: Option<Uuid>,
    pub period: Option<MapPeriod>,
}

/// Period of the map: `from`/`to` when given, else `period` (default 24 h) ending at `to`/now.
pub fn map_period(
    q: &MapQuery,
    now: DateTime<Utc>,
) -> Result<(DateTime<Utc>, DateTime<Utc>), ApiError> {
    let to = q.to.unwrap_or(now);
    let from = match q.from {
        Some(f) => f,
        None => {
            to - match q.period.unwrap_or(MapPeriod::OneDay) {
                MapPeriod::OneHour => Duration::hours(1),
                MapPeriod::OneDay => Duration::hours(24),
                MapPeriod::SevenDays => Duration::days(7),
            }
        }
    };
    if from >= to {
        return Err(ApiError::BadRequest("from must be before to".into()));
    }
    Ok((from, to))
}

/// `GET /internal-map` (EF-83).
pub async fn internal_map(
    p: Principal,
    State(state): State<AppState>,
    q: Result<Query<MapQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<InternalMap>, ApiError> {
    p.require(Role::Viewer)?;
    let Query(q) = q.map_err(|e| ApiError::BadRequest(e.body_text()))?;
    let (from, to) = map_period(&q, Utc::now())?;
    let rows = state.logs.store()?.internal_edges(from, to, q.zone).await?;
    let doc = state.logs.load_policy(None).await;
    let alert_counts = alerts::count_by_agent_address(&state, from, to).await?;
    let agent_by_ip: HashMap<IpAddr, &afw_core::policy::Agent> = doc
        .iter()
        .flat_map(|d| d.agents.iter())
        .flat_map(|a| a.addresses.iter().map(move |ip| (*ip, a)))
        .collect();
    let mut nodes: BTreeMap<String, MapNode> = BTreeMap::new();
    let agent_node = |id: Uuid, zone: Option<Uuid>| {
        let a = doc
            .as_ref()
            .and_then(|d| d.agents.iter().find(|a| a.id == id));
        MapNode {
            id: id.to_string(),
            label: a.map_or_else(|| id.to_string(), |a| a.name.clone()),
            kind: MapNodeKind::Agent,
            agent_id: Some(id),
            zone_id: a.map(|a| a.zone_id).or(zone),
            address: a.and_then(|a| a.addresses.first()).map(|ip| ip.to_string()),
        }
    };
    let internal_node = |ip: &str| MapNode {
        id: ip.to_owned(),
        label: ip.to_owned(),
        kind: MapNodeKind::Internal,
        agent_id: None,
        zone_id: None,
        address: Some(ip.to_owned()),
    };
    let mut edges = Vec::with_capacity(rows.len());
    for r in rows {
        let source = match r.agent_id {
            Some(a) => {
                nodes
                    .entry(a.to_string())
                    .or_insert_with(|| agent_node(a, r.zone_id));
                a.to_string()
            }
            None => {
                nodes
                    .entry(r.src.clone())
                    .or_insert_with(|| internal_node(&r.src));
                r.src.clone()
            }
        };
        let target = match r
            .dst
            .parse::<IpAddr>()
            .ok()
            .and_then(|ip| agent_by_ip.get(&ip))
        {
            Some(a) => {
                nodes
                    .entry(a.id.to_string())
                    .or_insert_with(|| agent_node(a.id, Some(a.zone_id)));
                a.id.to_string()
            }
            None => {
                nodes
                    .entry(r.dst.clone())
                    .or_insert_with(|| internal_node(&r.dst));
                r.dst.clone()
            }
        };
        let alerts = r
            .agent_id
            .and_then(|a| alert_counts.get(&(a, r.dst.clone())))
            .copied()
            .unwrap_or(0);
        edges.push(MapEdge {
            source,
            target,
            protocol: r.protocol,
            port: r.port,
            app: r.app,
            flows: r.flows,
            bytes: r.bytes,
            alerts,
            first_seen_at: r.first_seen_at,
            last_seen_at: r.last_seen_at,
            new: r.first_seen_at >= from,
        });
    }
    Ok(Json(InternalMap {
        nodes: nodes.into_values().collect(),
        edges,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use afw_core::policy::{L4Proto, PortRange, Service, Zone, ZoneMode};

    fn decision(n: Option<u32>, name: &str, layer: &str) -> DecisionRef {
        DecisionRef {
            rule_id: None,
            rule_number: n,
            rule_name: name.into(),
            revision: Some(3),
            layer: layer.into(),
            reason: String::new(),
        }
    }

    fn flow(verdict: Verdict, domain: Option<&str>) -> FlowEvent {
        FlowEvent {
            id: Uuid::from_u128(9),
            gateway_id: Uuid::nil(),
            agent_id: Some(Uuid::from_u128(1)),
            zone_id: Some(Uuid::from_u128(2)),
            src: "10.0.0.5:40000".parse().unwrap(),
            dst: "93.184.216.34:443".parse().unwrap(),
            protocol: L4Proto::Tcp,
            app: Some(AppProto::Https),
            domain: domain.map(str::to_owned),
            sni: None,
            bytes_out: 1,
            bytes_in: 1,
            started_at: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            ended_at: None,
            verdict,
            decision: decision(Some(12), "web", "zone"),
            internal: false,
            llm_provider: false,
            tls_inspected: true,
            data_classes: vec![],
            observed: false,
            content_inspected: true,
            deny_mode: None,
        }
    }

    #[test]
    fn rule_labels() {
        assert_eq!(
            rule_label(&decision(Some(12), "web", "zone"), Verdict::Allow),
            "12 · web"
        );
        assert_eq!(
            rule_label(&decision(None, "dns", "baseline"), Verdict::Allow),
            "socle · dns"
        );
        assert_eq!(
            rule_label(&decision(None, "cleanup", "implicit"), Verdict::Deny),
            "default-deny"
        );
        assert_eq!(
            rule_label(
                &decision(None, "internal-monitor", "implicit"),
                Verdict::Allow
            ),
            "internal-monitor"
        );
    }

    #[test]
    fn agent_message_follows_ef21_format() {
        let f = flow(Verdict::Deny, Some("api.exemple.com"));
        assert_eq!(
            agent_message(&f, Some("daniel-bot")).as_deref(),
            Some(
                "blocked by agents-firewall: api.exemple.com not allowed for daniel-bot (rule 12)"
            )
        );
        assert_eq!(
            agent_message(&flow(Verdict::Allow, Some("a.b")), None),
            None
        );
        let mut ssh = f.clone();
        ssh.app = Some(AppProto::Ssh);
        assert_eq!(
            agent_message(&ssh, None),
            None,
            "non-HTTP denial is a refused connection"
        );
        let mut opaque = f.clone();
        opaque.tls_inspected = false;
        assert_eq!(agent_message(&opaque, None), None);
        // A proxy CONNECT refused with a 403 (TLS never inspected) did get the message.
        let mut connect = opaque.clone();
        connect.deny_mode = Some(DenyMode::Http403);
        assert!(agent_message(&connect, None).is_some());
        let mut reset = f;
        reset.deny_mode = Some(DenyMode::TcpReset);
        assert_eq!(agent_message(&reset, None), None, "a reset carries no message");
    }

    #[test]
    fn allow_proposal_offers_exact_wildcard_existing_and_rule_number() {
        let zone = Uuid::from_u128(2);
        let other = Uuid::from_u128(3);
        let svc = Uuid::from_u128(50);
        let obj = Uuid::from_u128(60);
        let group = Uuid::from_u128(61);
        let doc = PolicyDocument {
            zones: vec![
                Zone {
                    id: zone,
                    name: "b-bots".into(),
                    comment: String::new(),
                    mode: ZoneMode::Enforce,
                    delegated_to_mcp: false,
                },
                Zone {
                    id: other,
                    name: "a-first".into(),
                    comment: String::new(),
                    mode: ZoneMode::Enforce,
                    delegated_to_mcp: false,
                },
            ],
            objects: vec![
                NetObject {
                    id: obj,
                    name: "exemple".into(),
                    comment: String::new(),
                    category: None,
                    spec: NetObjectSpec::Domain {
                        pattern: "*.exemple.com".into(),
                    },
                },
                NetObject {
                    id: group,
                    name: "partners".into(),
                    comment: String::new(),
                    category: None,
                    spec: NetObjectSpec::Group { members: vec![obj] },
                },
                NetObject {
                    id: Uuid::from_u128(62),
                    name: "any".into(),
                    comment: String::new(),
                    category: None,
                    spec: NetObjectSpec::Any,
                },
            ],
            services: vec![
                Service {
                    id: Uuid::from_u128(51),
                    name: "high".into(),
                    comment: String::new(),
                    protocol: L4Proto::Tcp,
                    ports: vec![PortRange {
                        start: 1,
                        end: 65535,
                    }],
                    app: None,
                },
                Service {
                    id: svc,
                    name: "https".into(),
                    comment: String::new(),
                    protocol: L4Proto::Tcp,
                    ports: vec![PortRange {
                        start: 443,
                        end: 443,
                    }],
                    app: None,
                },
            ],
            rules: vec![
                rule(Uuid::from_u128(100), Layer::Baseline, 0),
                rule(Uuid::from_u128(101), Layer::Zone { zone_id: other }, 0),
                rule(Uuid::from_u128(102), Layer::Zone { zone_id: zone }, 0),
            ],
            ..Default::default()
        };
        let p = allow_proposal(&flow(Verdict::Deny, Some("api.exemple.com")), Some(&doc)).unwrap();
        let kinds: Vec<_> = p
            .destinations
            .iter()
            .map(|d| (d.kind, d.label.as_str()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (ProposedDestinationKind::Exact, "api.exemple.com"),
                (ProposedDestinationKind::Wildcard, "*.exemple.com"),
                (ProposedDestinationKind::Existing, "exemple"),
                (ProposedDestinationKind::Existing, "partners"),
            ]
        );
        assert_eq!(p.service.service_id, Some(svc));
        // Baseline (1), zone a-first (2), then the new rule heads zone b-bots.
        assert_eq!(p.rule_number, Some(3));
        assert_eq!(p.zone_name.as_deref(), Some("b-bots"));
        // No wildcard on a top-level domain, no proposal for allowed flows.
        let p = allow_proposal(&flow(Verdict::Deny, Some("exemple.com")), None).unwrap();
        assert_eq!(p.destinations.len(), 1);
        assert_eq!(p.service.label, "tcp/443");
        assert!(allow_proposal(&flow(Verdict::Allow, Some("a.b.c")), None).is_none());
        let p = allow_proposal(&flow(Verdict::Deny, None), None).unwrap();
        assert_eq!(
            p.destinations[0].spec,
            Some(NetObjectSpec::Host {
                ip: "93.184.216.34".parse().unwrap()
            })
        );
    }

    fn rule(id: Uuid, layer: Layer, position: u32) -> Rule {
        Rule {
            id,
            name: "r".into(),
            layer,
            section: None,
            position,
            sources: vec![],
            destinations: vec![],
            services: vec![],
            data_classes: vec![],
            action: Action::Accept,
            track: Track::Log,
            expires_at: None,
            comment: String::new(),
            enabled: true,
        }
    }

    #[test]
    fn trace_is_recomputed_on_the_revision() {
        use afw_core::api::TraceOutcome as O;
        let zone = Uuid::from_u128(2);
        let obj = Uuid::from_u128(60);
        let mut accept = rule(Uuid::from_u128(100), Layer::Zone { zone_id: zone }, 0);
        accept.name = "other".into();
        accept.sources = vec![zone];
        accept.destinations = vec![obj];
        let mut off = rule(Uuid::from_u128(101), Layer::Zone { zone_id: zone }, 1);
        off.enabled = false;
        off.sources = vec![zone];
        let doc = PolicyDocument {
            zones: vec![Zone {
                id: zone,
                name: "bots".into(),
                comment: String::new(),
                mode: ZoneMode::Enforce,
                delegated_to_mcp: false,
            }],
            agents: vec![afw_core::policy::Agent {
                id: Uuid::from_u128(1),
                name: "bot".into(),
                zone_id: zone,
                kind: afw_core::policy::AgentKind::Container,
                gateway_id: None,
                addresses: vec!["10.0.0.5".parse().unwrap()],
                labels: Default::default(),
                hermes: false,
                mcp_admin: false,
            }],
            objects: vec![NetObject {
                id: obj,
                name: "o".into(),
                comment: String::new(),
                category: None,
                spec: NetObjectSpec::Domain {
                    pattern: "other.org".into(),
                },
            }],
            rules: vec![accept, off],
            ..Default::default()
        };
        let steps = trace(&flow(Verdict::Deny, Some("api.exemple.com")), &doc, 3, None);
        let got: Vec<_> = steps
            .iter()
            .map(|s| (s.rule_label.as_str(), s.outcome))
            .collect();
        assert_eq!(
            got,
            vec![
                ("1 · other", O::NotMatched),
                ("2 · r", O::Skipped),
                ("default-deny", O::Matched)
            ]
        );
        assert_eq!(steps[0].reason, "destination does not match");
    }

    #[test]
    fn map_period_defaults_and_shortcuts() {
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let (f, t) = map_period(&MapQuery::default(), now).unwrap();
        assert_eq!((t - f, t), (Duration::hours(24), now));
        let q = MapQuery {
            period: Some(MapPeriod::SevenDays),
            ..Default::default()
        };
        assert_eq!(map_period(&q, now).unwrap().0, now - Duration::days(7));
        let q = MapQuery {
            from: Some(now),
            to: Some(now),
            ..Default::default()
        };
        assert!(map_period(&q, now).is_err());
    }
}
