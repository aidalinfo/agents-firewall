//! Filtering DNS (`:53` UDP and TCP, EF-31). A name may be resolved when the policy would
//! allow the agent to reach it (ADR 0018): a DNS-service decision first; when that only hits
//! the cleanup rule, the services of the policy are tried for the name (without resolving it),
//! then, for enrolled agents' names only, the internal monitor on the resolved addresses.
//! Refused names get `REFUSED` and are never resolved upstream. Answers come from the
//! gateway's own resolver and are remembered per agent (name attribution of later raw TCP
//! connections). Every query is logged.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use afw_core::events::{DnsEvent, GatewayEvent, Verdict};
use afw_core::policy::{AppProto, L4Proto};
use chrono::Utc;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType, rdata};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use uuid::Uuid;

use crate::engine::{Decision, FlowContext, Implicit};
use crate::state::GatewayState;
use crate::upstream::{is_cloud_metadata, normalize};

pub const ANSWER_TTL: u32 = 60;

pub async fn serve_udp(state: Arc<GatewayState>, sock: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let query = buf[..n].to_vec();
        let (state, sock) = (state.clone(), sock.clone());
        tokio::spawn(async move {
            if let Some(resp) = answer(&state, src, &query).await {
                let _ = sock.send_to(&resp, src).await;
            }
        });
    }
}

pub async fn serve_tcp(state: Arc<GatewayState>, listener: TcpListener) {
    loop {
        let Ok((mut s, src)) = listener.accept().await else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 2];
                let read = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    s.read_exact(&mut len),
                )
                .await;
                if !matches!(read, Ok(Ok(_))) {
                    return;
                }
                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                if s.read_exact(&mut q).await.is_err() {
                    return;
                }
                let Some(resp) = answer(&state, src, &q).await else {
                    return;
                };
                if s.write_all(&(resp.len() as u16).to_be_bytes())
                    .await
                    .is_err()
                    || s.write_all(&resp).await.is_err()
                {
                    return;
                }
            }
        });
    }
}

fn reply(query: &Message, code: ResponseCode, answers: Vec<Record>) -> Option<Vec<u8>> {
    let mut m = Message::new();
    m.set_id(query.id())
        .set_message_type(MessageType::Response)
        .set_op_code(query.op_code())
        .set_recursion_desired(query.recursion_desired())
        .set_recursion_available(true)
        .set_response_code(code);
    m.add_queries(query.queries().to_vec());
    m.add_answers(answers);
    m.to_vec().ok()
}

fn ctx(
    agent: IpAddr,
    name: &str,
    l4: L4Proto,
    port: u16,
    app: Option<AppProto>,
    ip: Option<IpAddr>,
) -> FlowContext {
    FlowContext {
        agent_ip: agent,
        dst_ip: ip,
        dst_ip_trusted: ip.is_some(),
        dst_port: port,
        l4,
        app,
        host: Some(name.to_string()),
        method: None,
        path: None,
        data_classes: vec![],
        now: Utc::now(),
    }
}

/// Policy decision for resolving `name` (see module docs).
async fn decide_name(
    state: &GatewayState,
    agent: IpAddr,
    name: &str,
) -> (Decision, Option<Vec<IpAddr>>) {
    let (d, active) = state.decide(&ctx(
        agent,
        name,
        L4Proto::Udp,
        53,
        Some(AppProto::Dns),
        None,
    ));
    if d.verdict == Verdict::Allow || d.implicit != Some(Implicit::Cleanup) {
        return (d, None);
    }
    // Only the cleanup rule refused the DNS service: would any service of the policy allow
    // a connection to this name?
    if let Some(p) = &active.installed {
        for svc in &p.document.services {
            let l4 = if svc.protocol == L4Proto::Any {
                L4Proto::Tcp
            } else {
                svc.protocol
            };
            let port = svc.ports.first().map(|r| r.start).unwrap_or(443);
            let app = svc.app.as_ref().map(|a| a.proto);
            let (d2, _) = state.decide(&ctx(agent, name, l4, port, app, None));
            if d2.verdict == Verdict::Allow || d2.needs_l7 {
                return (d2, None);
            }
        }
        for (port, app) in [(443, AppProto::Https), (80, AppProto::Http)] {
            let (d2, _) = state.decide(&ctx(agent, name, L4Proto::Tcp, port, Some(app), None));
            if d2.verdict == Verdict::Allow || d2.needs_l7 {
                return (d2, None);
            }
        }
    }
    // A refused name is never sent upstream (exfiltration through the query name). Names
    // matching an `internal` object are already accepted by the engine (internal monitor);
    // the only other internal names resolved are those of enrolled agents (`<agent>` or
    // `<agent>.<domain>`), accepted when every address is a monitored internal one.
    let is_agent_name = active.installed.as_ref().is_some_and(|p| {
        p.document.agents.iter().any(|a| {
            let n = a.name.to_ascii_lowercase();
            name == n || name.strip_prefix(n.as_str()).is_some_and(|r| r.starts_with('.'))
        })
    });
    if !is_agent_name {
        return (d, None);
    }
    if let Ok(ips) = state.resolver.lookup(name).await
        && !ips.is_empty()
    {
        let mut last = None;
        for ip in &ips {
            let (d2, _) = state.decide(&ctx(
                agent,
                name,
                L4Proto::Udp,
                53,
                Some(AppProto::Dns),
                Some(*ip),
            ));
            if d2.verdict != Verdict::Allow {
                return (d, None);
            }
            last = Some(d2);
        }
        if let Some(d2) = last {
            return (d2, Some(ips));
        }
    }
    (d, None)
}

/// Builds the answer to one DNS query from `src`. `None` = drop (unparsable).
pub async fn answer(state: &GatewayState, src: SocketAddr, raw: &[u8]) -> Option<Vec<u8>> {
    let query = Message::from_vec(raw).ok()?;
    if query.message_type() != MessageType::Query {
        return None;
    }
    state.metrics.dns_queries.fetch_add(1, Ordering::Relaxed);
    let Some(q) = query.queries().first().cloned() else {
        return reply(&query, ResponseCode::FormErr, vec![]);
    };
    let qname = normalize(&q.name().to_ascii());
    let qtype = q.query_type();
    let agent = src.ip();
    let (mut d, pre) = decide_name(state, agent, &qname).await;
    if state.metadata_blocked(&d, None, Some(&qname)) {
        state.alerts.cloud_metadata(d.agent_id, &qname);
        d.verdict = Verdict::Deny;
    }
    let log = |verdict: Verdict, d: &Decision, answers: Vec<String>| {
        if verdict == Verdict::Deny {
            state.metrics.denied_total.fetch_add(1, Ordering::Relaxed);
            state.alerts.on_deny(d.agent_id);
        }
        state.events.emit(GatewayEvent::Dns(DnsEvent {
            id: Uuid::now_v7(),
            gateway_id: state.gateway_id,
            agent_id: d.agent_id,
            zone_id: d.zone_id,
            at: Utc::now(),
            qname: qname.clone(),
            qtype: qtype.to_string(),
            answers,
            verdict,
            decision: d.to_ref(),
        }));
    };
    if d.verdict != Verdict::Allow {
        log(Verdict::Deny, &d, vec![]);
        return reply(&query, ResponseCode::Refused, vec![]);
    }
    match qtype {
        RecordType::A | RecordType::AAAA | RecordType::ANY => {
            let ips = match pre {
                Some(ips) => Ok(ips),
                None => state.resolver.lookup(&qname).await,
            };
            let ips = match ips {
                Ok(ips) => ips,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    log(Verdict::Allow, &d, vec![]);
                    return reply(&query, ResponseCode::NXDomain, vec![]);
                }
                Err(_) => {
                    log(Verdict::Allow, &d, vec![]);
                    return reply(&query, ResponseCode::ServFail, vec![]);
                }
            };
            // A metadata address behind a name is never handed out (ADR 0018).
            let meta = ips.iter().any(|i| is_cloud_metadata(*i));
            if meta
                && state.metadata_blocked(
                    &d,
                    ips.iter().copied().find(|i| is_cloud_metadata(*i)),
                    None,
                )
            {
                state.alerts.cloud_metadata(d.agent_id, &qname);
                let mut dd = d.clone();
                dd.verdict = Verdict::Deny;
                log(Verdict::Deny, &dd, vec![]);
                return reply(&query, ResponseCode::Refused, vec![]);
            }
            let mut records = Vec::new();
            let mut shown = Vec::new();
            for ip in ips {
                let rdata = match (ip, qtype) {
                    (IpAddr::V4(v4), RecordType::A | RecordType::ANY) => RData::A(rdata::A(v4)),
                    (IpAddr::V6(v6), RecordType::AAAA | RecordType::ANY) => {
                        RData::AAAA(rdata::AAAA(v6))
                    }
                    _ => continue,
                };
                state.dns_cache.insert(agent, ip, &qname);
                shown.push(ip.to_string());
                records.push(Record::from_rdata(q.name().clone(), ANSWER_TTL, rdata));
            }
            log(Verdict::Allow, &d, shown);
            reply(&query, ResponseCode::NoError, records)
        }
        _ => match state.resolver.forward(raw).await {
            Some(resp) => {
                log(Verdict::Allow, &d, vec![]);
                Some(resp)
            }
            None => {
                log(Verdict::Allow, &d, vec![]);
                reply(&query, ResponseCode::NotImp, vec![])
            }
        },
    }
}
