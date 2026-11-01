//! `GET /logs/stream`: live events as Server-Sent Events, fed by a `tokio::sync::broadcast`
//! channel on the ingestion. `event:` is the GatewayEvent type, `data:` its JSON. HTTP events
//! never carry contents on the stream (read them in the audited flow detail).

use std::convert::Infallible;
use std::sync::Arc;

use afw_core::api::Role;
use afw_core::events::{GatewayEvent, Verdict};
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::{Stream, StreamExt};
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

use super::routes::query;
use super::store::Destination;
use crate::AppState;
use crate::auth::Principal;
use crate::error::ApiError;

#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct StreamQuery {
    pub agent: Option<Uuid>,
    pub zone: Option<Uuid>,
    pub destination: Option<String>,
    pub verdict: Option<Verdict>,
    pub rule: Option<Uuid>,
}

/// Filter of the stream. A filter on a dimension an event does not carry (e.g. `zone` for an
/// HTTP event) excludes that event.
#[derive(Debug, Default)]
pub struct StreamFilter {
    pub agent: Option<Uuid>,
    pub zone: Option<Uuid>,
    pub destination: Option<Destination>,
    pub verdict: Option<Verdict>,
    pub rule: Option<Uuid>,
}

fn ok<T: PartialEq>(want: Option<T>, have: Option<T>) -> bool {
    want.is_none() || (have.is_some() && want == have)
}

impl StreamFilter {
    pub fn matches(&self, ev: &GatewayEvent) -> bool {
        match ev {
            GatewayEvent::Flow(f) => {
                ok(self.agent, f.agent_id)
                    && ok(self.zone, f.zone_id)
                    && ok(self.verdict, Some(f.verdict))
                    && ok(self.rule, f.decision.rule_id)
                    && self.destination.as_ref().is_none_or(|d| {
                        d.matches_ip(f.dst.ip())
                            || d.matches_domain(f.domain.as_deref())
                            || d.matches_domain(f.sni.as_deref())
                    })
            }
            GatewayEvent::Dns(e) => {
                ok(self.agent, e.agent_id)
                    && ok(self.zone, e.zone_id)
                    && ok(self.verdict, Some(e.verdict))
                    && ok(self.rule, e.decision.rule_id)
                    && self.destination.as_ref().is_none_or(|d| {
                        d.matches_domain(Some(&e.qname))
                            || e.answers
                                .iter()
                                .filter_map(|a| a.parse().ok())
                                .any(|ip| d.matches_ip(ip))
                    })
            }
            GatewayEvent::Http(h) => {
                ok(self.agent, h.agent_id)
                    && self.zone.is_none()
                    && self.verdict.is_none()
                    && self.rule.is_none()
                    && self
                        .destination
                        .as_ref()
                        .is_none_or(|d| d.matches_domain(Some(&h.host)))
            }
            GatewayEvent::Alert(a) => {
                ok(self.agent, a.agent_id)
                    && self.zone.is_none()
                    && self.verdict.is_none()
                    && self.rule.is_none()
                    && self.destination.is_none()
            }
            GatewayEvent::RuleHits { .. } => false,
        }
    }
}

fn event_name(ev: &GatewayEvent) -> &'static str {
    match ev {
        GatewayEvent::Flow(_) => "flow",
        GatewayEvent::Dns(_) => "dns",
        GatewayEvent::Http(_) => "http",
        GatewayEvent::Alert(_) => "alert",
        GatewayEvent::RuleHits { .. } => "rule_hits",
    }
}

pub async fn stream(
    p: Principal,
    State(state): State<AppState>,
    q: Result<Query<StreamQuery>, QueryRejection>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    p.require(Role::Viewer)?;
    let q = query(q)?;
    let destination = match q.destination.as_deref() {
        None | Some("") => None,
        Some(d) => Some(
            Destination::parse(d)
                .ok_or_else(|| ApiError::BadRequest("invalid destination".into()))?,
        ),
    };
    let filter = Arc::new(StreamFilter {
        agent: q.agent,
        zone: q.zone,
        destination,
        verdict: q.verdict,
        rule: q.rule,
    });
    let rx = state.logs.events.subscribe();
    let events = futures::stream::unfold((rx, filter), |(mut rx, filter)| async move {
        loop {
            match rx.recv().await {
                Ok(mut ev) => {
                    if !filter.matches(&ev) {
                        continue;
                    }
                    if let GatewayEvent::Http(h) = &mut ev {
                        // Defense in depth: never stream contents.
                        h.request_headers.clear();
                        h.response_headers.clear();
                        h.request_body = None;
                        h.response_body = None;
                    }
                    let data = serde_json::to_string(&ev).unwrap_or_default();
                    let sse = Event::default().event(event_name(&ev)).data(data);
                    return Some((Ok(sse), (rx, filter)));
                }
                Err(RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "log stream subscriber lagging");
                    let sse = Event::default()
                        .event("lagged")
                        .data(serde_json::json!({"skipped": n}).to_string());
                    return Some((Ok(sse), (rx, filter)));
                }
                Err(RecvError::Closed) => return None,
            }
        }
    });
    // Bounded lifetime: the client reconnects, which authenticates its token again.
    let events = events.take_until(tokio::time::sleep(state.logs.stream_max));
    Ok(Sse::new(events).keep_alive(KeepAlive::default()))
}
