//! Rule engine of agents-firewall (lot L5).
//!
//! [`CompiledPolicy::compile`] turns an [`afw_core::InstalledPolicy`] into a structure that
//! decides each flow ([`CompiledPolicy::evaluate`]) following the frozen evaluation order
//! (plan §3.1, ADR 0005, ADR 0016):
//!
//! 1. baseline rules by position (first match);
//! 2. rules of the agent's zone by position (first match);
//! 3. internal destination not handled by a rule: implicit allow, monitored in detail;
//! 4. implicit cleanup: deny.
//!
//! Then: zone in observe mode turns a denial into an observed allow, except for cloud metadata
//! destinations. Anything the engine cannot evaluate (unknown agent, no policy, malformed host
//! or path) never leads to an allow it would not otherwise give.
//!
//! [`verify`] and [`where_used`] work on a raw [`afw_core::policy::PolicyDocument`] (EF-11,
//! EF-02).

mod compile;
mod matching;
mod verify;

use std::net::IpAddr;

use afw_core::events::{DecisionRef, Verdict};
use afw_core::policy::{AppProto, L4Proto, Track};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use compile::{CompileError, CompiledPolicy};
pub use verify::{Usage, VerifyWarning, verify, verify_warnings, where_used};

/// Everything the gateway knows about a flow when it asks for a decision.
///
/// Missing information (`None`) never satisfies a condition that needs it: a service with
/// methods does not match a flow without `method`. The gateway re-evaluates HTTP(S) requests
/// with method and path once it sees them, and with `data_classes` once the content is scanned.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FlowContext {
    /// Source address; the engine resolves the agent from it.
    pub agent_ip: IpAddr,
    /// Address actually connected to (transparent mode) or resolved by the gateway.
    pub dst_ip: Option<IpAddr>,
    /// Gateway contract (ADR 0016): `true` when `dst_ip` is the address the gateway itself
    /// resolved for `host` (or there is no name) and really connects to; `false` when it is
    /// the original address chosen by the agent while a name is present. With a name and an
    /// untrusted address, no accept by address object, no implicit internal allow, no
    /// inspection bypass and no LLM exemption are granted on that address; deny rules on
    /// addresses still apply.
    pub dst_ip_trusted: bool,
    pub dst_port: u16,
    pub l4: L4Proto,
    pub app: Option<AppProto>,
    /// SNI, `Host` header, CONNECT authority host or DNS query name (without port). An IP
    /// literal is treated as an address when `dst_ip` is absent.
    pub host: Option<String>,
    pub method: Option<String>,
    /// Request target path as sent (`/a/b?q`); normalised by the engine.
    pub path: Option<String>,
    /// Data classes detected in the content.
    pub data_classes: Vec<Uuid>,
    pub now: DateTime<Utc>,
}

/// Layer that took the decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionLayer {
    Baseline,
    Zone,
    Implicit,
}

impl DecisionLayer {
    pub fn as_str(self) -> &'static str {
        match self {
            DecisionLayer::Baseline => "baseline",
            DecisionLayer::Zone => "zone",
            DecisionLayer::Implicit => "implicit",
        }
    }
}

/// Implicit rule that decided when no explicit rule matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Implicit {
    /// Internal destination, allowed and logged in detail (EF-80).
    InternalMonitor,
    /// Default deny at the end of the rulebase.
    Cleanup,
    /// Source address of no enrolled agent.
    UnknownAgent,
    /// The gateway has no valid policy.
    NoPolicy,
}

impl Implicit {
    /// Name shown as the rule name and in the EF-21 denial message.
    pub fn rule_name(self) -> &'static str {
        match self {
            Implicit::InternalMonitor => "internal-monitor",
            Implicit::Cleanup => "default-deny",
            Implicit::UnknownAgent => "unknown-agent",
            Implicit::NoPolicy => "no-policy",
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Implicit::InternalMonitor => "internal destination: allowed and monitored by default",
            Implicit::Cleanup => "no rule matched: default deny",
            Implicit::UnknownAgent => "source address is not an enrolled agent",
            Implicit::NoPolicy => "no valid policy installed",
        }
    }
}

/// Why a rule examined during evaluation did or did not match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceOutcome {
    Matched,
    Disabled,
    Expired,
    SourceMismatch,
    /// Rule with data classes skipped because the destination is an LLM provider (EF-25).
    LlmExempt,
    DataClassMismatch,
    DestinationMismatch,
    ServiceMismatch,
    /// The host or path is malformed: an accept rule depending on it does not apply.
    Indeterminate,
    /// Accept rule that does not name a cloud metadata object or address: it cannot accept a
    /// metadata destination.
    MetadataProtected,
    /// Connection stage: this rule depends on the HTTP method or path, unknown yet.
    NeedsL7,
}

/// One rule examined during evaluation (the console's "evaluation trace").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceStep {
    pub rule_id: Uuid,
    pub rule_number: Option<u32>,
    pub layer: DecisionLayer,
    pub outcome: TraceOutcome,
}

/// Decision on a flow.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub verdict: Verdict,
    pub agent_id: Option<Uuid>,
    pub agent_name: Option<String>,
    pub zone_id: Option<Uuid>,
    pub zone_name: Option<String>,
    pub rule_id: Option<Uuid>,
    /// Displayed rule number (global rank); `None` for implicit decisions.
    pub rule_number: Option<u32>,
    pub rule_name: String,
    pub layer: DecisionLayer,
    pub implicit: Option<Implicit>,
    pub track: Track,
    /// Whether HTTPS to this destination should be decrypted (EF-09).
    pub inspect_tls: bool,
    /// Zone in observe mode: the flow was allowed although the policy denies it (EF-12).
    pub observed: bool,
    pub llm_provider: bool,
    pub internal: bool,
    /// Connection stage (no method nor path): a rule earlier than the deciding one depends on
    /// the HTTP method or path. The gateway must inspect (decrypt HTTPS) and re-evaluate every
    /// request; when such a rule is an accept, `verdict` is a provisional `Allow` given only so
    /// that requests can be evaluated (ADR 0016).
    pub needs_l7: bool,
    /// Policy revision that decided; `None` without a valid policy.
    pub revision: Option<u64>,
    /// Rules examined, in order, and why they (did not) match.
    pub trace: Vec<TraceStep>,
}

impl Decision {
    /// Reference stored in events.
    pub fn to_ref(&self) -> DecisionRef {
        let mut reason = match self.implicit {
            Some(i) => i.reason().to_owned(),
            None => format!(
                "rule matched: {}",
                match self.verdict {
                    Verdict::Allow => "accept",
                    Verdict::Deny => "deny",
                }
            ),
        };
        if self.observed {
            reason = format!("{reason} (observe mode: denial not enforced)");
        }
        if self.needs_l7 {
            reason.push_str("; pending per-request (L7) evaluation");
        }
        if self.llm_provider {
            reason.push_str("; llm provider: data-class rules skipped");
        }
        DecisionRef {
            rule_id: self.rule_id,
            rule_number: self.rule_number,
            rule_name: self.rule_name.clone(),
            revision: self.revision,
            layer: self.layer.as_str().to_owned(),
            reason,
        }
    }

    /// EF-21 denial body: `blocked by agents-firewall: <destination> not allowed for <agent>
    /// (rule <n>)`. Implicit denials name the implicit rule (`default-deny`, `unknown-agent`,
    /// `no-policy`); an unknown agent is shown as `unknown`.
    pub fn deny_message(&self, destination: &str) -> String {
        let agent = self.agent_name.as_deref().unwrap_or("unknown");
        let rule = match (self.rule_number, self.implicit) {
            (Some(n), _) => n.to_string(),
            (None, Some(i)) => i.rule_name().to_owned(),
            (None, None) => self.rule_name.clone(),
        };
        format!("blocked by agents-firewall: {destination} not allowed for {agent} (rule {rule})")
    }
}
