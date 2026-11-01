//! Flow <-> tool call correlation (ADR 0007), a pure function of the agent's tool calls.
//!
//! - `certain`: exactly one call of the agent is active when the flow starts;
//! - `probable`: several calls are active, the most recently started one is kept;
//! - `uncertain`: no active call, the call that ended closest before the flow, within 5 s.
//!
//! A call blocked by the plugin (`gated`, `denied`, `blocked`) produced no traffic and is never
//! a candidate. A call whose end was never reported is considered active for at most
//! [`MAX_OPEN_CALL`].

use afw_core::api::{Confidence, Correlation};
use afw_core::events::ToolCallEvent;
use chrono::{DateTime, Duration, Utc};

/// Grace period after the end of a call for an `uncertain` attachment.
pub const UNCERTAIN_WINDOW: Duration = Duration::seconds(5);
/// Longest time a call without a reported end is considered active.
pub const MAX_OPEN_CALL: Duration = Duration::hours(1);

/// Statuses of calls that were blocked before running.
const BLOCKED: [&str; 3] = ["gated", "denied", "blocked"];

fn ran(call: &ToolCallEvent) -> bool {
    !call
        .status
        .as_deref()
        .is_some_and(|s| BLOCKED.contains(&s.to_ascii_lowercase().as_str()))
}

fn active_at(call: &ToolCallEvent, at: DateTime<Utc>) -> bool {
    call.started_at <= at
        && match call.ended_at {
            Some(end) => end >= at,
            None => at - call.started_at <= MAX_OPEN_CALL,
        }
}

/// Correlates a flow of the agent starting at `flow_start` with the agent's `calls`.
pub fn correlate(
    flow_start: DateTime<Utc>,
    calls: &[ToolCallEvent],
) -> Option<(&ToolCallEvent, Correlation)> {
    let candidates: Vec<&ToolCallEvent> = calls.iter().filter(|c| ran(c)).collect();
    let active: Vec<&ToolCallEvent> = candidates
        .iter()
        .copied()
        .filter(|c| active_at(c, flow_start))
        .collect();
    let (call, confidence) = match active.len() {
        1 => (active[0], Confidence::Certain),
        0 => {
            let call = candidates
                .iter()
                .copied()
                .filter(|c| {
                    c.ended_at
                        .is_some_and(|e| e < flow_start && flow_start - e <= UNCERTAIN_WINDOW)
                })
                .max_by_key(|c| (c.ended_at, c.started_at, c.id))?;
            (call, Confidence::Uncertain)
        }
        _ => (
            active
                .into_iter()
                .max_by_key(|c| (c.started_at, c.id))
                .expect("non-empty"),
            Confidence::Probable,
        ),
    };
    Some((
        call,
        Correlation {
            tool_call_id: call.id,
            conversation_id: call.conversation_id.clone(),
            confidence,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn t(s: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + s, 0).unwrap()
    }

    fn call(n: u128, start: i64, end: Option<i64>, status: Option<&str>) -> ToolCallEvent {
        ToolCallEvent {
            id: Uuid::from_u128(n),
            agent: "bot".into(),
            conversation_id: format!("conv-{n}"),
            tool: "terminal".into(),
            args_summary: "curl".into(),
            started_at: t(start),
            ended_at: end.map(t),
            status: status.map(str::to_owned),
        }
    }

    fn conf(at: i64, calls: &[ToolCallEvent]) -> Option<(u128, Confidence)> {
        correlate(t(at), calls).map(|(c, k)| (c.id.as_u128(), k.confidence))
    }

    #[test]
    fn single_active_call_is_certain() {
        let calls = [call(1, 0, Some(10), Some("ok")), call(2, 20, None, None)];
        assert_eq!(conf(5, &calls), Some((1, Confidence::Certain)));
        // Open call (start event only) is active.
        assert_eq!(conf(25, &calls), Some((2, Confidence::Certain)));
    }

    #[test]
    fn several_active_calls_are_probable_most_recent_wins() {
        let calls = [
            call(1, 0, Some(30), Some("ok")),
            call(2, 10, Some(40), None),
        ];
        assert_eq!(conf(15, &calls), Some((2, Confidence::Probable)));
    }

    #[test]
    fn closest_call_ended_within_5s_is_uncertain() {
        let calls = [
            call(1, 0, Some(10), Some("ok")),
            call(2, 0, Some(12), Some("ok")),
        ];
        assert_eq!(conf(14, &calls), Some((2, Confidence::Uncertain)));
        assert_eq!(conf(17, &calls), Some((2, Confidence::Uncertain)));
        assert_eq!(conf(18, &calls), None, "more than 5 s after the end");
    }

    #[test]
    fn no_call_or_future_call_gives_nothing() {
        assert_eq!(conf(5, &[]), None);
        assert_eq!(conf(5, &[call(1, 6, None, None)]), None);
    }

    #[test]
    fn blocked_calls_are_never_candidates() {
        let calls = [
            call(1, 0, Some(10), Some("gated")),
            call(2, 0, None, Some("denied")),
            call(3, 0, Some(10), Some("BLOCKED")),
        ];
        assert_eq!(conf(5, &calls), None);
        let calls = [
            call(1, 0, Some(10), Some("gated")),
            call(4, 0, Some(10), Some("error")),
        ];
        assert_eq!(conf(5, &calls), Some((4, Confidence::Certain)));
    }

    #[test]
    fn open_call_expires_after_max_duration() {
        let calls = [call(1, 0, None, None)];
        assert_eq!(conf(3600, &calls), Some((1, Confidence::Certain)));
        assert_eq!(conf(3601, &calls), None);
    }
}
