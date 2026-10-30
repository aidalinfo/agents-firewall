//! Counters and decision latency (Prometheus text format on `/metrics`).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const SAMPLES: usize = 4096;

#[derive(Default)]
pub struct Metrics {
    pub flows_total: AtomicU64,
    pub denied_total: AtomicU64,
    pub active_flows: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub dns_queries: AtomicU64,
    pub http_requests: AtomicU64,
    pub content_blocks: AtomicU64,
    latencies_us: Mutex<VecDeque<u64>>,
    /// Latency added by the gateway per request/connection (upstream time excluded).
    added_us: Mutex<VecDeque<u64>>,
    started: Mutex<Option<Instant>>,
}

pub struct ActiveGuard<'a>(&'a Metrics);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.active_flows.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Metrics {
    pub fn new() -> Self {
        let m = Self::default();
        *m.started.lock().unwrap() = Some(Instant::now());
        m
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|s| s.elapsed().as_secs())
            .unwrap_or(0)
    }

    pub fn active(&self) -> ActiveGuard<'_> {
        self.active_flows.fetch_add(1, Ordering::Relaxed);
        ActiveGuard(self)
    }

    pub fn decision_latency(&self, us: u64) {
        let mut l = self.latencies_us.lock().unwrap_or_else(|e| e.into_inner());
        if l.len() == SAMPLES {
            l.pop_front();
        }
        l.push_back(us);
    }

    pub fn added_latency(&self, us: u64) {
        let mut l = self.added_us.lock().unwrap_or_else(|e| e.into_inner());
        if l.len() == SAMPLES {
            l.pop_front();
        }
        l.push_back(us);
    }

    /// (p50, p95) of the latency added by the gateway, in milliseconds.
    pub fn added_percentiles_ms(&self) -> (f64, f64) {
        let (a, b) = pct(&self.added_us);
        (a as f64 / 1000.0, b as f64 / 1000.0)
    }

    /// (p50, p95) of the recent decision latencies, in microseconds.
    pub fn percentiles(&self) -> (u64, u64) {
        pct(&self.latencies_us)
    }

    pub fn render(&self, revision: Option<u64>, events_queued: u64, events_dropped: u64) -> String {
        let (p50, p95) = self.percentiles();
        let (a50, a95) = self.added_percentiles_ms();
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        format!(
            "# TYPE afw_flows_total counter\nafw_flows_total {}\n\
             # TYPE afw_denied_total counter\nafw_denied_total {}\n\
             # TYPE afw_active_flows gauge\nafw_active_flows {}\n\
             # TYPE afw_bytes_in_total counter\nafw_bytes_in_total {}\n\
             # TYPE afw_bytes_out_total counter\nafw_bytes_out_total {}\n\
             # TYPE afw_dns_queries_total counter\nafw_dns_queries_total {}\n\
             # TYPE afw_http_requests_total counter\nafw_http_requests_total {}\n\
             # TYPE afw_content_blocks_total counter\nafw_content_blocks_total {}\n\
             # TYPE afw_decision_latency_us gauge\nafw_decision_latency_us{{quantile=\"0.5\"}} {p50}\nafw_decision_latency_us{{quantile=\"0.95\"}} {p95}\n\
             # TYPE afw_added_latency_ms gauge\nafw_added_latency_ms{{quantile=\"0.5\"}} {a50}\nafw_added_latency_ms{{quantile=\"0.95\"}} {a95}\n\
             # TYPE afw_policy_revision gauge\nafw_policy_revision {}\n\
             # TYPE afw_events_queued gauge\nafw_events_queued {events_queued}\n\
             # TYPE afw_events_dropped_total counter\nafw_events_dropped_total {events_dropped}\n\
             # TYPE afw_uptime_seconds gauge\nafw_uptime_seconds {}\n",
            g(&self.flows_total),
            g(&self.denied_total),
            g(&self.active_flows),
            g(&self.bytes_in),
            g(&self.bytes_out),
            g(&self.dns_queries),
            g(&self.http_requests),
            g(&self.content_blocks),
            revision.map(|r| r as i64).unwrap_or(-1),
            self.uptime_secs(),
        )
    }
}

fn pct(m: &Mutex<VecDeque<u64>>) -> (u64, u64) {
    let mut v: Vec<u64> = m.lock().unwrap_or_else(|e| e.into_inner()).iter().copied().collect();
    if v.is_empty() {
        return (0, 0);
    }
    v.sort_unstable();
    let at = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize];
    (at(0.5), at(0.95))
}
