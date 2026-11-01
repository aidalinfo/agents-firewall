//! Event pipeline: bounded in-memory queue, asynchronous append-only disk spool, rule hit
//! aggregation, and a broadcast channel (live observers, tests).
//!
//! Traceability over availability: when the backlog exceeds what the gateway can keep (memory
//! queue full and disk spool full or not writable), the sink becomes **saturated** and the
//! gateway refuses NEW flows (`GatewayState::decide`) instead of letting traffic through
//! unlogged; an alert is raised when saturation starts and when it ends.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use afw_core::events::{AlertEvent, AlertKind, GatewayEvent, RuleHit, Severity};
use chrono::Utc;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Notify, broadcast, mpsc};
use uuid::Uuid;

/// Events kept in memory before spilling to disk.
pub const MEMORY_CAPACITY: usize = 10_000;
/// Maximum size of the disk spool.
pub const SPOOL_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Batch size sent to the console.
pub const BATCH_MAX: usize = 500;

pub struct EventSink {
    tx: broadcast::Sender<GatewayEvent>,
    queue: Mutex<VecDeque<GatewayEvent>>,
    spool_path: Option<PathBuf>,
    spool_tx: OnceLock<mpsc::Sender<Vec<GatewayEvent>>>,
    /// Serialises access to the spool file (appends vs. reads + truncation).
    spool_lock: tokio::sync::Mutex<()>,
    spool_bytes: AtomicU64,
    hits: Mutex<HashMap<Uuid, RuleHit>>,
    saturated: AtomicBool,
    capacity: usize,
    pub notify: Notify,
    pub dropped: AtomicU64,
    pub spooled: AtomicU64,
}

impl EventSink {
    pub fn new(spool: Option<PathBuf>) -> Self {
        Self::with_capacity(spool, MEMORY_CAPACITY)
    }

    pub fn with_capacity(spool: Option<PathBuf>, capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(4096);
        let spool_bytes = spool
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .unwrap_or(0);
        Self {
            tx,
            queue: Mutex::new(VecDeque::new()),
            spool_path: spool,
            spool_tx: OnceLock::new(),
            spool_lock: tokio::sync::Mutex::new(()),
            spool_bytes: AtomicU64::new(spool_bytes),
            hits: Mutex::new(HashMap::new()),
            saturated: AtomicBool::new(false),
            capacity,
            notify: Notify::new(),
            dropped: AtomicU64::new(0),
            spooled: AtomicU64::new(0),
        }
    }

    /// Starts the asynchronous spool writer (call once, inside the runtime).
    pub fn start(self: &std::sync::Arc<Self>) {
        let Some(path) = self.spool_path.clone() else {
            return;
        };
        let (tx, mut rx) = mpsc::channel::<Vec<GatewayEvent>>(8);
        if self.spool_tx.set(tx).is_err() {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            while let Some(batch) = rx.recv().await {
                let n = batch.len() as u64;
                let mut buf = Vec::new();
                for e in &batch {
                    if serde_json::to_writer(&mut buf, e).is_ok() {
                        buf.push(b'\n');
                    }
                }
                let _guard = me.spool_lock.lock().await;
                if me.spool_bytes.load(Ordering::Relaxed) + buf.len() as u64 > SPOOL_MAX_BYTES {
                    me.lose(n, "event spool full");
                    continue;
                }
                let res = async {
                    let mut f = tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                        .await?;
                    f.write_all(&buf).await?;
                    f.flush().await
                }
                .await;
                match res {
                    Ok(()) => {
                        me.spool_bytes
                            .fetch_add(buf.len() as u64, Ordering::Relaxed);
                        me.spooled.fetch_add(n, Ordering::Relaxed);
                    }
                    Err(e) => me.lose(n, &format!("cannot spool events: {e}")),
                }
            }
        });
    }

    pub fn subscribe(&self) -> broadcast::Receiver<GatewayEvent> {
        self.tx.subscribe()
    }

    /// `true` while events are being lost: the gateway then refuses new flows.
    pub fn saturated(&self) -> bool {
        self.saturated.load(Ordering::Relaxed)
    }

    fn lose(&self, n: u64, why: &str) {
        self.dropped.fetch_add(n, Ordering::Relaxed);
        if !self.saturated.swap(true, Ordering::Relaxed) {
            tracing::error!(
                why,
                "event backlog saturated: refusing new flows until it drains"
            );
            self.push(alert(
                Severity::Critical,
                format!("event backlog saturated ({why}): new flows are refused until events are delivered"),
            ));
        }
    }

    pub fn emit(&self, ev: GatewayEvent) {
        let _ = self.tx.send(ev.clone());
        self.push(ev);
    }

    fn push(&self, ev: GatewayEvent) {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        q.push_back(ev);
        if q.len() >= self.capacity {
            let spill: Vec<GatewayEvent> = q.drain(..).collect();
            drop(q);
            let n = spill.len() as u64;
            match self.spool_tx.get() {
                Some(tx) => {
                    if tx.try_send(spill).is_err() {
                        self.lose(n, "event spool busy");
                    }
                }
                None => self.lose(n, "no event spool"),
            }
        } else if q.len() >= BATCH_MAX {
            self.notify.notify_one();
        }
    }

    /// Counts a rule hit (aggregated into a `RuleHits` event at the next batch).
    pub fn rule_hit(&self, rule_id: Uuid, revision: u64) {
        let mut h = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        let e = h.entry(rule_id).or_insert(RuleHit {
            rule_id,
            revision,
            hits: 0,
            last_hit_at: Utc::now(),
        });
        e.hits += 1;
        e.revision = revision;
        e.last_hit_at = Utc::now();
    }

    /// Takes up to `max` events (spooled ones first) plus the aggregated rule hits.
    pub async fn take_batch(&self, max: usize) -> Vec<GatewayEvent> {
        let mut out = Vec::new();
        if let Some(path) = &self.spool_path
            && self.spool_bytes.load(Ordering::Relaxed) > 0
        {
            let _guard = self.spool_lock.lock().await;
            if let Ok(text) = tokio::fs::read_to_string(path).await {
                let mut rest = String::new();
                for line in text.lines() {
                    if out.len() < max {
                        if let Ok(ev) = serde_json::from_str::<GatewayEvent>(line) {
                            out.push(ev);
                        }
                    } else {
                        rest.push_str(line);
                        rest.push('\n');
                    }
                }
                // Rewrite the remainder (rare: more than one batch spooled).
                let ok = if rest.is_empty() {
                    tokio::fs::remove_file(path).await.is_ok()
                } else {
                    tokio::fs::write(path, rest.as_bytes()).await.is_ok()
                };
                if ok {
                    self.spool_bytes.store(rest.len() as u64, Ordering::Relaxed);
                    if rest.is_empty() {
                        self.spooled.store(0, Ordering::Relaxed);
                    }
                }
            }
        }
        {
            let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
            while out.len() < max {
                match q.pop_front() {
                    Some(e) => out.push(e),
                    None => break,
                }
            }
        }
        let hits: Vec<RuleHit> = self
            .hits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .map(|(_, v)| v)
            .collect();
        if !hits.is_empty() {
            out.push(GatewayEvent::RuleHits { hits });
        }
        self.check_recovery();
        out
    }

    /// Leaves saturation once the backlog is back under half of its bounds.
    fn check_recovery(&self) {
        if !self.saturated() {
            return;
        }
        let q = self.queue.lock().unwrap_or_else(|e| e.into_inner()).len();
        if q < self.capacity / 2 && self.spool_bytes.load(Ordering::Relaxed) < SPOOL_MAX_BYTES / 2 {
            self.saturated.store(false, Ordering::Relaxed);
            tracing::warn!("event backlog drained: accepting new flows again");
            self.push(alert(
                Severity::Warning,
                format!(
                    "event backlog drained: new flows accepted again ({} events were lost)",
                    self.dropped.load(Ordering::Relaxed)
                ),
            ));
        }
    }

    /// Puts back a batch that could not be delivered (in front of the queue).
    pub fn requeue(&self, batch: Vec<GatewayEvent>) {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        for ev in batch.into_iter().rev() {
            q.push_front(ev);
        }
        let overflow = q.len().saturating_sub(self.capacity);
        if overflow > 0 {
            let spill: Vec<GatewayEvent> = q.drain(..overflow).collect();
            drop(q);
            let n = spill.len() as u64;
            match self.spool_tx.get() {
                Some(tx) if tx.try_send(spill).is_ok() => {}
                _ => self.lose(n, "event spool busy"),
            }
        }
    }

    pub fn queued(&self) -> u64 {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).len() as u64
            + self.spooled.load(Ordering::Relaxed)
    }
}

fn alert(severity: Severity, summary: String) -> GatewayEvent {
    GatewayEvent::Alert(AlertEvent {
        id: Uuid::now_v7(),
        at: Utc::now(),
        // No dedicated kind in the contract: a backlog is a volume problem.
        kind: AlertKind::VolumeSpike,
        severity,
        agent_id: None,
        summary,
        details: serde_json::json!({"source": "gateway-event-backlog"}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev() -> GatewayEvent {
        alert(Severity::Info, "x".into())
    }

    #[tokio::test]
    async fn saturation_then_recovery() {
        // No spool: overflowing the memory queue loses events => saturated.
        let sink = std::sync::Arc::new(EventSink::with_capacity(None, 10));
        for _ in 0..10 {
            sink.emit(ev());
        }
        assert!(sink.saturated());
        assert!(sink.dropped.load(Ordering::Relaxed) >= 10);
        let batch = sink.take_batch(100).await;
        assert!(!sink.saturated(), "drained => recovered");
        assert!(
            batch
                .iter()
                .any(|e| matches!(e, GatewayEvent::Alert(a) if a.summary.contains("saturated")))
        );
        let next = sink.take_batch(100).await;
        assert!(
            next.iter()
                .any(|e| matches!(e, GatewayEvent::Alert(a) if a.summary.contains("drained")))
        );
    }

    #[tokio::test]
    async fn spool_is_appended_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let sink = std::sync::Arc::new(EventSink::with_capacity(
            Some(dir.path().join("s.jsonl")),
            5,
        ));
        sink.start();
        for _ in 0..12 {
            sink.emit(ev());
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!sink.saturated());
        let mut total = 0;
        for _ in 0..5 {
            total += sink.take_batch(100).await.len();
        }
        assert_eq!(total, 12);
    }
}
