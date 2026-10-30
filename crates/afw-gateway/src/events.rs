//! Event pipeline: bounded in-memory queue with disk overflow, rule hit aggregation, and a
//! broadcast channel (live observers, tests).

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use afw_core::events::{GatewayEvent, RuleHit};
use chrono::Utc;
use tokio::sync::{Notify, broadcast};
use uuid::Uuid;

/// Events kept in memory before spilling to disk.
pub const MEMORY_CAPACITY: usize = 10_000;
/// Maximum size of the disk spool; beyond, events are dropped (and counted).
pub const SPOOL_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Batch size sent to the console.
pub const BATCH_MAX: usize = 500;

pub struct EventSink {
    tx: broadcast::Sender<GatewayEvent>,
    queue: Mutex<VecDeque<GatewayEvent>>,
    spool: Option<PathBuf>,
    hits: Mutex<HashMap<Uuid, RuleHit>>,
    pub notify: Notify,
    pub dropped: AtomicU64,
    pub spooled: AtomicU64,
}

impl EventSink {
    pub fn new(spool: Option<PathBuf>) -> Self {
        let (tx, _) = broadcast::channel(4096);
        Self {
            tx,
            queue: Mutex::new(VecDeque::new()),
            spool,
            hits: Mutex::new(HashMap::new()),
            notify: Notify::new(),
            dropped: AtomicU64::new(0),
            spooled: AtomicU64::new(0),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<GatewayEvent> {
        self.tx.subscribe()
    }

    pub fn emit(&self, ev: GatewayEvent) {
        let _ = self.tx.send(ev.clone());
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        q.push_back(ev);
        if q.len() >= MEMORY_CAPACITY {
            let spill: Vec<GatewayEvent> = q.drain(..).collect();
            drop(q);
            self.spill(spill);
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

    fn spill(&self, events: Vec<GatewayEvent>) {
        let Some(path) = &self.spool else {
            self.dropped.fetch_add(events.len() as u64, Ordering::Relaxed);
            return;
        };
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if size >= SPOOL_MAX_BYTES {
            self.dropped.fetch_add(events.len() as u64, Ordering::Relaxed);
            tracing::warn!(n = events.len(), "event spool full: dropping events");
            return;
        }
        let res = (|| -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
            let mut buf = Vec::new();
            for e in &events {
                serde_json::to_writer(&mut buf, e)?;
                buf.push(b'\n');
            }
            f.write_all(&buf)?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                self.spooled.fetch_add(events.len() as u64, Ordering::Relaxed);
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot spool events");
                self.dropped.fetch_add(events.len() as u64, Ordering::Relaxed);
            }
        }
    }

    /// Takes up to `max` events (spooled ones first) plus the aggregated rule hits.
    pub fn take_batch(&self, max: usize) -> Vec<GatewayEvent> {
        let mut out = Vec::new();
        if let Some(path) = &self.spool
            && let Ok(f) = std::fs::File::open(path)
        {
            let mut rest = Vec::new();
            for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
                if let Ok(ev) = serde_json::from_str::<GatewayEvent>(&line) {
                    if out.len() < max {
                        out.push(ev);
                    } else {
                        rest.push(ev);
                    }
                }
            }
            let _ = std::fs::remove_file(path);
            self.spooled.store(0, Ordering::Relaxed);
            if !rest.is_empty() {
                self.spill(rest);
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
        out
    }

    /// Puts back a batch that could not be delivered (in front of the queue).
    pub fn requeue(&self, batch: Vec<GatewayEvent>) {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        for ev in batch.into_iter().rev() {
            q.push_front(ev);
        }
        if q.len() >= MEMORY_CAPACITY {
            let spill: Vec<GatewayEvent> = q.drain(..).collect();
            drop(q);
            self.spill(spill);
        }
    }

    pub fn queued(&self) -> u64 {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).len() as u64 + self.spooled.load(Ordering::Relaxed)
    }
}
