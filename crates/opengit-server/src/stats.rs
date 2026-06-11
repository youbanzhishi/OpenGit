//! Server statistics — Track operational metrics
//!
//! P2: Lightweight counters for monitoring server activity.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Server statistics with atomic counters
#[derive(Debug)]
pub struct ServerStats {
    pub total_pushes: AtomicU64,
    pub total_clones: AtomicU64,
    pub total_denials: AtomicU64,
    pub total_webhooks_sent: AtomicU64,
    pub started_at: Instant,
}

impl ServerStats {
    pub fn new() -> Self {
        Self {
            total_pushes: AtomicU64::new(0),
            total_clones: AtomicU64::new(0),
            total_denials: AtomicU64::new(0),
            total_webhooks_sent: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }

    pub fn record_push(&self) {
        self.total_pushes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_clone(&self) {
        self.total_clones.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_denial(&self) {
        self.total_denials.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_webhook(&self) {
        self.total_webhooks_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            total_pushes: self.total_pushes.load(Ordering::Relaxed),
            total_clones: self.total_clones.load(Ordering::Relaxed),
            total_denials: self.total_denials.load(Ordering::Relaxed),
            total_webhooks_sent: self.total_webhooks_sent.load(Ordering::Relaxed),
            uptime_seconds: self.started_at.elapsed().as_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsSnapshot {
    pub total_pushes: u64,
    pub total_clones: u64,
    pub total_denials: u64,
    pub total_webhooks_sent: u64,
    pub uptime_seconds: u64,
}

impl Default for ServerStats {
    fn default() -> Self {
        Self::new()
    }
}
