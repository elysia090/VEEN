use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;

#[derive(Clone)]
pub struct HubObservability {
    started_at: Instant,
    submit_ok_total: Arc<AtomicU64>,
    submit_err_total: Arc<dashmap::DashMap<String, AtomicU64>>,
}

impl HubObservability {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            submit_ok_total: Arc::new(AtomicU64::new(0)),
            submit_err_total: Arc::new(dashmap::DashMap::new()),
        }
    }

    pub fn record_submit_ok(&self) {
        self.submit_ok_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_submit_err(&self, code: &str) {
        let entry = self
            .submit_err_total
            .entry(code.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        entry.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ObservabilitySnapshot {
        let mut errors = BTreeMap::new();
        for item in self.submit_err_total.iter() {
            errors.insert(item.key().clone(), item.value().load(Ordering::Relaxed));
        }
        ObservabilitySnapshot {
            uptime: self.started_at.elapsed(),
            submit_ok_total: self.submit_ok_total.load(Ordering::Relaxed),
            submit_err_total: errors,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ObservabilitySnapshot {
    #[serde(with = "humantime_serde")]
    pub uptime: Duration,
    pub submit_ok_total: u64,
    pub submit_err_total: BTreeMap<String, u64>,
}
