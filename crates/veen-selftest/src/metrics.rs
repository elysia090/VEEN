use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HubMetricsSnapshot {
    pub submit_ok_total: u64,
    pub submit_err_total: BTreeMap<String, u64>,
    pub verify_latency_ms: HistogramSnapshot,
    pub commit_latency_ms: HistogramSnapshot,
    pub end_to_end_latency_ms: HistogramSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramSnapshot {
    pub count: u64,
    pub sum: f64,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub p95: Option<f64>,
    pub p99: Option<f64>,
}

impl Default for HistogramSnapshot {
    fn default() -> Self {
        Self {
            count: 0,
            sum: 0.0,
            min: None,
            max: None,
            p95: None,
            p99: None,
        }
    }
}

impl HistogramSnapshot {
    pub fn average(&self) -> Option<f64> {
        if self.count == 0 {
            None
        } else {
            Some(self.sum / self.count as f64)
        }
    }

    pub fn record(&mut self, value: f64) {
        self.count = self.count.saturating_add(1);
        self.sum += value;
        self.min = Some(match self.min {
            Some(current) => current.min(value),
            None => value,
        });
        self.max = Some(match self.max {
            Some(current) => current.max(value),
            None => value,
        });
    }

    pub fn from_histogram(hist: &Histogram<u64>, stats: &LatencyStats) -> Self {
        let count = stats.count.load(Ordering::Relaxed);
        if count == 0 {
            return Self::default();
        }
        let sum = stats.sum.load(Ordering::Relaxed) as f64;
        let min = stats.min.load(Ordering::Relaxed);
        let max = stats.max.load(Ordering::Relaxed);
        let p95 = hist.value_at_percentile(95.0) as f64;
        let p99 = hist.value_at_percentile(99.0) as f64;

        Self {
            count,
            sum,
            min: Some(min as f64),
            max: Some(max as f64),
            p95: Some(p95),
            p99: Some(p99),
        }
    }
}

pub struct LatencyRecorder {
    histogram: Histogram<u64>,
    count: AtomicU64,
    sum: AtomicU64,
    min: AtomicU64,
    max: AtomicU64,
}

#[derive(Default)]
pub struct LatencyStats {
    pub count: AtomicU64,
    pub sum: AtomicU64,
    pub min: AtomicU64,
    pub max: AtomicU64,
}

impl LatencyRecorder {
    pub fn with_bounds(low: u64, high: u64, sigfig: u8) -> anyhow::Result<Self> {
        let histogram = Histogram::new_with_bounds(low, high, sigfig)?;
        Ok(Self {
            histogram,
            count: AtomicU64::new(0),
            sum: AtomicU64::new(0),
            min: AtomicU64::new(u64::MAX),
            max: AtomicU64::new(0),
        })
    }

    pub fn record_ms(&mut self, duration_ms: u64) -> anyhow::Result<()> {
        let value = duration_ms.max(1);
        self.histogram.record(value)?;
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(value, Ordering::Relaxed);
        self.min.fetch_min(value, Ordering::Relaxed);
        self.max.fetch_max(value, Ordering::Relaxed);
        Ok(())
    }

    pub fn merge_from(&mut self, other: &LatencyRecorder) -> anyhow::Result<()> {
        let stats = other.stats();
        let count = stats.count.load(Ordering::Relaxed);
        if count == 0 {
            return Ok(());
        }
        self.histogram.add(other.histogram())?;
        self.count.fetch_add(count, Ordering::Relaxed);
        self.sum
            .fetch_add(stats.sum.load(Ordering::Relaxed), Ordering::Relaxed);
        self.min
            .fetch_min(stats.min.load(Ordering::Relaxed), Ordering::Relaxed);
        self.max
            .fetch_max(stats.max.load(Ordering::Relaxed), Ordering::Relaxed);
        Ok(())
    }

    pub fn histogram(&self) -> &Histogram<u64> {
        &self.histogram
    }

    pub fn stats(&self) -> LatencyStats {
        LatencyStats {
            count: AtomicU64::new(self.count.load(Ordering::Relaxed)),
            sum: AtomicU64::new(self.sum.load(Ordering::Relaxed)),
            min: AtomicU64::new(self.min.load(Ordering::Relaxed)),
            max: AtomicU64::new(self.max.load(Ordering::Relaxed)),
        }
    }
}

impl LatencyStats {
    pub fn combine_from(stats: &[LatencyStats]) -> LatencyStats {
        let combined = LatencyStats::default();
        for stat in stats {
            combined
                .count
                .fetch_add(stat.count.load(Ordering::Relaxed), Ordering::Relaxed);
            combined
                .sum
                .fetch_add(stat.sum.load(Ordering::Relaxed), Ordering::Relaxed);
            combined
                .min
                .fetch_min(stat.min.load(Ordering::Relaxed), Ordering::Relaxed);
            combined
                .max
                .fetch_max(stat.max.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        combined
    }
}
