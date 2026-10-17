//! Mutable crawl statistics accumulated during a job run.

use std::sync::Mutex;
use std::time::Instant;

use super::types::CrawlStats;

pub struct StatsTracker {
    started: Instant,
    inner: Mutex<CrawlStats>,
}

impl StatsTracker {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            inner: Mutex::new(CrawlStats::default()),
        }
    }

    pub fn record_request(&self, duration_ms: f64, status: Option<u16>) {
        let Ok(mut stats) = self.inner.lock() else {
            return;
        };
        stats.requests_total += 1;
        stats.requests_finished += 1;
        stats.total_response_time_ms += duration_ms;
        stats.avg_response_time_ms =
            stats.total_response_time_ms / stats.requests_finished.max(1) as f64;
        stats.max_response_time_ms = stats.max_response_time_ms.max(duration_ms);
        stats.min_response_time_ms = if stats.requests_finished == 1 {
            duration_ms
        } else {
            stats.min_response_time_ms.min(duration_ms)
        };
        if let Some(status) = status {
            *stats.requests_with_status_code.entry(status).or_insert(0) += 1;
        }
    }

    pub fn record_failure(&self, error_type: &str) {
        let Ok(mut stats) = self.inner.lock() else {
            return;
        };
        stats.requests_total += 1;
        stats.requests_failed += 1;
        *stats
            .errors_per_type
            .entry(error_type.to_string())
            .or_insert(0) += 1;
    }

    pub fn record_retry(&self) {
        if let Ok(mut stats) = self.inner.lock() {
            stats.requests_retried += 1;
        }
    }

    pub fn snapshot(&self) -> CrawlStats {
        let mut stats = match self.inner.lock() {
            Ok(stats) => stats.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        stats.crawler_runtime_ms = self.started.elapsed().as_millis() as u64;
        stats
    }
}

impl Default for StatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_durations_and_status_counts() {
        let tracker = StatsTracker::new();
        tracker.record_request(10.0, Some(200));
        tracker.record_request(30.0, Some(404));
        tracker.record_request(20.0, Some(200));
        let stats = tracker.snapshot();
        assert_eq!(stats.requests_total, 3);
        assert_eq!(stats.requests_finished, 3);
        assert_eq!(stats.avg_response_time_ms, 20.0);
        assert_eq!(stats.max_response_time_ms, 30.0);
        assert_eq!(stats.min_response_time_ms, 10.0);
        let counts = stats.requests_with_status_code.clone();
        assert_eq!(counts.get(&200), Some(&2));
        assert_eq!(counts.get(&404), Some(&1));
    }

    #[test]
    fn failures_track_error_types() {
        let tracker = StatsTracker::new();
        tracker.record_failure("timeout");
        tracker.record_failure("timeout");
        tracker.record_failure("dns");
        let stats = tracker.snapshot();
        assert_eq!(stats.requests_failed, 3);
        assert_eq!(stats.errors_per_type.get("timeout"), Some(&2));
        assert_eq!(stats.errors_per_type.get("dns"), Some(&1));
    }
}
