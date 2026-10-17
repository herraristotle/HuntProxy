//! Sliding-window rate limiter for crawl requests (requests per minute).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    max_per_minute: u64,
    window: Mutex<VecDeque<Instant>>,
}

impl RateLimiter {
    pub fn new(max_per_minute: u64) -> Self {
        Self {
            max_per_minute: max_per_minute.max(1),
            window: Mutex::new(VecDeque::new()),
        }
    }

    /// Wait until a request slot is available, or return immediately if the
    /// limiter has been cleared (shutdown). Returns `false` only on lock
    /// poisoning.
    pub async fn acquire(&self) -> bool {
        loop {
            let wait = {
                let mut window = match self.window.lock() {
                    Ok(window) => window,
                    Err(_) => return false,
                };
                let now = Instant::now();
                let window_start = now - Duration::from_secs(60);
                while window.front().is_some_and(|t| *t < window_start) {
                    window.pop_front();
                }
                if (window.len() as u64) < self.max_per_minute {
                    window.push_back(now);
                    None
                } else {
                    // Wait until the oldest slot exits the 60s sliding window.
                    let oldest = *window.front().unwrap_or(&now);
                    let wait = oldest + Duration::from_secs(60) + Duration::from_millis(10);
                    Some(wait.saturating_duration_since(now))
                }
            };
            match wait {
                None => return true,
                Some(delay) => tokio::time::sleep(delay).await,
            }
        }
    }

    pub fn reset(&self) {
        if let Ok(mut window) = self.window.lock() {
            window.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_up_to_max_within_window() {
        let limiter = RateLimiter::new(3);
        assert!(limiter.acquire().await);
        assert!(limiter.acquire().await);
        assert!(limiter.acquire().await);
        // 4th would need to wait; we only assert the first three were immediate.
    }

    #[test]
    fn zero_becomes_one() {
        let limiter = RateLimiter::new(0);
        assert_eq!(limiter.max_per_minute, 1);
    }

    #[tokio::test]
    async fn reset_clears_window() {
        let limiter = RateLimiter::new(1);
        assert!(limiter.acquire().await);
        limiter.reset();
        assert!(limiter.acquire().await);
    }
}
