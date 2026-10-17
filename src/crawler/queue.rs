//! Priority crawl request queue with URL deduplication and retry support.

use super::types::{CrawlRequest, CrawlRequestState};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Default)]
pub struct QueueStats {
    pub pending: usize,
    pub in_progress: usize,
    pub completed: usize,
    pub failed: usize,
    pub total: usize,
}

pub struct CrawlQueue {
    pending: Vec<CrawlRequest>,
    in_progress: HashMap<String, CrawlRequest>,
    completed: HashSet<String>,
    failed: HashMap<String, CrawlRequest>,
    unique_keys: HashSet<String>,
    retry_queue: Vec<CrawlRequest>,
    max_size: usize,
    is_paused: bool,
}

impl CrawlQueue {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            in_progress: HashMap::new(),
            completed: HashSet::new(),
            failed: HashMap::new(),
            unique_keys: HashSet::new(),
            retry_queue: Vec::new(),
            max_size: usize::MAX,
            is_paused: false,
        }
    }

    pub fn with_max_size(max_size: usize) -> Self {
        let mut queue = Self::new();
        queue.max_size = max_size;
        queue
    }

    pub fn add(&mut self, request: CrawlRequest) -> bool {
        if self.unique_keys.contains(&request.unique_key) {
            return false;
        }
        if self.unique_keys.len() >= self.max_size {
            return false;
        }
        self.unique_keys.insert(request.unique_key.clone());
        self.insert_by_priority(request);
        true
    }

    fn insert_by_priority(&mut self, request: CrawlRequest) {
        let position = self
            .pending
            .partition_point(|existing| existing.priority >= request.priority);
        self.pending.insert(position, request);
    }

    pub fn fetch_next(&mut self) -> Option<CrawlRequest> {
        if self.is_paused {
            return None;
        }
        if let Some(mut request) = self.retry_queue.first().cloned() {
            self.retry_queue.remove(0);
            request.state = CrawlRequestState::Processing;
            let id = request.id.clone();
            self.in_progress.insert(id, request.clone());
            return Some(request);
        }
        if let Some(mut request) = self.pending.first().cloned() {
            self.pending.remove(0);
            request.state = CrawlRequestState::Processing;
            let id = request.id.clone();
            self.in_progress.insert(id, request.clone());
            return Some(request);
        }
        None
    }

    pub fn mark_handled(&mut self, request: &CrawlRequest) {
        self.in_progress.remove(&request.id);
        self.completed.insert(request.unique_key.clone());
    }

    pub fn handle_failure(&mut self, request: &mut CrawlRequest, error: &str) {
        request.error = Some(error.to_string());
        self.in_progress.remove(&request.id);
        if request.can_retry() {
            request.state = CrawlRequestState::Retrying;
            request.retry_count += 1;
            self.retry_queue.push(request.clone());
        } else {
            request.state = CrawlRequestState::Failed;
            self.failed.insert(request.id.clone(), request.clone());
        }
    }

    pub fn reclaim_all_in_progress(&mut self) {
        let in_flight: Vec<CrawlRequest> = self.in_progress.drain().map(|(_, req)| req).collect();
        for mut request in in_flight {
            request.state = CrawlRequestState::Pending;
            self.insert_by_priority(request);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.retry_queue.is_empty() && self.in_progress.is_empty()
    }

    pub fn has_next(&self) -> bool {
        !self.is_paused && (!self.pending.is_empty() || !self.retry_queue.is_empty())
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len() + self.retry_queue.len()
    }

    pub fn in_progress_count(&self) -> usize {
        self.in_progress.len()
    }

    pub fn pause(&mut self) {
        self.is_paused = true;
    }

    pub fn resume(&mut self) {
        self.is_paused = false;
    }

    pub fn is_paused(&self) -> bool {
        self.is_paused
    }

    pub fn clear(&mut self) {
        self.pending.clear();
        self.retry_queue.clear();
        self.in_progress.clear();
        self.completed.clear();
        self.failed.clear();
        self.unique_keys.clear();
        self.is_paused = false;
    }

    pub fn stats(&self) -> QueueStats {
        QueueStats {
            pending: self.pending_count(),
            in_progress: self.in_progress.len(),
            completed: self.completed.len(),
            failed: self.failed.len(),
            total: self.unique_keys.len(),
        }
    }
}

impl Default for CrawlQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(url: &str) -> CrawlRequest {
        CrawlRequest::new(url, 3)
    }

    #[test]
    fn deduplicates_by_unique_key() {
        let mut queue = CrawlQueue::new();
        assert!(queue.add(request("https://example.com/a")));
        assert!(!queue.add(request("https://example.com/a")));
        assert!(queue.add(request("https://example.com/b")));
    }

    #[test]
    fn normalizes_query_order_for_dedup() {
        let mut queue = CrawlQueue::new();
        assert!(queue.add(request("https://example.com/a?x=1&y=2")));
        assert!(!queue.add(request("https://example.com/a?y=2&x=1")));
    }

    #[test]
    fn respects_priority_order() {
        let mut queue = CrawlQueue::new();
        let mut low = request("https://example.com/low");
        low.priority = 0;
        let mut high = request("https://example.com/high");
        high.priority = 10;
        queue.add(low);
        queue.add(high);
        let next = queue.fetch_next().unwrap();
        assert_eq!(next.url, "https://example.com/high");
    }

    #[test]
    fn retry_moves_to_retry_queue_then_fails() {
        let mut queue = CrawlQueue::new();
        queue.add(request("https://example.com/a"));
        let mut fetched = queue.fetch_next().unwrap();
        queue.handle_failure(&mut fetched, "timeout");
        assert_eq!(fetched.retry_count, 1);
        assert_eq!(fetched.state, CrawlRequestState::Retrying);

        let mut again = queue.fetch_next().unwrap();
        queue.handle_failure(&mut again, "timeout");
        let mut third = queue.fetch_next().unwrap();
        queue.handle_failure(&mut third, "timeout");
        let mut fourth = queue.fetch_next().unwrap();
        assert!(!fourth.can_retry());
        queue.handle_failure(&mut fourth, "timeout");
        assert_eq!(fourth.state, CrawlRequestState::Failed);
        assert!(queue.fetch_next().is_none());
    }

    #[test]
    fn pause_blocks_fetching_and_resume_restores() {
        let mut queue = CrawlQueue::new();
        queue.add(request("https://example.com/a"));
        queue.pause();
        assert!(queue.fetch_next().is_none());
        queue.resume();
        assert!(queue.fetch_next().is_some());
    }

    #[test]
    fn child_increments_depth_and_links_parent() {
        let parent = request("https://example.com/");
        let child = CrawlRequest::child_of(&parent, "https://example.com/next", 3);
        assert_eq!(child.depth, 1);
        assert_eq!(child.parent_id.as_deref(), Some(parent.id.as_str()));
    }

    #[test]
    fn max_size_blocks_new_unique_keys() {
        let mut queue = CrawlQueue::with_max_size(1);
        assert!(queue.add(request("https://example.com/a")));
        assert!(!queue.add(request("https://example.com/b")));
    }
}
