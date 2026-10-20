//! Scan job state and progress tracking.

use super::policy::ScanPolicy;
use crate::domain::*;
use crate::fuzzer::variants::InjectionPoint;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanJobState {
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub job_id: i64,
    pub project_id: ProjectId,
    pub exchange_id: ExchangeId,
    pub state: ScanJobState,
    pub progress_percent: u8,
    pub current_check: Option<String>,
    pub checks_completed: usize,
    pub checks_total: usize,
    pub findings_count: usize,
    pub injection_points_count: usize,
}

/// Active scan job with progress tracking.
pub struct ActiveScanJob {
    pub job_id: i64,
    pub project_id: ProjectId,
    pub exchange_id: ExchangeId,
    pub injection_points: Vec<InjectionPoint>,
    pub policy: ScanPolicy,

    state: Mutex<ScanJobState>,
    cancel_token: CancellationToken,
    progress_percent: AtomicU8,
    current_check: Mutex<Option<String>>,
    checks_completed: AtomicUsize,
    checks_total: AtomicUsize,
    findings_count: AtomicUsize,
}

impl ActiveScanJob {
    pub fn new(
        job_id: i64,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        injection_points: Vec<InjectionPoint>,
        policy: ScanPolicy,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            job_id,
            project_id,
            exchange_id,
            injection_points,
            policy,
            state: Mutex::new(ScanJobState::Queued),
            cancel_token,
            progress_percent: AtomicU8::new(0),
            current_check: Mutex::new(None),
            checks_completed: AtomicUsize::new(0),
            checks_total: AtomicUsize::new(0),
            findings_count: AtomicUsize::new(0),
        }
    }

    pub fn set_state(&self, state: ScanJobState) {
        *self.state.lock().unwrap() = state;
    }

    pub fn get_state(&self) -> ScanJobState {
        *self.state.lock().unwrap()
    }

    pub fn cancel(&self) {
        self.cancel_token.cancel();
        self.set_state(ScanJobState::Cancelled);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel_token.is_cancelled()
    }

    pub fn update_progress(&self, percent: u8) {
        self.progress_percent.store(percent, Ordering::Relaxed);
    }

    pub fn set_current_check(&self, check_name: String) {
        *self.current_check.lock().unwrap() = Some(check_name);
    }

    pub fn set_total_checks(&self, total: usize) {
        self.checks_total.store(total, Ordering::Relaxed);
    }

    pub fn increment_completed_checks(&self) {
        self.checks_completed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_findings(&self) {
        self.findings_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_progress(&self) -> ScanProgress {
        ScanProgress {
            job_id: self.job_id,
            project_id: self.project_id,
            exchange_id: self.exchange_id,
            state: self.get_state(),
            progress_percent: self.progress_percent.load(Ordering::Relaxed),
            current_check: self.current_check.lock().unwrap().clone(),
            checks_completed: self.checks_completed.load(Ordering::Relaxed),
            checks_total: self.checks_total.load(Ordering::Relaxed),
            findings_count: self.findings_count.load(Ordering::Relaxed),
            injection_points_count: self.injection_points.len(),
        }
    }
}
