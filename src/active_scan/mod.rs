//! Active scanning framework for automated vulnerability detection.
//!
//! Orchestrates scan jobs across multiple checks, manages dependencies,
//! tracks progress, and applies scan policies.

mod additional_checks;
mod checks;
mod job;
mod policy;
mod scheduler;

pub use checks::{ActiveCheck, CheckResult, CheckSeverity};
pub use job::{ActiveScanJob, ScanJobState, ScanProgress};
pub use policy::{ScanPolicy, AttackStrength};
pub use scheduler::ScanScheduler;

use crate::domain::*;
use crate::fuzzer::variants;
use crate::reply::ReplyService;
use crate::storage::Db;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Active scan service that runs automated vulnerability checks.
pub struct ActiveScanService {
    db: Arc<Db>,
    reply: Arc<ReplyService>,
    jobs: Arc<DashMap<i64, Arc<ActiveScanJob>>>,
    scheduler: Arc<ScanScheduler>,
    next_job_id: Arc<std::sync::atomic::AtomicI64>,
}

impl ActiveScanService {
    pub fn new(db: Arc<Db>, reply: Arc<ReplyService>) -> Self {
        let mut checks = checks::load_default_checks();
        checks.extend(additional_checks::load_additional_checks());
        let scheduler = Arc::new(ScanScheduler::new(checks));

        Self {
            db,
            reply,
            jobs: Arc::new(DashMap::new()),
            scheduler,
            next_job_id: Arc::new(std::sync::atomic::AtomicI64::new(1)),
        }
    }

    /// Start active scan on a specific exchange.
    pub async fn start_scan(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        policy: ScanPolicy,
    ) -> DomainResult<i64> {
        let job_id = self
            .next_job_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // Fetch exchange and extract injection points
        let exchange = self.db.get_exchange_for_active_scan(project_id, exchange_id).await?;
        let injection_points = variants::extract_injection_points(
            &exchange.method,
            &exchange.url,
            &exchange.request_headers,
            exchange.request_body.as_deref(),
        );

        let cancel_token = CancellationToken::new();
        let job = Arc::new(ActiveScanJob::new(
            job_id,
            project_id,
            exchange_id,
            injection_points,
            policy.clone(),
            cancel_token.clone(),
        ));

        self.jobs.insert(job_id, job.clone());

        // Spawn scan task
        let db = self.db.clone();
        let reply = self.reply.clone();
        let scheduler = self.scheduler.clone();
        let job_clone = job.clone();

        tokio::spawn(async move {
            if let Err(e) = run_scan_job(job_clone, db, reply, scheduler).await {
                tracing::error!(job_id, error = %e, "scan job failed");
            }
        });

        Ok(job_id)
    }

    /// Get scan job status and progress.
    pub fn get_job_status(&self, job_id: i64) -> Option<ScanProgress> {
        self.jobs.get(&job_id).map(|job| job.get_progress())
    }

    /// Cancel running scan.
    pub fn cancel_scan(&self, job_id: i64) -> DomainResult<()> {
        if let Some(job) = self.jobs.get(&job_id) {
            job.cancel();
            Ok(())
        } else {
            Err(DomainError::not_found("scan job"))
        }
    }

    /// List all active scan jobs for project.
    pub fn list_jobs(&self, project_id: ProjectId) -> Vec<ScanProgress> {
        self.jobs
            .iter()
            .filter(|entry| entry.value().project_id == project_id)
            .map(|entry| entry.value().get_progress())
            .collect()
    }
}

/// Run scan job: execute all enabled checks against target.
async fn run_scan_job(
    job: Arc<ActiveScanJob>,
    db: Arc<Db>,
    reply: Arc<ReplyService>,
    scheduler: Arc<ScanScheduler>,
) -> DomainResult<()> {
    job.set_state(ScanJobState::Running);

    // Get ordered checks based on policy and dependencies
    let checks = scheduler.schedule_checks(&job.policy);

    let total_checks = checks.len();
    job.set_total_checks(total_checks);

    for (index, check) in checks.iter().enumerate() {
        if job.is_cancelled() {
            job.set_state(ScanJobState::Cancelled);
            return Ok(());
        }

        if !job.policy.is_check_enabled(check.id()) {
            continue;
        }

        job.set_current_check(check.name().to_string());

        // Run check against all injection points
        for point in &job.injection_points {
            if job.is_cancelled() {
                break;
            }

            match check.execute(&job, point, &db, &reply).await {
                Ok(Some(result)) => {
                    // Store finding
                    db.insert_active_scan_finding(job.project_id, job.exchange_id, &result)
                        .await?;
                    job.increment_findings();
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        check_id = check.id(),
                        injection_point = %point.name,
                        error = %e,
                        "check execution failed"
                    );
                }
            }
        }

        job.increment_completed_checks();
        job.update_progress(((index + 1) as f32 / total_checks as f32 * 100.0) as u8);
    }

    job.set_state(ScanJobState::Completed);
    Ok(())
}

/// Minimal exchange data for active scanning.
#[derive(Debug, Clone)]
pub struct ActiveScanExchange {
    pub exchange_id: ExchangeId,
    pub method: String,
    pub url: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: Option<Vec<u8>>,
}
