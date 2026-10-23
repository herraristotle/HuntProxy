//! Managed crawl jobs: start, cancel, list, and worker orchestration.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::app::AppEvent;
use crate::domain::*;
use crate::reply::ReplyService;
use crate::storage::Db;

use super::engine::{CrawlEngine, CrawlEngineConfig};
use super::types::{CrawlerOptions, LinkStrategy};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartCrawlRequest {
    pub seed_url: String,
    #[serde(default)]
    pub options: CrawlerOptions,
    #[serde(default)]
    pub strategy: LinkStrategy,
    #[serde(default)]
    pub title: Option<String>,
}

pub struct CrawlJobManager {
    db: Arc<Db>,
    engine: Arc<CrawlEngine>,
    cancel_flags: Arc<DashMap<i64, CancellationToken>>,
    pause_flags: Arc<DashMap<i64, Arc<AtomicBool>>>,
}

impl CrawlJobManager {
    pub fn new(db: Arc<Db>, reply: Arc<ReplyService>, events: broadcast::Sender<AppEvent>) -> Self {
        Self {
            db: db.clone(),
            engine: Arc::new(CrawlEngine::new(db, reply, events)),
            cancel_flags: Arc::new(DashMap::new()),
            pause_flags: Arc::new(DashMap::new()),
        }
    }

    pub async fn mark_interrupted_all(&self) -> DomainResult<u64> {
        self.db.mark_crawl_jobs_interrupted().await
    }

    pub async fn start(
        &self,
        project_id: ProjectId,
        request: StartCrawlRequest,
    ) -> DomainResult<CrawlJob> {
        let parsed = Url::parse(request.seed_url.trim())
            .map_err(|error| DomainError::invalid(format!("invalid seed_url: {error}")))?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(DomainError::invalid("seed_url must be http or https"));
        }
        if !request
            .options
            .filter
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
        {
            super::filter::parse_crawl_filter(request.options.filter.as_deref().unwrap())?;
        }
        let host = parsed.host_str().unwrap_or_default().to_string();
        let project = self.db.get_project(project_id).await?;

        let engine_config = CrawlEngineConfig {
            project_id,
            job_id: CrawlJobId(0),
            seed_url: parsed.to_string(),
            options: request.options.clone(),
            scope: project.scope.clone(),
            strategy: request.strategy,
        };
        let config_json = serde_json::to_string(&engine_config)
            .map_err(|error| DomainError::new(ErrorCode::InvalidArgument, error.to_string()))?;

        let job = self
            .db
            .create_crawl_job(
                project_id,
                parsed.to_string(),
                host,
                config_json,
                request.options.max_concurrency.max(1) as u32,
            )
            .await?;
        if let Some(title) = &request.title {
            self.db
                .rename_crawl_job(project_id, job.id, Some(title.clone()))
                .await?;
        }

        let mut engine_config = engine_config;
        engine_config.job_id = job.id;
        let cancel = CancellationToken::new();
        let pause = Arc::new(AtomicBool::new(false));
        self.cancel_flags.insert(job.id.get(), cancel.clone());
        self.pause_flags.insert(job.id.get(), pause.clone());

        let db = self.db.clone();
        let engine = self.engine.clone();
        let cancel_flags = self.cancel_flags.clone();
        let pause_flags = self.pause_flags.clone();
        let job_id = job.id;
        tokio::spawn(async move {
            let result = engine.run(engine_config, cancel, pause).await;
            if let Err(error) = result {
                let _ = db
                    .set_crawl_job_state(
                        project_id,
                        job_id,
                        CrawlJobState::Failed,
                        Some(error.to_string()),
                    )
                    .await;
            }
            cancel_flags.remove(&job_id.get());
            pause_flags.remove(&job_id.get());
        });

        Ok(job)
    }

    pub async fn cancel_for_project(
        &self,
        project_id: ProjectId,
        job_id: CrawlJobId,
    ) -> DomainResult<()> {
        let job = self.db.get_crawl_job(project_id, job_id).await?;
        if matches!(
            job.state,
            CrawlJobState::Completed | CrawlJobState::Failed | CrawlJobState::Interrupted
        ) {
            return Err(DomainError::conflict("crawl job is already terminal"));
        }
        let token = self
            .cancel_flags
            .get(&job_id.get())
            .map(|entry| entry.value().clone());
        if let Some(token) = token {
            self.db
                .set_crawl_job_state(project_id, job_id, CrawlJobState::Cancelling, None)
                .await?;
            token.cancel();
        } else {
            self.db
                .set_crawl_job_state(
                    project_id,
                    job_id,
                    CrawlJobState::Interrupted,
                    Some("crawl worker is not active".into()),
                )
                .await?;
        }
        Ok(())
    }

    pub async fn pause(&self, project_id: ProjectId, job_id: CrawlJobId) -> DomainResult<()> {
        let job = self.db.get_crawl_job(project_id, job_id).await?;
        if !matches!(job.state, CrawlJobState::Queued | CrawlJobState::Running) {
            return Err(DomainError::conflict(
                "only queued or running crawl jobs can be paused",
            ));
        }
        let flag = self
            .pause_flags
            .get(&job_id.get())
            .map(|entry| entry.value().clone())
            .ok_or_else(|| DomainError::conflict("crawl worker is not active"))?;
        flag.store(true, Ordering::Relaxed);
        self.db
            .set_crawl_job_state(project_id, job_id, CrawlJobState::Paused, None)
            .await
    }

    pub async fn resume(&self, project_id: ProjectId, job_id: CrawlJobId) -> DomainResult<()> {
        let job = self.db.get_crawl_job(project_id, job_id).await?;
        if job.state != CrawlJobState::Paused {
            return Err(DomainError::conflict("crawl job is not paused"));
        }
        let flag = self
            .pause_flags
            .get(&job_id.get())
            .map(|entry| entry.value().clone())
            .ok_or_else(|| DomainError::conflict("crawl worker is not active"))?;
        flag.store(false, Ordering::Relaxed);
        self.db
            .set_crawl_job_state(project_id, job_id, CrawlJobState::Running, None)
            .await
    }

    pub async fn list(&self, project_id: ProjectId) -> DomainResult<Vec<CrawlJob>> {
        self.db.list_crawl_jobs(project_id).await
    }

    pub async fn get(&self, project_id: ProjectId, job_id: CrawlJobId) -> DomainResult<CrawlJob> {
        self.db.get_crawl_job(project_id, job_id).await
    }

    pub async fn delete(&self, project_id: ProjectId, job_id: CrawlJobId) -> DomainResult<()> {
        let job = self.db.get_crawl_job(project_id, job_id).await?;
        if !matches!(
            job.state,
            CrawlJobState::Completed | CrawlJobState::Failed | CrawlJobState::Interrupted
        ) {
            return Err(DomainError::conflict(
                "cancel the crawl job before deleting it",
            ));
        }
        self.db.delete_crawl_job(project_id, job_id).await
    }

    pub async fn clear_completed(&self, project_id: ProjectId) -> DomainResult<u64> {
        self.db.clear_completed_crawl_jobs(project_id).await
    }

    pub async fn rename(
        &self,
        project_id: ProjectId,
        job_id: CrawlJobId,
        title: Option<String>,
    ) -> DomainResult<()> {
        self.db.rename_crawl_job(project_id, job_id, title).await
    }

    pub fn is_active(&self, job_id: CrawlJobId) -> bool {
        self.cancel_flags.contains_key(&job_id.get())
    }
}
