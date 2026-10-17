//! Project-scoped crawl job persistence.

use crate::domain::*;
use crate::storage::projects::{now_rfc3339, parse_time};
use crate::storage::{write_transaction, Db};
use rusqlite::params;

impl Db {
    pub async fn create_crawl_job(
        &self,
        project_id: ProjectId,
        target_url: String,
        host: String,
        config_json: String,
        agent_count: u32,
    ) -> DomainResult<CrawlJob> {
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            let tx = write_transaction(conn).map_err(storage_error)?;
            let project_exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM projects WHERE id=?1)",
                    params![project_id.get()],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            if !project_exists {
                return Err(DomainError::not_found("project"));
            }
            tx.execute(
                "INSERT INTO crawl_jobs
                 (project_id, target_url, host, state, depth, discovered_urls, crawled_urls,
                  failed_urls, agent_count, title, config_json, error, created_at, updated_at, completed_at)
                 VALUES (?1,?2,?3,'queued',0,0,0,0,?4,NULL,?5,NULL,?6,?6,NULL)",
                params![
                    project_id.get(),
                    target_url,
                    host,
                    agent_count as i64,
                    config_json,
                    ts
                ],
            )
            .map_err(storage_error)?;
            let id = CrawlJobId(tx.last_insert_rowid());
            tx.commit().map_err(storage_error)?;
            Ok(CrawlJob {
                id,
                project_id,
                target_url,
                host,
                state: CrawlJobState::Queued,
                depth: 0,
                discovered_urls: 0,
                crawled_urls: 0,
                failed_urls: 0,
                agent_count,
                title: None,
                created_at: parse_time(&ts),
                updated_at: parse_time(&ts),
                completed_at: None,
                error: None,
            })
        })
        .await
    }

    pub async fn set_crawl_job_state(
        &self,
        project_id: ProjectId,
        job_id: CrawlJobId,
        state: CrawlJobState,
        error: Option<String>,
    ) -> DomainResult<()> {
        let ts = now_rfc3339();
        let state_s = crawl_state_str(state);
        let completed_at = matches!(
            state,
            CrawlJobState::Completed | CrawlJobState::Failed | CrawlJobState::Interrupted
        )
        .then(|| ts.clone());
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE crawl_jobs SET state=?1, error=?2, updated_at=?3, completed_at=?4
                     WHERE id=?5 AND project_id=?6",
                    params![
                        state_s,
                        error,
                        ts,
                        completed_at,
                        job_id.get(),
                        project_id.get()
                    ],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Err(DomainError::not_found("crawl job"));
            }
            Ok(())
        })
        .await
    }

    pub async fn update_crawl_job_stats(
        &self,
        project_id: ProjectId,
        job_id: CrawlJobId,
        depth: u32,
        discovered_urls: u64,
        crawled_urls: u64,
        failed_urls: u64,
    ) -> DomainResult<()> {
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE crawl_jobs SET depth=?1, discovered_urls=?2, crawled_urls=?3,
                             failed_urls=?4, updated_at=?5
                     WHERE id=?6 AND project_id=?7",
                    params![
                        depth as i64,
                        discovered_urls as i64,
                        crawled_urls as i64,
                        failed_urls as i64,
                        ts,
                        job_id.get(),
                        project_id.get()
                    ],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Err(DomainError::not_found("crawl job"));
            }
            Ok(())
        })
        .await
    }

    pub async fn rename_crawl_job(
        &self,
        project_id: ProjectId,
        job_id: CrawlJobId,
        title: Option<String>,
    ) -> DomainResult<()> {
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE crawl_jobs SET title=?1, updated_at=?2
                     WHERE id=?3 AND project_id=?4",
                    params![title, ts, job_id.get(), project_id.get()],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Err(DomainError::not_found("crawl job"));
            }
            Ok(())
        })
        .await
    }

    pub async fn get_crawl_job(
        &self,
        project_id: ProjectId,
        job_id: CrawlJobId,
    ) -> DomainResult<CrawlJob> {
        self.with_conn(move |conn| load_crawl_job(conn, Some(project_id), job_id))
            .await
    }

    pub async fn get_crawl_job_by_id(&self, job_id: CrawlJobId) -> DomainResult<CrawlJob> {
        self.with_conn(move |conn| load_crawl_job(conn, None, job_id))
            .await
    }

    pub async fn list_crawl_jobs(&self, project_id: ProjectId) -> DomainResult<Vec<CrawlJob>> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, project_id, target_url, host, state, depth, discovered_urls,
                            crawled_urls, failed_urls, agent_count, title, error,
                            created_at, updated_at, completed_at
                     FROM crawl_jobs WHERE project_id=?1 ORDER BY id DESC LIMIT 100",
                )
                .map_err(storage_error)?;
            let rows = stmt
                .query_map(params![project_id.get()], map_crawl_job)
                .map_err(storage_error)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_error)
        })
        .await
    }

    pub async fn delete_crawl_job(
        &self,
        project_id: ProjectId,
        job_id: CrawlJobId,
    ) -> DomainResult<()> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM crawl_jobs WHERE id=?1 AND project_id=?2",
                    params![job_id.get(), project_id.get()],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Err(DomainError::not_found("crawl job"));
            }
            Ok(())
        })
        .await
    }

    pub async fn clear_completed_crawl_jobs(&self, project_id: ProjectId) -> DomainResult<u64> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM crawl_jobs
                     WHERE project_id=?1 AND state IN ('completed','failed','interrupted')",
                    params![project_id.get()],
                )
                .map_err(storage_error)?;
            Ok(changed as u64)
        })
        .await
    }

    pub async fn mark_crawl_jobs_interrupted(&self) -> DomainResult<u64> {
        let ts = now_rfc3339();
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE crawl_jobs SET state='interrupted', error='daemon restarted',
                             updated_at=?1, completed_at=?1
                     WHERE state IN ('queued','running','cancelling')",
                    params![ts],
                )
                .map_err(storage_error)?;
            Ok(changed as u64)
        })
        .await
    }
}

fn load_crawl_job(
    conn: &rusqlite::Connection,
    project_id: Option<ProjectId>,
    job_id: CrawlJobId,
) -> DomainResult<CrawlJob> {
    let sql_base = "SELECT id, project_id, target_url, host, state, depth, discovered_urls,
                           crawled_urls, failed_urls, agent_count, title, error,
                           created_at, updated_at, completed_at
                    FROM crawl_jobs";
    let result = if let Some(project_id) = project_id {
        conn.query_row(
            &format!("{sql_base} WHERE id=?1 AND project_id=?2"),
            params![job_id.get(), project_id.get()],
            map_crawl_job,
        )
    } else {
        conn.query_row(
            &format!("{sql_base} WHERE id=?1"),
            params![job_id.get()],
            map_crawl_job,
        )
    };
    result.map_err(not_found_crawl_job)
}

fn map_crawl_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<CrawlJob> {
    let created_at: String = row.get(12)?;
    let updated_at: String = row.get(13)?;
    let completed_at: Option<String> = row.get(14)?;
    Ok(CrawlJob {
        id: CrawlJobId(row.get(0)?),
        project_id: ProjectId(row.get(1)?),
        target_url: row.get(2)?,
        host: row.get(3)?,
        state: parse_crawl_state(&row.get::<_, String>(4)?),
        depth: row.get::<_, i64>(5)? as u32,
        discovered_urls: row.get::<_, i64>(6)? as u64,
        crawled_urls: row.get::<_, i64>(7)? as u64,
        failed_urls: row.get::<_, i64>(8)? as u64,
        agent_count: row.get::<_, i64>(9)? as u32,
        title: row.get(10)?,
        error: row.get(11)?,
        created_at: parse_time(&created_at),
        updated_at: parse_time(&updated_at),
        completed_at: completed_at.as_deref().map(parse_time),
    })
}

fn crawl_state_str(state: CrawlJobState) -> &'static str {
    match state {
        CrawlJobState::Queued => "queued",
        CrawlJobState::Running => "running",
        CrawlJobState::Paused => "paused",
        CrawlJobState::Cancelling => "cancelling",
        CrawlJobState::Completed => "completed",
        CrawlJobState::Failed => "failed",
        CrawlJobState::Interrupted => "interrupted",
    }
}

fn parse_crawl_state(state: &str) -> CrawlJobState {
    match state {
        "running" => CrawlJobState::Running,
        "paused" => CrawlJobState::Paused,
        "cancelling" => CrawlJobState::Cancelling,
        "completed" => CrawlJobState::Completed,
        "failed" => CrawlJobState::Failed,
        "interrupted" => CrawlJobState::Interrupted,
        _ => CrawlJobState::Queued,
    }
}

fn not_found_crawl_job(error: rusqlite::Error) -> DomainError {
    match error {
        rusqlite::Error::QueryReturnedNoRows => DomainError::not_found("crawl job"),
        other => storage_error(other),
    }
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}
