//! Flow job orchestration: spawns runs, tracks jobs, and supports cancellation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::domain::{
    DomainError, DomainResult, ErrorCode, FlowDefinition, FlowId, FlowKind, ProjectId,
};
use crate::reply::ReplyService;
use crate::storage::Db;

use super::interp::{trigger_kind_for, FlowRunOptions, FlowRunOutcome, FlowTrigger};
use super::nodes::BuiltInHandler;
use super::validate::validate_flow;

/// Maximum concurrent jobs per project.
pub const MAX_CONCURRENT_FLOW_JOBS: usize = 4;
/// Finished jobs kept in memory for inspection and SSE.
pub const MAX_FINISHED_FLOW_JOBS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowJobState {
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FlowJobView {
    pub id: Uuid,
    pub project_id: ProjectId,
    pub flow_id: FlowId,
    pub flow_name: String,
    pub state: FlowJobState,
    pub started_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<FlowRunOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

struct JobEntry {
    view: FlowJobView,
    cancel: CancellationToken,
}

pub struct FlowService {
    db: Arc<Db>,
    reply: Option<Arc<ReplyService>>,
    allow_shell: bool,
    shutdown: CancellationToken,
    jobs: Arc<Mutex<HashMap<Uuid, JobEntry>>>,
}

impl FlowService {
    pub fn new(
        db: Arc<Db>,
        reply: Option<Arc<ReplyService>>,
        allow_shell: bool,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            db,
            reply,
            allow_shell,
            shutdown,
            jobs: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Runs a flow now. The trigger must match the flow kind: exchange for
    /// passive flows, manual for active ones.
    pub async fn run_now(
        &self,
        project_id: ProjectId,
        flow_id: FlowId,
        trigger: FlowTrigger,
        input: Value,
    ) -> DomainResult<Uuid> {
        let flow = self.db.get_flow(project_id, flow_id).await?;
        validate_flow(&flow.definition)?;
        if !flow.enabled {
            return Err(DomainError::invalid("flow is disabled"));
        }
        let wanted = trigger_kind_for(flow.kind);
        let trigger = match (wanted, trigger) {
            ("exchange", FlowTrigger::Exchange(payload)) => FlowTrigger::Exchange(payload),
            ("manual", _) => FlowTrigger::Manual(input),
            (expected, other) => {
                return Err(DomainError::invalid(format!(
                    "{} flows run with a `{expected}` trigger, got `{}`",
                    flow.kind.as_str(),
                    other.kind()
                )))
            }
        };
        self.spawn_job(project_id, flow.id, flow.definition, trigger, flow.name)
            .await
    }

    /// Queues every enabled passive flow for an exchange event. Returns the
    /// spawned job ids; invalid flows and flows skipped by the concurrency cap
    /// are omitted.
    pub async fn trigger_passive(
        &self,
        project_id: ProjectId,
        payload: Value,
    ) -> DomainResult<Vec<Uuid>> {
        let flows = self.db.list_flows(project_id).await?;
        let mut spawned = Vec::new();
        for flow in flows {
            if !flow.enabled || flow.kind != FlowKind::Passive {
                continue;
            }
            if validate_flow(&flow.definition).is_err() {
                continue;
            }
            let job = self
                .spawn_job(
                    project_id,
                    flow.id,
                    flow.definition,
                    FlowTrigger::Exchange(payload.clone()),
                    flow.name,
                )
                .await;
            if let Ok(job) = job {
                spawned.push(job);
            }
        }
        Ok(spawned)
    }

    pub async fn cancel_job(&self, job_id: Uuid) -> DomainResult<()> {
        let jobs = self.jobs.lock().await;
        let entry = jobs
            .get(&job_id)
            .ok_or_else(|| DomainError::not_found("flow job"))?;
        entry.cancel.cancel();
        Ok(())
    }

    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    pub async fn get_job(&self, job_id: Uuid) -> Option<FlowJobView> {
        self.jobs
            .lock()
            .await
            .get(&job_id)
            .map(|entry| entry.view.clone())
    }

    pub async fn list_jobs(&self, project_id: ProjectId) -> Vec<FlowJobView> {
        let jobs = self.jobs.lock().await;
        let mut views: Vec<FlowJobView> = jobs
            .values()
            .filter(|entry| entry.view.project_id == project_id)
            .map(|entry| entry.view.clone())
            .collect();
        views.sort_by(|a, b| b.started_at_ms.cmp(&a.started_at_ms));
        views
    }

    pub async fn has_active_jobs(&self, project_id: ProjectId) -> bool {
        let jobs = self.jobs.lock().await;
        jobs.values().any(|entry| {
            entry.view.project_id == project_id && entry.view.state == FlowJobState::Running
        })
    }

    async fn spawn_job(
        &self,
        project_id: ProjectId,
        flow_id: FlowId,
        definition: FlowDefinition,
        trigger: FlowTrigger,
        flow_name: String,
    ) -> DomainResult<Uuid> {
        let job_id = Uuid::new_v4();
        let cancel = self.shutdown.child_token();
        {
            let mut jobs = self.jobs.lock().await;
            let running = jobs
                .values()
                .filter(|entry| {
                    entry.view.project_id == project_id && entry.view.state == FlowJobState::Running
                })
                .count();
            if running >= MAX_CONCURRENT_FLOW_JOBS {
                return Err(DomainError::new(
                    ErrorCode::Conflict,
                    format!("project already has {running} flow jobs running"),
                ));
            }
            prune_finished(&mut jobs);
            jobs.insert(
                job_id,
                JobEntry {
                    view: FlowJobView {
                        id: job_id,
                        project_id,
                        flow_id,
                        flow_name,
                        state: FlowJobState::Running,
                        started_at_ms: unix_ms(),
                        duration_ms: None,
                        outcome: None,
                        error: None,
                    },
                    cancel: cancel.clone(),
                },
            );
        }

        let jobs = Arc::clone(&self.jobs);
        let db = Arc::clone(&self.db);
        let reply = self.reply.clone();
        let allow_shell = self.allow_shell;
        let shutdown = self.shutdown.clone();
        let run_cancel = cancel.clone();
        let job_cancel = cancel;
        tokio::spawn(async move {
            let handler = BuiltInHandler::new(Some(db), reply, allow_shell);
            let options = FlowRunOptions {
                cancel: run_cancel.clone(),
                project_id,
                ..FlowRunOptions::default()
            };
            let started = std::time::Instant::now();
            let outcome = tokio::select! {
                biased;
                _ = job_cancel.cancelled() => Ok(FlowRunOutcome {
                    steps: Vec::new(),
                    outputs: Default::default(),
                    duration_ms: started.elapsed().as_millis() as u64,
                    error: Some("flow cancelled".into()),
                }),
                result = super::interp::run_flow(&definition, trigger, &handler, &options) => result,
            };
            let mut jobs = jobs.lock().await;
            if let Some(entry) = jobs.get_mut(&job_id) {
                match outcome {
                    Ok(outcome) => {
                        entry.view.state = if job_cancel.is_cancelled() || shutdown.is_cancelled() {
                            FlowJobState::Cancelled
                        } else if outcome.succeeded() {
                            FlowJobState::Succeeded
                        } else {
                            FlowJobState::Failed
                        };
                        entry.view.duration_ms = Some(outcome.duration_ms);
                        entry.view.error = outcome.error.clone();
                        entry.view.outcome = Some(outcome);
                    }
                    Err(error) => {
                        entry.view.state = FlowJobState::Failed;
                        entry.view.error = Some(error.to_string());
                        entry.view.duration_ms = Some(started.elapsed().as_millis() as u64);
                    }
                }
            }
        });
        Ok(job_id)
    }
}

fn prune_finished(jobs: &mut HashMap<Uuid, JobEntry>) {
    let mut finished: Vec<(Uuid, u64)> = jobs
        .iter()
        .filter(|(_, entry)| entry.view.state != FlowJobState::Running)
        .map(|(id, entry)| (*id, entry.view.started_at_ms))
        .collect();
    if finished.len() <= MAX_FINISHED_FLOW_JOBS {
        return;
    }
    finished.sort_by_key(|(_, started)| *started);
    let excess = finished.len() - MAX_FINISHED_FLOW_JOBS;
    for (id, _) in finished.into_iter().take(excess) {
        jobs.remove(&id);
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::domain::CreateProjectRequest;
    use std::path::Path;
    use std::time::Duration as StdDuration;

    fn test_config(root: &Path) -> Config {
        let mut config = Config::default();
        config.data_dir = root.join("data");
        config.spool_dir = config.data_dir.join("spool");
        config.export_dir = config.data_dir.join("exports");
        config.runtime_dir = config.data_dir.join("runtime");
        config.plugin_dir = config.data_dir.join("plugins");
        config.ensure_layout().unwrap();
        config
    }

    fn manual_flow(name: &str, template: &str) -> FlowDefinition {
        serde_json::from_value(serde_json::json!({
            "edition": 1,
            "kind": "active",
            "name": name,
            "graph": {
                "nodes": [
                    {"type": "flow/manual-start", "alias": "go", "inputs": {}},
                    {"type": "flow/template", "alias": "echo", "inputs": {
                        "template": {"kind": "const", "value": template}
                    }}
                ],
                "edges": [
                    {"source": {"node": "go", "port": "exec"},
                     "target": {"node": "echo", "port": "exec"}}
                ]
            }
        }))
        .unwrap()
    }

    async fn setup() -> (tempfile::TempDir, Arc<Db>, ProjectId) {
        let directory = tempfile::tempdir().unwrap();
        let config = test_config(directory.path());
        let db = Arc::new(Db::open(&config).await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "flows".into(),
                target_url: "https://example.test/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        (directory, db, project.id)
    }

    async fn wait_for_job(service: &FlowService, job: Uuid) -> FlowJobView {
        for _ in 0..400 {
            if let Some(view) = service.get_job(job).await {
                if view.state != FlowJobState::Running {
                    return view;
                }
            }
            tokio::time::sleep(StdDuration::from_millis(25)).await;
        }
        panic!("job did not finish");
    }

    #[tokio::test]
    async fn manual_flow_runs_to_success() {
        let (_dir, db, project_id) = setup().await;
        let service = FlowService::new(db.clone(), None, true, CancellationToken::new());
        let flow = db
            .create_flow(project_id, manual_flow("echo", "hello"))
            .await
            .unwrap();
        let job = service
            .run_now(
                project_id,
                flow.id,
                FlowTrigger::Manual(Value::Null),
                Value::Null,
            )
            .await
            .unwrap();
        let view = wait_for_job(&service, job).await;
        assert_eq!(view.state, FlowJobState::Succeeded, "{:?}", view.error);
        let outcome = view.outcome.expect("outcome recorded");
        assert_eq!(outcome.outputs["echo.text"], "hello");
        assert!(!service.has_active_jobs(project_id).await);
    }

    #[tokio::test]
    async fn rejects_wrong_trigger_and_disabled_flow() {
        let (_dir, db, project_id) = setup().await;
        let service = FlowService::new(db.clone(), None, true, CancellationToken::new());
        let flow = db
            .create_flow(project_id, manual_flow("echo", "hi"))
            .await
            .unwrap();

        let error = service
            .run_now(
                project_id,
                flow.id,
                FlowTrigger::Exchange(Value::Object(Default::default())),
                Value::Null,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("trigger"), "{error}");

        db.set_flow_enabled(project_id, flow.id, false)
            .await
            .unwrap();
        let error = service
            .run_now(
                project_id,
                flow.id,
                FlowTrigger::Manual(Value::Null),
                Value::Null,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("disabled"), "{error}");
    }

    #[tokio::test]
    async fn cancel_marks_job_cancelled() {
        let (_dir, db, project_id) = setup().await;
        let service = FlowService::new(db.clone(), None, true, CancellationToken::new());
        let definition = serde_json::from_value::<FlowDefinition>(serde_json::json!({
            "edition": 1,
            "kind": "active",
            "name": "slow",
            "graph": {
                "nodes": [
                    {"type": "flow/manual-start", "alias": "go", "inputs": {}},
                    {"type": "flow/shell", "alias": "sleep", "inputs": {
                        "command": {"kind": "const", "value": "sleep"},
                        "args": {"kind": "const", "value": ["5"]}
                    }}
                ],
                "edges": [
                    {"source": {"node": "go", "port": "exec"},
                     "target": {"node": "sleep", "port": "exec"}}
                ]
            }
        }))
        .unwrap();
        let flow = db.create_flow(project_id, definition).await.unwrap();
        let job = service
            .run_now(
                project_id,
                flow.id,
                FlowTrigger::Manual(Value::Null),
                Value::Null,
            )
            .await
            .unwrap();
        tokio::time::sleep(StdDuration::from_millis(150)).await;
        service.cancel_job(job).await.unwrap();
        let view = wait_for_job(&service, job).await;
        assert_eq!(view.state, FlowJobState::Cancelled, "{:?}", view.error);
    }

    #[tokio::test]
    async fn passive_trigger_skips_when_no_passive_flows() {
        let (_dir, db, project_id) = setup().await;
        let service = FlowService::new(db.clone(), None, true, CancellationToken::new());
        let spawned = service
            .trigger_passive(project_id, serde_json::json!({"exchange_id": 1}))
            .await
            .unwrap();
        assert!(spawned.is_empty());
    }
}
