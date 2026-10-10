use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use huntproxy::app::bootstrap_state;
use huntproxy::config::Config;
use huntproxy::domain::*;
use huntproxy::storage::NewExchange;
use tempfile::TempDir;
use tower::ServiceExt;

async fn test_state() -> (TempDir, std::sync::Arc<huntproxy::app::AppState>, ProjectId) {
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        data_dir: directory.path().to_path_buf(),
        spool_dir: directory.path().join("spool"),
        export_dir: directory.path().join("exports"),
        runtime_dir: directory.path().join("runtime"),
        plugin_dir: directory.path().join("plugins"),
        browser_worker_path: Some(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("browser-worker")
                .join("index.js"),
        ),
        ..Config::default()
    };
    let state = bootstrap_state(config).await.unwrap();
    let project = state
        .db
        .create_project(CreateProjectRequest {
            name: "Flow integration".into(),
            target_url: "https://example.com/".into(),
            advanced: None,
        })
        .await
        .unwrap();
    (directory, state, project.id)
}

fn exchange(project_id: ProjectId, path: &str) -> NewExchange {
    NewExchange {
        project_id,
        source: ExchangeSource::Proxy,
        protocol: "HTTP/2".into(),
        method: "GET".into(),
        scheme: "https".into(),
        authority: "example.com".into(),
        host: "example.com".into(),
        port: 443,
        path: path.into(),
        query: None,
        status_code: Some(200),
        mime: Some("text/plain".into()),
        completion: CompletionState::Complete,
        capture_quality: CaptureQuality::Semantic,
        header_representation: HeaderRepresentation::Semantic,
        body_representation: BodyRepresentation::SemanticEncoded,
        cache_provenance: CacheProvenance::None,
        transport_provenance: Some(TransportProvenance::ProtocolProfileOnly),
        transport_profile: Some("test".into()),
        request_headers: Vec::new(),
        response_headers: Vec::new(),
        request_body: None,
        response_body: Some(b"response".to_vec()),
        duration_ms: Some(3),
        lineage: ExchangeLineage::default(),
        page_title: None,
        error_message: None,
    }
}

async fn json_response(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn echo_flow(name: &str) -> serde_json::Value {
    serde_json::json!({
        "edition": 1,
        "kind": "active",
        "name": name,
        "graph": {
            "nodes": [
                {"type": "flow/manual-start", "alias": "go", "inputs": {}},
                {"type": "flow/template", "alias": "echo", "inputs": {
                    "template": {"kind": "const", "value": "hello from flow"}
                }}
            ],
            "edges": [
                {"source": {"node": "go", "port": "exec"},
                 "target": {"node": "echo", "port": "exec"}}
            ]
        }
    })
}

fn color_flow(name: &str, color: &str) -> serde_json::Value {
    serde_json::json!({
        "edition": 1,
        "kind": "passive",
        "name": name,
        "graph": {
            "nodes": [
                {"type": "flow/on-intercept-response", "alias": "start", "inputs": {}},
                {"type": "flow/set-color", "alias": "paint", "inputs": {
                    "color": {"kind": "const", "value": color}
                }}
            ],
            "edges": [
                {"source": {"node": "start", "port": "exec"},
                 "target": {"node": "paint", "port": "exec"}}
            ]
        }
    })
}

async fn wait_for_job(
    state: &std::sync::Arc<huntproxy::app::AppState>,
    project_id: i64,
    job_id: &str,
) -> serde_json::Value {
    let app = huntproxy::api::router(state.clone());
    for _ in 0..100 {
        let response = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/projects/{project_id}/flow-jobs/{job_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let job = json_response(response).await;
        if job["state"] != "running" {
            return job;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("flow job {job_id} did not finish");
}

#[tokio::test]
async fn flow_node_catalog_lists_engine_nodes() {
    let (_directory, state, _project_id) = test_state().await;
    let app = huntproxy::api::router(state);
    let response = app
        .oneshot(
            Request::get("/api/v1/flow-nodes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_response(response).await;
    let nodes = body["nodes"].as_array().expect("node catalog");
    assert!(nodes.len() >= 12);
    assert!(nodes.iter().any(|node| node["type_name"] == "flow/if-else"));
    assert!(nodes
        .iter()
        .any(|node| node["type_name"] == "flow/set-color"));
}

#[tokio::test]
async fn flow_crud_run_and_jobs_via_rest() {
    let (_directory, state, project_id) = test_state().await;
    let app = huntproxy::api::router(state.clone());
    let base = format!("/api/v1/projects/{}/flows", project_id.get());

    let created = app
        .clone()
        .oneshot(
            Request::post(base.clone())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "definition": echo_flow("echo-flow") }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let flow = json_response(created).await;
    let flow_id = flow["id"].as_i64().expect("flow id");
    assert_eq!(flow["enabled"], true);
    assert_eq!(flow["kind"], "active");

    let listed = app
        .clone()
        .oneshot(Request::get(base.clone()).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let flows = json_response(listed).await["flows"]
        .as_array()
        .expect("flows list")
        .clone();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0]["id"], flow_id);

    let fetched = app
        .clone()
        .oneshot(
            Request::get(format!("{base}/{flow_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json_response(fetched).await["name"], "echo-flow");

    let run = app
        .clone()
        .oneshot(
            Request::post(format!("{base}/{flow_id}/run"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(run.status(), StatusCode::ACCEPTED);
    let job_id = json_response(run).await["job_id"]
        .as_str()
        .expect("job id")
        .to_string();
    let job = wait_for_job(&state, project_id.get(), &job_id).await;
    assert_eq!(job["state"], "succeeded", "{job}");
    assert_eq!(job["outcome"]["outputs"]["echo.text"], "hello from flow");

    let disabled = app
        .clone()
        .oneshot(
            Request::post(format!("{base}/{flow_id}/disable"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json_response(disabled).await["enabled"], false);

    let rejected = app
        .clone()
        .oneshot(
            Request::post(format!("{base}/{flow_id}/run"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

    let mut definition = echo_flow("echo-flow");
    definition["description"] = serde_json::json!("renamed later");
    let updated = app
        .clone()
        .oneshot(
            Request::put(format!("{base}/{flow_id}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "definition": definition }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(updated.status(), StatusCode::OK);
    assert_eq!(json_response(updated).await["description"], "renamed later");

    let deleted = app
        .clone()
        .oneshot(
            Request::delete(format!("{base}/{flow_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let missing = app
        .clone()
        .oneshot(
            Request::get(format!("{base}/{flow_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn passive_flow_colors_recorded_exchange() {
    let (_directory, state, project_id) = test_state().await;
    let app = huntproxy::api::router(state.clone());

    let created = app
        .oneshot(
            Request::post(format!("/api/v1/projects/{}/flows", project_id.get()))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "definition": color_flow("color-flow", "orange") })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);

    let exchange_id = state
        .db
        .insert_exchange(exchange(project_id, "/colored"))
        .await
        .unwrap();
    let spawned = state
        .flows
        .trigger_passive(
            project_id,
            serde_json::json!({
                "exchange_id": exchange_id.get(),
                "source": "proxy",
                "status": 200,
                "method": "GET",
                "scheme": "https",
                "authority": "example.com",
                "path": "/colored",
                "query": null,
            }),
        )
        .await
        .unwrap();
    assert_eq!(spawned.len(), 1);
    let job_id = spawned[0].to_string();
    let job = wait_for_job(&state, project_id.get(), &job_id).await;
    assert_eq!(job["state"], "succeeded", "{job}");

    let summary = state
        .db
        .get_exchange_summary(project_id, exchange_id)
        .await
        .unwrap();
    assert_eq!(summary.color.as_deref(), Some("orange"));
}

#[tokio::test]
async fn flow_shell_kill_switch_blocks_shell_node() {
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        data_dir: directory.path().to_path_buf(),
        spool_dir: directory.path().join("spool"),
        export_dir: directory.path().join("exports"),
        runtime_dir: directory.path().join("runtime"),
        plugin_dir: directory.path().join("plugins"),
        browser_worker_path: Some(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("browser-worker")
                .join("index.js"),
        ),
        flows: huntproxy::config::FlowsConfig { allow_shell: false },
        ..Config::default()
    };
    let state = bootstrap_state(config).await.unwrap();
    let project = state
        .db
        .create_project(CreateProjectRequest {
            name: "Shell off".into(),
            target_url: "https://example.com/".into(),
            advanced: None,
        })
        .await
        .unwrap();
    let app = huntproxy::api::router(state.clone());

    let definition = serde_json::json!({
        "edition": 1,
        "kind": "active",
        "name": "shell-flow",
        "graph": {
            "nodes": [
                {"type": "flow/manual-start", "alias": "go", "inputs": {}},
                {"type": "flow/shell", "alias": "run", "inputs": {
                    "command": {"kind": "const", "value": "echo"},
                    "args": {"kind": "const", "value": ["hi"]}
                }}
            ],
            "edges": [
                {"source": {"node": "go", "port": "exec"},
                 "target": {"node": "run", "port": "exec"}}
            ]
        }
    });
    let created = app
        .oneshot(
            Request::post(format!("/api/v1/projects/{}/flows", project.id.get()))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "definition": definition }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let flow_id = json_response(created).await["id"].as_i64().unwrap();

    let run = app
        .oneshot(
            Request::post(format!(
                "/api/v1/projects/{}/flows/{flow_id}/run",
                project.id.get()
            ))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
        )
        .await
        .unwrap();
    let job_id = json_response(run).await["job_id"]
        .as_str()
        .unwrap()
        .to_string();
    let job = wait_for_job(&state, project.id.get(), &job_id).await;
    assert_eq!(job["state"], "failed", "{job}");
    let error = job["error"].as_str().expect("error message");
    assert!(error.contains("shell node is disabled"), "{error}");
}
