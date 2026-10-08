//! Flow execution engine: resolves inputs, drives exec edges breadth-first,
//! and runs each node at most once per run.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::domain::{DomainError, DomainResult, FlowDefinition, FlowNode, FlowProperty};
use crate::domain::{ErrorCode, FlowKind};

use super::registry::{node_info, NodeInfo};

/// Maximum node handler invocations per run.
pub const MAX_FLOW_STEPS: usize = 1_000;
/// Default wall-clock deadline for a whole run.
pub const DEFAULT_FLOW_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub enum FlowTrigger {
    Exchange(Value),
    Manual(Value),
}

impl FlowTrigger {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Exchange(_) => "exchange",
            Self::Manual(_) => "manual",
        }
    }

    pub fn payload(&self) -> &Value {
        match self {
            Self::Exchange(value) | Self::Manual(value) => value,
        }
    }

    /// Exchange id carried by an exchange trigger, when present.
    pub fn exchange_id(&self) -> Option<i64> {
        match self {
            Self::Exchange(value) => value
                .get("exchange_id")
                .and_then(Value::as_i64)
                .or_else(|| value.get("id").and_then(Value::as_i64)),
            Self::Manual(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowRunOptions {
    pub cancel: CancellationToken,
    pub max_steps: usize,
    pub deadline: Duration,
    pub project_id: crate::domain::ProjectId,
}

impl Default for FlowRunOptions {
    fn default() -> Self {
        Self {
            cancel: CancellationToken::new(),
            max_steps: MAX_FLOW_STEPS,
            deadline: DEFAULT_FLOW_DEADLINE,
            project_id: crate::domain::ProjectId(0),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeOutcome {
    pub port: String,
    pub outputs: BTreeMap<String, Value>,
}

impl NodeOutcome {
    pub fn port(port: &str) -> Self {
        Self {
            port: port.to_string(),
            outputs: BTreeMap::new(),
        }
    }

    pub fn with(mut self, name: &str, value: Value) -> Self {
        self.outputs.insert(name.to_string(), value);
        self
    }
}

/// Request context handed to node handlers alongside their resolved inputs.
pub struct NodeExecCtx<'a> {
    pub trigger: &'a FlowTrigger,
    pub project_id: crate::domain::ProjectId,
    pub cancel: CancellationToken,
}

#[async_trait::async_trait]
pub trait NodeHandler: Send + Sync {
    async fn exec(
        &self,
        node: &FlowNode,
        inputs: &BTreeMap<String, Value>,
        ctx: &NodeExecCtx<'_>,
    ) -> DomainResult<NodeOutcome>;
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FlowStepLog {
    pub alias: String,
    pub node_type: String,
    pub port: String,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FlowRunOutcome {
    pub steps: Vec<FlowStepLog>,
    /// Produced outputs keyed `alias.output`.
    pub outputs: BTreeMap<String, Value>,
    pub duration_ms: u64,
    /// Set when the run aborted early (node failure, step limit, or cancel).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl FlowRunOutcome {
    pub fn succeeded(&self) -> bool {
        self.error.is_none()
    }
}

/// Outputs a trigger node produces for its payload.
fn trigger_outputs(trigger: &FlowTrigger) -> BTreeMap<String, Value> {
    match trigger {
        FlowTrigger::Exchange(payload) => {
            let mut outputs = BTreeMap::new();
            outputs.insert("exchange".into(), payload.clone());
            outputs.insert(
                "status".into(),
                payload.get("status_code").cloned().unwrap_or(Value::Null),
            );
            outputs.insert(
                "method".into(),
                payload.get("method").cloned().unwrap_or(Value::Null),
            );
            let url = payload
                .get("scheme")
                .and_then(Value::as_str)
                .map(|scheme| {
                    let mut url = String::new();
                    url.push_str(scheme);
                    url.push_str("://");
                    if let Some(authority) = payload.get("authority").and_then(Value::as_str) {
                        url.push_str(authority);
                    }
                    if let Some(path) = payload.get("path").and_then(Value::as_str) {
                        url.push_str(path);
                    }
                    if let Some(query) = payload.get("query").and_then(Value::as_str) {
                        if !query.is_empty() {
                            url.push('?');
                            url.push_str(query);
                        }
                    }
                    Value::String(url)
                })
                .unwrap_or(Value::Null);
            outputs.insert("url".into(), url);
            outputs
        }
        FlowTrigger::Manual(payload) => {
            let mut outputs = BTreeMap::new();
            outputs.insert("input".into(), payload.clone());
            outputs
        }
    }
}

fn trigger_node_type(trigger: &FlowTrigger) -> &'static str {
    match trigger {
        FlowTrigger::Exchange(_) => "flow/on-intercept-response",
        FlowTrigger::Manual(_) => "flow/manual-start",
    }
}

pub async fn run_flow(
    definition: &FlowDefinition,
    trigger: FlowTrigger,
    handler: &dyn NodeHandler,
    options: &FlowRunOptions,
) -> DomainResult<FlowRunOutcome> {
    super::validate::validate_flow(definition)?;

    let started = Instant::now();
    let trigger_type = trigger_node_type(&trigger);
    let nodes: HashMap<&str, &FlowNode> = definition
        .graph
        .nodes
        .iter()
        .map(|node| (node.alias.as_str(), node))
        .collect();
    let start = definition
        .graph
        .nodes
        .iter()
        .find(|node| node.node_type == trigger_type)
        .ok_or_else(|| {
            DomainError::invalid(format!("flow is missing trigger node `{trigger_type}`"))
        })?;

    let mut values: BTreeMap<(String, String), Value> = BTreeMap::new();
    let mut executed: BTreeMap<&str, ()> = BTreeMap::new();
    let mut queue: VecDeque<(String, String)> = VecDeque::new();
    let mut steps: Vec<FlowStepLog> = Vec::new();
    let mut outputs: BTreeMap<String, Value> = BTreeMap::new();

    for (name, value) in trigger_outputs(&trigger) {
        values.insert((start.alias.clone(), name.clone()), value.clone());
        outputs.insert(format!("{}.{}", start.alias, name), value);
    }
    executed.insert(start.alias.as_str(), ());
    queue.push_back((start.alias.clone(), "exec".to_string()));

    let mut error: Option<String> = None;
    let deadline = started + options.deadline;

    while let Some((source_alias, source_port)) = queue.pop_front() {
        if options.cancel.is_cancelled() {
            error = Some("flow cancelled".into());
            break;
        }
        if Instant::now() >= deadline {
            error = Some(format!("flow exceeded {} ms", options.deadline.as_millis()));
            break;
        }
        for edge in &definition.graph.edges {
            if edge.source.node != source_alias || edge.source.port != source_port {
                continue;
            }
            if executed.contains_key(edge.target.node.as_str()) {
                continue;
            }
            let node = nodes[edge.target.node.as_str()];
            let info = node_info(&node.node_type).expect("validated node type");
            executed.insert(node.alias.as_str(), ());

            if steps.len() >= options.max_steps {
                error = Some(format!("flow exceeded {} steps", options.max_steps));
                break;
            }

            let exec_started = Instant::now();
            let resolved = resolve_inputs(node, info, &values);
            let exec_ctx = NodeExecCtx {
                trigger: &trigger,
                project_id: options.project_id,
                cancel: options.cancel.clone(),
            };
            let outcome = match resolved {
                Ok(inputs) => handler.exec(node, &inputs, &exec_ctx).await,
                Err(error) => Err(error),
            };
            let duration_ms = exec_started.elapsed().as_millis() as u64;
            match outcome {
                Ok(outcome) => {
                    for (name, value) in &outcome.outputs {
                        values.insert((node.alias.clone(), name.clone()), value.clone());
                        outputs.insert(format!("{}.{}", node.alias, name), value.clone());
                    }
                    steps.push(FlowStepLog {
                        alias: node.alias.clone(),
                        node_type: node.node_type.clone(),
                        port: outcome.port.clone(),
                        duration_ms,
                        error: None,
                    });
                    queue.push_back((node.alias.clone(), outcome.port));
                }
                Err(node_error) => {
                    let message = node_error.to_string();
                    steps.push(FlowStepLog {
                        alias: node.alias.clone(),
                        node_type: node.node_type.clone(),
                        port: "error".into(),
                        duration_ms,
                        error: Some(message.clone()),
                    });
                    if definition
                        .graph
                        .edges
                        .iter()
                        .any(|edge| edge.source.node == node.alias && edge.source.port == "error")
                    {
                        values.insert(
                            (node.alias.clone(), "error".into()),
                            Value::String(message.clone()),
                        );
                        outputs.insert(format!("{}.error", node.alias), Value::String(message));
                        queue.push_back((node.alias.clone(), "error".to_string()));
                    } else {
                        error = Some(message);
                    }
                    continue;
                }
            }
        }
        if error.is_some() {
            break;
        }
    }

    Ok(FlowRunOutcome {
        steps,
        outputs,
        duration_ms: started.elapsed().as_millis() as u64,
        error,
    })
}

fn resolve_inputs(
    node: &FlowNode,
    info: &'static NodeInfo,
    values: &BTreeMap<(String, String), Value>,
) -> DomainResult<BTreeMap<String, Value>> {
    let mut inputs = BTreeMap::new();
    for (name, property) in &node.inputs {
        let spec = info.input(name).ok_or_else(|| {
            DomainError::invalid(format!("unknown input `{name}` on `{}`", node.alias))
        })?;
        let value = match property {
            FlowProperty::Const { value } => value.clone(),
            FlowProperty::Ref { node: source, output } => values
                .get(&(source.clone(), output.clone()))
                .cloned()
                .ok_or_else(|| {
                    DomainError::new(
                        ErrorCode::ProtocolError,
                        format!(
                            "input `{name}` on `{}` needs `{source}.{output}`, which has not been produced",
                            node.alias
                        ),
                    )
                })?,
        };
        if !spec.kind.holds(&value) {
            return Err(DomainError::new(
                ErrorCode::ProtocolError,
                format!(
                    "input `{name}` on `{}` expected {}, got {}",
                    node.alias,
                    spec.kind.as_str(),
                    match &value {
                        Value::Null => "null",
                        Value::Bool(_) => "boolean",
                        Value::Number(_) => "number",
                        Value::String(_) => "string",
                        Value::Array(_) => "array",
                        Value::Object(_) => "object",
                    }
                ),
            ));
        }
        inputs.insert(name.clone(), value);
    }
    Ok(inputs)
}

/// Active flows require a manual trigger; passive flows an exchange trigger.
pub fn trigger_kind_for(flow_kind: FlowKind) -> &'static str {
    match flow_kind {
        FlowKind::Passive => "exchange",
        FlowKind::Active | FlowKind::Convert => "manual",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{FlowEdge, FlowPort};

    struct MockHandler;

    #[async_trait::async_trait]
    impl NodeHandler for MockHandler {
        async fn exec(
            &self,
            node: &FlowNode,
            inputs: &BTreeMap<String, Value>,
            _ctx: &NodeExecCtx<'_>,
        ) -> DomainResult<NodeOutcome> {
            match node.node_type.as_str() {
                "flow/if-else" => {
                    let left = inputs.get("left").cloned().unwrap_or(Value::Null);
                    let right = inputs.get("right").cloned().unwrap_or(Value::Null);
                    let op = inputs
                        .get("op")
                        .and_then(Value::as_str)
                        .unwrap_or("eq")
                        .to_string();
                    let eq = left == right;
                    let port = match op.as_str() {
                        "eq" => eq,
                        "ne" => !eq,
                        _ => eq,
                    };
                    Ok(NodeOutcome::port(if port { "true" } else { "false" }))
                }
                "flow/set-color" => {
                    let color = inputs
                        .get("color")
                        .and_then(Value::as_str)
                        .unwrap_or("none")
                        .to_string();
                    if color == "boom" {
                        return Err(DomainError::invalid("bad color"));
                    }
                    Ok(NodeOutcome::port("ok")
                        .with("exchange_id", Value::from(42))
                        .with("color", Value::String(color)))
                }
                "flow/template" => {
                    let template = inputs
                        .get("template")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    Ok(NodeOutcome::port("ok")
                        .with("text", Value::String(template.replace("{{status}}", "200"))))
                }
                other => Err(DomainError::invalid(format!("unhandled {other}"))),
            }
        }
    }

    fn definition(json: serde_json::Value) -> FlowDefinition {
        serde_json::from_value(json).unwrap()
    }

    fn passive_sample() -> FlowDefinition {
        definition(serde_json::json!({
            "edition": 1,
            "kind": "passive",
            "name": "sample",
            "graph": {
                "nodes": [
                    {"type": "flow/on-intercept-response", "alias": "start", "inputs": {}},
                    {"type": "flow/if-else", "alias": "check", "inputs": {
                        "left": {"kind": "const", "value": 500},
                        "right": {"kind": "ref", "node": "start", "output": "status"}
                    }},
                    {"type": "flow/set-color", "alias": "paint", "inputs": {
                        "color": {"kind": "const", "value": "red"}
                    }}
                ],
                "edges": [
                    {"source": {"node": "start", "port": "exec"},
                     "target": {"node": "check", "port": "exec"}},
                    {"source": {"node": "check", "port": "true"},
                     "target": {"node": "paint", "port": "exec"}}
                ]
            }
        }))
    }

    fn exchange_trigger(status: i64) -> FlowTrigger {
        FlowTrigger::Exchange(serde_json::json!({
            "exchange_id": 7,
            "status_code": status,
            "method": "GET",
            "scheme": "https",
            "authority": "example.test",
            "path": "/x",
            "query": "a=1"
        }))
    }

    #[tokio::test]
    async fn runs_branch_taken_and_collects_outputs() {
        let outcome = run_flow(
            &passive_sample(),
            exchange_trigger(500),
            &MockHandler,
            &FlowRunOptions::default(),
        )
        .await
        .unwrap();
        assert!(outcome.succeeded(), "{:?}", outcome.error);
        assert_eq!(
            outcome
                .steps
                .iter()
                .map(|s| s.alias.as_str())
                .collect::<Vec<_>>(),
            vec!["check", "paint"]
        );
        assert_eq!(outcome.outputs["start.status"], 500);
        assert_eq!(outcome.outputs["paint.exchange_id"], 42);
        assert_eq!(
            outcome.outputs["start.url"].as_str(),
            Some("https://example.test/x?a=1")
        );
    }

    #[tokio::test]
    async fn skips_false_branch() {
        let outcome = run_flow(
            &passive_sample(),
            exchange_trigger(200),
            &MockHandler,
            &FlowRunOptions::default(),
        )
        .await
        .unwrap();
        assert!(outcome.succeeded());
        assert_eq!(outcome.steps.len(), 1);
        assert_eq!(outcome.steps[0].port, "false");
        assert!(outcome.outputs.get("paint.exchange_id").is_none());
    }

    #[tokio::test]
    async fn unhandled_node_error_aborts_run() {
        let mut definition = passive_sample();
        definition.graph.nodes[2].inputs.insert(
            "color".into(),
            FlowProperty::Const {
                value: "boom".into(),
            },
        );
        let outcome = run_flow(
            &definition,
            exchange_trigger(500),
            &MockHandler,
            &FlowRunOptions::default(),
        )
        .await
        .unwrap();
        let error = outcome.error.expect("run must fail");
        assert!(error.contains("bad color"), "{error}");
        assert_eq!(outcome.steps.last().unwrap().port, "error");
    }

    #[tokio::test]
    async fn error_port_continues_when_wired() {
        let mut definition = passive_sample();
        definition.graph.nodes[2].inputs.insert(
            "color".into(),
            FlowProperty::Const {
                value: "boom".into(),
            },
        );
        definition.graph.edges.push(FlowEdge {
            source: FlowPort {
                node: "paint".into(),
                port: "error".into(),
            },
            target: FlowPort {
                node: "check".into(),
                port: "exec".into(),
            },
        });
        let outcome = run_flow(
            &definition,
            exchange_trigger(500),
            &MockHandler,
            &FlowRunOptions::default(),
        )
        .await
        .unwrap();
        // check already executed, so the error edge is a no-op and the run
        // finishes with the recorded error output instead of aborting.
        assert!(outcome.succeeded(), "{:?}", outcome.error);
        assert_eq!(
            outcome.outputs.get("paint.error").and_then(Value::as_str),
            Some("bad color")
        );
    }

    #[tokio::test]
    async fn manual_trigger_supplies_input() {
        let definition = definition(serde_json::json!({
            "edition": 1,
            "kind": "active",
            "name": "manual",
            "graph": {
                "nodes": [
                    {"type": "flow/manual-start", "alias": "go", "inputs": {}},
                    {"type": "flow/template", "alias": "echo", "inputs": {
                        "template": {"kind": "const", "value": "got {{status}}"}
                    }}
                ],
                "edges": [
                    {"source": {"node": "go", "port": "exec"},
                     "target": {"node": "echo", "port": "exec"}}
                ]
            }
        }));
        let outcome = run_flow(
            &definition,
            FlowTrigger::Manual(serde_json::json!({"job": 1})),
            &MockHandler,
            &FlowRunOptions::default(),
        )
        .await
        .unwrap();
        assert!(outcome.succeeded(), "{:?}", outcome.error);
        assert_eq!(outcome.outputs["go.input"], serde_json::json!({"job": 1}));
        assert_eq!(outcome.outputs["echo.text"], "got 200");
    }

    #[tokio::test]
    async fn step_limit_stops_runaway_graphs() {
        let mut definition = passive_sample();
        // Chain extra set-color nodes to exceed a tiny step budget.
        let mut last = "check".to_string();
        for index in 0..10 {
            let alias = format!("extra{index}");
            definition.graph.nodes.push(
                serde_json::from_value(serde_json::json!({
                    "type": "flow/set-color",
                    "alias": alias,
                    "inputs": {"color": {"kind": "const", "value": "red"}}
                }))
                .unwrap(),
            );
            definition.graph.edges.push(FlowEdge {
                source: FlowPort {
                    node: last.clone(),
                    port: if last == "check" { "true" } else { "ok" }.into(),
                },
                target: FlowPort {
                    node: alias.clone(),
                    port: "exec".into(),
                },
            });
            last = alias;
        }
        let outcome = run_flow(
            &definition,
            exchange_trigger(500),
            &MockHandler,
            &FlowRunOptions {
                max_steps: 3,
                ..FlowRunOptions::default()
            },
        )
        .await
        .unwrap();
        let error = outcome.error.expect("step limit must trip");
        assert!(error.contains("steps"), "{error}");
    }
}
