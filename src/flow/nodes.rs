//! Built-in node implementations for the flow engine.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use regex::RegexBuilder;
use serde_json::{json, Value};

use crate::domain::{
    DomainError, DomainResult, ErrorCode, ExchangeId, FlowNode, HeaderPatch, ProjectId,
    ProtocolPreference, ReplyCredentialMode, ReplyDraft, ReplyInheritance,
};
use crate::reply::ReplyService;
use crate::storage::Db;

use super::interp::{NodeExecCtx, NodeHandler, NodeOutcome};
use super::js::run_flow_js;
use super::shell::{run_flow_shell, shell_args, shell_timeout_ms, ShellRequest};

const DEFAULT_JS_TIMEOUT_MS: u64 = 5_000;
const MAX_JS_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_HTTP_TIMEOUT_MS: u64 = 30_000;

pub struct BuiltInHandler {
    pub db: Option<Arc<Db>>,
    pub reply: Option<Arc<ReplyService>>,
    pub allow_shell: bool,
}

impl BuiltInHandler {
    pub fn new(db: Option<Arc<Db>>, reply: Option<Arc<ReplyService>>, allow_shell: bool) -> Self {
        Self {
            db,
            reply,
            allow_shell,
        }
    }

    fn db(&self) -> DomainResult<&Arc<Db>> {
        self.db.as_ref().ok_or_else(|| {
            DomainError::new(ErrorCode::Unavailable, "flow node requires the database")
        })
    }

    async fn shell_node(
        &self,
        node: &FlowNode,
        inputs: &BTreeMap<String, Value>,
        ctx: &NodeExecCtx<'_>,
    ) -> DomainResult<NodeOutcome> {
        if !self.allow_shell {
            return Err(DomainError::new(
                ErrorCode::Unavailable,
                "flow shell node is disabled (flows.allow_shell = false)",
            ));
        }
        let command = input_str(inputs, "command")?.to_string();
        let args = shell_args(inputs.get("args"))?;
        let timeout = shell_timeout_ms(input_number(inputs, "timeout_ms"));
        let request = ShellRequest {
            command: command.clone(),
            args: args.clone(),
            timeout,
        };
        let audit = |outcome: Value| {
            let db = self.db.clone();
            let project_id = ctx.project_id;
            let alias = node.alias.clone();
            async move {
                if let Some(db) = db {
                    let _ = db
                        .audit(
                            Some(project_id),
                            "flow.shell",
                            Some("flow"),
                            Some("flow"),
                            Some(&alias),
                            outcome,
                        )
                        .await;
                }
            }
        };
        match run_flow_shell(request).await {
            Ok(output) => {
                audit(json!({
                    "command": command,
                    "args": args,
                    "code": output.code,
                    "truncated": output.truncated,
                    "timeout_ms": timeout.as_millis(),
                }))
                .await;
                Ok(NodeOutcome::port("ok")
                    .with("stdout", Value::String(output.stdout))
                    .with("stderr", Value::String(output.stderr))
                    .with("code", output.code.map(Value::from).unwrap_or(Value::Null)))
            }
            Err(error) => {
                audit(json!({
                    "command": command,
                    "args": args,
                    "error": error.code().as_str(),
                    "timeout_ms": timeout.as_millis(),
                }))
                .await;
                Err(error)
            }
        }
    }

    async fn http_node(
        &self,
        inputs: &BTreeMap<String, Value>,
        ctx: &NodeExecCtx<'_>,
    ) -> DomainResult<NodeOutcome> {
        let reply = self.reply.as_ref().ok_or_else(|| {
            DomainError::new(
                ErrorCode::Unavailable,
                "flow http-request node requires the Reply service",
            )
        })?;
        let method = input_str(inputs, "method")?.to_string();
        let url = input_str(inputs, "url")?.to_string();
        let headers = match inputs.get("headers") {
            Some(Value::Object(map)) => map
                .iter()
                .map(|(name, value)| {
                    Ok(HeaderPatch {
                        name: name.clone(),
                        value: scalar_bytes(value)?,
                    })
                })
                .collect::<DomainResult<Vec<_>>>()?,
            None => Vec::new(),
            Some(other) => {
                return Err(DomainError::invalid(format!(
                    "headers must be an object, got {other}"
                )))
            }
        };
        let draft = ReplyDraft {
            method: Some(method),
            url: Some(url),
            header_overrides: headers,
            header_tombstones: Vec::new(),
            inheritance: ReplyInheritance::FullRequest,
            body_override: None,
            body_text: input_optional_str(inputs, "body")?,
            body_json: None,
            body_format: None,
            body_params: Vec::new(),
            body_cleared: false,
            credential_mode: ReplyCredentialMode::WithProjectCredentials,
        };
        let timeout = Duration::from_millis(clamp_number(
            input_number(inputs, "timeout_ms"),
            1_000,
            300_000,
            DEFAULT_HTTP_TIMEOUT_MS,
        ));
        let sent = tokio::time::timeout(
            timeout,
            reply.send(
                ctx.project_id,
                None,
                None,
                &draft,
                ProtocolPreference::Auto,
                0,
            ),
        )
        .await;
        let result = match sent {
            Ok(result) => result?,
            Err(_) => {
                return Err(DomainError::new(
                    ErrorCode::Timeout,
                    format!("http-request exceeded {} ms", timeout.as_millis()),
                ))
            }
        };
        let headers_out = match result.exchange_id {
            Some(exchange_id) => {
                response_header_object(self.db.as_ref(), ctx.project_id, exchange_id).await?
            }
            None => Value::Object(Default::default()),
        };
        Ok(NodeOutcome::port("ok")
            .with("status", Value::from(result.status_code))
            .with("body", Value::String(result.response_preview.text))
            .with("headers", headers_out)
            .with(
                "exchange_id",
                result
                    .exchange_id
                    .map(|id| Value::from(id.get()))
                    .unwrap_or(Value::Null),
            )
            .with("duration_ms", Value::from(result.duration_ms)))
    }

    async fn set_color_node(
        &self,
        inputs: &BTreeMap<String, Value>,
        ctx: &NodeExecCtx<'_>,
    ) -> DomainResult<NodeOutcome> {
        let color = input_str(inputs, "color")?.to_string();
        validate_color(&color)?;
        let exchange_id = self.resolve_exchange_id(inputs, ctx)?;
        self.db()?
            .set_exchange_color(ctx.project_id, exchange_id, Some(color))
            .await?;
        Ok(NodeOutcome::port("ok").with("exchange_id", Value::from(exchange_id.get())))
    }

    async fn report_finding_node(
        &self,
        inputs: &BTreeMap<String, Value>,
        ctx: &NodeExecCtx<'_>,
    ) -> DomainResult<NodeOutcome> {
        let title = input_str(inputs, "title")?.to_string();
        let description = input_str(inputs, "description")?.to_string();
        let exchange_id = self.resolve_exchange_id(inputs, ctx)?;
        let finding = self
            .db()?
            .create_finding(ctx.project_id, exchange_id, title, description)
            .await?;
        Ok(NodeOutcome::port("ok").with("finding_id", Value::from(finding.id.get())))
    }

    fn resolve_exchange_id(
        &self,
        inputs: &BTreeMap<String, Value>,
        ctx: &NodeExecCtx<'_>,
    ) -> DomainResult<ExchangeId> {
        if let Some(id) = input_number(inputs, "exchange_id") {
            return Ok(ExchangeId(id as i64));
        }
        ctx.trigger.exchange_id().map(ExchangeId).ok_or_else(|| {
            DomainError::invalid(
                "exchange_id is required when the flow was not triggered by an exchange",
            )
        })
    }
}

#[async_trait::async_trait]
impl NodeHandler for BuiltInHandler {
    async fn exec(
        &self,
        node: &FlowNode,
        inputs: &BTreeMap<String, Value>,
        ctx: &NodeExecCtx<'_>,
    ) -> DomainResult<NodeOutcome> {
        match node.node_type.as_str() {
            "flow/if-else" => if_else(inputs),
            "flow/template" => template(inputs),
            "flow/json-parse" => json_parse(inputs),
            "flow/json-select" => json_select(inputs),
            "flow/regex-match" => regex_match(inputs),
            "flow/js" => {
                let code = input_str(inputs, "code")?.to_string();
                let input = inputs.get("input").cloned().unwrap_or(Value::Null);
                let timeout = Duration::from_millis(clamp_number(
                    input_number(inputs, "timeout_ms"),
                    1,
                    MAX_JS_TIMEOUT_MS,
                    DEFAULT_JS_TIMEOUT_MS,
                ));
                let output = run_flow_js(&code, &input, timeout, ctx.cancel.clone()).await?;
                Ok(NodeOutcome::port("ok").with("output", output))
            }
            "flow/shell" => self.shell_node(node, inputs, ctx).await,
            "flow/http-request" => self.http_node(inputs, ctx).await,
            "flow/set-color" => self.set_color_node(inputs, ctx).await,
            "flow/report-finding" => self.report_finding_node(inputs, ctx).await,
            other => Err(DomainError::invalid(format!(
                "node type `{other}` is not executable"
            ))),
        }
    }
}

fn input_str<'a>(inputs: &'a BTreeMap<String, Value>, name: &str) -> DomainResult<&'a str> {
    inputs
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| DomainError::invalid(format!("input `{name}` must be a string")))
}

fn input_optional_str(
    inputs: &BTreeMap<String, Value>,
    name: &str,
) -> DomainResult<Option<String>> {
    match inputs.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(other) => Err(DomainError::invalid(format!(
            "input `{name}` must be a string, got {other}"
        ))),
    }
}

fn input_number(inputs: &BTreeMap<String, Value>, name: &str) -> Option<f64> {
    inputs.get(name).and_then(Value::as_f64)
}

fn clamp_number(value: Option<f64>, min: u64, max: u64, default: u64) -> u64 {
    value
        .and_then(|value| u64::try_from(value as i64).ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn scalar_bytes(value: &Value) -> DomainResult<Vec<u8>> {
    match value {
        Value::String(text) => Ok(text.as_bytes().to_vec()),
        Value::Number(number) => Ok(number.to_string().into_bytes()),
        Value::Bool(flag) => Ok(flag.to_string().into_bytes()),
        other => Err(DomainError::invalid(format!(
            "header values must be scalars, got {other}"
        ))),
    }
}

fn validate_color(color: &str) -> DomainResult<()> {
    if color.is_empty()
        || color.len() > 64
        || !color
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "#(),. -".contains(ch))
    {
        return Err(DomainError::invalid(format!(
            "invalid color `{color}` (use a name, #rgb, or #rrggbb)"
        )));
    }
    Ok(())
}

fn if_else(inputs: &BTreeMap<String, Value>) -> DomainResult<NodeOutcome> {
    let left = inputs.get("left").cloned().unwrap_or(Value::Null);
    let right = inputs.get("right").cloned().unwrap_or(Value::Null);
    let op = input_optional_str(inputs, "op")?.unwrap_or_else(|| "eq".into());
    let matched = match op.as_str() {
        "eq" => left == right,
        "ne" => left != right,
        "gt" | "gte" | "lt" | "lte" => {
            let left = left.as_f64().ok_or_else(|| {
                DomainError::invalid(format!("op `{op}` requires numeric left operand"))
            })?;
            let right = right.as_f64().ok_or_else(|| {
                DomainError::invalid(format!("op `{op}` requires numeric right operand"))
            })?;
            match op.as_str() {
                "gt" => left > right,
                "gte" => left >= right,
                "lt" => left < right,
                _ => left <= right,
            }
        }
        "contains" => match (&left, &right) {
            (Value::String(haystack), Value::String(needle)) => haystack.contains(needle.as_str()),
            (Value::Array(items), value) => items.contains(value),
            _ => {
                return Err(DomainError::invalid(
                    "op `contains` requires string or array left operand",
                ))
            }
        },
        "startswith" => left
            .as_str()
            .zip(right.as_str())
            .map(|(prefix, value)| value.starts_with(prefix))
            .ok_or_else(|| DomainError::invalid("op `startswith` requires string operands"))?,
        "endswith" => left
            .as_str()
            .zip(right.as_str())
            .map(|(suffix, value)| value.ends_with(suffix))
            .ok_or_else(|| DomainError::invalid("op `endswith` requires string operands"))?,
        "matches" => {
            let text = left.as_str().ok_or_else(|| {
                DomainError::invalid("op `matches` requires a string left operand")
            })?;
            let pattern = right
                .as_str()
                .ok_or_else(|| DomainError::invalid("op `matches` requires a string pattern"))?;
            let regex = RegexBuilder::new(pattern)
                .build()
                .map_err(|error| DomainError::invalid(format!("invalid pattern: {error}")))?;
            regex.is_match(text)
        }
        other => {
            return Err(DomainError::invalid(format!(
                "unknown comparison op `{other}`"
            )))
        }
    };
    Ok(NodeOutcome::port(if matched { "true" } else { "false" }))
}

fn template(inputs: &BTreeMap<String, Value>) -> DomainResult<NodeOutcome> {
    let mut text = input_str(inputs, "template")?.to_string();
    if let Some(Value::Object(vars)) = inputs.get("vars") {
        for (key, value) in vars {
            let rendered = match value {
                Value::String(text) => text.clone(),
                Value::Null => String::new(),
                other => other.to_string(),
            };
            text = text.replace(&format!("{{{{{key}}}}}"), &rendered);
        }
    }
    Ok(NodeOutcome::port("ok").with("text", Value::String(text)))
}

fn json_parse(inputs: &BTreeMap<String, Value>) -> DomainResult<NodeOutcome> {
    let text = input_str(inputs, "text")?;
    let value: Value = serde_json::from_str(text)
        .map_err(|error| DomainError::invalid(format!("invalid JSON: {error}")))?;
    Ok(NodeOutcome::port("ok").with("value", value))
}

fn json_select(inputs: &BTreeMap<String, Value>) -> DomainResult<NodeOutcome> {
    let root = inputs.get("value").cloned().unwrap_or(Value::Null);
    let path = input_str(inputs, "path")?;
    if path.is_empty() || path.split('.').any(str::is_empty) {
        return Err(DomainError::invalid(format!(
            "invalid path `{path}` (use dotted segments like a.b.0)"
        )));
    }
    let mut current: Option<&Value> = Some(&root);
    let mut found = true;
    for segment in path.split('.') {
        current = match current {
            Some(Value::Object(map)) => map.get(segment),
            Some(Value::Array(items)) => segment
                .parse::<usize>()
                .ok()
                .and_then(|index| items.get(index)),
            _ => None,
        };
        if current.is_none() {
            found = false;
            break;
        }
    }
    let value = current.cloned().unwrap_or(Value::Null);
    Ok(NodeOutcome::port("ok")
        .with("found", Value::Bool(found))
        .with("value", value))
}

fn regex_match(inputs: &BTreeMap<String, Value>) -> DomainResult<NodeOutcome> {
    let text = input_str(inputs, "text")?.to_string();
    let pattern = input_str(inputs, "pattern")?;
    let flags = input_optional_str(inputs, "flags")?.unwrap_or_default();
    let mut builder = RegexBuilder::new(pattern);
    for flag in flags.chars() {
        match flag {
            'i' => {
                builder.case_insensitive(true);
            }
            'm' => {
                builder.multi_line(true);
            }
            's' => {
                builder.dot_matches_new_line(true);
            }
            other => {
                return Err(DomainError::invalid(format!(
                    "unknown regex flag `{other}` (use i, m, or s)"
                )))
            }
        }
    }
    let regex = builder
        .build()
        .map_err(|error| DomainError::invalid(format!("invalid pattern: {error}")))?;
    let groups = match regex.captures(&text) {
        Some(captures) => captures
            .iter()
            .map(|capture| match capture {
                Some(value) => Value::String(value.as_str().to_string()),
                None => Value::Null,
            })
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };
    let matched = !groups.is_empty();
    Ok(NodeOutcome::port("ok")
        .with("matched", Value::Bool(matched))
        .with("groups", Value::Array(groups)))
}

async fn response_header_object(
    db: Option<&Arc<Db>>,
    project_id: ProjectId,
    exchange_id: ExchangeId,
) -> DomainResult<Value> {
    let db = db.ok_or_else(|| {
        DomainError::new(ErrorCode::Unavailable, "flow node requires the database")
    })?;
    let headers = db
        .load_raw_headers(
            project_id,
            exchange_id,
            crate::domain::MessageSide::Response,
        )
        .await?;
    let mut map = serde_json::Map::new();
    for header in headers {
        let entry = map
            .entry(header.name)
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(items) = entry {
            items.push(Value::String(
                String::from_utf8_lossy(&header.value).into_owned(),
            ));
        }
    }
    Ok(Value::Object(map))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(pairs: serde_json::Value) -> BTreeMap<String, Value> {
        serde_json::from_value(pairs).unwrap()
    }

    #[test]
    fn if_else_branches_on_operators() {
        let outcome = if_else(&inputs(json!({
            "left": 10, "right": 10, "op": "eq"
        })))
        .unwrap();
        assert_eq!(outcome.port, "true");

        let outcome = if_else(&inputs(json!({
            "left": 10, "right": 11, "op": "lt"
        })))
        .unwrap();
        assert_eq!(outcome.port, "true");

        let outcome = if_else(&inputs(json!({
            "left": "abc", "right": "b", "op": "contains"
        })))
        .unwrap();
        assert_eq!(outcome.port, "true");

        let outcome = if_else(&inputs(json!({
            "left": "hello", "right": "h.llo", "op": "matches"
        })))
        .unwrap();
        assert_eq!(outcome.port, "true");

        assert!(if_else(&inputs(json!({"left": "x", "right": 1, "op": "gt"}))).is_err());
        assert!(if_else(&inputs(json!({"left": 1, "right": 2, "op": "nope"}))).is_err());
    }

    #[test]
    fn template_renders_vars_and_keeps_unknown_placeholders() {
        let outcome = template(&inputs(json!({
            "template": "hi {{name}}, {{missing}}",
            "vars": {"name": "ada", "n": 3, "flag": true, "none": null}
        })))
        .unwrap();
        assert_eq!(outcome.outputs["text"], "hi ada, {{missing}}");

        let outcome = template(&inputs(json!({
            "template": "n={{n}}",
            "vars": {"n": 42}
        })))
        .unwrap();
        assert_eq!(outcome.outputs["text"], "n=42");
    }

    #[test]
    fn json_nodes_parse_and_select() {
        let outcome = json_parse(&inputs(json!({"text": r#"{"a":{"b":[1,2]}}"#}))).unwrap();
        assert_eq!(outcome.outputs["value"], json!({"a": {"b": [1, 2]}}));
        assert!(json_parse(&inputs(json!({"text": "{bad"}))).is_err());

        let outcome = json_select(&inputs(json!({
            "value": {"a": {"b": [10, 20]}},
            "path": "a.b.1"
        })))
        .unwrap();
        assert_eq!(outcome.outputs["found"], true);
        assert_eq!(outcome.outputs["value"], 20);

        let outcome = json_select(&inputs(json!({
            "value": {"a": 1},
            "path": "a.z"
        })))
        .unwrap();
        assert_eq!(outcome.outputs["found"], false);
        assert_eq!(outcome.outputs["value"], Value::Null);
        assert!(json_select(&inputs(json!({"value": 1, "path": ".a"}))).is_err());
    }

    #[test]
    fn regex_node_applies_flags() {
        let outcome = regex_match(&inputs(json!({
            "text": "ID: ABC",
            "pattern": "id: (\\w+)",
            "flags": "i"
        })))
        .unwrap();
        assert_eq!(outcome.outputs["matched"], true);
        assert_eq!(outcome.outputs["groups"], json!(["ID: ABC", "ABC"]));

        let outcome = regex_match(&inputs(json!({
            "text": "abc",
            "pattern": "^x"
        })))
        .unwrap();
        assert_eq!(outcome.outputs["matched"], false);
        assert!(regex_match(&inputs(json!({"text": "a", "pattern": "[", "flags": "q"}))).is_err());
    }

    #[test]
    fn color_validation() {
        assert!(validate_color("#ff0044").is_ok());
        assert!(validate_color("red").is_ok());
        assert!(validate_color("").is_err());
        assert!(validate_color("<script>").is_err());
        assert!(validate_color(&"x".repeat(65)).is_err());
    }
}
