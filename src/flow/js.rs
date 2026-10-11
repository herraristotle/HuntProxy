//! QuickJS execution for `flow/js` nodes, mirroring the plugin host's
//! runtime limits: memory cap, stack cap, deadline interrupt, cancel support.
//!
//! Scripts run as `run(input, sdk)` and get a Caido-workflow-compatible SDK
//! surface: `RequestSpec`/`RequestSpecRaw`/`Body`/`console` globals,
//! `sdk.console`, `sdk.asString`, and `sdk.requests.send` backed by the Reply
//! service (gated by `flows.allow_js_network`). Saved exchanges are surfaced
//! as lazy Request/Response handles whose headers/body/raw are loaded from
//! the database on demand.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use rquickjs::promise::MaybePromise;
use rquickjs::{CatchResultExt, Context, Ctx, Function, Runtime};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use crate::domain::{
    DomainError, DomainResult, ErrorCode, ExchangeId, HeaderPatch, MessageSide, ProjectId,
    ProtocolPreference, ReplyCredentialMode, ReplyDraft, ReplyInheritance,
};
use crate::reply::{ReplySendResult, ReplyService};
use crate::storage::Db;

const MAX_JS_MEMORY: usize = 16 * 1024 * 1024;
const MAX_JS_STACK: usize = 512 * 1024;
const MAX_JS_ERROR_CHARS: usize = 2_048;
const MAX_SDK_HTTP_TIMEOUT_MS: u64 = 30_000;

/// Host capabilities handed to the JS runtime. `allow_network` mirrors the
/// `flows.allow_js_network` config; when false, `sdk.requests.send` throws.
pub struct JsHost {
    pub allow_network: bool,
    pub reply: Option<Arc<ReplyService>>,
    pub db: Option<Arc<Db>>,
    pub project_id: ProjectId,
    pub exchange_id: Option<i64>,
}

impl JsHost {
    /// Every capability disabled; used by unit tests and service-less nodes.
    pub fn disabled() -> Self {
        Self {
            allow_network: false,
            reply: None,
            db: None,
            project_id: ProjectId::from(0),
            exchange_id: None,
        }
    }
}

struct HostInner {
    allow_network: bool,
    reply: Option<Arc<ReplyService>>,
    db: Option<Arc<Db>>,
    project_id: ProjectId,
    exchange_id: Option<i64>,
    deadline: Instant,
    cancel: CancellationToken,
}

/// Runs user code that must define `function run(input)` (optionally async,
/// optionally taking a second `sdk` argument) and returns the JSON value it
/// produced. A run result of `undefined` becomes `null`.
pub async fn run_flow_js(
    code: &str,
    input: &Value,
    timeout: Duration,
    cancel: CancellationToken,
    host: JsHost,
) -> DomainResult<Value> {
    let code = code.to_string();
    let input = input.to_string();
    tokio::task::spawn_blocking(move || run_js_sync(&code, &input, timeout, cancel, host))
        .await
        .map_err(|error| DomainError::new(ErrorCode::Internal, format!("js task: {error}")))?
}

fn run_js_sync(
    code: &str,
    input: &str,
    timeout: Duration,
    cancel: CancellationToken,
    host: JsHost,
) -> DomainResult<Value> {
    let runtime = Runtime::new().map_err(|error| {
        DomainError::new(ErrorCode::Unavailable, format!("QuickJS runtime: {error}"))
    })?;
    runtime.set_memory_limit(MAX_JS_MEMORY);
    runtime.set_max_stack_size(MAX_JS_STACK);
    let deadline = Instant::now() + timeout;
    let expired = Arc::new(AtomicBool::new(false));
    let expired_handler = expired.clone();
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancelled_handler = cancelled.clone();
    let cancel_flag = cancel.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || {
        if cancel_flag.is_cancelled() {
            cancelled_handler.store(true, Ordering::Relaxed);
            return true;
        }
        let hit = Instant::now() >= deadline;
        if hit {
            expired_handler.store(true, Ordering::Relaxed);
        }
        hit
    })));
    let context = Context::full(&runtime).map_err(|error| {
        DomainError::new(ErrorCode::Unavailable, format!("QuickJS context: {error}"))
    })?;
    let inner = Arc::new(HostInner {
        allow_network: host.allow_network,
        reply: host.reply,
        db: host.db,
        project_id: host.project_id,
        exchange_id: host.exchange_id,
        deadline,
        cancel,
    });
    let output = context.with(|ctx| -> Result<String, String> {
        register_host(&ctx, &inner)
            .catch(&ctx)
            .map_err(|error| bounded_js_error(error.to_string()))?;
        ctx.eval::<(), _>(JS_SDK_PRELUDE)
            .catch(&ctx)
            .map_err(|error| bounded_js_error(format!("sdk prelude: {error}")))?;
        ctx.eval::<(), _>(code)
            .catch(&ctx)
            .map_err(|error| bounded_js_error(error.to_string()))?;
        let prepare: Function = ctx
            .globals()
            .get("__hp_prepare")
            .catch(&ctx)
            .map_err(|error| bounded_js_error(error.to_string()))?;
        let input_value = ctx
            .json_parse(input.as_bytes())
            .catch(&ctx)
            .map_err(|error| bounded_js_error(error.to_string()))?;
        let prepared: rquickjs::Value = prepare
            .call((input_value,))
            .catch(&ctx)
            .map_err(|error| bounded_js_error(error.to_string()))?;
        let run: Function = ctx
            .globals()
            .get("run")
            .catch(&ctx)
            .map_err(|error| bounded_js_error(error.to_string()))?;
        let sdk: rquickjs::Value = ctx
            .globals()
            .get("sdk")
            .catch(&ctx)
            .map_err(|error| bounded_js_error(error.to_string()))?;
        let result: rquickjs::Value = run
            .call((prepared, sdk))
            .catch(&ctx)
            .map_err(|error| bounded_js_error(error.to_string()))?;
        let settled = MaybePromise::from_value(result).finish::<rquickjs::Value>();
        let settled = match settled {
            Ok(value) => value,
            Err(rquickjs::Error::WouldBlock) => {
                return Err("script awaited a promise that never resolved".to_string());
            }
            Err(error) => {
                return Err(bounded_js_error(
                    rquickjs::CaughtError::from_error(&ctx, error).to_string(),
                ));
            }
        };
        match ctx.json_stringify(settled).catch(&ctx) {
            Ok(Some(stringified)) => stringified
                .to_string()
                .map_err(|error| bounded_js_error(error.to_string())),
            Ok(None) => Ok("null".to_string()),
            Err(error) => Err(bounded_js_error(error.to_string())),
        }
    });
    if cancelled.load(Ordering::Relaxed) {
        return Err(DomainError::new(ErrorCode::Cancelled, "flow js cancelled"));
    }
    if expired.load(Ordering::Relaxed) {
        return Err(DomainError::new(
            ErrorCode::Timeout,
            format!("flow js exceeded {} ms", timeout.as_millis()),
        ));
    }
    let output = output
        .map_err(|error| DomainError::new(ErrorCode::ProtocolError, format!("flow js: {error}")))?;
    serde_json::from_str(&output).map_err(|error| {
        DomainError::new(
            ErrorCode::ProtocolError,
            format!("flow js returned invalid JSON: {error}"),
        )
    })
}

fn bounded_js_error(mut message: String) -> String {
    if let Some((index, _)) = message.char_indices().nth(MAX_JS_ERROR_CHARS) {
        message.truncate(index);
        message.push('…');
    }
    message
}

fn err_json(message: &str) -> String {
    json!({ "error": message }).to_string()
}

fn register_host(ctx: &Ctx<'_>, inner: &Arc<HostInner>) -> rquickjs::Result<()> {
    ctx.globals()
        .set("__hp_network_enabled", inner.allow_network)?;
    let log = Function::new(
        ctx.clone(),
        move |_ctx: Ctx<'_>, level: String, message: String| -> rquickjs::Result<()> {
            match level.as_str() {
                "error" => tracing::error!(target: "flow.js", "{message}"),
                "warn" => tracing::warn!(target: "flow.js", "{message}"),
                "debug" => tracing::debug!(target: "flow.js", "{message}"),
                _ => tracing::info!(target: "flow.js", "{message}"),
            }
            Ok(())
        },
    )?;
    ctx.globals().set("__hp_log", log)?;
    let send_inner = inner.clone();
    let send = Function::new(ctx.clone(), move |_ctx: Ctx<'_>, payload: String| {
        Ok::<String, rquickjs::Error>(host_send(&send_inner, &payload))
    })?;
    ctx.globals().set("__hp_send", send)?;
    let exchange_inner = inner.clone();
    let exchange = Function::new(
        ctx.clone(),
        move |_ctx: Ctx<'_>, exchange_id: i64, field: String| {
            Ok::<String, rquickjs::Error>(host_exchange(&exchange_inner, exchange_id, &field))
        },
    )?;
    ctx.globals().set("__hp_exchange", exchange)?;
    let finding_inner = inner.clone();
    let finding = Function::new(ctx.clone(), move |_ctx: Ctx<'_>, payload: String| {
        Ok::<String, rquickjs::Error>(host_finding_create(&finding_inner, &payload))
    })?;
    ctx.globals().set("__hp_finding_create", finding)?;
    Ok(())
}

/// Creates a finding attached to the flow's triggering exchange, backing
/// `sdk.findings.create`. The payload carries the Caido finding shape;
/// `dedupe_key` and `severity` are accepted and ignored (no equivalent).
fn host_finding_create(inner: &HostInner, payload: &str) -> String {
    let Some(db) = inner.db.clone() else {
        return err_json("sdk.findings.create requires the database");
    };
    let Ok(spec) = serde_json::from_str::<Value>(payload) else {
        return err_json("sdk.findings.create: invalid payload");
    };
    let title = spec
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let description = spec
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let Some(exchange_id) = inner.exchange_id else {
        return err_json(
            "sdk.findings.create requires an exchange-triggered flow (no exchange to attach to)",
        );
    };
    let project_id = inner.project_id;
    let cancel = inner.cancel.clone();
    let handle = tokio::runtime::Handle::current();
    let guarded = handle.block_on(async {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => None,
            outcome = db.create_finding(project_id, ExchangeId::from(exchange_id), title, description) => Some(outcome),
        }
    });
    match guarded {
        None => err_json("flow js cancelled"),
        Some(Ok(finding)) => json!({
            "id": finding.id.get(),
            "title": finding.title,
            "description": finding.description,
        })
        .to_string(),
        Some(Err(error)) => err_json(&error.to_string()),
    }
}

fn host_send(inner: &HostInner, payload: &str) -> String {
    if !inner.allow_network {
        return err_json(
            "sdk.requests.send is disabled; set flows.allow_js_network = true to allow it",
        );
    }
    let Some(reply) = inner.reply.clone() else {
        return err_json("sdk.requests.send requires the Reply service");
    };
    let Ok(spec) = serde_json::from_str::<Value>(payload) else {
        return err_json("sdk.requests.send: invalid payload");
    };
    let draft = match sdk_spec_to_draft(&spec) {
        Ok(draft) => draft,
        Err(error) => return err_json(&error.to_string()),
    };
    let requested_ms = spec
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(MAX_SDK_HTTP_TIMEOUT_MS);
    let requested_ms = requested_ms.clamp(1, MAX_SDK_HTTP_TIMEOUT_MS);
    let remaining = inner.deadline.saturating_duration_since(Instant::now());
    let timeout = Duration::from_millis(requested_ms).min(remaining);
    if timeout.is_zero() {
        return err_json(&format!(
            "Timeout: sdk.requests.send exceeded {requested_ms} ms"
        ));
    }
    let project_id = inner.project_id;
    let cancel = inner.cancel.clone();
    let handle = tokio::runtime::Handle::current();
    let guarded = handle.block_on(async {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => None,
            outcome = tokio::time::timeout(timeout, reply.send(project_id, None, None, &draft, ProtocolPreference::Auto, 0)) => {
                Some(outcome)
            }
        }
    });
    let outcome = guarded;
    match outcome {
        None => err_json("flow js cancelled"),
        Some(Ok(Ok(sent))) => host_send_success(inner, &spec, &sent).to_string(),
        Some(Ok(Err(error))) => err_json(&error.to_string()),
        Some(Err(_elapsed)) => err_json(&format!(
            "Timeout: sdk.requests.send exceeded {requested_ms} ms"
        )),
    }
}

fn sdk_spec_to_draft(spec: &Value) -> DomainResult<ReplyDraft> {
    let get_str = |name: &str| -> DomainResult<String> {
        spec.get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| DomainError::invalid(format!("send spec is missing `{name}`")))
    };
    let method = get_str("method")?;
    let tls = spec.get("tls").and_then(Value::as_bool).unwrap_or(false);
    let host = get_str("host")?;
    let port = spec
        .get("port")
        .and_then(Value::as_u64)
        .unwrap_or(if tls { 443 } else { 80 });
    let mut path = get_str("path")?;
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    let query = spec
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let scheme = if tls { "https" } else { "http" };
    let url = if query.is_empty() {
        format!("{scheme}://{host}:{port}{path}")
    } else {
        format!("{scheme}://{host}:{port}{path}?{query}")
    };
    let mut headers = Vec::new();
    if let Some(Value::Object(map)) = spec.get("headers") {
        for (name, value) in map {
            let values = match value {
                Value::Array(items) => items
                    .iter()
                    .map(|item| {
                        item.as_str().map(str::to_string).ok_or_else(|| {
                            DomainError::invalid(format!("header `{name}` values must be strings"))
                        })
                    })
                    .collect::<DomainResult<Vec<_>>>()?,
                Value::String(single) => vec![single.to_string()],
                other => {
                    return Err(DomainError::invalid(format!(
                        "header `{name}` must be a string or array, got {other}"
                    )))
                }
            };
            for value in values {
                headers.push(HeaderPatch {
                    name: name.clone(),
                    value: value.into_bytes(),
                });
            }
        }
    }
    let body_override = match spec.get("body_b64") {
        Some(Value::String(b64)) if !b64.is_empty() => Some(
            base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|error| {
                    DomainError::invalid(format!("body_b64 is not valid base64: {error}"))
                })?,
        ),
        _ => None,
    };
    Ok(ReplyDraft {
        method: Some(method),
        url: Some(url),
        header_overrides: headers,
        header_tombstones: Vec::new(),
        inheritance: ReplyInheritance::FullRequest,
        body_override,
        body_text: None,
        body_json: None,
        body_format: None,
        body_params: Vec::new(),
        // Standalone sends pass base_exchange_id=None, so inheritance never
        // applies; FullRequest is inert. Do not mark the body cleared: a
        // spec with no body simply sends no body.
        body_cleared: false,
        credential_mode: ReplyCredentialMode::WithProjectCredentials,
    })
}

fn host_send_success(inner: &HostInner, spec: &Value, sent: &ReplySendResult) -> Value {
    if let Some(exchange_id) = sent.exchange_id {
        if let Some(db) = inner.db.clone() {
            let project_id = inner.project_id;
            let summary = tokio::runtime::Handle::current()
                .block_on(db.get_exchange_summary(project_id, exchange_id));
            if let Ok(summary) = summary {
                return json!({
                    "request": {
                        "exchange_id": exchange_id.get(),
                        "method": summary.method,
                        "scheme": summary.scheme,
                        "authority": summary.authority,
                        "host": summary.host,
                        "port": summary.port,
                        "path": summary.path,
                        "query": summary.query,
                        "tls": summary.scheme == "https",
                    },
                    "response": {
                        "exchange_id": exchange_id.get(),
                        "status": summary.status_code,
                        "duration_ms": summary.duration_ms.unwrap_or(sent.duration_ms),
                    },
                });
            }
        }
    }
    let request = json!({
        "exchange_id": 0i64,
        "method": spec.get("method").cloned().unwrap_or(Value::Null),
        "scheme": if spec.get("tls").and_then(Value::as_bool).unwrap_or(false) { "https" } else { "http" },
        "host": spec.get("host").cloned().unwrap_or(Value::Null),
        "port": spec.get("port").cloned().unwrap_or(Value::Null),
        "path": spec.get("path").cloned().unwrap_or(Value::Null),
        "query": spec.get("query").cloned().unwrap_or(Value::Null),
        "headers": ephemeral_pairs(spec.get("headers")),
        "body_b64": spec.get("body_b64").cloned().unwrap_or(Value::Null),
    });
    let response = match sent.response.as_ref() {
        Some(ephemeral) => json!({
            "exchange_id": 0i64,
            "status": ephemeral.status_code,
            "duration_ms": ephemeral.duration_ms,
            "headers": ephemeral
                .headers
                .iter()
                .map(|header| json!([header.name, header.value]))
                .collect::<Vec<_>>(),
            "body_b64": ephemeral.body_base64,
        }),
        None => json!({
            "exchange_id": 0i64,
            "status": sent.status_code,
            "duration_ms": sent.duration_ms,
        }),
    };
    json!({ "request": request, "response": response })
}

fn ephemeral_pairs(headers: Option<&Value>) -> Value {
    let mut pairs = Vec::new();
    if let Some(Value::Object(map)) = headers {
        for (name, value) in map {
            match value {
                Value::Array(items) => {
                    for item in items {
                        if let Some(text) = item.as_str() {
                            pairs.push(json!([name, text]));
                        }
                    }
                }
                Value::String(text) => pairs.push(json!([name, text])),
                _ => {}
            }
        }
    }
    Value::Array(pairs)
}

fn host_exchange(inner: &HostInner, exchange_id: i64, field: &str) -> String {
    let Some(db) = inner.db.clone() else {
        return err_json("exchange access requires the database");
    };
    let project_id = inner.project_id;
    let id = ExchangeId::from(exchange_id);
    let handle = tokio::runtime::Handle::current();
    let outcome: DomainResult<Value> = match field {
        "headers_request" | "headers_response" => {
            let side = if field == "headers_request" {
                MessageSide::Request
            } else {
                MessageSide::Response
            };
            handle
                .block_on(db.load_raw_headers(project_id, id, side))
                .map(|headers| {
                    Value::Array(
                        headers
                            .iter()
                            .map(|header| {
                                json!([header.name, String::from_utf8_lossy(&header.value)])
                            })
                            .collect(),
                    )
                })
        }
        "body_request" | "body_response" => {
            let side = if field == "body_request" {
                MessageSide::Request
            } else {
                MessageSide::Response
            };
            handle
                .block_on(db.load_raw_body(project_id, id, side))
                .map(|body| match body {
                    Some(bytes) => json!({
                        "b64": base64::engine::general_purpose::STANDARD.encode(&bytes),
                        "length": bytes.len(),
                    }),
                    None => Value::Null,
                })
        }
        "raw_request" | "raw_response" => (|| -> DomainResult<Value> {
            let is_request = field == "raw_request";
            let side = if is_request {
                MessageSide::Request
            } else {
                MessageSide::Response
            };
            let summary = handle.block_on(db.get_exchange_summary(project_id, id))?;
            let headers = handle.block_on(db.load_raw_headers(project_id, id, side))?;
            let body = handle.block_on(db.load_raw_body(project_id, id, side))?;
            let mut raw = Vec::new();
            if is_request {
                let query = summary.query.as_deref().unwrap_or_default();
                let request_line = if query.is_empty() {
                    format!("{} {} HTTP/1.1\r\n", summary.method, summary.path)
                } else {
                    format!("{} {}?{} HTTP/1.1\r\n", summary.method, summary.path, query)
                };
                raw.extend_from_slice(request_line.as_bytes());
            } else {
                let status_line = format!("HTTP/1.1 {}\r\n", summary.status_code.unwrap_or(0));
                raw.extend_from_slice(status_line.as_bytes());
            }
            for header in &headers {
                raw.extend_from_slice(header.name.as_bytes());
                raw.extend_from_slice(b": ");
                raw.extend_from_slice(&header.value);
                raw.extend_from_slice(b"\r\n");
            }
            raw.extend_from_slice(b"\r\n");
            if let Some(bytes) = body {
                raw.extend_from_slice(&bytes);
            }
            Ok(json!({
                "b64": base64::engine::general_purpose::STANDARD.encode(&raw),
            }))
        })(),
        "meta" => (|| -> DomainResult<Value> {
            let summary = handle.block_on(db.get_exchange_summary(project_id, id))?;
            Ok(json!({
                "duration_ms": summary.duration_ms,
                "started_at_ms": summary.started_at.unix_timestamp_nanos() / 1_000_000,
            }))
        })(),
        other => Err(DomainError::invalid(format!(
            "unknown exchange field `{other}`"
        ))),
    };
    match outcome {
        Ok(value) => value.to_string(),
        Err(error) => err_json(&error.to_string()),
    }
}

/// Caido-workflow SDK prelude. Declared with `var` so both subsequent script
/// evals and `globals().get` from Rust can reach the bindings.
const JS_SDK_PRELUDE: &str = r#"
var console = {
  debug: function () { __hp_log("debug", __hp_args(arguments)); },
  log: function () { __hp_log("info", __hp_args(arguments)); },
  warn: function () { __hp_log("warn", __hp_args(arguments)); },
  error: function () { __hp_log("error", __hp_args(arguments)); },
};
function __hp_args(args) {
  var parts = [];
  for (var i = 0; i < args.length; i++) {
    var v = args[i];
    if (v instanceof Error) parts.push(String(v));
    else if (typeof v === "object" && v !== null) {
      try { parts.push(JSON.stringify(v)); } catch (e) { parts.push(String(v)); }
    } else parts.push(String(v));
  }
  return parts.join(" ");
}
function __hp_not(name) {
  return function () { throw new Error(name + " is not implemented yet"); };
}
function __hp_stub(name) {
  return new Proxy({}, {
    get: function (t, prop) {
      if (prop === "then") return undefined;
      return function () { throw new Error("sdk." + name + "." + String(prop) + " is not implemented yet"); };
    },
  });
}
function __hp_utf8Encode(str) {
  var out = [];
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
      var c2 = str.charCodeAt(++i);
      var cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
      out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  return out;
}
function __hp_utf8Decode(bytes) {
  var out = "", i = 0;
  while (i < bytes.length) {
    var b = bytes[i++];
    if (b < 0x80) out += String.fromCharCode(b);
    else if ((b & 0xe0) === 0xc0 && i < bytes.length) {
      out += String.fromCharCode(((b & 0x1f) << 6) | (bytes[i++] & 0x3f));
    } else if ((b & 0xf0) === 0xe0 && i + 1 < bytes.length) {
      out += String.fromCharCode(((b & 0x0f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f));
    } else if ((b & 0xf8) === 0xf0 && i + 2 < bytes.length) {
      var cp = ((b & 0x07) << 18) | ((bytes[i++] & 0x3f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f);
      cp -= 0x10000;
      out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
    } else out += "�";
  }
  return out;
}
var __hp_b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function __hp_b64encode(bytes) {
  var out = "", i;
  for (i = 0; i + 2 < bytes.length; i += 3) {
    var n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += __hp_b64chars[(n >> 18) & 63] + __hp_b64chars[(n >> 12) & 63] + __hp_b64chars[(n >> 6) & 63] + __hp_b64chars[n & 63];
  }
  var rem = bytes.length - i;
  if (rem === 1) {
    var a = bytes[i] << 16;
    out += __hp_b64chars[(a >> 18) & 63] + __hp_b64chars[(a >> 12) & 63] + "==";
  } else if (rem === 2) {
    var b = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += __hp_b64chars[(b >> 18) & 63] + __hp_b64chars[(b >> 12) & 63] + __hp_b64chars[(b >> 6) & 63] + "=";
  }
  return out;
}
function __hp_b64decode(str) {
  var clean = String(str).replace(/[^A-Za-z0-9+/]/g, "");
  var bytes = [], i = 0;
  while (i + 3 < clean.length) {
    var n = (__hp_b64idx(clean[i]) << 18) | (__hp_b64idx(clean[i + 1]) << 12) | (__hp_b64idx(clean[i + 2]) << 6) | __hp_b64idx(clean[i + 3]);
    bytes.push((n >> 16) & 255, (n >> 8) & 255, n & 255);
    i += 4;
  }
  var rem = clean.length - i;
  if (rem === 3) {
    var m = (__hp_b64idx(clean[i]) << 18) | (__hp_b64idx(clean[i + 1]) << 12) | (__hp_b64idx(clean[i + 2]) << 6);
    bytes.push((m >> 16) & 255, (m >> 8) & 255);
  } else if (rem === 2) {
    var p = (__hp_b64idx(clean[i]) << 18) | (__hp_b64idx(clean[i + 1]) << 12);
    bytes.push((p >> 16) & 255);
  }
  return bytes;
}
function __hp_b64idx(ch) {
  return __hp_b64chars.indexOf(ch);
}
function __hp_toBytes(v) {
  if (typeof v === "string") return __hp_utf8Encode(v);
  if (v instanceof Uint8Array) return Array.prototype.slice.call(v);
  if (Array.isArray(v)) return v.slice();
  throw new Error("expected string, Array<number>, or Uint8Array");
}
function __hp_toStr(v) {
  if (typeof v === "string") return v;
  return __hp_utf8Decode(__hp_toBytes(v));
}
var Body = class Body {
  constructor(data) {
    this._bytes = __hp_toBytes(data);
  }
  static __from(b64) {
    var body = new Body("");
    body._bytes = b64 ? __hp_b64decode(b64) : [];
    return body;
  }
  toText() { return __hp_utf8Decode(this._bytes); }
  toJson() { return JSON.parse(this.toText()); }
  toRaw() { return Uint8Array.from(this._bytes); }
  get length() { return this._bytes.length; }
};
function __hp_headerFind(pairs, name) {
  var needle = String(name).toLowerCase(), out = [];
  for (var i = 0; i < pairs.length; i++) {
    if (String(pairs[i][0]).toLowerCase() === needle) out.push(pairs[i][1]);
  }
  return out;
}
function __hp_headerRecord(pairs) {
  var rec = {};
  for (var i = 0; i < pairs.length; i++) {
    var name = pairs[i][0];
    if (!Object.prototype.hasOwnProperty.call(rec, name)) rec[name] = [];
    rec[name].push(pairs[i][1]);
  }
  return rec;
}
function __hp_getHeader(pairs, nameOrOpts) {
  var name = typeof nameOrOpts === "string" ? nameOrOpts : nameOrOpts && nameOrOpts.name;
  if (name == null) throw new Error("getHeader: name is required");
  var values = __hp_headerFind(pairs, name);
  if (!values.length) return undefined;
  if (typeof nameOrOpts === "object" && nameOrOpts.split) {
    values = String(values[0]).split(",").map(function (s) { return s.trim(); });
  }
  return values;
}
function __hp_parse_url(url) {
  var m = /^(https?):\/\/(\[[^\]]+\]|[^:/?#]+)(?::(\d+))?([^?#]*)(?:\?([^#]*))?/.exec(String(url));
  if (!m) throw new Error("RequestSpec: invalid URL: " + url);
  var scheme = m[1];
  var port = m[3] ? parseInt(m[3], 10) : (scheme === "https" ? 443 : 80);
  var path = m[4] || "/";
  if (path.charAt(0) !== "/") path = "/" + path;
  return { tls: scheme === "https", host: m[2], port: port, path: path, query: m[5] || "" };
}
function __hp_hostHeader(host, port, tls) {
  var def = tls ? 443 : 80;
  return port === def ? host : host + ":" + port;
}
var RequestSpec = class RequestSpec {
  constructor(url) {
    var p = __hp_parse_url(url);
    this._tls = p.tls;
    this._host = p.host;
    this._port = p.port;
    this._path = p.path;
    this._query = p.query;
    this._method = "GET";
    this._headers = [];
    this._body = null;
    this._setHeaderInternal("Host", __hp_hostHeader(p.host, p.port, p.tls));
  }
  static parse() { throw new Error("RequestSpec.parse is not supported yet"); }
  getInfo() { return { host: this._host, port: this._port, tls: this._tls, sni: undefined }; }
  getHost() { return this._host; }
  setHost(host) {
    this._host = String(host);
    this._setHeaderInternal("Host", __hp_hostHeader(this._host, this._port, this._tls));
  }
  getPort() { return this._port; }
  setPort(port) {
    var n = Number(port);
    if (!(n >= 1 && n <= 65535)) throw new Error("RequestSpec.setPort: port must be between 1 and 65535");
    this._port = n;
  }
  getTls() { return this._tls; }
  setTls(tls) { this._tls = !!tls; }
  getMethod(options) {
    if (options && options.raw) return Uint8Array.from(__hp_utf8Encode(this._method));
    return this._method;
  }
  setMethod(method) { this._method = __hp_toStr(method); }
  getPath(options) {
    if (options && options.raw) return Uint8Array.from(__hp_utf8Encode(this._path));
    return this._path;
  }
  setPath(path) {
    var text = __hp_toStr(path);
    this._path = text.charAt(0) === "/" ? text : "/" + text;
  }
  getQuery(options) {
    if (options && options.raw) return Uint8Array.from(__hp_utf8Encode(this._query));
    return this._query;
  }
  setQuery(query) {
    var text = __hp_toStr(query);
    if (text.charAt(0) === "?") text = text.slice(1);
    this._query = text;
  }
  getUrl() {
    var base = (this._tls ? "https" : "http") + "://" + this._host + ":" + this._port + this._path;
    return this._query ? base + "?" + this._query : base;
  }
  _idx(name) {
    var needle = String(name).toLowerCase();
    for (var i = 0; i < this._headers.length; i++) {
      if (String(this._headers[i][0]).toLowerCase() === needle) return i;
    }
    return -1;
  }
  _setHeaderInternal(name, value) {
    var i = this._idx(name);
    if (i >= 0) this._headers[i] = [name, value];
    else this._headers.push([name, value]);
  }
  getHeaders() { return __hp_headerRecord(this._headers); }
  getHeader(nameOrOpts) { return __hp_getHeader(this._headers, nameOrOpts); }
  setHeader(name, value) { this._setHeaderInternal(String(name), String(value)); }
  removeHeader(name) {
    var i = this._idx(name);
    if (i >= 0) this._headers.splice(i, 1);
  }
  getBody() { return this._body === null ? undefined : Body.__from(__hp_b64encode(this._body)); }
  setBody(body, options) {
    var bytes = body instanceof Body ? __hp_toBytes(body.toRaw()) : __hp_toBytes(body);
    this._body = bytes;
    if (!options || options.updateContentLength !== false) {
      this._setHeaderInternal("Content-Length", String(bytes.length));
    }
  }
  setRaw(raw) {
    var specRaw = new RequestSpecRaw(this.getUrl());
    specRaw.setTls(this._tls);
    specRaw.setHost(this._host);
    specRaw.setPort(this._port);
    specRaw.setRaw(raw);
    return specRaw;
  }
  getRaw() {
    return this.setRaw(this._serialize());
  }
  _serialize() {
    var text = this._method + " " + this._path + (this._query ? "?" + this._query : "") + " HTTP/1.1\r\n";
    for (var i = 0; i < this._headers.length; i++) {
      text += this._headers[i][0] + ": " + this._headers[i][1] + "\r\n";
    }
    text += "\r\n";
    var bytes = __hp_utf8Encode(text);
    if (this._body) bytes = bytes.concat(this._body);
    return bytes;
  }
  __payload() {
    var headers = {};
    for (var i = 0; i < this._headers.length; i++) {
      headers[this._headers[i][0]] = [this._headers[i][1]];
    }
    return {
      method: this._method,
      tls: this._tls,
      host: this._host,
      port: this._port,
      path: this._path,
      query: this._query,
      headers: headers,
      body_b64: this._body ? __hp_b64encode(this._body) : null,
    };
  }
};
var RequestSpecRaw = class RequestSpecRaw {
  constructor(url) {
    var p = __hp_parse_url(url);
    this._tls = p.tls;
    this._host = p.host;
    this._port = p.port;
    this._bytes = null;
  }
  getInfo() { return { host: this._host, port: this._port, tls: this._tls, sni: undefined }; }
  getHost() { return this._host; }
  setHost(host) { this._host = String(host); }
  getPort() { return this._port; }
  setPort(port) {
    var n = Number(port);
    if (!(n >= 1 && n <= 65535)) throw new Error("RequestSpecRaw.setPort: port must be between 1 and 65535");
    this._port = n;
  }
  getTls() { return this._tls; }
  setTls(tls) { this._tls = !!tls; }
  getRaw() {
    if (this._bytes === null) throw new Error("RequestSpecRaw: no raw bytes set");
    return Uint8Array.from(this._bytes);
  }
  setRaw(raw) { this._bytes = __hp_toBytes(raw); }
  toSpec() { throw new Error("RequestSpecRaw.toSpec() is not supported yet"); }
  getSpec() { throw new Error("RequestSpecRaw.getSpec() is not supported yet"); }
};
function __hpLoad(exchangeId, field) {
  var parsed = JSON.parse(__hp_exchange(Number(exchangeId), field));
  if (parsed && parsed.error) throw new Error(parsed.error);
  return parsed;
}
var RequestView = class RequestView {
  constructor(d) {
    this._d = d || {};
    this._pairs = null;
    this._body = null;
    this._raw = null;
    this._meta = null;
  }
  getId() { return String(this._d.exchange_id != null ? this._d.exchange_id : 0); }
  getHost() { return this._d.host; }
  getPort() { return this._d.port; }
  getTls() {
    if (this._d.tls != null) return !!this._d.tls;
    return this._d.scheme === "https";
  }
  getMethod() { return this._d.method; }
  getPath() { return this._d.path; }
  getQuery() { return this._d.query || ""; }
  getUrl() {
    var scheme = this._d.scheme || (this.getTls() ? "https" : "http");
    var host = this._d.host;
    var port = this._d.port;
    var url = scheme + "://" + host + (port != null ? ":" + port : "") + (this._d.path || "/");
    var query = this.getQuery();
    return query ? url + "?" + query : url;
  }
  _headerPairs() {
    if (this._pairs !== null) return this._pairs;
    if (this._d.headers) { this._pairs = this._d.headers; return this._pairs; }
    if (this._d.exchange_id) {
      this._pairs = __hpLoad(this._d.exchange_id, "headers_request") || [];
      return this._pairs;
    }
    this._pairs = [];
    return this._pairs;
  }
  getHeaders() { return __hp_headerRecord(this._headerPairs()); }
  getHeader(nameOrOpts) { return __hp_getHeader(this._headerPairs(), nameOrOpts); }
  getBody() {
    if (this._body !== null) return this._body;
    if (this._d.body_b64 != null) {
      this._body = this._d.body_b64 === null ? undefined : Body.__from(this._d.body_b64);
      return this._body;
    }
    if (this._d.exchange_id) {
      var loaded = __hpLoad(this._d.exchange_id, "body_request");
      this._body = loaded ? Body.__from(loaded.b64) : undefined;
      return this._body;
    }
    this._body = undefined;
    return undefined;
  }
  getRaw() {
    var self = this;
    if (!this._raw) {
      this._raw = {
        toText: function () { return __hp_utf8Decode(self._rawBytes()); },
        toBytes: function () { return Uint8Array.from(self._rawBytes()); },
      };
    }
    return this._raw;
  }
  _rawBytes() {
    if (this._rawCache) return this._rawCache;
    if (this._d.exchange_id) {
      var loaded = __hpLoad(this._d.exchange_id, "raw_request");
      this._rawCache = loaded ? __hp_b64decode(loaded.b64) : [];
      return this._rawCache;
    }
    var text = this.getMethod() + " " + this.getPath() + (this.getQuery() ? "?" + this.getQuery() : "") + " HTTP/1.1\r\n";
    var pairs = this._headerPairs();
    for (var i = 0; i < pairs.length; i++) text += pairs[i][0] + ": " + pairs[i][1] + "\r\n";
    text += "\r\n";
    var bytes = __hp_utf8Encode(text);
    var body = this.getBody();
    if (body) bytes = bytes.concat(__hp_toBytes(body.toRaw()));
    this._rawCache = bytes;
    return this._rawCache;
  }
  getCreatedAt() {
    var meta = this._metaData();
    return new Date(meta.started_at_ms != null ? meta.started_at_ms : 0);
  }
  _metaData() {
    if (this._meta !== null) return this._meta;
    if (this._d.started_at_ms != null || this._d.duration_ms != null) {
      this._meta = { started_at_ms: this._d.started_at_ms, duration_ms: this._d.duration_ms };
      return this._meta;
    }
    if (this._d.exchange_id) {
      this._meta = __hpLoad(this._d.exchange_id, "meta") || {};
      return this._meta;
    }
    this._meta = {};
    return this._meta;
  }
  toSpec() {
    var spec = new RequestSpec(this.getUrl());
    spec.setMethod(this.getMethod());
    var pairs = this._headerPairs();
    for (var i = 0; i < pairs.length; i++) spec.setHeader(pairs[i][0], pairs[i][1]);
    var body = this.getBody();
    if (body) spec.setBody(body);
    return spec;
  }
};
var ResponseView = class ResponseView {
  constructor(d) {
    this._d = d || {};
    this._pairs = null;
    this._body = null;
    this._raw = null;
    this._meta = null;
  }
  getId() { return String(this._d.exchange_id != null ? this._d.exchange_id : 0); }
  getCode() {
    if (this._d.status != null) return this._d.status;
    return this._d.status_code;
  }
  _headerPairs() {
    if (this._pairs !== null) return this._pairs;
    if (this._d.headers) { this._pairs = this._d.headers; return this._pairs; }
    if (this._d.exchange_id) {
      this._pairs = __hpLoad(this._d.exchange_id, "headers_response") || [];
      return this._pairs;
    }
    this._pairs = [];
    return this._pairs;
  }
  getHeaders() { return __hp_headerRecord(this._headerPairs()); }
  getHeader(nameOrOpts) { return __hp_getHeader(this._headerPairs(), nameOrOpts); }
  getBody() {
    if (this._body !== null) return this._body;
    if (this._d.body_b64 != null) {
      this._body = Body.__from(this._d.body_b64);
      return this._body;
    }
    if (this._d.exchange_id) {
      var loaded = __hpLoad(this._d.exchange_id, "body_response");
      this._body = loaded ? Body.__from(loaded.b64) : undefined;
      return this._body;
    }
    this._body = undefined;
    return undefined;
  }
  getRaw() {
    var self = this;
    if (!this._raw) {
      this._raw = {
        toText: function () { return __hp_utf8Decode(self._rawBytes()); },
        toBytes: function () { return Uint8Array.from(self._rawBytes()); },
      };
    }
    return this._raw;
  }
  _rawBytes() {
    if (this._rawCache) return this._rawCache;
    if (this._d.exchange_id) {
      var loaded = __hpLoad(this._d.exchange_id, "raw_response");
      this._rawCache = loaded ? __hp_b64decode(loaded.b64) : [];
      return this._rawCache;
    }
    var text = "HTTP/1.1 " + this.getCode() + " \r\n";
    var pairs = this._headerPairs();
    for (var i = 0; i < pairs.length; i++) text += pairs[i][0] + ": " + pairs[i][1] + "\r\n";
    text += "\r\n";
    var bytes = __hp_utf8Encode(text);
    var body = this.getBody();
    if (body) bytes = bytes.concat(__hp_toBytes(body.toRaw()));
    this._rawCache = bytes;
    return this._rawCache;
  }
  getRoundtripTime() {
    var meta = this._metaData();
    if (meta.duration_ms != null) return meta.duration_ms;
    if (this._d.duration_ms != null) return this._d.duration_ms;
    return 0;
  }
  getCreatedAt() {
    var meta = this._metaData();
    return new Date(meta.started_at_ms != null ? meta.started_at_ms : 0);
  }
  _metaData() {
    if (this._meta !== null) return this._meta;
    if (this._d.started_at_ms != null || this._d.duration_ms != null) {
      this._meta = { started_at_ms: this._d.started_at_ms, duration_ms: this._d.duration_ms };
      return this._meta;
    }
    if (this._d.exchange_id) {
      this._meta = __hpLoad(this._d.exchange_id, "meta") || {};
      return this._meta;
    }
    this._meta = {};
    return this._meta;
  }
};
var sdk = {
  console: console,
  asString: function (bytes) {
    if (typeof bytes === "string") return bytes;
    return __hp_utf8Decode(__hp_toBytes(bytes));
  },
  requests: {
    send: function (spec, options) {
      if (!__hp_network_enabled) {
        throw new Error("sdk.requests.send is disabled; set flows.allow_js_network = true to allow it");
      }
      var payload;
      if (spec instanceof RequestSpec) payload = spec.__payload();
      else if (spec instanceof RequestSpecRaw) throw new Error("sdk.requests.send: RequestSpecRaw is not supported yet");
      else throw new Error("sdk.requests.send: expected a RequestSpec");
      var timeoutMs;
      if (typeof options === "number") timeoutMs = options;
      else if (options && options.timeouts != null) {
        timeoutMs = typeof options.timeouts === "number"
          ? options.timeouts
          : options.timeouts.global;
      }
      if (timeoutMs != null) payload.timeout_ms = timeoutMs;
      var res = JSON.parse(__hp_send(JSON.stringify(payload)));
      if (res.error) throw new Error(res.error);
      return { request: new RequestView(res.request), response: new ResponseView(res.response) };
    },
    get: __hp_not("sdk.requests.get"),
    query: __hp_not("sdk.requests.query"),
    matches: __hp_not("sdk.requests.matches"),
    inScope: __hp_not("sdk.requests.inScope"),
  },
  findings: {
    create: function (finding) {
      var res = JSON.parse(__hp_finding_create(JSON.stringify(finding || {})));
      if (res.error) throw new Error(res.error);
      return res;
    },
    get: __hp_not("sdk.findings.get"),
    exists: __hp_not("sdk.findings.exists"),
  },
  env: {
    getVar: function () { return undefined; },
    getVars: function () { return []; },
    setVar: __hp_not("sdk.env.setVar"),
    getEnvironments: __hp_not("sdk.env.getEnvironments"),
    getEnvironment: __hp_not("sdk.env.getEnvironment"),
    createEnvironment: __hp_not("sdk.env.createEnvironment"),
    updateEnvironment: __hp_not("sdk.env.updateEnvironment"),
    deleteEnvironment: __hp_not("sdk.env.deleteEnvironment"),
  },
  replay: __hp_stub("replay"),
  projects: __hp_stub("projects"),
  scope: __hp_stub("scope"),
  runtime: { version: "huntproxy" },
  graphql: __hp_stub("graphql"),
  hostedFile: __hp_stub("hostedFile"),
  net: __hp_stub("net"),
};
function __hp_prepare(input) {
  if (input && typeof input === "object" && !Array.isArray(input)
      && typeof input.exchange_id === "number") {
    input.request = new RequestView({
      exchange_id: input.exchange_id,
      method: input.method,
      scheme: input.scheme,
      authority: input.authority,
      host: input.host,
      port: input.port,
      path: input.path,
      query: input.query,
      tls: input.scheme === "https",
    });
    input.response = new ResponseView({
      exchange_id: input.exchange_id,
      status: input.status != null ? input.status : input.status_code,
      duration_ms: input.duration_ms,
    });
  }
  return input;
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(code: &str, input: Value) -> DomainResult<Value> {
        run_flow_js(
            code,
            &input,
            Duration::from_secs(5),
            CancellationToken::new(),
            JsHost::disabled(),
        )
        .await
    }

    #[tokio::test]
    async fn computes_return_value() {
        let output = run(
            "function run(input) { return { doubled: input.n * 2, tag: input.tag }; }",
            serde_json::json!({"n": 21, "tag": "a"}),
        )
        .await
        .unwrap();
        assert_eq!(output, serde_json::json!({"doubled": 42, "tag": "a"}));
    }

    #[tokio::test]
    async fn missing_run_function_is_an_error() {
        let error = run("const x = 1;", Value::Null)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("flow js"), "{error}");
    }

    #[tokio::test]
    async fn infinite_loop_hits_timeout() {
        let started = Instant::now();
        let error = run_flow_js(
            "function run() { while (true) {} }",
            &Value::Null,
            Duration::from_millis(50),
            CancellationToken::new(),
            JsHost::disabled(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("exceeded"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn cancellation_stops_execution() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = run_flow_js(
            "function run() { while (true) {} }",
            &Value::Null,
            Duration::from_secs(30),
            cancel,
            JsHost::disabled(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("cancelled"), "{error}");
    }

    #[tokio::test]
    async fn runtime_errors_are_bounded_messages() {
        let error = run("function run() { throw new Error('nope'); }", Value::Null)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("nope"), "{error}");
    }

    #[tokio::test]
    async fn async_run_function_is_awaited() {
        let output = run(
            "async function run(input) { await null; return input.n + 1; }",
            serde_json::json!({"n": 41}),
        )
        .await
        .unwrap();
        assert_eq!(output, serde_json::json!(42));
    }

    #[tokio::test]
    async fn undefined_result_becomes_null() {
        let output = run("function run() {}", Value::Null).await.unwrap();
        assert_eq!(output, Value::Null);
    }

    #[tokio::test]
    async fn sdk_asstring_and_console() {
        let output = run(
            "function run(input, sdk) { sdk.console.log('hello'); return sdk.asString(input.bytes); }",
            serde_json::json!({"bytes": [104, 105]}),
        )
        .await
        .unwrap();
        assert_eq!(output, serde_json::json!("hi"));
    }

    #[tokio::test]
    async fn request_spec_round_trips() {
        let output = run(
            r#"
            function run(input, sdk) {
              const spec = new RequestSpec("https://example.com:8443/a/b?q=1");
              spec.setMethod("POST");
              spec.setHeader("X-Test", "a");
              spec.setBody("hi");
              const raw = spec.getRaw().getRaw();
              return {
                url: spec.getUrl(),
                method: spec.getMethod(),
                host: spec.getHost(),
                port: spec.getPort(),
                tls: spec.getTls(),
                query: spec.getQuery(),
                cl: spec.getHeader("content-length")[0],
                xtest: spec.getHeader("x-test")[0],
                rawLen: raw.length,
              };
            }
            "#,
            Value::Null,
        )
        .await
        .unwrap();
        let request_line = "POST /a/b?q=1 HTTP/1.1\r\n".len();
        let host_header = "Host: example.com:8443\r\n".len();
        let x_test_header = "X-Test: a\r\n".len();
        let content_length_header = "Content-Length: 2\r\n".len();
        let blank_line = "\r\n".len();
        let body = "hi".len();
        assert_eq!(
            output,
            serde_json::json!({
                "url": "https://example.com:8443/a/b?q=1",
                "method": "POST",
                "host": "example.com",
                "port": 8443,
                "tls": true,
                "query": "q=1",
                "cl": "2",
                "xtest": "a",
                "rawLen": request_line
                    + host_header
                    + x_test_header
                    + content_length_header
                    + blank_line
                    + body,
            })
        );
    }

    #[tokio::test]
    async fn request_spec_set_host_updates_host_header() {
        let output = run(
            r#"
            function run() {
              const spec = new RequestSpec("http://old.test/");
              spec.setHost("new.test");
              return spec.getHeader("Host")[0];
            }
            "#,
            Value::Null,
        )
        .await
        .unwrap();
        assert_eq!(output, serde_json::json!("new.test"));
    }

    #[tokio::test]
    async fn send_is_disabled_by_default() {
        let output = run(
            r#"
            function run(input, sdk) {
              try {
                sdk.requests.send(new RequestSpec("http://example.com/"));
                return "sent";
              } catch (err) {
                return String(err);
              }
            }
            "#,
            Value::Null,
        )
        .await
        .unwrap();
        let text = output.as_str().unwrap_or_default();
        assert!(text.contains("flows.allow_js_network"), "{text}");
    }

    #[tokio::test]
    async fn findings_create_without_db_errors() {
        let output = run(
            r#"
            function run(input, sdk) {
              try {
                sdk.findings.create({ title: "t" });
                return "created";
              } catch (err) {
                return String(err);
              }
            }
            "#,
            Value::Null,
        )
        .await
        .unwrap();
        let text = output.as_str().unwrap_or_default();
        assert!(text.contains("requires the database"), "{text}");
    }

    #[tokio::test]
    async fn trigger_input_shapes_request_and_response_views() {
        let output = run(
            r#"
            function run({ request, response }) {
              return {
                url: request.getUrl(),
                method: request.getMethod(),
                tls: request.getTls(),
                id: request.getId(),
                code: response.getCode(),
                responseId: response.getId(),
              };
            }
            "#,
            serde_json::json!({
                "exchange_id": 7,
                "method": "GET",
                "scheme": "https",
                "host": "x.test",
                "port": 443,
                "path": "/p",
                "query": "a=1",
                "status": 200,
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            output,
            serde_json::json!({
                "url": "https://x.test:443/p?a=1",
                "method": "GET",
                "tls": true,
                "id": "7",
                "code": 200,
                "responseId": "7",
            })
        );
    }

    #[tokio::test]
    async fn convert_style_input_is_passed_through_untouched() {
        let output = run(
            r#"
            function run(input) { return { isArray: Array.isArray(input), first: input[0] }; }
            "#,
            serde_json::json!([104, 101, 108, 108, 111]),
        )
        .await
        .unwrap();
        assert_eq!(output, serde_json::json!({"isArray": true, "first": 104}));
    }
}
