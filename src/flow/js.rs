//! QuickJS execution for `flow/js` nodes, mirroring the plugin host's
//! runtime limits: memory cap, stack cap, deadline interrupt, cancel support.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rquickjs::{CatchResultExt, Context, Function, Runtime};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::domain::{DomainError, DomainResult, ErrorCode};

const MAX_JS_MEMORY: usize = 16 * 1024 * 1024;
const MAX_JS_STACK: usize = 512 * 1024;
const MAX_JS_ERROR_CHARS: usize = 2_048;

/// Runs user code that must define `function run(input)` and returns the
/// JSON value it produced.
pub async fn run_flow_js(
    code: &str,
    input: &Value,
    timeout: Duration,
    cancel: CancellationToken,
) -> DomainResult<Value> {
    let code = code.to_string();
    let input = input.to_string();
    tokio::task::spawn_blocking(move || run_js_sync(&code, &input, timeout, cancel))
        .await
        .map_err(|error| DomainError::new(ErrorCode::Internal, format!("js task: {error}")))?
}

fn run_js_sync(
    code: &str,
    input: &str,
    timeout: Duration,
    cancel: CancellationToken,
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
    runtime.set_interrupt_handler(Some(Box::new(move || {
        if cancel.is_cancelled() {
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
    let output = context.with(|ctx| -> Result<String, String> {
        ctx.eval::<(), _>(code)
            .catch(&ctx)
            .map_err(|error| bounded_js_error(error.to_string()))?;
        let run: Function = ctx
            .globals()
            .get("run")
            .catch(&ctx)
            .map_err(|error| bounded_js_error(error.to_string()))?;
        let input_value = ctx
            .json_parse(input.as_bytes())
            .catch(&ctx)
            .map_err(|error| bounded_js_error(error.to_string()))?;
        let result: rquickjs::Value = run
            .call((input_value,))
            .catch(&ctx)
            .map_err(|error| bounded_js_error(error.to_string()))?;
        let stringified = ctx
            .json_stringify(result)
            .catch(&ctx)
            .map_err(|error| bounded_js_error(error.to_string()))?
            .ok_or_else(|| "run() returned undefined".to_string())?;
        stringified
            .to_string()
            .map_err(|error| bounded_js_error(error.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn computes_return_value() {
        let output = run_flow_js(
            "function run(input) { return { doubled: input.n * 2, tag: input.tag }; }",
            &serde_json::json!({"n": 21, "tag": "a"}),
            Duration::from_secs(5),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(output, serde_json::json!({"doubled": 42, "tag": "a"}));
    }

    #[tokio::test]
    async fn missing_run_function_is_an_error() {
        let error = run_flow_js(
            "const x = 1;",
            &Value::Null,
            Duration::from_secs(5),
            CancellationToken::new(),
        )
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
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("cancelled"), "{error}");
    }

    #[tokio::test]
    async fn runtime_errors_are_bounded_messages() {
        let error = run_flow_js(
            "function run() { throw new Error('nope'); }",
            &Value::Null,
            Duration::from_secs(5),
            CancellationToken::new(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("nope"), "{error}");
    }
}
