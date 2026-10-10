//! Direct (non-interpreted) command execution for `flow/shell` nodes.
//! The executable is invoked with an argv vector: no shell expansion happens.

use std::time::Duration;

use serde_json::Value;
use tokio::io::AsyncReadExt;

use crate::domain::{DomainError, DomainResult, ErrorCode};

/// Cap per stream so a noisy command cannot exhaust memory.
pub const MAX_SHELL_OUTPUT: usize = 1024 * 1024;
pub const DEFAULT_SHELL_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_SHELL_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub struct ShellRequest {
    pub command: String,
    pub args: Vec<String>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ShellOutput {
    pub stdout: String,
    pub stderr: String,
    /// Exit code, or null when the process died from a signal.
    pub code: Option<i32>,
    pub truncated: bool,
}

pub fn shell_timeout_ms(input: Option<f64>) -> Duration {
    let requested = match input {
        None => DEFAULT_SHELL_TIMEOUT.as_millis() as u64,
        Some(value) => u64::try_from(value as i64).unwrap_or(1),
    };
    let capped = requested.clamp(1, MAX_SHELL_TIMEOUT.as_millis() as u64);
    Duration::from_millis(capped)
}

pub async fn run_flow_shell(request: ShellRequest) -> DomainResult<ShellOutput> {
    if request.command.trim().is_empty() {
        return Err(DomainError::invalid("shell command must not be empty"));
    }
    let mut command = tokio::process::Command::new(&request.command);
    command
        .args(&request.args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|error| {
        DomainError::new(
            ErrorCode::Unavailable,
            format!("spawn {}: {error}", request.command),
        )
    })?;

    let stdout_pipe = child.stdout.take().expect("piped stdout");
    let stderr_pipe = child.stderr.take().expect("piped stderr");
    let stdout_task = tokio::spawn(async move {
        let mut buffer = Vec::new();
        let mut limited = stdout_pipe.take(MAX_SHELL_OUTPUT as u64);
        let truncated =
            limited.read_to_end(&mut buffer).await.is_ok() && buffer.len() == MAX_SHELL_OUTPUT;
        (buffer, truncated)
    });
    let stderr_task = tokio::spawn(async move {
        let mut buffer = Vec::new();
        let mut limited = stderr_pipe.take(MAX_SHELL_OUTPUT as u64);
        let truncated =
            limited.read_to_end(&mut buffer).await.is_ok() && buffer.len() == MAX_SHELL_OUTPUT;
        (buffer, truncated)
    });

    let status = match tokio::time::timeout(request.timeout, child.wait()).await {
        Ok(status) => status.map_err(|error| {
            DomainError::new(
                ErrorCode::Unavailable,
                format!("wait {}: {error}", request.command),
            )
        })?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            return Err(DomainError::new(
                ErrorCode::Timeout,
                format!(
                    "{} exceeded {} ms",
                    request.command,
                    request.timeout.as_millis()
                ),
            ));
        }
    };

    let (stdout, stdout_truncated) = stdout_task.await.unwrap_or_default();
    let (stderr, stderr_truncated) = stderr_task.await.unwrap_or_default();
    Ok(ShellOutput {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        code: status.code(),
        truncated: stdout_truncated || stderr_truncated,
    })
}

/// Shape a shell argv value: arrays of scalars, scalars stringified.
pub fn shell_args(value: Option<&Value>) -> DomainResult<Vec<String>> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => Ok(text.clone()),
                Value::Number(number) => Ok(number.to_string()),
                Value::Bool(flag) => Ok(flag.to_string()),
                Value::Null => Ok(String::new()),
                other => Err(DomainError::invalid(format!(
                    "shell args must be scalars, got {other}"
                ))),
            })
            .collect(),
        Some(other) => Err(DomainError::invalid(format!(
            "shell args must be an array, got {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(command: &str, args: &[&str]) -> ShellRequest {
        ShellRequest {
            command: command.into(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn captures_stdout_and_exit_code() {
        let output = run_flow_shell(request("echo", &["hello"])).await.unwrap();
        assert_eq!(output.stdout, "hello\n");
        assert_eq!(output.code, Some(0));
        assert!(!output.truncated);
    }

    #[tokio::test]
    async fn reports_nonzero_exit_and_stderr() {
        let output = run_flow_shell(request("sh", &["-c", "echo oops >&2; exit 3"]))
            .await
            .unwrap();
        assert_eq!(output.code, Some(3));
        assert_eq!(output.stderr, "oops\n");
    }

    #[tokio::test]
    async fn missing_binary_is_unavailable() {
        let error = run_flow_shell(request("huntproxy-definitely-missing", &[]))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("spawn"), "{error}");
    }

    #[tokio::test]
    async fn timeout_kills_the_process() {
        let error = run_flow_shell(ShellRequest {
            command: "sleep".into(),
            args: vec!["5".into()],
            timeout: Duration::from_millis(50),
        })
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("exceeded"), "{error}");
    }

    #[tokio::test]
    async fn args_accept_scalars_only() {
        let args = shell_args(Some(&serde_json::json!(["a", 1, true]))).unwrap();
        assert_eq!(args, vec!["a", "1", "true"]);
        assert!(shell_args(Some(&serde_json::json!([{"x": 1}]))).is_err());
        assert!(shell_args(Some(&serde_json::json!("str"))).is_err());
        assert!(shell_args(None).unwrap().is_empty());
    }

    #[test]
    fn timeout_ms_is_clamped() {
        assert_eq!(shell_timeout_ms(None), DEFAULT_SHELL_TIMEOUT);
        assert_eq!(shell_timeout_ms(Some(-5.0)), Duration::from_millis(1));
        assert_eq!(shell_timeout_ms(Some(10_000_000.0)), MAX_SHELL_TIMEOUT);
    }
}
