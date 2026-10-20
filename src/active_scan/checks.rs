//! Active scan checks - vulnerability detection logic.

use super::job::ActiveScanJob;
use crate::domain::*;
use crate::fuzzer::variants::{self, InjectionPoint, VariantType};
use crate::policy::PresentationOptions;
use crate::reply::{ReplySendContext, ReplyService};
use crate::storage::Db;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub check_id: String,
    pub name: String,
    pub severity: CheckSeverity,
    pub confidence: u8,
    pub cwe_id: Option<u32>,
    pub description: String,
    pub evidence: String,
    pub attack_payload: String,
    pub injection_point: String,
}

impl CheckResult {
    pub fn to_finding_title(&self) -> String {
        let severity = format!("{:?}", self.severity).to_lowercase();
        let title = format!("[{}] {}", severity, self.name);
        if title.len() > 256 {
            title.chars().take(200).collect()
        } else {
            title
        }
    }

    pub fn to_finding_description(&self) -> String {
        format!(
            "{}\n\nConfidence: {}%\nCWE: {}\nInjection point: {}\nPayload: {}\nEvidence: {}\nCheck: {}",
            self.description,
            self.confidence,
            self.cwe_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            self.injection_point,
            self.attack_payload,
            self.evidence,
            self.check_id,
        )
    }
}

/// Response returned by [`send_probe`]: status, response headers (available
/// only when the probe exchange was captured), decoded body preview.
pub struct ProbeResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl ProbeResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Build a `ReplyDraft` with `payload` applied to `point` on the base request.
pub fn draft_for_payload(
    job: &ActiveScanJob,
    point: &InjectionPoint,
    payload: &str,
) -> ReplyDraft {
    let (url, headers, body) = variants::apply_payload(
        point,
        payload,
        &job.base_request.method,
        &job.base_request.url,
        &job.base_request.headers,
        job.base_request.body.clone(),
    );
    ReplyDraft {
        method: Some(job.base_request.method.clone()),
        url: Some(url),
        header_overrides: headers
            .into_iter()
            .map(|(name, value)| HeaderPatch {
                name,
                value: value.into_bytes(),
            })
            .collect(),
        body_override: body,
        inheritance: ReplyInheritance::FullRequest,
        ..Default::default()
    }
}

/// Replay `draft` through the reply transport and collect the probe response.
pub async fn send_probe(
    job: &ActiveScanJob,
    db: &Arc<Db>,
    reply: &Arc<ReplyService>,
    draft: ReplyDraft,
) -> DomainResult<ProbeResponse> {
    let result = reply
        .send_with_context(
            job.project_id,
            Some(job.exchange_id),
            &draft,
            ProtocolPreference::Auto,
            0,
            ReplySendContext::reply(Some(job.exchange_id), None),
        )
        .await?;

    let mut headers = Vec::new();
    if let Some(probe_id) = result.exchange_id {
        if let Ok(detail) = db
            .get_exchange_detail(job.project_id, probe_id, PresentationOptions::default())
            .await
        {
            headers = detail
                .response_headers
                .into_iter()
                .map(|h| (h.name, h.value))
                .collect();
        }
    }

    Ok(ProbeResponse {
        status: result.status_code,
        headers,
        body: result.response_preview.text,
    })
}

/// Replay the base request unchanged (no injection point involved).
pub async fn send_base(
    job: &ActiveScanJob,
    db: &Arc<Db>,
    reply: &Arc<ReplyService>,
) -> DomainResult<ProbeResponse> {
    send_probe(
        job,
        db,
        reply,
        ReplyDraft {
            inheritance: ReplyInheritance::FullRequest,
            ..Default::default()
        },
    )
    .await
}

#[async_trait]
pub trait ActiveCheck: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn dependencies(&self) -> Vec<&str> {
        Vec::new()
    }
    /// When false the check runs once per job instead of per injection point.
    fn uses_points(&self) -> bool {
        true
    }
    fn applicable_types(&self) -> Vec<VariantType> {
        vec![
            VariantType::UrlQuery,
            VariantType::Json,
            VariantType::Xml,
            VariantType::Cookie,
            VariantType::Header,
        ]
    }

    async fn execute(
        &self,
        job: &ActiveScanJob,
        point: &InjectionPoint,
        db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>>;
}

pub fn load_default_checks() -> Vec<Box<dyn ActiveCheck>> {
    vec![
        Box::new(XssCheck),
        Box::new(SqlInjectionCheck),
        Box::new(CommandInjectionCheck),
    ]
}

// Check 1: XSS Detection
struct XssCheck;

#[async_trait]
impl ActiveCheck for XssCheck {
    fn id(&self) -> &str {
        "xss-reflected"
    }

    fn name(&self) -> &str {
        "Cross-Site Scripting (Reflected)"
    }

    async fn execute(
        &self,
        job: &ActiveScanJob,
        point: &InjectionPoint,
        db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        if !self.applicable_types().contains(&point.variant_type) {
            return Ok(None);
        }

        let strength = job.policy.get_attack_strength(self.id());
        let payloads = xss_payloads(strength.payload_count());

        for payload in payloads {
            if job.is_cancelled() {
                return Ok(None);
            }

            let draft = draft_for_payload(job, point, &payload);
            let Ok(resp) = send_probe(job, db, reply, draft).await else {
                continue;
            };

            // Raw reflection of script-bearing payloads indicates reflected XSS.
            if resp.body.contains(&payload) && payload.contains('<') {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::High,
                    confidence: 90,
                    cwe_id: Some(79),
                    description: format!("Reflected XSS in {}", point.name),
                    evidence: "Payload reflected unencoded in response".to_string(),
                    attack_payload: payload.clone(),
                    injection_point: point.location.clone(),
                }));
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(strength.delay_ms())).await;
        }

        Ok(None)
    }
}

// Check 2: SQL Injection
struct SqlInjectionCheck;

#[async_trait]
impl ActiveCheck for SqlInjectionCheck {
    fn id(&self) -> &str {
        "sql-injection"
    }

    fn name(&self) -> &str {
        "SQL Injection"
    }

    async fn execute(
        &self,
        job: &ActiveScanJob,
        point: &InjectionPoint,
        db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        if !self.applicable_types().contains(&point.variant_type) {
            return Ok(None);
        }

        let strength = job.policy.get_attack_strength(self.id());
        let payloads = sql_payloads(strength.payload_count());

        for payload in payloads {
            if job.is_cancelled() {
                return Ok(None);
            }

            let draft = draft_for_payload(job, point, &payload);
            let Ok(resp) = send_probe(job, db, reply, draft).await else {
                continue;
            };

            if let Some(pattern) = sql_error_in(&resp.body) {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::High,
                    confidence: 90,
                    cwe_id: Some(89),
                    description: format!("SQL error triggered in {} by injected syntax", point.name),
                    evidence: format!("Database error: {}", pattern),
                    attack_payload: payload.clone(),
                    injection_point: point.location.clone(),
                }));
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(strength.delay_ms())).await;
        }

        Ok(None)
    }
}

fn sql_error_in(body: &str) -> Option<&'static str> {
    const PATTERNS: &[&str] = &[
        "you have an error in your sql syntax",
        "warning: mysql_",
        "mysql_fetch",
        "mysqli",
        "pg_query",
        "psql:",
        "unterminated quoted string",
        "sqlite/sqlite3",
        "sqlite error",
        "unrecognized token",
        "ora-01756",
        "ora-00933",
        "ora-00921",
        "unclosed quotation mark after the character string",
        "incorrect syntax near",
        "microsoft ole db provider",
        "odbc sql server driver",
        "postgresql query failed",
        "syntax error at or near",
        "supplied argument is not a valid",
    ];
    let lower = body.to_ascii_lowercase();
    PATTERNS.iter().copied().find(|p| lower.contains(p))
}

// Check 3: Command Injection
struct CommandInjectionCheck;

#[async_trait]
impl ActiveCheck for CommandInjectionCheck {
    fn id(&self) -> &str {
        "command-injection"
    }

    fn name(&self) -> &str {
        "OS Command Injection"
    }

    async fn execute(
        &self,
        job: &ActiveScanJob,
        point: &InjectionPoint,
        db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        if !self.applicable_types().contains(&point.variant_type) {
            return Ok(None);
        }

        let strength = job.policy.get_attack_strength(self.id());
        // Unique marker proves the injected command executed and its output
        // came back; absent from the baseline response it cannot be a
        // reflection false positive.
        let marker = format!(
            "hp{}",
            &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]
        );
        let Ok(baseline) = send_base(job, db, reply).await else {
            return Ok(None);
        };
        if baseline.body.contains(&marker) {
            return Ok(None);
        }

        let payloads = command_payloads(&marker, strength.payload_count());

        for payload in payloads {
            if job.is_cancelled() {
                return Ok(None);
            }

            let draft = draft_for_payload(job, point, &payload);
            let Ok(resp) = send_probe(job, db, reply, draft).await else {
                continue;
            };

            if resp.body.contains(&marker) {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::Critical,
                    confidence: 95,
                    cwe_id: Some(78),
                    description: format!(
                        "OS command injection in {}: injected command output observed",
                        point.name
                    ),
                    evidence: format!("Marker {} echoed by target", marker),
                    attack_payload: payload.clone(),
                    injection_point: point.location.clone(),
                }));
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(strength.delay_ms())).await;
        }

        Ok(None)
    }
}

fn xss_payloads(count: usize) -> Vec<String> {
    let all = vec![
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'",
        "\"><script>alert(1)</script>",
    ];
    all.into_iter().take(count).map(String::from).collect()
}

fn sql_payloads(count: usize) -> Vec<String> {
    let all = vec![
        "'",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL--",
        "1' AND SLEEP(5)--",
        "' AND 1=CONVERT(int, @@version)--",
    ];
    all.into_iter().take(count).map(String::from).collect()
}

fn command_payloads(marker: &str, count: usize) -> Vec<String> {
    let all = vec![
        format!("; echo {}", marker),
        format!("| echo {}", marker),
        format!("`echo {}`", marker),
        format!("$(echo {})", marker),
        format!("'; echo {}; '", marker),
        format!("\" & echo {} & \"", marker),
        format!("&& echo {}", marker),
        format!("|| echo {}", marker),
        format!("; printf %s {}", marker),
        format!("|/bin/echo {}", marker),
        format!("$(echo ${marker})"),
        format!("'; /bin/echo {}; '", marker),
    ];
    all.into_iter().take(count).collect()
}
