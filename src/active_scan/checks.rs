//! Active scan checks - vulnerability detection logic.

use super::job::ActiveScanJob;
use crate::domain::*;
use crate::fuzzer::variants::{InjectionPoint, VariantType};
use crate::reply::ReplyService;
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

#[async_trait]
pub trait ActiveCheck: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn dependencies(&self) -> Vec<&str> {
        Vec::new()
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

            // TODO: Send modified request via reply service
            // Check if payload reflected unencoded in response
            // For now, placeholder logic

            // Simulated detection
            if payload.contains("<script>") {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::High,
                    confidence: 85,
                    cwe_id: Some(79),
                    description: format!("XSS vulnerability in {}", point.name),
                    evidence: format!("Payload reflected: {}", payload),
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
        _db: &Arc<Db>,
        _reply: &Arc<ReplyService>,
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

            // TODO: Send request, check for SQL errors or timing differences

            tokio::time::sleep(tokio::time::Duration::from_millis(strength.delay_ms())).await;
        }

        Ok(None)
    }
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
        _db: &Arc<Db>,
        _reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        if !self.applicable_types().contains(&point.variant_type) {
            return Ok(None);
        }

        let strength = job.policy.get_attack_strength(self.id());
        let payloads = command_payloads(strength.payload_count());

        for payload in payloads {
            if job.is_cancelled() {
                return Ok(None);
            }

            // TODO: Send request with OAST callback

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

fn command_payloads(count: usize) -> Vec<String> {
    let all = vec![
        "; whoami",
        "| whoami",
        "`whoami`",
        "$(whoami)",
        "; ping -c 4 oast.example.com",
        "& nslookup oast.example.com",
    ];
    all.into_iter().take(count).map(String::from).collect()
}
