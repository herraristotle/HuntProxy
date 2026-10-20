//! GraphQL and infrastructure active checks: introspection, host header
//! injection, subdomain takeover.

use super::checks::{send_base, send_probe, ActiveCheck, CheckResult, CheckSeverity};
use super::job::ActiveScanJob;
use crate::domain::*;
use crate::fuzzer::variants::InjectionPoint;
use crate::reply::ReplyService;
use crate::storage::Db;
use async_trait::async_trait;
use std::sync::Arc;

// ============================================================================
// GraphQL Introspection Check
// ============================================================================

pub struct GraphQlIntrospectionCheck;

#[async_trait]
impl ActiveCheck for GraphQlIntrospectionCheck {
    fn id(&self) -> &str {
        "graphql-introspection"
    }

    fn name(&self) -> &str {
        "GraphQL Introspection Enabled"
    }

    fn uses_points(&self) -> bool {
        false
    }

    async fn execute(
        &self,
        job: &ActiveScanJob,
        _point: &InjectionPoint,
        db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        if !job
            .base_request
            .url
            .to_ascii_lowercase()
            .contains("graphql")
        {
            return Ok(None);
        }

        let introspection = r#"{"query":"{ __schema { types { name } } }"}"#;

        let draft = ReplyDraft {
            method: Some("POST".to_string()),
            url: Some(job.base_request.url.clone()),
            header_overrides: vec![HeaderPatch {
                name: "Content-Type".to_string(),
                value: b"application/json".to_vec(),
            }],
            body_text: Some(introspection.to_string()),
            inheritance: ReplyInheritance::FullRequest,
            ..Default::default()
        };

        let Ok(resp) = send_probe(job, db, reply, draft).await else {
            return Ok(None);
        };

        if resp.body.contains("__schema") || resp.body.contains("__type") {
            return Ok(Some(CheckResult {
                check_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: CheckSeverity::Medium,
                confidence: 95,
                cwe_id: Some(16),
                description: "GraphQL introspection enabled: full schema is exposed to any client"
                    .to_string(),
                evidence: "Introspection query returned type inventory".to_string(),
                attack_payload: introspection.to_string(),
                injection_point: "graphql endpoint".to_string(),
            }));
        }

        Ok(None)
    }
}

// ============================================================================
// Host Header Injection Check
// ============================================================================

pub struct HostHeaderInjectionCheck;

#[async_trait]
impl ActiveCheck for HostHeaderInjectionCheck {
    fn id(&self) -> &str {
        "host-header-injection"
    }

    fn name(&self) -> &str {
        "Host Header Injection"
    }

    fn uses_points(&self) -> bool {
        false
    }

    async fn execute(
        &self,
        job: &ActiveScanJob,
        _point: &InjectionPoint,
        db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        let test_host = "evil.example.com";

        let draft = ReplyDraft {
            header_overrides: vec![HeaderPatch {
                name: "Host".to_string(),
                value: test_host.as_bytes().to_vec(),
            }],
            inheritance: ReplyInheritance::FullRequest,
            ..Default::default()
        };

        let Ok(resp) = send_probe(job, db, reply, draft).await else {
            return Ok(None);
        };

        if let Some(location) = resp.header("location") {
            if location.contains(test_host) {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::High,
                    confidence: 90,
                    cwe_id: Some(644),
                    description: "Host header influences redirect Location: enables password-reset poisoning and cache poisoning"
                        .to_string(),
                    evidence: format!("Location: {location}"),
                    attack_payload: format!("Host: {test_host}"),
                    injection_point: "Host header".to_string(),
                }));
            }
        }

        if resp.body.contains(test_host) {
            return Ok(Some(CheckResult {
                check_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: CheckSeverity::Medium,
                confidence: 75,
                cwe_id: Some(644),
                description:
                    "Host header reflected in response body: possible cache/web-cache deception"
                        .to_string(),
                evidence: "Injected Host value echoed in body".to_string(),
                attack_payload: format!("Host: {test_host}"),
                injection_point: "Host header".to_string(),
            }));
        }

        Ok(None)
    }
}

// ============================================================================
// Subdomain Takeover Check
// ============================================================================

pub struct SubdomainTakeoverCheck;

#[async_trait]
impl ActiveCheck for SubdomainTakeoverCheck {
    fn id(&self) -> &str {
        "subdomain-takeover"
    }

    fn name(&self) -> &str {
        "Subdomain Takeover Vulnerability"
    }

    fn uses_points(&self) -> bool {
        false
    }

    async fn execute(
        &self,
        job: &ActiveScanJob,
        _point: &InjectionPoint,
        db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        let Ok(resp) = send_base(job, db, reply).await else {
            return Ok(None);
        };
        let body = resp.body;

        // Fingerprints of dangling services still answering for the host.
        const FINGERPRINTS: &[(&str, &str, CheckSeverity)] = &[
            (
                "There isn't a GitHub Pages site here",
                "GitHub Pages",
                CheckSeverity::High,
            ),
            ("Repository not found", "GitHub Pages", CheckSeverity::High),
            ("Project not found", "GitLab Pages", CheckSeverity::High),
            ("No such app", "Heroku", CheckSeverity::High),
            (
                "The specified bucket does not exist",
                "AWS S3",
                CheckSeverity::Critical,
            ),
            ("NoSuchBucket", "AWS S3", CheckSeverity::Critical),
            ("Unrecognized domain", "Fastly", CheckSeverity::High),
            (
                "is not a registered InCloud YouTrack",
                "JetBrains",
                CheckSeverity::Medium,
            ),
        ];

        for (pattern, service, severity) in FINGERPRINTS {
            if body.contains(pattern) {
                return Ok(Some(CheckResult {
                    check_id: format!(
                        "{}-{}",
                        self.id(),
                        service.to_ascii_lowercase().replace(' ', "-")
                    ),
                    name: format!("Subdomain Takeover: {service}"),
                    severity: *severity,
                    confidence: 80,
                    cwe_id: Some(350),
                    description: format!(
                        "Host serves the unclaimed-{service} error page; dangling DNS may allow takeover"
                    ),
                    evidence: format!("Fingerprint: {pattern}"),
                    attack_payload: "N/A (no probe sent; response inspected)".to_string(),
                    injection_point: "DNS / subdomain".to_string(),
                }));
            }
        }

        Ok(None)
    }
}

pub fn load_graphql_and_advanced_checks() -> Vec<Box<dyn ActiveCheck>> {
    vec![
        Box::new(GraphQlIntrospectionCheck),
        Box::new(HostHeaderInjectionCheck),
        Box::new(SubdomainTakeoverCheck),
    ]
}
