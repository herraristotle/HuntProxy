//! Infrastructure and miscellaneous security issue detection rules.

use super::{PassiveRule, PassiveRuleResult, PassiveScanExchange, RuleSeverity};
use async_trait::async_trait;
use regex::Regex;

// ============================================================================
// Directory Listing Detection
// ============================================================================

pub struct DirectoryListingDetection;

#[async_trait]
impl PassiveRule for DirectoryListingDetection {
    fn id(&self) -> &str {
        "directory-listing"
    }

    fn name(&self) -> &str {
        "Directory Listing Enabled"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        let indicators = [
            ("<title>Index of /", "Apache/nginx index"),
            ("<h1>Index of /", "Generic index page"),
            ("Directory listing for /", "Python SimpleHTTPServer"),
            ("<title>Directory Listing", "Generic directory listing"),
            ("Parent Directory</a>", "Parent directory link"),
        ];

        for (pattern, source) in &indicators {
            if body_str.contains(pattern) {
                return Some(PassiveRuleResult {
                    rule_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: RuleSeverity::Medium,
                    confidence: 95,
                    cwe_id: Some(548), // CWE-548: Information Exposure Through Directory Listing
                    description: format!(
                        "Directory listing enabled ({source}). Exposes file structure."
                    ),
                    evidence: format!("Pattern: {pattern}"),
                    references: vec![
                        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
                            .to_string(),
                    ],
                });
            }
        }

        None
    }
}

// ============================================================================
// NPM Debug Log Detection
// ============================================================================

pub struct NpmDebugLogDetection;

#[async_trait]
impl PassiveRule for NpmDebugLogDetection {
    fn id(&self) -> &str {
        "npm-debug-log"
    }

    fn name(&self) -> &str {
        "NPM Debug Log Exposed"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let url_lower = exchange.url.to_lowercase();
        let status = exchange.status?;

        if !(200..300).contains(&status) {
            return None;
        }

        if url_lower.ends_with("npm-debug.log") || url_lower.ends_with("npm-debug.log.txt") {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Low,
                confidence: 100,
                cwe_id: Some(538),
                description:
                    "NPM debug log exposed. May contain paths, environment info, and error details."
                        .to_string(),
                evidence: format!("Accessible at: {}", exchange.url),
                references: vec![],
            });
        }

        None
    }
}

// ============================================================================
// Security.txt Detection
// ============================================================================

pub struct SecurityTxtDetection;

#[async_trait]
impl PassiveRule for SecurityTxtDetection {
    fn id(&self) -> &str {
        "security-txt"
    }

    fn name(&self) -> &str {
        "Security.txt Present"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let url_lower = exchange.url.to_lowercase();
        let status = exchange.status?;

        if !(200..300).contains(&status) {
            return None;
        }

        if url_lower.ends_with("/.well-known/security.txt") || url_lower.ends_with("/security.txt")
        {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Info,
                confidence: 100,
                cwe_id: None,
                description: "Security.txt found. Site provides security contact information."
                    .to_string(),
                evidence: format!("Found at: {}", exchange.url),
                references: vec!["https://securitytxt.org/".to_string()],
            });
        }

        None
    }
}

// ============================================================================
// WordPress README Detection
// ============================================================================

pub struct WordPressReadmeDetection;

#[async_trait]
impl PassiveRule for WordPressReadmeDetection {
    fn id(&self) -> &str {
        "wordpress-readme"
    }

    fn name(&self) -> &str {
        "WordPress README Exposed"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let url_lower = exchange.url.to_lowercase();
        let status = exchange.status?;

        if !(200..300).contains(&status) {
            return None;
        }

        if url_lower.ends_with("/readme.html") || url_lower.contains("/wp-") {
            let body = exchange.response_body.as_ref()?;
            let body_str = String::from_utf8_lossy(body);

            if body_str.contains("WordPress") && body_str.contains("readme") {
                return Some(PassiveRuleResult {
                    rule_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: RuleSeverity::Low,
                    confidence: 90,
                    cwe_id: Some(200),
                    description: "WordPress readme.html exposed. Reveals WordPress version."
                        .to_string(),
                    evidence: format!("Found at: {}", exchange.url),
                    references: vec![],
                });
            }
        }

        None
    }
}

// ============================================================================
// GitLab Token Detection
// ============================================================================

pub struct GitLabTokenDetection;

#[async_trait]
impl PassiveRule for GitLabTokenDetection {
    fn id(&self) -> &str {
        "gitlab-token-disclosure"
    }

    fn name(&self) -> &str {
        "GitLab Token Disclosure"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        // GitLab personal access token: glpat-
        let pattern = Regex::new(r"glpat-[0-9a-zA-Z_-]{20}").ok()?;

        if let Some(matched) = pattern.find(&body_str) {
            let token = matched.as_str();
            let redacted = format!("{}...{}", &token[..10], &token[token.len() - 4..]);

            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Critical,
                confidence: 95,
                cwe_id: Some(798),
                description: "GitLab personal access token exposed. Grants API access.".to_string(),
                evidence: format!("Token: {redacted}"),
                references: vec![
                    "https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html"
                        .to_string(),
                ],
            });
        }

        None
    }
}

// ============================================================================
// Missing Content-Type Header
// ============================================================================

pub struct MissingContentType;

#[async_trait]
impl PassiveRule for MissingContentType {
    fn id(&self) -> &str {
        "missing-content-type"
    }

    fn name(&self) -> &str {
        "Missing Content-Type Header"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let status = exchange.status?;

        // Only check successful responses with body
        if !(200..300).contains(&status) || exchange.response_body.is_none() {
            return None;
        }

        let has_content_type = exchange
            .response_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));

        if !has_content_type {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Low,
                confidence: 100,
                cwe_id: Some(345), // CWE-345: Insufficient Verification of Data Authenticity
                description:
                    "Response missing Content-Type header. Browser may misinterpret content."
                        .to_string(),
                evidence: "No Content-Type header present".to_string(),
                references: vec![],
            });
        }

        None
    }
}

// ============================================================================
// CSP Untrusted Style
// ============================================================================

pub struct CspUntrustedStyle;

#[async_trait]
impl PassiveRule for CspUntrustedStyle {
    fn id(&self) -> &str {
        "csp-untrusted-style"
    }

    fn name(&self) -> &str {
        "CSP Allows Untrusted Styles"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let csp = exchange
            .response_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-security-policy"))?
            .1
            .as_str();

        // Check for unsafe-inline in style-src
        if csp.contains("style-src") && csp.contains("'unsafe-inline'") {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Medium,
                confidence: 100,
                cwe_id: Some(79),
                description: "CSP allows unsafe-inline styles. May enable CSS injection attacks.".to_string(),
                evidence: "style-src contains 'unsafe-inline'".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/style-src".to_string(),
                ],
            });
        }

        None
    }
}

pub fn load_infrastructure_rules() -> Vec<Box<dyn PassiveRule + Send + Sync>> {
    vec![
        Box::new(DirectoryListingDetection),
        Box::new(NpmDebugLogDetection),
        Box::new(SecurityTxtDetection),
        Box::new(WordPressReadmeDetection),
        Box::new(GitLabTokenDetection),
        Box::new(MissingContentType),
        Box::new(CspUntrustedStyle),
    ]
}
