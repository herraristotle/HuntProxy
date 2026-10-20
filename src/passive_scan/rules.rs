//! Passive scanning rules for common vulnerabilities.

use super::PassiveScanExchange;
use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveRuleResult {
    pub rule_id: String,
    pub name: String,
    pub severity: RuleSeverity,
    pub confidence: u8, // 0-100
    pub cwe_id: Option<u32>,
    pub description: String,
    pub evidence: String,
    pub references: Vec<String>,
}

#[async_trait]
pub trait PassiveRule {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn enabled(&self) -> bool;
    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult>;
}

/// Load default passive scanning rules
pub fn load_default_rules() -> Vec<Box<dyn PassiveRule + Send + Sync>> {
    let mut rules: Vec<Box<dyn PassiveRule + Send + Sync>> = vec![
        Box::new(MissingSecurityHeaders),
        Box::new(WeakCspRule),
        Box::new(InsecureCookieRule),
        Box::new(InfoDisclosureRule),
        Box::new(XssReflectionRule),
        Box::new(SqlErrorRule),
    ];

    // Load additional rule modules
    rules.extend(super::disclosure_rules::load_disclosure_rules());
    rules.extend(super::file_rules::load_file_rules());
    rules.extend(super::framework_rules::load_framework_rules());
    rules.extend(super::advanced_csp_rules::load_advanced_csp_rules());
    rules.extend(super::injection_rules::load_injection_rules());
    rules.extend(super::misconfiguration_rules::load_misconfiguration_rules());
    rules.extend(super::pii_rules::load_pii_rules());
    rules.extend(super::infrastructure_rules::load_infrastructure_rules());
    rules.extend(super::misc_rules::load_misc_rules());

    rules
}

// Rule 1: Missing Security Headers
struct MissingSecurityHeaders;

#[async_trait]
impl PassiveRule for MissingSecurityHeaders {
    fn id(&self) -> &str {
        "missing-security-headers"
    }

    fn name(&self) -> &str {
        "Missing Security Headers"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let headers_lower: HashSet<String> = exchange
            .response_headers
            .iter()
            .map(|(k, _)| k.to_lowercase())
            .collect();

        let mut missing = Vec::new();

        if !headers_lower.contains("x-frame-options")
            && !headers_lower.contains("content-security-policy")
        {
            missing.push("X-Frame-Options or CSP frame-ancestors");
        }
        if !headers_lower.contains("x-content-type-options") {
            missing.push("X-Content-Type-Options");
        }
        if !headers_lower.contains("strict-transport-security") && exchange.url.starts_with("https")
        {
            missing.push("Strict-Transport-Security");
        }

        if missing.is_empty() {
            return None;
        }

        Some(PassiveRuleResult {
            rule_id: self.id().to_string(),
            name: self.name().to_string(),
            severity: RuleSeverity::Low,
            confidence: 90,
            cwe_id: Some(693), // CWE-693: Protection Mechanism Failure
            description: format!("Missing security headers: {}", missing.join(", ")),
            evidence: format!("Response from {}", exchange.url),
            references: vec!["https://owasp.org/www-project-secure-headers/".to_string()],
        })
    }
}

// Rule 2: Weak CSP
struct WeakCspRule;

#[async_trait]
impl PassiveRule for WeakCspRule {
    fn id(&self) -> &str {
        "weak-csp"
    }

    fn name(&self) -> &str {
        "Weak Content Security Policy"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let csp = exchange
            .response_headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-security-policy")
            .map(|(_, v)| v)?;

        let csp_lower = csp.to_lowercase();
        let mut issues = Vec::new();

        if csp_lower.contains("unsafe-inline") {
            issues.push("'unsafe-inline' allows inline scripts/styles");
        }
        if csp_lower.contains("unsafe-eval") {
            issues.push("'unsafe-eval' allows eval() and similar");
        }
        if csp_lower.contains("*") && !csp_lower.contains("'strict-dynamic'") {
            issues.push("wildcard (*) without 'strict-dynamic'");
        }

        if issues.is_empty() {
            return None;
        }

        Some(PassiveRuleResult {
            rule_id: self.id().to_string(),
            name: self.name().to_string(),
            severity: RuleSeverity::Medium,
            confidence: 95,
            cwe_id: Some(1021), // CWE-1021: Improper Restriction of Rendered UI Layers
            description: format!("Weak CSP: {}", issues.join("; ")),
            evidence: format!("CSP: {}", csp),
            references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP".to_string()],
        })
    }
}

// Rule 3: Insecure Cookies
struct InsecureCookieRule;

#[async_trait]
impl PassiveRule for InsecureCookieRule {
    fn id(&self) -> &str {
        "insecure-cookie"
    }

    fn name(&self) -> &str {
        "Insecure Cookie Configuration"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let set_cookies: Vec<&str> = exchange
            .response_headers
            .iter()
            .filter(|(k, _)| k.to_lowercase() == "set-cookie")
            .map(|(_, v)| v.as_str())
            .collect();

        if set_cookies.is_empty() {
            return None;
        }

        let mut issues = Vec::new();
        let is_https = exchange.url.starts_with("https");

        for cookie in &set_cookies {
            let cookie_lower = cookie.to_lowercase();
            let cookie_name = cookie.split('=').next().unwrap_or("unknown");

            if is_https && !cookie_lower.contains("secure") {
                issues.push(format!("{}: missing Secure flag", cookie_name));
            }
            if !cookie_lower.contains("httponly") && !cookie_name.starts_with("__Host-") {
                issues.push(format!("{}: missing HttpOnly flag", cookie_name));
            }
            if !cookie_lower.contains("samesite") {
                issues.push(format!("{}: missing SameSite attribute", cookie_name));
            }
        }

        if issues.is_empty() {
            return None;
        }

        Some(PassiveRuleResult {
            rule_id: self.id().to_string(),
            name: self.name().to_string(),
            severity: RuleSeverity::Low,
            confidence: 95,
            cwe_id: Some(614), // CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure'
            description: format!("Insecure cookie(s): {}", issues.join("; ")),
            evidence: set_cookies.join("; "),
            references: vec![
                "https://owasp.org/www-community/controls/SecureCookieAttribute".to_string(),
            ],
        })
    }
}

// Rule 4: Information Disclosure
struct InfoDisclosureRule;

#[async_trait]
impl PassiveRule for InfoDisclosureRule {
    fn id(&self) -> &str {
        "info-disclosure"
    }

    fn name(&self) -> &str {
        "Information Disclosure"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        // Check response body for stack traces and sensitive paths
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        let patterns = [
            (r"at\s+[\w.$]+\([^)]*\.java:\d+\)", "Java stack trace"),
            (
                r"Fatal error:.*in /[\w/]+\.php on line \d+",
                "PHP error with path",
            ),
            (r"Traceback \(most recent call last\):", "Python traceback"),
            (r"Microsoft.*SQL Server.*Error", "SQL Server error"),
            (r"ORA-\d{5}", "Oracle error"),
            (r"/usr/|/var/|/etc/|C:\\", "Absolute file path"),
            (r"root:.*:\d+:\d+:", "Unix password file"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(matched) = re.find(&body_str) {
                    let evidence = matched.as_str();
                    return Some(PassiveRuleResult {
                        rule_id: self.id().to_string(),
                        name: self.name().to_string(),
                        severity: RuleSeverity::Medium,
                        confidence: 85,
                        cwe_id: Some(209), // CWE-209: Information Exposure Through Error Message
                        description: format!("Potential information disclosure: {}", desc),
                        evidence: evidence.chars().take(200).collect(),
                        references: vec![
                            "https://owasp.org/www-community/Improper_Error_Handling".to_string()
                        ],
                    });
                }
            }
        }

        None
    }
}

// Rule 5: XSS Reflection Detection
struct XssReflectionRule;

#[async_trait]
impl PassiveRule for XssReflectionRule {
    fn id(&self) -> &str {
        "xss-reflection"
    }

    fn name(&self) -> &str {
        "Possible XSS Reflection"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        // Extract query params from URL
        let url_parts: Vec<&str> = exchange.url.split('?').collect();
        if url_parts.len() < 2 {
            return None;
        }

        let query = url_parts[1];
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);
        let body_lower = body_str.to_lowercase();

        // Check if response is HTML
        if !body_lower.contains("<html") && !body_lower.contains("<!doctype") {
            return None;
        }

        // Look for reflected parameter values in HTML context
        for param_pair in query.split('&') {
            if let Some((_, value)) = param_pair.split_once('=') {
                if value.len() < 3 {
                    continue;
                }

                let decoded = urlencoding::decode(value).ok()?;
                if body_str.contains(decoded.as_ref()) {
                    // Check if it's in a dangerous context (not in comments/attributes)
                    let dangerous_contexts = [
                        format!(">{}<", decoded),
                        format!("<script>{}", decoded),
                        format!("javascript:{}", decoded),
                    ];

                    for ctx in &dangerous_contexts {
                        if body_str.contains(ctx) {
                            return Some(PassiveRuleResult {
                                rule_id: self.id().to_string(),
                                name: self.name().to_string(),
                                severity: RuleSeverity::High,
                                confidence: 60, // Lower confidence - needs active verification
                                cwe_id: Some(79), // CWE-79: Cross-site Scripting
                                description: "Parameter value reflected in HTML response in potentially dangerous context".to_string(),
                                evidence: format!("Reflected: {}", decoded.chars().take(100).collect::<String>()),
                                references: vec![
                                    "https://owasp.org/www-community/attacks/xss/".to_string(),
                                ],
                            });
                        }
                    }
                }
            }
        }

        None
    }
}

// Rule 6: SQL Error Detection
struct SqlErrorRule;

#[async_trait]
impl PassiveRule for SqlErrorRule {
    fn id(&self) -> &str {
        "sql-error"
    }

    fn name(&self) -> &str {
        "SQL Error Message"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        let sql_errors = [
            ("SQL syntax.*MySQL", "MySQL"),
            ("Warning.*mysql_", "MySQL"),
            ("PostgreSQL.*ERROR", "PostgreSQL"),
            ("Warning.*pg_", "PostgreSQL"),
            ("Microsoft SQL Server", "SQL Server"),
            ("ORA-[0-9]{5}", "Oracle"),
            ("SQLite.*(error|exception)", "SQLite"),
            ("SQLSTATE\\[", "Generic SQL"),
            ("Unclosed quotation mark", "SQL Server"),
        ];

        for (pattern, db_type) in &sql_errors {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(matched) = re.find(&body_str) {
                    return Some(PassiveRuleResult {
                        rule_id: self.id().to_string(),
                        name: self.name().to_string(),
                        severity: RuleSeverity::Medium,
                        confidence: 90,
                        cwe_id: Some(89), // CWE-89: SQL Injection
                        description: format!("SQL error message detected ({})", db_type),
                        evidence: matched.as_str().chars().take(200).collect(),
                        references: vec![
                            "https://owasp.org/www-community/attacks/SQL_Injection".to_string()
                        ],
                    });
                }
            }
        }

        None
    }
}
