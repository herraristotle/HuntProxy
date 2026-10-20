//! Additional injection and attack pattern detection rules.

use super::{PassiveRule, PassiveRuleResult, PassiveScanExchange, RuleSeverity};
use async_trait::async_trait;

pub struct SstiDetection;

#[async_trait]
impl PassiveRule for SstiDetection {
    fn id(&self) -> &str {
        "ssti-detection"
    }

    fn name(&self) -> &str {
        "Server-Side Template Injection Indicators"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        let patterns = [
            ("{{", "Jinja2/Twig template syntax"),
            ("<#", "FreeMarker template syntax"),
            ("${", "Expression language syntax"),
            ("<%=", "ERB/JSP template syntax"),
            ("#set", "Velocity template syntax"),
        ];

        let url_lower = exchange.url.to_lowercase();
        let has_test_param =
            url_lower.contains("{{") || url_lower.contains("${") || url_lower.contains("<%=");

        if has_test_param {
            for (pattern, desc) in &patterns {
                if body_str.contains(pattern) {
                    return Some(PassiveRuleResult {
                        rule_id: self.id().to_string(),
                        name: self.name().to_string(),
                        severity: RuleSeverity::High,
                        confidence: 70,
                        cwe_id: Some(1336), // CWE-1336: Template Injection
                        description: format!("Template syntax in URL reflected in response: {}. Possible SSTI vulnerability.", desc),
                        evidence: format!("Pattern: {}", pattern),
                        references: vec![
                            "https://portswigger.net/web-security/server-side-template-injection".to_string(),
                        ],
                    });
                }
            }
        }

        None
    }
}

pub struct PathTraversalPatterns;

#[async_trait]
impl PassiveRule for PathTraversalPatterns {
    fn id(&self) -> &str {
        "path-traversal-patterns"
    }

    fn name(&self) -> &str {
        "Path Traversal Pattern in Response"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        let patterns = [
            "/etc/passwd",
            "/etc/shadow",
            "C:\\Windows\\System32",
            "C:\\boot.ini",
            "/var/www",
            "/proc/self/environ",
        ];

        for pattern in &patterns {
            if body_str.contains(pattern) {
                return Some(PassiveRuleResult {
                    rule_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: RuleSeverity::High,
                    confidence: 85,
                    cwe_id: Some(22), // CWE-22: Path Traversal
                    description: format!("System file path ({}) found in response. May indicate path traversal vulnerability.", pattern),
                    evidence: format!("Pattern: {}", pattern),
                    references: vec![
                        "https://owasp.org/www-community/attacks/Path_Traversal".to_string(),
                    ],
                });
            }
        }

        None
    }
}

pub struct XxeIndicators;

#[async_trait]
impl PassiveRule for XxeIndicators {
    fn id(&self) -> &str {
        "xxe-indicators"
    }

    fn name(&self) -> &str {
        "XML External Entity Indicators"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        if body_str.contains("<!DOCTYPE") && body_str.contains("<!ENTITY") {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Medium,
                confidence: 60,
                cwe_id: Some(611), // CWE-611: XXE
                description: "Response contains XML DOCTYPE with ENTITY declarations. May indicate XXE testing or vulnerability.".to_string(),
                evidence: "XML with DOCTYPE and ENTITY found".to_string(),
                references: vec![
                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing".to_string(),
                ],
            });
        }

        None
    }
}

pub struct LdapInjectionPatterns;

#[async_trait]
impl PassiveRule for LdapInjectionPatterns {
    fn id(&self) -> &str {
        "ldap-injection-patterns"
    }

    fn name(&self) -> &str {
        "LDAP Injection Error Patterns"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        let patterns = [
            "javax.naming.NameNotFoundException",
            "LDAPException",
            "com.sun.jndi.ldap",
            "[LDAP: error code",
            "javax.naming.directory.InvalidSearchFilterException",
        ];

        for pattern in &patterns {
            if body_str.contains(pattern) {
                return Some(PassiveRuleResult {
                    rule_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: RuleSeverity::Medium,
                    confidence: 80,
                    cwe_id: Some(90), // CWE-90: LDAP Injection
                    description:
                        "LDAP error message in response. May indicate LDAP injection vulnerability."
                            .to_string(),
                    evidence: format!("Pattern: {}", pattern),
                    references: vec![
                        "https://owasp.org/www-community/attacks/LDAP_Injection".to_string()
                    ],
                });
            }
        }

        None
    }
}

pub struct NoSqlInjectionPatterns;

#[async_trait]
impl PassiveRule for NoSqlInjectionPatterns {
    fn id(&self) -> &str {
        "nosql-injection-patterns"
    }

    fn name(&self) -> &str {
        "NoSQL Error Patterns"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        let patterns = [
            ("MongoError", "MongoDB"),
            ("CouchDB", "CouchDB"),
            ("com.mongodb", "MongoDB"),
            (
                "ReferenceError: $ is not defined",
                "MongoDB operator injection",
            ),
            ("Can't canonicalize query", "MongoDB"),
        ];

        for (pattern, db_type) in &patterns {
            if body_str.contains(pattern) {
                return Some(PassiveRuleResult {
                    rule_id: format!("{}-{}", self.id(), db_type.to_lowercase()),
                    name: format!("{} Error Detected", db_type),
                    severity: RuleSeverity::Medium,
                    confidence: 75,
                    cwe_id: Some(943), // CWE-943: Improper Neutralization of Special Elements
                    description: format!("{} error in response. May indicate NoSQL injection vulnerability.", db_type),
                    evidence: format!("Pattern: {}", pattern),
                    references: vec![
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection".to_string(),
                    ],
                });
            }
        }

        None
    }
}

pub fn load_injection_rules() -> Vec<Box<dyn PassiveRule + Send + Sync>> {
    vec![
        Box::new(SstiDetection),
        Box::new(PathTraversalPatterns),
        Box::new(XxeIndicators),
        Box::new(LdapInjectionPatterns),
        Box::new(NoSqlInjectionPatterns),
    ]
}
