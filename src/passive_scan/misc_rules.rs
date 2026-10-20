//! Remaining Caido-parity passive checks: big redirects, JSON-as-HTML,
//! SQL statements in params, GraphQL detection, debug errors, link
//! manipulation.

use super::{PassiveRule, PassiveRuleResult, PassiveScanExchange, RuleSeverity};
use async_trait::async_trait;
use regex::Regex;

// ============================================================================
// Big Redirects
// ============================================================================

pub struct BigRedirects;

#[async_trait]
impl PassiveRule for BigRedirects {
    fn id(&self) -> &str {
        "big-redirects"
    }

    fn name(&self) -> &str {
        "Oversized Redirect Response"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let status = exchange.status?;
        if !(300..400).contains(&status) || status == 304 {
            return None;
        }

        let location = exchange
            .response_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))?
            .1
            .clone();

        let body = exchange.response_body.as_deref().unwrap_or(&[]);
        let href_count = Regex::new("(?i)href")
            .ok()?
            .find_iter(&String::from_utf8_lossy(body))
            .count();

        if body.len() > location.len() + 300 {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Low,
                confidence: 80,
                cwe_id: Some(200),
                description: format!(
                    "Redirect response body ({} bytes) far exceeds Location length ({} bytes); sensitive data may leak in redirect pages",
                    body.len(),
                    location.len()
                ),
                evidence: format!("Location: {location}"),
                references: vec![],
            });
        }

        if href_count > 1 {
            return Some(PassiveRuleResult {
                rule_id: format!("{}-multi-href", self.id()),
                name: "Redirect Response Contains Links".to_string(),
                severity: RuleSeverity::Info,
                confidence: 70,
                cwe_id: Some(200),
                description: format!(
                    "Redirect response embeds {href_count} href links; unusual for a redirect and may leak content"
                ),
                evidence: format!("{href_count} href occurrences"),
                references: vec![],
            });
        }

        None
    }
}

// ============================================================================
// JSON Response with HTML Content-Type
// ============================================================================

pub struct JsonHtmlResponse;

#[async_trait]
impl PassiveRule for JsonHtmlResponse {
    fn id(&self) -> &str {
        "json-html-response"
    }

    fn name(&self) -> &str {
        "JSON Payload Served as text/html"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let status = exchange.status?;
        if status != 200 {
            return None;
        }

        let is_html = exchange
            .response_headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.contains("text/html"))
            || exchange
                .mime
                .as_deref()
                .is_some_and(|m| m.contains("text/html"));
        if !is_html {
            return None;
        }

        let body = exchange.response_body.as_ref()?;
        let text = std::str::from_utf8(body).ok()?.trim();
        if text.is_empty() {
            return None;
        }

        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            if value.is_object() || value.is_array() {
                return Some(PassiveRuleResult {
                    rule_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: RuleSeverity::Info,
                    confidence: 90,
                    cwe_id: Some(79),
                    description: "Response body is valid JSON but Content-Type is text/html; browser may render attacker-controlled JSON as HTML (XSS)"
                        .to_string(),
                    evidence: format!("First bytes: {}", &text[..text.len().min(80)]),
                    references: vec![],
                });
            }
        }

        None
    }
}

// ============================================================================
// SQL Statement in Parameters
// ============================================================================

pub struct SqlStatementInParams;

#[async_trait]
impl PassiveRule for SqlStatementInParams {
    fn id(&self) -> &str {
        "sql-statement-in-params"
    }

    fn name(&self) -> &str {
        "SQL Statement in Parameter Value"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let (_, query) = exchange.url.split_once('?')?;

        for pair in query.split('&') {
            let value = match pair.split_once('=') {
                Some((_, v)) => urlencoding::decode(v).unwrap_or_default().to_string(),
                None => continue,
            };
            if let Some(pattern) = looks_like_sql(&value) {
                return Some(PassiveRuleResult {
                    rule_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: RuleSeverity::Medium,
                    confidence: 85,
                    cwe_id: Some(89),
                    description: "Request parameter carries raw SQL statement text; if it reaches a query builder this is direct SQL injection"
                        .to_string(),
                    evidence: format!("Pattern: {pattern} (value redacted)"),
                    references: vec![
                        "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
                    ],
                });
            }
        }

        None
    }
}

fn looks_like_sql(value: &str) -> Option<&'static str> {
    if value.len() < 10 {
        return None;
    }
    let lower = value.to_ascii_lowercase();

    const INJECTION: &[(&str, &str)] = &[
        ("union all select", "union-all-select"),
        ("union select", "union-select"),
        ("insert into", "insert-into"),
        ("delete from", "delete-from"),
        ("drop table", "drop-table"),
        ("drop database", "drop-database"),
        ("update ", "update-set"),
        ("information_schema", "information-schema"),
        ("waitfor delay", "waitfor-delay"),
        ("benchmark(", "benchmark"),
        ("sleep(", "sleep"),
        ("pg_sleep(", "pg-sleep"),
        ("'; drop", "semicolon-drop"),
    ];
    for (needle, name) in INJECTION {
        if lower.contains(needle) {
            // "update " needs a SET clause nearby to count
            if *name == "update-set" && !lower.contains("set ") {
                continue;
            }
            return Some(name);
        }
    }
    None
}

// ============================================================================
// GraphQL Endpoint Detection (passive)
// ============================================================================

pub struct GraphQlEndpoint;

#[async_trait]
impl PassiveRule for GraphQlEndpoint {
    fn id(&self) -> &str {
        "graphql-endpoint"
    }

    fn name(&self) -> &str {
        "GraphQL Endpoint Detected"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let url_lower = exchange.url.to_ascii_lowercase();

        if url_lower.contains("/graphql") {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Info,
                confidence: 95,
                cwe_id: None,
                description:
                    "GraphQL endpoint observed; worth testing for introspection and injection"
                        .to_string(),
                evidence: format!("URL: {}", exchange.url),
                references: vec![],
            });
        }

        // GraphQL over POST with {"query": "..."} body shape
        if exchange.method.eq_ignore_ascii_case("POST") {
            if let Some(body) = exchange.request_body.as_ref() {
                let text = String::from_utf8_lossy(body);
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                    if value
                        .get("query")
                        .and_then(|q| q.as_str())
                        .is_some_and(|q| {
                            q.contains("__schema")
                                || q.trim_start().starts_with('{')
                                || q.contains("mutation ")
                        })
                    {
                        return Some(PassiveRuleResult {
                            rule_id: format!("{}-body", self.id()),
                            name: "GraphQL Query in Request Body".to_string(),
                            severity: RuleSeverity::Info,
                            confidence: 85,
                            cwe_id: None,
                            description: "Request body carries a GraphQL query document"
                                .to_string(),
                            evidence: "JSON body with 'query' field of GraphQL shape".to_string(),
                            references: vec![],
                        });
                    }
                }
            }
        }

        None
    }
}

// ============================================================================
// GraphQL Content-Type Accepted
// ============================================================================

pub struct GraphQlContentType;

#[async_trait]
impl PassiveRule for GraphQlContentType {
    fn id(&self) -> &str {
        "graphql-content-type"
    }

    fn name(&self) -> &str {
        "GraphQL Content-Type in Use"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let uses_graphql_ct = exchange.request_headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("content-type")
                && (v.contains("application/graphql") || v.contains("text/graphql"))
        });

        if uses_graphql_ct {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Info,
                confidence: 90,
                cwe_id: None,
                description: "Client sends application/graphql content type; server parses raw GraphQL documents"
                    .to_string(),
                evidence: "Request Content-Type: application/graphql".to_string(),
                references: vec![],
            });
        }

        None
    }
}

// ============================================================================
// Generic Debug Error Disclosure
// ============================================================================

pub struct DebugErrors;

#[async_trait]
impl PassiveRule for DebugErrors {
    fn id(&self) -> &str {
        "debug-errors"
    }

    fn name(&self) -> &str {
        "Debug Error Information Disclosure"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let text = String::from_utf8_lossy(body);

        const PATTERNS: &[(&str, &str)] = &[
            ("PHP Debug", "PHP"),
            ("PHP Warning", "PHP"),
            ("PHP Notice", "PHP"),
            ("PHP Fatal error", "PHP"),
            ("PHP Parse error", "PHP"),
            ("Stack Trace", "generic"),
            ("Exception Details", "ASP.NET"),
            ("Exception in thread", "Java"),
            (".java:", "Java"),
            ("Traceback (most recent call last)", "Python"),
            ("NoMethodError", "Ruby"),
            ("ArgumentError", "Ruby"),
            ("Query failed:", "database"),
            ("SQL Error:", "database"),
            ("Database connection failed", "database"),
            ("Configuration error", "config"),
            ("Config file not found", "config"),
        ];

        for (pattern, family) in PATTERNS {
            if text.contains(pattern) {
                return Some(PassiveRuleResult {
                    rule_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: RuleSeverity::Low,
                    confidence: 75,
                    cwe_id: Some(209),
                    description: format!(
                        "Debug error output ({family} family) leaks internal structure during reconnaissance"
                    ),
                    evidence: format!("Pattern: {pattern}"),
                    references: vec![],
                });
            }
        }

        None
    }
}

// ============================================================================
// Link Manipulation (parameter reflected into href/src)
// ============================================================================

pub struct LinkManipulation;

#[async_trait]
impl PassiveRule for LinkManipulation {
    fn id(&self) -> &str {
        "link-manipulation"
    }

    fn name(&self) -> &str {
        "Parameter Reflected into Link Attribute"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let status = exchange.status?;
        if status != 200 {
            return None;
        }

        let body = exchange.response_body.as_ref()?;
        let text = String::from_utf8_lossy(body);
        if !text.contains("href=") && !text.contains("src=") {
            return None;
        }

        let (_, query) = exchange.url.split_once('?')?;

        for pair in query.split('&') {
            let Some((key, raw)) = pair.split_once('=') else {
                continue;
            };
            let value = urlencoding::decode(raw).unwrap_or_default().to_string();
            if value.len() < 5 {
                continue;
            }

            // Value embedded in a URL-ish attribute without obvious encoding
            for attr in ["href=\"", "src=\"", "href='", "src='"] {
                if let Some(start) = text.find(attr) {
                    let rest = &text[start + attr.len()..];
                    if let Some(end) = rest.find(['"', '\'']) {
                        let attr_value = &rest[..end];
                        if attr_value.contains(&value) {
                            return Some(PassiveRuleResult {
                                rule_id: self.id().to_string(),
                                name: self.name().to_string(),
                                severity: RuleSeverity::Medium,
                                confidence: 80,
                                cwe_id: Some(601),
                                description: format!(
                                    "Parameter {} is reflected into a link attribute; javascript: or //evil values enable XSS/open-redirect via links",
                                    urlencoding::decode(key).unwrap_or_default()
                                ),
                                evidence: format!("{attr}<redacted>"),
                                references: vec![],
                            });
                        }
                    }
                }
            }
        }

        None
    }
}

pub fn load_misc_rules() -> Vec<Box<dyn PassiveRule + Send + Sync>> {
    vec![
        Box::new(BigRedirects),
        Box::new(JsonHtmlResponse),
        Box::new(SqlStatementInParams),
        Box::new(GraphQlEndpoint),
        Box::new(GraphQlContentType),
        Box::new(DebugErrors),
        Box::new(LinkManipulation),
    ]
}
