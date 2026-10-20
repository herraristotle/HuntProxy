//! Framework-specific debug mode and error page detection.

use super::{PassiveRule, PassiveRuleResult, PassiveScanExchange, RuleSeverity};
use async_trait::async_trait;

pub struct DjangoDebugMode;

#[async_trait]
impl PassiveRule for DjangoDebugMode {
    fn id(&self) -> &str {
        "django-debug-mode"
    }

    fn name(&self) -> &str {
        "Django Debug Mode Enabled"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        let indicators = [
            "Traceback (most recent call last):",
            "Django version",
            "SHOW SETTINGS",
            "You're seeing this error because you have <code>DEBUG = True</code>",
            "Request Method:",
            "Request URL:",
            "Django Version:",
            "Exception Type:",
            "Exception Value:",
        ];

        let matches: Vec<&str> = indicators
            .iter()
            .filter(|&&ind| body_str.contains(ind))
            .copied()
            .collect();

        if matches.len() >= 3 {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Medium,
                confidence: 95,
                cwe_id: Some(215), // CWE-215: Information Exposure Through Debug Information
                description: "Django application running in debug mode. Debug pages expose source code, local variables, settings, and internal paths.".to_string(),
                evidence: format!("Found indicators: {}", matches.join(", ")),
                references: vec![
                    "https://docs.djangoproject.com/en/stable/ref/settings/#debug".to_string(),
                ],
            });
        }

        None
    }
}

pub struct LaravelDebugMode;

#[async_trait]
impl PassiveRule for LaravelDebugMode {
    fn id(&self) -> &str {
        "laravel-debug-mode"
    }

    fn name(&self) -> &str {
        "Laravel Debug Mode Enabled"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        if body_str.contains("Whoops, looks like something went wrong.")
            && (body_str.contains("Laravel") || body_str.contains("Illuminate\\"))
        {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Medium,
                confidence: 90,
                cwe_id: Some(215),
                description: "Laravel application showing detailed error pages. May expose source code paths and environment details.".to_string(),
                evidence: "Laravel error page detected".to_string(),
                references: vec![
                    "https://laravel.com/docs/errors#configuration".to_string(),
                ],
            });
        }

        None
    }
}

pub struct SymfonyProfiler;

#[async_trait]
impl PassiveRule for SymfonyProfiler {
    fn id(&self) -> &str {
        "symfony-profiler"
    }

    fn name(&self) -> &str {
        "Symfony Web Profiler Exposed"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let url_lower = exchange.url.to_lowercase();

        if url_lower.contains("/_profiler/") || url_lower.contains("/_wdt/") {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::High,
                confidence: 100,
                cwe_id: Some(215),
                description: "Symfony Web Debug Toolbar/Profiler accessible. Exposes detailed application state, database queries, and configuration.".to_string(),
                evidence: format!("Profiler URL: {}", exchange.url),
                references: vec![
                    "https://symfony.com/doc/current/profiler.html".to_string(),
                ],
            });
        }

        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        if body_str.contains("symfony-toolbar") || body_str.contains("sf-toolbar") {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: "Symfony Debug Toolbar Enabled".to_string(),
                severity: RuleSeverity::Medium,
                confidence: 95,
                cwe_id: Some(215),
                description: "Symfony debug toolbar enabled in production.".to_string(),
                evidence: "Debug toolbar HTML found in response".to_string(),
                references: vec!["https://symfony.com/doc/current/profiler.html".to_string()],
            });
        }

        None
    }
}

pub struct SpringActuator;

#[async_trait]
impl PassiveRule for SpringActuator {
    fn id(&self) -> &str {
        "spring-actuator"
    }

    fn name(&self) -> &str {
        "Spring Boot Actuator Exposed"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let url_lower = exchange.url.to_lowercase();

        let sensitive_endpoints = [
            "/actuator",
            "/actuator/env",
            "/actuator/health",
            "/actuator/metrics",
            "/actuator/trace",
            "/actuator/dump",
            "/actuator/heapdump",
            "/actuator/configprops",
            "/actuator/beans",
        ];

        for endpoint in &sensitive_endpoints {
            if url_lower.contains(endpoint) {
                let severity = if endpoint.contains("heapdump")
                    || endpoint.contains("dump")
                    || endpoint.contains("env")
                {
                    RuleSeverity::High
                } else {
                    RuleSeverity::Medium
                };

                return Some(PassiveRuleResult {
                    rule_id: format!("{}-{}", self.id(), endpoint.replace('/', "-")),
                    name: format!("Spring Boot Actuator: {endpoint}"),
                    severity,
                    confidence: 100,
                    cwe_id: Some(215),
                    description: format!("Spring Boot Actuator endpoint exposed: {endpoint}. May reveal environment variables, configuration, and application state."),
                    evidence: format!("Endpoint: {}", exchange.url),
                    references: vec![
                        "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html".to_string(),
                    ],
                });
            }
        }

        None
    }
}

pub struct DotNetTrace;

#[async_trait]
impl PassiveRule for DotNetTrace {
    fn id(&self) -> &str {
        "dotnet-trace"
    }

    fn name(&self) -> &str {
        "ASP.NET Trace Enabled"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let url_lower = exchange.url.to_lowercase();

        if url_lower.contains("/trace.axd") {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::High,
                confidence: 100,
                cwe_id: Some(215),
                description: "ASP.NET trace.axd accessible. Exposes detailed request information including form data, cookies, and session state.".to_string(),
                evidence: format!("Trace URL: {}", exchange.url),
                references: vec![
                    "https://docs.microsoft.com/en-us/previous-versions/aspnet/bb386420(v=vs.100)".to_string(),
                ],
            });
        }

        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        if body_str.contains("Application Trace") && body_str.contains("Request Details") {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::High,
                confidence: 95,
                cwe_id: Some(215),
                description: "ASP.NET detailed trace information exposed.".to_string(),
                evidence: "Trace output found in response".to_string(),
                references: vec![
                    "https://docs.microsoft.com/en-us/previous-versions/aspnet/bb386420(v=vs.100)"
                        .to_string(),
                ],
            });
        }

        None
    }
}

pub struct NodeJsError;

#[async_trait]
impl PassiveRule for NodeJsError {
    fn id(&self) -> &str {
        "nodejs-error-page"
    }

    fn name(&self) -> &str {
        "Node.js Error Page"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        if (body_str.contains("at Object.") || body_str.contains("at Function."))
            && (body_str.contains("/node_modules/") || body_str.contains("Error: "))
        {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Medium,
                confidence: 85,
                cwe_id: Some(209), // CWE-209: Information Exposure Through Error Message
                description:
                    "Node.js stack trace exposed. Reveals application structure and file paths."
                        .to_string(),
                evidence: "Node.js error stack trace detected".to_string(),
                references: vec!["https://expressjs.com/en/guide/error-handling.html".to_string()],
            });
        }

        None
    }
}

/// Load all framework detection rules.
pub fn load_framework_rules() -> Vec<Box<dyn PassiveRule + Send + Sync>> {
    vec![
        Box::new(DjangoDebugMode),
        Box::new(LaravelDebugMode),
        Box::new(SymfonyProfiler),
        Box::new(SpringActuator),
        Box::new(DotNetTrace),
        Box::new(NodeJsError),
    ]
}
