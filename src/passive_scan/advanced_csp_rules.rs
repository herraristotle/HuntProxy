//! Advanced Content Security Policy analysis rules.

use super::{PassiveRule, PassiveRuleResult, PassiveScanExchange, RuleSeverity};
use async_trait::async_trait;

pub struct MalformedCsp;

#[async_trait]
impl PassiveRule for MalformedCsp {
    fn id(&self) -> &str {
        "malformed-csp"
    }

    fn name(&self) -> &str {
        "Malformed Content Security Policy"
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

        let issues: Vec<&str> = [
            (";;", "Double semicolon"),
            ("'none' ", "Directive after 'none'"),
            (" 'none'", "Directive before 'none'"),
            ("default-src;", "Empty directive"),
        ]
        .iter()
        .filter_map(|(pattern, desc)| if csp.contains(pattern) { Some(*desc) } else { None })
        .collect();

        if !issues.is_empty() {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Medium,
                confidence: 90,
                cwe_id: Some(1021), // CWE-1021: Improper Restriction of Rendered UI Layers
                description: format!("CSP contains syntax errors: {}. Browser may ignore entire policy.", issues.join(", ")),
                evidence: format!("CSP: {}", csp),
                references: vec![
                    "https://content-security-policy.com/".to_string(),
                ],
            });
        }

        None
    }
}

pub struct ClickjackingCsp;

#[async_trait]
impl PassiveRule for ClickjackingCsp {
    fn id(&self) -> &str {
        "clickjacking-csp"
    }

    fn name(&self) -> &str {
        "CSP Missing frame-ancestors"
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

        if !csp.contains("frame-ancestors") {
            // Check if X-Frame-Options is present as fallback
            let has_xfo = exchange
                .response_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("x-frame-options"));

            if !has_xfo {
                return Some(PassiveRuleResult {
                    rule_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: RuleSeverity::Medium,
                    confidence: 85,
                    cwe_id: Some(1021),
                    description: "CSP lacks frame-ancestors directive and no X-Frame-Options header. Page vulnerable to clickjacking.".to_string(),
                    evidence: "Missing frame-ancestors directive".to_string(),
                    references: vec![
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors".to_string(),
                    ],
                });
            }
        }

        None
    }
}

pub struct FormActionCsp;

#[async_trait]
impl PassiveRule for FormActionCsp {
    fn id(&self) -> &str {
        "form-action-csp"
    }

    fn name(&self) -> &str {
        "CSP Missing form-action"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        if !body_str.contains("<form") {
            return None;
        }

        let csp = exchange
            .response_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-security-policy"))?
            .1
            .as_str();

        if !csp.contains("form-action") {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Low,
                confidence: 80,
                cwe_id: Some(352), // CWE-352: Cross-Site Request Forgery
                description: "Page contains forms but CSP lacks form-action directive. Forms could submit to attacker-controlled domains.".to_string(),
                evidence: "Form detected without form-action restriction".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/form-action".to_string(),
                ],
            });
        }

        None
    }
}

pub struct AllowlistedScriptCsp;

#[async_trait]
impl PassiveRule for AllowlistedScriptCsp {
    fn id(&self) -> &str {
        "allowlisted-script-csp"
    }

    fn name(&self) -> &str {
        "CSP Allowlisted Script Domains"
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

        let risky_domains = [
            "googleapis.com",
            "gstatic.com",
            "ajax.aspnetcdn.com",
            "cloudflare.com",
            "cdnjs.cloudflare.com",
        ];

        let script_src_start = csp.find("script-src")?;
        let script_src_end = csp[script_src_start..].find(';').unwrap_or(csp.len() - script_src_start);
        let script_src_value = &csp[script_src_start..script_src_start + script_src_end];

        let found_risky: Vec<&str> = risky_domains
            .iter()
            .filter(|&&domain| script_src_value.contains(domain))
            .copied()
            .collect();

        if !found_risky.is_empty() {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Medium,
                confidence: 75,
                cwe_id: Some(646), // CWE-646: Reliance on File Name or Extension
                description: format!(
                    "CSP allowlists domains known to host JSONP or Angular endpoints that bypass CSP: {}",
                    found_risky.join(", ")
                ),
                evidence: format!("Risky domains in script-src: {}", found_risky.join(", ")),
                references: vec![
                    "https://research.google/pubs/pub45542/".to_string(),
                    "https://github.com/google/csp-evaluator".to_string(),
                ],
            });
        }

        None
    }
}

pub struct BaseUriCsp;

#[async_trait]
impl PassiveRule for BaseUriCsp {
    fn id(&self) -> &str {
        "base-uri-csp"
    }

    fn name(&self) -> &str {
        "CSP Missing base-uri"
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

        if !csp.contains("base-uri") {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Low,
                confidence: 70,
                cwe_id: Some(79), // CWE-79: XSS
                description: "CSP lacks base-uri directive. Attacker could inject <base> tag to hijack relative URLs.".to_string(),
                evidence: "Missing base-uri directive".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/base-uri".to_string(),
                ],
            });
        }

        None
    }
}

pub struct ObjectSrcCsp;

#[async_trait]
impl PassiveRule for ObjectSrcCsp {
    fn id(&self) -> &str {
        "object-src-csp"
    }

    fn name(&self) -> &str {
        "CSP Permissive object-src"
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

        if !csp.contains("object-src") || csp.contains("object-src *") {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Medium,
                confidence: 80,
                cwe_id: Some(79),
                description: "CSP lacks object-src restriction. Legacy plugins (<object>, <embed>, <applet>) can bypass CSP.".to_string(),
                evidence: "Missing or wildcard object-src".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/object-src".to_string(),
                ],
            });
        }

        None
    }
}

pub fn load_advanced_csp_rules() -> Vec<Box<dyn PassiveRule + Send + Sync>> {
    vec![
        Box::new(MalformedCsp),
        Box::new(ClickjackingCsp),
        Box::new(FormActionCsp),
        Box::new(AllowlistedScriptCsp),
        Box::new(BaseUriCsp),
        Box::new(ObjectSrcCsp),
    ]
}
