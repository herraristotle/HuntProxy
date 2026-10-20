//! Security misconfiguration detection rules.

use super::{PassiveRule, PassiveRuleResult, PassiveScanExchange, RuleSeverity};
use async_trait::async_trait;

pub struct CorsWildcard;

#[async_trait]
impl PassiveRule for CorsWildcard {
    fn id(&self) -> &str {
        "cors-wildcard"
    }

    fn name(&self) -> &str {
        "CORS Wildcard with Credentials"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let acao = exchange
            .response_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-origin"))?
            .1
            .as_str();

        let acac = exchange
            .response_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-credentials"))
            .map(|(_, v)| v.as_str());

        if acao == "*" && acac == Some("true") {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::High,
                confidence: 100,
                cwe_id: Some(942), // CWE-942: Permissive Cross-domain Policy
                description: "CORS configured with wildcard origin (*) and credentials enabled. This is invalid and may be misconfigured.".to_string(),
                evidence: "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS".to_string(),
                ],
            });
        }

        None
    }
}

pub struct CorsReflectedOrigin;

#[async_trait]
impl PassiveRule for CorsReflectedOrigin {
    fn id(&self) -> &str {
        "cors-reflected-origin"
    }

    fn name(&self) -> &str {
        "CORS Reflected Origin"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let request_origin = exchange
            .request_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("origin"))
            .map(|(_, v)| v.as_str())?;

        let acao = exchange
            .response_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-origin"))
            .map(|(_, v)| v.as_str())?;

        let acac = exchange
            .response_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-credentials"))
            .map(|(_, v)| v.as_str());

        if acao == request_origin && acac == Some("true") {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::High,
                confidence: 90,
                cwe_id: Some(942),
                description: "CORS reflects arbitrary origin with credentials. Any site can read authenticated responses.".to_string(),
                evidence: format!("Origin {} reflected in Access-Control-Allow-Origin", request_origin),
                references: vec![
                    "https://portswigger.net/web-security/cors".to_string(),
                ],
            });
        }

        None
    }
}

pub struct DangerousHttpMethods;

#[async_trait]
impl PassiveRule for DangerousHttpMethods {
    fn id(&self) -> &str {
        "dangerous-http-methods"
    }

    fn name(&self) -> &str {
        "Dangerous HTTP Methods Allowed"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        if exchange.method != "OPTIONS" {
            return None;
        }

        let allow = exchange
            .response_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("allow"))?
            .1
            .as_str();

        let dangerous = ["TRACE", "TRACK", "PUT", "DELETE"];
        let found: Vec<&str> = dangerous
            .iter()
            .filter(|&&m| allow.to_uppercase().contains(m))
            .copied()
            .collect();

        if !found.is_empty() {
            let severity = if found.contains(&"TRACE") || found.contains(&"TRACK") {
                RuleSeverity::Medium
            } else {
                RuleSeverity::Low
            };

            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity,
                confidence: 95,
                cwe_id: Some(16), // CWE-16: Configuration
                description: format!("Dangerous HTTP methods enabled: {}. TRACE/TRACK enable XST attacks. PUT/DELETE may allow unauthorized modifications.", found.join(", ")),
                evidence: format!("Allow: {}", allow),
                references: vec![
                    "https://owasp.org/www-community/attacks/Cross_Site_Tracing".to_string(),
                ],
            });
        }

        None
    }
}

pub struct TlsVersionCheck;

#[async_trait]
impl PassiveRule for TlsVersionCheck {
    fn id(&self) -> &str {
        "weak-tls-version"
    }

    fn name(&self) -> &str {
        "Weak TLS Version Detected"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        // Note: This requires TLS info from the transport layer
        // Placeholder for when we add TLS metadata to exchanges
        None
    }
}

pub struct CacheControlMisconfiguration;

#[async_trait]
impl PassiveRule for CacheControlMisconfiguration {
    fn id(&self) -> &str {
        "cache-control-sensitive"
    }

    fn name(&self) -> &str {
        "Sensitive Data Cached"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let url_lower = exchange.url.to_lowercase();
        let is_sensitive = url_lower.contains("login")
            || url_lower.contains("password")
            || url_lower.contains("auth")
            || url_lower.contains("account")
            || url_lower.contains("profile");

        if !is_sensitive {
            return None;
        }

        let cache_control = exchange
            .response_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
            .map(|(_, v)| v.as_str());

        let pragma = exchange
            .response_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("pragma"))
            .map(|(_, v)| v.as_str());

        let has_no_cache = cache_control
            .map(|cc| cc.contains("no-store") || cc.contains("no-cache"))
            .unwrap_or(false);

        let has_pragma_no_cache = pragma == Some("no-cache");

        if !has_no_cache && !has_pragma_no_cache {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Medium,
                confidence: 75,
                cwe_id: Some(524), // CWE-524: Information Exposure Through Caching
                description: "Sensitive URL lacks cache prevention headers. Response may be cached by browser or proxy.".to_string(),
                evidence: format!("URL: {}", exchange.url),
                references: vec![
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses".to_string(),
                ],
            });
        }

        None
    }
}

pub struct MissingReferrerPolicy;

#[async_trait]
impl PassiveRule for MissingReferrerPolicy {
    fn id(&self) -> &str {
        "missing-referrer-policy"
    }

    fn name(&self) -> &str {
        "Missing Referrer-Policy"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let has_referrer_policy = exchange
            .response_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("referrer-policy"));

        if !has_referrer_policy {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Info,
                confidence: 95,
                cwe_id: Some(200), // CWE-200: Information Exposure
                description: "Referrer-Policy header missing. URLs may leak in Referer header to third parties.".to_string(),
                evidence: "No Referrer-Policy header".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy".to_string(),
                ],
            });
        }

        None
    }
}

pub struct PermissionsPolicy;

#[async_trait]
impl PassiveRule for PermissionsPolicy {
    fn id(&self) -> &str {
        "missing-permissions-policy"
    }

    fn name(&self) -> &str {
        "Missing Permissions-Policy"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let has_permissions_policy = exchange.response_headers.iter().any(|(k, _)| {
            k.eq_ignore_ascii_case("permissions-policy") || k.eq_ignore_ascii_case("feature-policy")
        });

        if !has_permissions_policy {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Info,
                confidence: 90,
                cwe_id: Some(16),
                description: "Permissions-Policy header missing. Browser features (geolocation, camera, mic) not restricted.".to_string(),
                evidence: "No Permissions-Policy or Feature-Policy header".to_string(),
                references: vec![
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy".to_string(),
                ],
            });
        }

        None
    }
}

pub fn load_misconfiguration_rules() -> Vec<Box<dyn PassiveRule + Send + Sync>> {
    vec![
        Box::new(CorsWildcard),
        Box::new(CorsReflectedOrigin),
        Box::new(DangerousHttpMethods),
        Box::new(CacheControlMisconfiguration),
        Box::new(MissingReferrerPolicy),
        Box::new(PermissionsPolicy),
    ]
}
