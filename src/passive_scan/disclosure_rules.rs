//! API key and secret disclosure detection rules.

use super::{PassiveRule, PassiveRuleResult, PassiveScanExchange, RuleSeverity};
use async_trait::async_trait;
use regex::Regex;

/// Pattern definitions for various API keys and secrets.
struct KeyPattern {
    name: &'static str,
    pattern: &'static str,
    severity: RuleSeverity,
    cwe_id: u32,
}

static KEY_PATTERNS: &[KeyPattern] = &[
    // AWS
    KeyPattern {
        name: "AWS Access Key ID",
        pattern: r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        severity: RuleSeverity::Critical,
        cwe_id: 798,
    },
    KeyPattern {
        name: "AWS Secret Access Key",
        pattern: r#"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"#,
        severity: RuleSeverity::Critical,
        cwe_id: 798,
    },
    KeyPattern {
        name: "AWS Session Token",
        pattern: r#"(?i)aws.{0,20}session.{0,20}token['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{100,}"#,
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    // GitHub
    KeyPattern {
        name: "GitHub Personal Access Token",
        pattern: r"ghp_[0-9a-zA-Z]{36}",
        severity: RuleSeverity::Critical,
        cwe_id: 798,
    },
    KeyPattern {
        name: "GitHub OAuth Token",
        pattern: r"gho_[0-9a-zA-Z]{36}",
        severity: RuleSeverity::Critical,
        cwe_id: 798,
    },
    KeyPattern {
        name: "GitHub App Token",
        pattern: r"(?:ghu|ghs)_[0-9a-zA-Z]{36}",
        severity: RuleSeverity::Critical,
        cwe_id: 798,
    },
    // Slack
    KeyPattern {
        name: "Slack Token",
        pattern: r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}",
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    KeyPattern {
        name: "Slack Webhook",
        pattern: r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        severity: RuleSeverity::Medium,
        cwe_id: 200,
    },
    // Stripe
    KeyPattern {
        name: "Stripe Secret Key",
        pattern: r"sk_live_[0-9a-zA-Z]{24,}",
        severity: RuleSeverity::Critical,
        cwe_id: 798,
    },
    KeyPattern {
        name: "Stripe Restricted Key",
        pattern: r"rk_live_[0-9a-zA-Z]{24,}",
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    // Google
    KeyPattern {
        name: "Google API Key",
        pattern: r"AIza[0-9A-Za-z\\-_]{35}",
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    KeyPattern {
        name: "Google OAuth Client Secret",
        pattern: r#"(?i)google.*client.{0,20}secret['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z\-_]{24}"#,
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    // Firebase
    KeyPattern {
        name: "Firebase Database URL",
        pattern: r"https://[a-z0-9-]+\.firebaseio\.com",
        severity: RuleSeverity::Medium,
        cwe_id: 200,
    },
    // Azure
    KeyPattern {
        name: "Azure Storage Account Key",
        pattern: r#"(?i)azure.*storage.*key['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z+/=]{88}"#,
        severity: RuleSeverity::Critical,
        cwe_id: 798,
    },
    KeyPattern {
        name: "Azure Client Secret",
        pattern: r#"(?i)azure.*client.{0,20}secret['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z\-_~.]{34,40}"#,
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    // Twilio
    KeyPattern {
        name: "Twilio API Key",
        pattern: r"SK[0-9a-fA-F]{32}",
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    KeyPattern {
        name: "Twilio Account SID",
        pattern: r"AC[0-9a-fA-F]{32}",
        severity: RuleSeverity::Medium,
        cwe_id: 200,
    },
    // SendGrid
    KeyPattern {
        name: "SendGrid API Key",
        pattern: r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    // Mailgun
    KeyPattern {
        name: "Mailgun API Key",
        pattern: r"key-[0-9a-zA-Z]{32}",
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    // Heroku
    KeyPattern {
        name: "Heroku API Key",
        pattern: r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    // NPM
    KeyPattern {
        name: "NPM Token",
        pattern: r"npm_[0-9a-zA-Z]{36}",
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    // AI services
    KeyPattern {
        name: "OpenAI Project API Key",
        pattern: r"sk-proj-[A-Za-z0-9_-]{40,}",
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    KeyPattern {
        name: "Anthropic API Key",
        pattern: r"sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{95}",
        severity: RuleSeverity::Critical,
        cwe_id: 798,
    },
    KeyPattern {
        name: "HuggingFace Token",
        pattern: r"hf_[A-Za-z0-9]{34}",
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    KeyPattern {
        name: "Groq API Key",
        pattern: r"gsk_[A-Za-z0-9]{52}",
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    // CI/CD
    KeyPattern {
        name: "Buildkite Token",
        pattern: r"bkua_[A-Za-z0-9]{40}",
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    KeyPattern {
        name: "CircleCI Token",
        pattern: r#"(?i)circle[_-]?token['\"]?\s*[:=]\s*['\"]?[a-f0-9]{40}"#,
        severity: RuleSeverity::High,
        cwe_id: 798,
    },
    // Messaging
    KeyPattern {
        name: "Discord Webhook",
        pattern: r"https://(?:discord|discordapp)\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,}",
        severity: RuleSeverity::High,
        cwe_id: 200,
    },
    // Generic patterns
    KeyPattern {
        name: "Generic API Key",
        pattern: r#"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z\-_]{32,}['\"]?"#,
        severity: RuleSeverity::Medium,
        cwe_id: 798,
    },
    KeyPattern {
        name: "Generic Secret",
        pattern: r#"(?i)(?:secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z\-_!@#$%^&*]{16,}['\"]?"#,
        severity: RuleSeverity::Medium,
        cwe_id: 798,
    },
    KeyPattern {
        name: "Private Key (RSA/SSH)",
        pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        severity: RuleSeverity::Critical,
        cwe_id: 798,
    },
    KeyPattern {
        name: "JWT Token",
        pattern: r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        severity: RuleSeverity::Medium,
        cwe_id: 200,
    },
];

pub struct ApiKeyDisclosure;

#[async_trait]
impl PassiveRule for ApiKeyDisclosure {
    fn id(&self) -> &str {
        "api-key-disclosure"
    }

    fn name(&self) -> &str {
        "API Key or Secret Disclosure"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        // Also check headers
        let all_text = format!(
            "{}\n{}",
            exchange.response_headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join("\n"),
            body_str
        );

        for pattern_def in KEY_PATTERNS {
            if let Ok(re) = Regex::new(pattern_def.pattern) {
                if let Some(matched) = re.find(&all_text) {
                    let evidence = matched.as_str();

                    // Redact most of the key for safety
                    let redacted = if evidence.len() > 10 {
                        format!("{}...{}", &evidence[..5], &evidence[evidence.len()-3..])
                    } else {
                        "[REDACTED]".to_string()
                    };

                    return Some(PassiveRuleResult {
                        rule_id: format!("{}-{}", self.id(), pattern_def.name.to_lowercase().replace(' ', "-")),
                        name: format!("{} Exposed", pattern_def.name),
                        severity: pattern_def.severity,
                        confidence: 90,
                        cwe_id: Some(pattern_def.cwe_id),
                        description: format!(
                            "{} found in response. This could allow unauthorized access to cloud resources or third-party services.",
                            pattern_def.name
                        ),
                        evidence: format!("Found: {}", redacted),
                        references: vec![
                            "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password".to_string(),
                            "https://cwe.mitre.org/data/definitions/798.html".to_string(),
                        ],
                    });
                }
            }
        }

        None
    }
}

pub fn load_disclosure_rules() -> Vec<Box<dyn PassiveRule + Send + Sync>> {
    vec![Box::new(ApiKeyDisclosure)]
}
