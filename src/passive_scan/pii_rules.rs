//! PII (Personally Identifiable Information) disclosure detection rules.

use super::{PassiveRule, PassiveRuleResult, PassiveScanExchange, RuleSeverity};
use async_trait::async_trait;
use regex::Regex;

// ============================================================================
// Credit Card Disclosure
// ============================================================================

pub struct CreditCardDisclosure;

#[async_trait]
impl PassiveRule for CreditCardDisclosure {
    fn id(&self) -> &str {
        "credit-card-disclosure"
    }

    fn name(&self) -> &str {
        "Credit Card Number Disclosure"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        // Luhn algorithm validation for credit cards
        let card_pattern = Regex::new(r"\b(?:\d[ -]*?){13,19}\b").ok()?;

        for capture in card_pattern.find_iter(&body_str) {
            let card_str = capture.as_str().replace([' ', '-'], "");

            if card_str.len() >= 13 && card_str.len() <= 19 && is_luhn_valid(&card_str) {
                let redacted = format!("{}...{}", &card_str[..4], &card_str[card_str.len() - 4..]);

                return Some(PassiveRuleResult {
                    rule_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity: RuleSeverity::Critical,
                    confidence: 90,
                    cwe_id: Some(359), // CWE-359: Exposure of Private Information
                    description: "Credit card number exposed in response. PCI-DSS violation."
                        .to_string(),
                    evidence: format!("Card number: {redacted}"),
                    references: vec!["https://www.pcisecuritystandards.org/".to_string()],
                });
            }
        }

        None
    }
}

fn is_luhn_valid(card: &str) -> bool {
    let digits: Vec<u32> = card.chars().filter_map(|c| c.to_digit(10)).collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let checksum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(idx, &digit)| {
            if idx % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                digit
            }
        })
        .sum();

    checksum % 10 == 0
}

// ============================================================================
// SSN Disclosure
// ============================================================================

pub struct SsnDisclosure;

#[async_trait]
impl PassiveRule for SsnDisclosure {
    fn id(&self) -> &str {
        "ssn-disclosure"
    }

    fn name(&self) -> &str {
        "Social Security Number Disclosure"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        // SSN patterns: 123-45-6789 or 123456789
        let ssn_pattern = Regex::new(r"\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b").ok()?;

        for capture in ssn_pattern.find_iter(&body_str) {
            let ssn = capture.as_str();

            // Basic validation (not 000-xx-xxxx, not xxx-00-xxxx, not in 900-999 range)
            let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();

            if digits.len() == 9 {
                let area: u32 = digits[0..3].parse().unwrap_or(0);
                let group: u32 = digits[3..5].parse().unwrap_or(0);

                if area > 0 && area < 900 && group > 0 {
                    let redacted = format!("***-**-{}", &digits[5..9]);

                    return Some(PassiveRuleResult {
                        rule_id: self.id().to_string(),
                        name: self.name().to_string(),
                        severity: RuleSeverity::Critical,
                        confidence: 85,
                        cwe_id: Some(359),
                        description:
                            "Social Security Number exposed in response. Severe privacy violation."
                                .to_string(),
                        evidence: format!("SSN: {redacted}"),
                        references: vec!["https://www.ssa.gov/".to_string()],
                    });
                }
            }
        }

        None
    }
}

// ============================================================================
// Email Disclosure
// ============================================================================

pub struct EmailDisclosure;

#[async_trait]
impl PassiveRule for EmailDisclosure {
    fn id(&self) -> &str {
        "email-disclosure"
    }

    fn name(&self) -> &str {
        "Email Address Disclosure"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        // Email pattern
        let email_pattern =
            Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").ok()?;

        let mut emails = Vec::new();
        for capture in email_pattern.find_iter(&body_str).take(5) {
            let email = capture.as_str();

            // Skip common false positives
            if email.contains("example.com") || email.contains("test.com") {
                continue;
            }

            emails.push(email.to_string());
        }

        if !emails.is_empty() {
            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Low,
                confidence: 70,
                cwe_id: Some(200), // CWE-200: Information Exposure
                description: format!(
                    "Email addresses exposed in response ({} found). May enable spam or phishing.",
                    emails.len()
                ),
                evidence: format!("Emails: {}", emails.join(", ")),
                references: vec![],
            });
        }

        None
    }
}

// ============================================================================
// Password Hash Disclosure
// ============================================================================

pub struct HashDisclosure;

#[async_trait]
impl PassiveRule for HashDisclosure {
    fn id(&self) -> &str {
        "hash-disclosure"
    }

    fn name(&self) -> &str {
        "Password Hash Disclosure"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        let hash_patterns = [
            (
                r"\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}",
                "bcrypt",
                RuleSeverity::High,
            ),
            (r"\{SHA\}[A-Za-z0-9+/=]{27,}", "SHA1", RuleSeverity::Medium),
            (
                r"\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}",
                "MD5",
                RuleSeverity::Medium,
            ),
            (
                r"\$6\$[./A-Za-z0-9]{16}\$[./A-Za-z0-9]{86}",
                "SHA512",
                RuleSeverity::High,
            ),
            (r"\b[a-f0-9]{32}\b", "MD5 (hex)", RuleSeverity::Low),
            (r"\b[a-f0-9]{40}\b", "SHA1 (hex)", RuleSeverity::Low),
            (r"\b[a-f0-9]{64}\b", "SHA256 (hex)", RuleSeverity::Medium),
        ];

        for (pattern, hash_type, severity) in &hash_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(matched) = re.find(&body_str) {
                    let hash = matched.as_str();
                    let redacted = format!("{}...{}", &hash[..8], &hash[hash.len() - 8..]);

                    return Some(PassiveRuleResult {
                        rule_id: format!("{}-{}", self.id(), hash_type.to_lowercase().replace(' ', "-")),
                        name: format!("{hash_type} Hash Exposed"),
                        severity: *severity,
                        confidence: 80,
                        cwe_id: Some(256), // CWE-256: Unprotected Storage of Credentials
                        description: format!("{hash_type} password hash exposed. May enable offline cracking."),
                        evidence: format!("Hash: {redacted}"),
                        references: vec![
                            "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html".to_string(),
                        ],
                    });
                }
            }
        }

        None
    }
}

// ============================================================================
// Private IP Disclosure
// ============================================================================

pub struct PrivateIpDisclosure;

#[async_trait]
impl PassiveRule for PrivateIpDisclosure {
    fn id(&self) -> &str {
        "private-ip-disclosure"
    }

    fn name(&self) -> &str {
        "Private IP Address Disclosure"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        let private_ip_pattern = Regex::new(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
        ).ok()?;

        if let Some(matched) = private_ip_pattern.find(&body_str) {
            let ip = matched.as_str();

            return Some(PassiveRuleResult {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: RuleSeverity::Low,
                confidence: 85,
                cwe_id: Some(200),
                description: "Private IP address exposed. May reveal internal network topology."
                    .to_string(),
                evidence: format!("IP: {ip}"),
                references: vec![],
            });
        }

        None
    }
}

// ============================================================================
// Database Connection String Disclosure
// ============================================================================

pub struct DbConnectionDisclosure;

#[async_trait]
impl PassiveRule for DbConnectionDisclosure {
    fn id(&self) -> &str {
        "db-connection-disclosure"
    }

    fn name(&self) -> &str {
        "Database Connection String Disclosure"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let body = exchange.response_body.as_ref()?;
        let body_str = String::from_utf8_lossy(body);

        let db_patterns = [
            (r#"(?i)mongodb://[^/\s]+/[^\s"'<>]+"#, "MongoDB"),
            (r#"(?i)mysql://[^/\s]+:[^@\s]+@[^/\s]+/[^\s"'<>]+"#, "MySQL"),
            (
                r#"(?i)postgres(?:ql)?://[^/\s]+:[^@\s]+@[^/\s]+/[^\s"'<>]+"#,
                "PostgreSQL",
            ),
            (r"(?i)Server=[^;]+;Database=[^;]+;", "SQL Server"),
            (r#"(?i)redis://[^/\s]+/[^\s"'<>]+"#, "Redis"),
        ];

        for (pattern, db_type) in &db_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(matched) = re.find(&body_str) {
                    let conn_str = matched.as_str();
                    let redacted = if conn_str.len() > 30 {
                        format!("{}...", &conn_str[..30])
                    } else {
                        "[REDACTED]".to_string()
                    };

                    return Some(PassiveRuleResult {
                        rule_id: format!("{}-{}", self.id(), db_type.to_lowercase()),
                        name: format!("{db_type} Connection String Exposed"),
                        severity: RuleSeverity::Critical,
                        confidence: 95,
                        cwe_id: Some(798), // CWE-798: Use of Hard-coded Credentials
                        description: format!(
                            "{db_type} database connection string with credentials exposed."
                        ),
                        evidence: format!("Connection: {redacted}"),
                        references: vec![],
                    });
                }
            }
        }

        None
    }
}

pub fn load_pii_rules() -> Vec<Box<dyn PassiveRule + Send + Sync>> {
    vec![
        Box::new(CreditCardDisclosure),
        Box::new(SsnDisclosure),
        Box::new(EmailDisclosure),
        Box::new(HashDisclosure),
        Box::new(PrivateIpDisclosure),
        Box::new(DbConnectionDisclosure),
    ]
}
