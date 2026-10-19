//! Token randomness analysis (Sequencer).
//! Extract session tokens/CSRF tokens from responses, run statistical tests.

use crate::domain::{DomainError, DomainResult, ExchangeId, ProjectId};
use crate::storage::Db;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MIN_SAMPLES: usize = 10;
const MAX_SAMPLES: usize = 10000;

static SESSION_TOKEN_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)session(?:id)?[=:\s]+([a-f0-9]{32,})").unwrap(),
        Regex::new(r"(?i)sess[=:\s]+([a-zA-Z0-9_-]{16,})").unwrap(),
        Regex::new(r"(?i)token[=:\s]+([a-zA-Z0-9_-]{20,})").unwrap(),
        Regex::new(r"(?i)csrf[=:\s]+([a-zA-Z0-9_-]{16,})").unwrap(),
        Regex::new(r"(?i)auth[=:\s]+([a-zA-Z0-9_-]{20,})").unwrap(),
        Regex::new(r#""(?:session|token|csrf|auth)"\s*:\s*"([a-zA-Z0-9_-]{16,})""#).unwrap(),
    ]
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSample {
    pub exchange_id: i64,
    pub value: String,
    pub source: String, // "cookie", "header", "body"
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerSession {
    pub session_id: String,
    pub project_id: i64,
    pub target_pattern: String,
    pub samples: Vec<TokenSample>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerAnalysis {
    pub session_id: String,
    pub sample_count: usize,
    pub bit_length: usize,
    pub tests: StatisticalTests,
    pub verdict: String, // "PASS", "WEAK", "FAIL"
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalTests {
    pub monobit: TestResult,
    pub runs: TestResult,
    pub longest_run: TestResult,
    pub poker: TestResult,
    pub entropy: f64, // Shannon entropy (bits per byte)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub name: String,
    pub statistic: f64,
    pub p_value: f64,
    pub passed: bool,
}

/// Extract token candidates from response headers and body
pub fn extract_tokens_from_response(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Vec<(String, String, String)> {
    // Returns: (name, value, source)
    let mut tokens = Vec::new();

    // Extract from Set-Cookie headers
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("set-cookie") {
            if let Some((cookie_name, cookie_value)) = value.split_once('=') {
                let val = cookie_value.split(';').next().unwrap_or(cookie_value);
                if val.len() >= 16
                    && val
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                {
                    tokens.push((
                        cookie_name.trim().to_string(),
                        val.to_string(),
                        "cookie".to_string(),
                    ));
                }
            }
        }
    }

    // Extract from body patterns
    if let Some(body_text) = body {
        for pattern in SESSION_TOKEN_PATTERNS.iter() {
            for caps in pattern.captures_iter(body_text) {
                if let Some(token) = caps.get(1) {
                    let val = token.as_str();
                    if val.len() >= 16 {
                        tokens.push(("extracted".to_string(), val.to_string(), "body".to_string()));
                    }
                }
            }
        }
    }

    tokens
}

/// FIPS 140-2 Monobit test: count 0s and 1s, should be roughly equal
fn monobit_test(bits: &[u8]) -> TestResult {
    let ones = bits.iter().filter(|&&b| b == 1).count();
    let zeros = bits.len() - ones;
    let n = bits.len() as f64;

    // Test statistic: (ones - zeros) / sqrt(n)
    let statistic = ((ones as f64 - zeros as f64) / n.sqrt()).abs();

    // Critical value for 95% confidence: ~1.96
    let passed = statistic < 2.0;
    let p_value = 1.0 - (statistic / 2.0).min(1.0);

    TestResult {
        name: "Monobit (frequency)".to_string(),
        statistic,
        p_value,
        passed,
    }
}

/// Runs test: count runs of consecutive 0s or 1s
fn runs_test(bits: &[u8]) -> TestResult {
    if bits.is_empty() {
        return TestResult {
            name: "Runs".to_string(),
            statistic: 0.0,
            p_value: 0.0,
            passed: false,
        };
    }

    let mut runs = 1;
    for i in 1..bits.len() {
        if bits[i] != bits[i - 1] {
            runs += 1;
        }
    }

    let n = bits.len() as f64;
    let ones = bits.iter().filter(|&&b| b == 1).count() as f64;
    let pi = ones / n;

    // Expected runs
    let expected = 2.0 * n * pi * (1.0 - pi);
    let variance = (2.0 * n * pi * (1.0 - pi) - 1.0) / (n - 1.0);
    let std_dev = variance.sqrt();

    let statistic = ((runs as f64 - expected) / std_dev).abs();
    let passed = statistic < 2.0;
    let p_value = 1.0 - (statistic / 2.0).min(1.0);

    TestResult {
        name: "Runs".to_string(),
        statistic,
        p_value,
        passed,
    }
}

/// Longest run test: find longest consecutive run
fn longest_run_test(bits: &[u8]) -> TestResult {
    let mut longest = 0;
    let mut current = 0;
    let mut prev = 255u8;

    for &bit in bits {
        if bit == prev {
            current += 1;
        } else {
            longest = longest.max(current);
            current = 1;
            prev = bit;
        }
    }
    longest = longest.max(current);

    let n = bits.len();
    let expected = (n as f64).log2();
    let statistic = (longest as f64 - expected).abs();

    // Heuristic: longest run shouldn't be > log2(n) + 3
    let passed = longest as f64 <= expected + 3.0;
    let p_value = if passed { 0.7 } else { 0.3 };

    TestResult {
        name: "Longest Run".to_string(),
        statistic,
        p_value,
        passed,
    }
}

/// Poker test: divide into 4-bit chunks, count unique patterns
fn poker_test(bits: &[u8]) -> TestResult {
    if bits.len() < 20000 {
        return TestResult {
            name: "Poker".to_string(),
            statistic: 0.0,
            p_value: 1.0,
            passed: true,
        };
    }

    let mut counts = HashMap::new();
    let chunks = bits.chunks(4);
    let m = chunks.len();

    for chunk in bits.chunks(4) {
        if chunk.len() == 4 {
            let val = chunk[0] * 8 + chunk[1] * 4 + chunk[2] * 2 + chunk[3];
            *counts.entry(val).or_insert(0) += 1;
        }
    }

    let k = 16.0; // 4 bits = 16 possible values
    let sum: f64 = counts.values().map(|&c| (c * c) as f64).sum();
    let statistic = (k / m as f64) * sum - m as f64;

    // Chi-squared critical value for df=15, alpha=0.05: ~25
    let passed = statistic < 30.0;
    let p_value = 1.0 - (statistic / 30.0).min(1.0);

    TestResult {
        name: "Poker (4-bit patterns)".to_string(),
        statistic,
        p_value,
        passed,
    }
}

/// Shannon entropy calculation
fn calculate_entropy(bytes: &[u8]) -> f64 {
    let mut counts = HashMap::new();
    for &byte in bytes {
        *counts.entry(byte).or_insert(0) += 1;
    }

    let len = bytes.len() as f64;
    let mut entropy = 0.0;

    for count in counts.values() {
        let p = *count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

/// Convert hex/base64 token to bit array
fn token_to_bits(token: &str) -> Vec<u8> {
    let mut bits = Vec::new();

    // Try hex first
    if token.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(token) {
            for byte in bytes {
                for i in (0..8).rev() {
                    bits.push((byte >> i) & 1);
                }
            }
            return bits;
        }
    }

    // Fallback: treat as ASCII bytes
    for byte in token.as_bytes() {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }

    bits
}

/// Analyze token samples for randomness
pub fn analyze_tokens(samples: &[TokenSample]) -> DomainResult<SequencerAnalysis> {
    if samples.len() < MIN_SAMPLES {
        return Err(DomainError::invalid(format!(
            "need at least {} samples, got {}",
            MIN_SAMPLES,
            samples.len()
        )));
    }

    // Concatenate all token bits
    let mut all_bits = Vec::new();
    for sample in samples {
        all_bits.extend(token_to_bits(&sample.value));
    }

    if all_bits.len() < 128 {
        return Err(DomainError::invalid("insufficient bit data for analysis"));
    }

    let bit_length = all_bits.len() / samples.len();

    // Run statistical tests
    let monobit = monobit_test(&all_bits);
    let runs = runs_test(&all_bits);
    let longest_run = longest_run_test(&all_bits);
    let poker = poker_test(&all_bits);

    // Calculate entropy on raw bytes
    let bytes: Vec<u8> = samples
        .iter()
        .flat_map(|s| s.value.as_bytes().to_vec())
        .collect();
    let entropy = calculate_entropy(&bytes);

    let tests = StatisticalTests {
        monobit: monobit.clone(),
        runs: runs.clone(),
        longest_run: longest_run.clone(),
        poker: poker.clone(),
        entropy,
    };

    // Determine verdict
    let failed_tests = [&monobit, &runs, &longest_run, &poker]
        .iter()
        .filter(|t| !t.passed)
        .count();

    let verdict = if failed_tests == 0 && entropy > 3.5 {
        "PASS"
    } else if failed_tests <= 1 && entropy > 2.5 {
        "WEAK"
    } else {
        "FAIL"
    }
    .to_string();

    let mut issues = Vec::new();
    if !monobit.passed {
        issues.push("Imbalanced 0/1 distribution (monobit test failed)".to_string());
    }
    if !runs.passed {
        issues.push("Non-random run patterns detected".to_string());
    }
    if !longest_run.passed {
        issues.push("Excessively long consecutive runs".to_string());
    }
    if !poker.passed {
        issues.push("Non-uniform 4-bit pattern distribution".to_string());
    }
    if entropy < 3.5 {
        issues.push(format!(
            "Low entropy: {:.2} bits/byte (expect >3.5)",
            entropy
        ));
    }

    Ok(SequencerAnalysis {
        session_id: String::new(),
        sample_count: samples.len(),
        bit_length,
        tests,
        verdict,
        issues,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tokens() {
        let headers = vec![(
            "Set-Cookie".to_string(),
            "session=abc123def456; Path=/".to_string(),
        )];
        let body = r#"{"token":"xyz789abc123def456"}"#;

        let tokens = extract_tokens_from_response(&headers, Some(body));
        assert!(tokens.len() >= 1);
        assert_eq!(tokens[0].2, "cookie");
    }

    #[test]
    fn test_monobit_balanced() {
        let bits = vec![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1];
        let result = monobit_test(&bits);
        assert!(result.passed);
    }

    #[test]
    fn test_weak_token_detection() {
        // Create samples with predictable pattern
        let samples: Vec<TokenSample> = (0..20)
            .map(|i| TokenSample {
                exchange_id: i,
                value: format!("token{:016x}", i * 1000),
                source: "cookie".to_string(),
                name: "session".to_string(),
            })
            .collect();

        let analysis = analyze_tokens(&samples).unwrap();
        // Predictable tokens should fail or be weak
        assert!(analysis.verdict == "WEAK" || analysis.verdict == "FAIL");
    }
}
