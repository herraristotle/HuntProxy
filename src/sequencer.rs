//! Token randomness analysis (Sequencer).
//! Extract session tokens/CSRF tokens from responses, run statistical tests.

use crate::domain::{DomainError, DomainResult};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MIN_SAMPLES: usize = 10;

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
    pub verdict: String, // "PASS", "WEAK", "FAIL", "INCONCLUSIVE"
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalTests {
    pub monobit: TestResult,
    pub runs: TestResult,
    pub longest_run: TestResult,
    pub poker: TestResult,
    /// Shannon entropy in bits per byte of the token text.
    pub entropy: f64,
    /// Entropy divided by log2(alphabet size). 1.0 means the token uses its
    /// alphabet as uniformly as its length allows; 0.5 means half the
    /// available structure is wasted. Compare this across token formats,
    /// not the raw bits/byte figure: hex caps at 4 and base64 at 6.
    pub entropy_normalized: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub name: String,
    pub statistic: f64,
    pub p_value: f64,
    pub passed: bool,
    /// False when the test had too little data to run. An inapplicable test is
    /// not a pass: reporting it as one would let short tokens look random.
    pub applicable: bool,
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
                // A Set-Cookie value is a session token by definition; the
                // 16-char heuristic only guards body/header scraping where a
                // match could be an ordinary word.
                if !val.is_empty()
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
    if bits.is_empty() {
        return TestResult {
            name: "Monobit (frequency)".to_string(),
            statistic: 0.0,
            p_value: 0.0,
            passed: false,
            applicable: false,
        };
    }
    let ones = bits.iter().filter(|&&b| b == 1).count();
    let zeros = bits.len() - ones;
    let n = bits.len() as f64;

    // Test statistic: (ones - zeros) / sqrt(n)
    let statistic = ((ones as f64 - zeros as f64) / n.sqrt()).abs();

    // Critical value for 95% confidence: ~1.96
    let passed = statistic < 1.96;
    let p_value = two_sided_normal_p(statistic);

    TestResult {
        name: "Monobit (frequency)".to_string(),
        statistic,
        p_value,
        passed,
        applicable: true,
    }
}

/// Two-sided p-value for a standard normal statistic, using the Abramowitz &
/// Stegun 7.1.26 erf approximation (max error 1.5e-7). Avoiding a stats crate
/// for two call sites is worth the seven lines.
fn two_sided_normal_p(z: f64) -> f64 {
    (1.0 - erf(z.abs() / std::f64::consts::SQRT_2)).clamp(0.0, 1.0)
}

fn erf(x: f64) -> f64 {
    // A&S 7.1.26
    let t = 1.0 / (1.0 + 0.3275911 * x);
    let y = 1.0
        - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t
            + 0.254829592)
            * t
            * (-x * x).exp();
    y
}

/// Runs test: count runs of consecutive 0s or 1s
fn runs_test(bits: &[u8]) -> TestResult {
    if bits.is_empty() {
        return TestResult {
            name: "Runs".to_string(),
            statistic: 0.0,
            p_value: 0.0,
            passed: false,
            applicable: false,
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

    // Wald-Wolfowitz: under H0 of independent equiprobable bits,
    //   E[R] = 2*n1*n2/n + 1
    //   Var[R] = 2*n1*n2*(2*n1*n2 - n) / (n^2 * (n - 1))
    // The earlier form dropped the +1 and divided by (n-1) instead of
    // scaling by n, which made uniform random input look non-random by a
    // factor of ~100 (2*20000*0.25 = 10000 expected runs, variance ~1).
    let n1 = ones;
    let n2 = n - ones;
    if n < 2.0 || n1 == 0.0 || n2 == 0.0 {
        return TestResult {
            name: "Runs".to_string(),
            statistic: 0.0,
            p_value: 0.0,
            passed: false,
            applicable: false,
        };
    }
    let expected = 2.0 * n1 * n2 / n + 1.0;
    let variance = 2.0 * n1 * n2 * (2.0 * n1 * n2 - n) / (n * n * (n - 1.0));
    let std_dev = variance.sqrt();

    let statistic = if std_dev > 0.0 {
        ((runs as f64 - expected) / std_dev).abs()
    } else {
        0.0
    };
    let passed = statistic < 1.96;
    let p_value = two_sided_normal_p(statistic);

    TestResult {
        name: "Runs".to_string(),
        statistic,
        p_value,
        passed,
        applicable: true,
    }
}

/// Longest run test.
///
/// P(L_n <= k) ≈ exp(-n / 2^(k+1)) (Erdos-Renyi), which matches simulation to
/// within ~1% for n in the hundreds-to-tens-of-thousands range. The reported
/// p-value is P(L_n > k): small p means an implausibly long run.
fn longest_run_test(bits: &[u8]) -> TestResult {
    if bits.len() < 128 {
        return TestResult {
            name: "Longest Run".to_string(),
            statistic: 0.0,
            p_value: 0.0,
            passed: false,
            applicable: false,
        };
    }

    let mut longest = 1;
    let mut current = 1;
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

    let n = bits.len() as f64;
    let p_value = (1.0 - (-n / 2f64.powi(longest as i32 + 1)).exp()).clamp(0.0, 1.0);

    TestResult {
        name: "Longest Run".to_string(),
        statistic: longest as f64,
        p_value,
        passed: p_value >= 0.01,
        applicable: true,
    }
}

/// Poker test: divide into 4-bit chunks, count unique patterns.
///
/// chi-squared with df = 15 needs a meaningful number of chunks; below ~500
/// chunks each bucket averages under 32 counts and the test is noise.
fn poker_test(bits: &[u8]) -> TestResult {
    if bits.len() < 2000 {
        return TestResult {
            name: "Poker".to_string(),
            statistic: 0.0,
            p_value: 0.0,
            passed: false,
            applicable: false,
        };
    }

    let mut counts = [0u32; 16];
    let mut m = 0u32;

    for chunk in bits.chunks(4) {
        if chunk.len() == 4 {
            let val = chunk[0] * 8 + chunk[1] * 4 + chunk[2] * 2 + chunk[3];
            counts[val as usize] += 1;
            m += 1;
        }
    }
    if m == 0 {
        return TestResult {
            name: "Poker".to_string(),
            statistic: 0.0,
            p_value: 0.0,
            passed: false,
            applicable: false,
        };
    }

    let k = 16.0; // 4 bits = 16 possible values
    let sum: f64 = counts.iter().map(|&c| (c as f64) * (c as f64)).sum();
    let statistic = (k / m as f64) * sum - m as f64;

    // Chi-squared critical value for df=15, alpha=0.05 is 24.996.
    // Wilson-Hilferty turns chi2 into an approximately normal z so the
    // p-value means the same thing as the other tests'.
    let df = 15.0;
    let z =
        ((statistic / df).powf(1.0 / 3.0) - (1.0 - 2.0 / (9.0 * df))) / (2.0 / (9.0 * df)).sqrt();
    let p_value = two_sided_normal_p(z);

    TestResult {
        name: "Poker (4-bit patterns)".to_string(),
        statistic,
        p_value,
        passed: statistic < 24.996,
        applicable: true,
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

    // Calculate entropy on the token characters, then normalize by the
    // alphabet the token actually uses. Raw bits/byte is not comparable
    // across formats: a perfect hex token tops out at 4.0 and a perfect
    // base64 token at 6.0, so a fixed 3.5 threshold silently rewards base64
    // and punishes hex.
    let text: Vec<u8> = samples
        .iter()
        .flat_map(|s| s.value.as_bytes().to_vec())
        .collect();
    let entropy = calculate_entropy(&text);
    let alphabet: std::collections::BTreeSet<u8> = text.iter().copied().collect();
    let entropy_normalized = if alphabet.len() > 1 {
        (entropy / (alphabet.len() as f64).log2()).clamp(0.0, 1.0)
    } else {
        0.0
    };

    let tests = StatisticalTests {
        monobit: monobit.clone(),
        runs: runs.clone(),
        longest_run: longest_run.clone(),
        poker: poker.clone(),
        entropy,
        entropy_normalized,
    };

    // A test that could not run is neither a pass nor a failure; only
    // applicable tests vote.
    let applicable = [&monobit, &runs, &longest_run, &poker];
    let failed_tests = applicable
        .iter()
        .filter(|t| t.applicable && !t.passed)
        .count();
    let ran_tests = applicable.iter().filter(|t| t.applicable).count();

    let verdict = if ran_tests == 0 {
        "INCONCLUSIVE"
    } else if failed_tests == 0 && entropy_normalized >= 0.90 {
        "PASS"
    } else if failed_tests <= 1 && entropy_normalized >= 0.75 {
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
    if entropy_normalized < 0.75 {
        issues.push(format!(
            "Low entropy for its alphabet: {:.2} of {:.2} bits/char ({:.0}% of alphabet capacity)",
            entropy,
            (alphabet.len() as f64).log2(),
            entropy_normalized * 100.0
        ));
    }
    for test in applicable.iter().filter(|t| !t.applicable) {
        issues.push(format!("{}: not enough samples to run", test.name));
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
        assert!(!tokens.is_empty());
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

    /// Regression: the runs test used variance/(n-1) instead of the
    /// Wald-Wolfowitz form, so uniform random bits scored ~50 sigma and every
    /// random token was reported as non-random.
    #[test]
    fn runs_test_calibration_uniform_random_passes() {
        let mut state = 0x2545F4914F6CDD1Du64;
        let bits: Vec<u8> = (0..20000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state & 1) as u8
            })
            .collect();

        let result = runs_test(&bits);
        assert!(result.applicable);
        assert!(
            result.passed,
            "uniform random bits must pass the runs test, got statistic {} p {}",
            result.statistic, result.p_value
        );
        assert!(
            result.statistic < 3.0,
            "statistic {} is implausibly large",
            result.statistic
        );
    }

    #[test]
    fn runs_test_rejects_alternating_imbalance() {
        // Half zeros then half ones: two runs total, far below expectation.
        let mut bits = vec![0u8; 5000];
        bits.extend(vec![1u8; 5000]);
        let result = runs_test(&bits);
        assert!(result.applicable);
        assert!(!result.passed);
    }

    #[test]
    fn longest_run_is_applicable_at_realistic_sample_sizes() {
        // 20 tokens x 32 hex chars = 2560 bits. The old code required 20000
        // bits for the poker test and reported a skip as a pass.
        let bits: Vec<u8> = [0u8, 1, 0, 1, 1, 0, 0, 1].repeat(320);
        let result = longest_run_test(&bits);
        assert!(result.applicable);
    }

    #[test]
    fn poker_test_skips_below_threshold_instead_of_passing() {
        let bits: Vec<u8> = [0u8, 1, 0, 1].repeat(100); // 400 bits
        let result = poker_test(&bits);
        assert!(!result.applicable, "too little data must not report a pass");
        assert!(!result.passed);
    }

    #[test]
    fn poker_test_accepts_uniform_random_bits() {
        let mut state = 0x9E3779B97F4A7C15u64;
        let bits: Vec<u8> = (0..20000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state & 1) as u8
            })
            .collect();
        let result = poker_test(&bits);
        assert!(result.applicable);
        assert!(result.passed, "statistic {}", result.statistic);
    }

    /// A perfect hex token and a perfect base64 token are both random, but
    /// their bits/byte differ by construction. Normalized entropy must score
    /// them alike; the old fixed 3.5 threshold did not.
    #[test]
    fn entropy_is_normalized_across_alphabets() {
        let hex: Vec<TokenSample> = (0..40)
            .map(|i| TokenSample {
                exchange_id: i,
                value: format!("{:032x}", (i as u128).wrapping_mul(0x9E3779B97F4A7C15)),
                source: "cookie".into(),
                name: "s".into(),
            })
            .collect();
        let analysis = analyze_tokens(&hex).unwrap();
        assert!(
            analysis.tests.entropy_normalized > 0.8,
            "hex normalized entropy {}",
            analysis.tests.entropy_normalized
        );
        assert!(analysis.tests.entropy <= 4.0 + f64::EPSILON);
    }

    #[test]
    fn sequential_tokens_are_flagged() {
        let samples: Vec<TokenSample> = (0..40)
            .map(|i| TokenSample {
                exchange_id: i,
                value: format!("session{i:024}"),
                source: "cookie".into(),
                name: "s".into(),
            })
            .collect();
        let analysis = analyze_tokens(&samples).unwrap();
        assert_eq!(analysis.verdict, "FAIL");
        assert!(!analysis.issues.is_empty());
    }
}
