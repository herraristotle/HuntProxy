//! Scan policy configuration - which checks run, attack strength, thresholds.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttackStrength {
    Low,
    Medium,
    High,
    Insane,
}

impl AttackStrength {
    /// Number of payloads to try per injection point.
    pub fn payload_count(&self) -> usize {
        match self {
            AttackStrength::Low => 6,
            AttackStrength::Medium => 12,
            AttackStrength::High => 24,
            AttackStrength::Insane => 48,
        }
    }

    /// Request delay in milliseconds to avoid rate limiting.
    pub fn delay_ms(&self) -> u64 {
        match self {
            AttackStrength::Low => 500,
            AttackStrength::Medium => 200,
            AttackStrength::High => 50,
            AttackStrength::Insane => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckConfig {
    pub enabled: bool,
    pub attack_strength: AttackStrength,
    /// Minimum confidence threshold to report finding (0-100).
    pub confidence_threshold: u8,
}

impl Default for CheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            attack_strength: AttackStrength::Medium,
            confidence_threshold: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPolicy {
    pub name: String,
    pub default_config: CheckConfig,
    /// Per-check overrides.
    pub check_configs: HashMap<String, CheckConfig>,
    /// Technology stack filter (e.g., ["php", "mysql"]).
    pub tech_filter: Vec<String>,
}

impl Default for ScanPolicy {
    fn default() -> Self {
        Self {
            name: "Default".to_string(),
            default_config: CheckConfig::default(),
            check_configs: HashMap::new(),
            tech_filter: Vec::new(),
        }
    }
}

impl ScanPolicy {
    pub fn new(name: String) -> Self {
        Self {
            name,
            ..Default::default()
        }
    }

    pub fn with_attack_strength(mut self, strength: AttackStrength) -> Self {
        self.default_config.attack_strength = strength;
        self
    }

    pub fn disable_check(&mut self, check_id: &str) {
        self.check_configs
            .entry(check_id.to_string())
            .or_default()
            .enabled = false;
    }

    pub fn enable_check(&mut self, check_id: &str) {
        self.check_configs
            .entry(check_id.to_string())
            .or_default()
            .enabled = true;
    }

    pub fn set_check_strength(&mut self, check_id: &str, strength: AttackStrength) {
        self.check_configs
            .entry(check_id.to_string())
            .or_default()
            .attack_strength = strength;
    }

    pub fn is_check_enabled(&self, check_id: &str) -> bool {
        self.check_configs
            .get(check_id)
            .map(|c| c.enabled)
            .unwrap_or(self.default_config.enabled)
    }

    pub fn get_attack_strength(&self, check_id: &str) -> AttackStrength {
        self.check_configs
            .get(check_id)
            .map(|c| c.attack_strength)
            .unwrap_or(self.default_config.attack_strength)
    }

    pub fn get_confidence_threshold(&self, check_id: &str) -> u8 {
        self.check_configs
            .get(check_id)
            .map(|c| c.confidence_threshold)
            .unwrap_or(self.default_config.confidence_threshold)
    }

    /// Check if tech stack filter matches detected technologies.
    pub fn tech_matches(&self, detected_techs: &[String]) -> bool {
        if self.tech_filter.is_empty() {
            return true; // No filter = run on all
        }

        self.tech_filter.iter().any(|filter_tech| {
            detected_techs.iter().any(|detected| {
                detected
                    .to_lowercase()
                    .contains(&filter_tech.to_lowercase())
            })
        })
    }
}

/// Predefined scan policies.
#[allow(dead_code)]
pub fn default_policies() -> Vec<ScanPolicy> {
    vec![
        ScanPolicy::default(),
        ScanPolicy {
            name: "Quick".to_string(),
            default_config: CheckConfig {
                enabled: true,
                attack_strength: AttackStrength::Low,
                confidence_threshold: 70,
            },
            check_configs: HashMap::new(),
            tech_filter: Vec::new(),
        },
        ScanPolicy {
            name: "Full".to_string(),
            default_config: CheckConfig {
                enabled: true,
                attack_strength: AttackStrength::High,
                confidence_threshold: 30,
            },
            check_configs: HashMap::new(),
            tech_filter: Vec::new(),
        },
    ]
}
