//! Passive vulnerability scanning engine.
//!
//! Analyzes every proxied response for common vulnerabilities without sending
//! additional requests. Emits standardized alerts to the findings database.

mod advanced_csp_rules;
mod disclosure_rules;
mod file_rules;
mod framework_rules;
mod infrastructure_rules;
mod injection_rules;
mod misc_rules;
mod misconfiguration_rules;
mod pii_rules;
mod rules;

use crate::domain::*;
use crate::storage::Db;
use std::sync::Arc;

pub use rules::{PassiveRule, PassiveRuleResult, RuleSeverity};

/// Passive scanning service that hooks into proxy response flow.
pub struct PassiveScanService {
    db: Arc<Db>,
    rules: Vec<Box<dyn PassiveRule + Send + Sync>>,
    enabled: bool,
}

impl PassiveScanService {
    pub fn new(db: Arc<Db>) -> Self {
        let rules = rules::load_default_rules();
        Self {
            db,
            rules,
            enabled: true,
        }
    }

    /// Analyze a captured exchange for vulnerabilities.
    /// Called automatically after each proxied response is stored.
    pub async fn scan_exchange(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
    ) -> DomainResult<Vec<PassiveRuleResult>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        // Fetch exchange from DB
        let exchange = self
            .db
            .get_exchange_for_passive_scan(project_id, exchange_id)
            .await?;

        let mut results = Vec::new();

        // Run all enabled rules
        for rule in &self.rules {
            if !rule.enabled() {
                continue;
            }

            if let Some(finding) = rule.scan(&exchange).await {
                // Store finding in alerts table (deduplicated)
                self.db
                    .insert_passive_scan_alert(project_id, exchange_id, &finding)
                    .await?;
                results.push(finding);
            }
        }

        Ok(results)
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Minimal exchange data for passive scanning.
#[derive(Debug, Clone)]
pub struct PassiveScanExchange {
    pub exchange_id: ExchangeId,
    pub method: String,
    pub url: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: Option<Vec<u8>>,
    pub status: Option<u16>,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Option<Vec<u8>>,
    pub mime: Option<String>,
}
