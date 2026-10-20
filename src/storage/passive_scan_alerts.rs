//! Storage methods for passive scan alerts.

use crate::domain::*;
use crate::passive_scan::{PassiveRuleResult, RuleSeverity};
use crate::storage::projects::now_rfc3339;
use crate::storage::Db;
use rusqlite::params;
use sha2::{Digest, Sha256};

/// Cap on body bytes handed to passive rules; large media responses would
/// otherwise be decoded and scanned wholesale on every proxied message.
const MAX_SCAN_BODY: usize = 1024 * 1024;

impl Db {
    /// Insert finding from passive scan rule, with deduplication.
    pub async fn insert_passive_scan_alert(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
        finding: &PassiveRuleResult,
    ) -> DomainResult<Option<i64>> {
        let dedup_key = compute_dedup_key(project_id, exchange_id, &finding.rule_id);
        let severity = severity_to_string(finding.severity);
        let rule_id = finding.rule_id.clone();
        let name = finding.name.clone();
        let confidence = finding.confidence;
        let cwe_id = finding.cwe_id;
        let description = finding.description.clone();
        let evidence = finding.evidence.clone();
        let timestamp = now_rfc3339();

        self.with_conn(move |conn| {
            // Check if already exists
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM passive_scan_alerts WHERE project_id=?1 AND dedup_key=?2)",
                    params![project_id.get(), dedup_key],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;

            if exists {
                return Ok(None);
            }

            conn.execute(
                "INSERT INTO passive_scan_alerts
                 (project_id, exchange_id, rule_id, name, severity, confidence, cwe_id, description, evidence, dedup_key, created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    project_id.get(),
                    exchange_id.get(),
                    rule_id,
                    name,
                    severity,
                    confidence,
                    cwe_id,
                    description,
                    evidence,
                    dedup_key,
                    timestamp
                ],
            )
            .map_err(storage_error)?;

            Ok(Some(conn.last_insert_rowid()))
        })
        .await
    }

    /// Fetch exchange data needed for passive scanning. Headers and bodies
    /// live in side tables, so they are loaded through the raw loaders (scan
    /// runs host-side; findings store redacted evidence only).
    pub async fn get_exchange_for_passive_scan(
        &self,
        project_id: ProjectId,
        exchange_id: ExchangeId,
    ) -> DomainResult<crate::passive_scan::PassiveScanExchange> {
        let (method, scheme, authority, path, query, status, mime) = self
            .with_conn(move |conn| {
                conn.query_row(
                    "SELECT method, scheme, authority, path, query, status_code, mime
                     FROM exchanges
                     WHERE project_id=?1 AND exchange_id=?2",
                    params![project_id.get(), exchange_id.get()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, Option<u16>>(5)?,
                            row.get::<_, Option<String>>(6)?,
                        ))
                    },
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => DomainError::not_found(format!(
                        "exchange {}/{}",
                        project_id.get(),
                        exchange_id.get()
                    )),
                    other => DomainError::new(ErrorCode::StorageError, other.to_string()),
                })
            })
            .await?;

        let url = format!(
            "{}://{}{}{}",
            scheme,
            authority,
            path,
            query.map(|q| format!("?{q}")).unwrap_or_default()
        );

        let mut request_body: Option<Vec<u8>> = self
            .load_raw_body(project_id, exchange_id, MessageSide::Request)
            .await?;
        if let Some(body) = &mut request_body {
            body.truncate(body.len().min(MAX_SCAN_BODY));
        }
        let mut response_body: Option<Vec<u8>> = self
            .load_raw_body(project_id, exchange_id, MessageSide::Response)
            .await?;
        if let Some(body) = &mut response_body {
            body.truncate(body.len().min(MAX_SCAN_BODY));
        }

        let request_headers: Vec<(String, String)> = self
            .load_raw_headers(project_id, exchange_id, MessageSide::Request)
            .await?
            .into_iter()
            .map(|h| (h.name, String::from_utf8_lossy(&h.value).into_owned()))
            .collect();
        let response_headers: Vec<(String, String)> = self
            .load_raw_headers(project_id, exchange_id, MessageSide::Response)
            .await?
            .into_iter()
            .map(|h| (h.name, String::from_utf8_lossy(&h.value).into_owned()))
            .collect();

        Ok(crate::passive_scan::PassiveScanExchange {
            exchange_id,
            method,
            url,
            request_headers,
            request_body,
            status,
            response_headers,
            response_body,
            mime,
        })
    }

    pub async fn list_passive_scan_alerts(
        &self,
        project_id: ProjectId,
    ) -> DomainResult<Vec<PassiveScanAlert>> {
        self.get_project(project_id).await?;
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, exchange_id, rule_id, name, severity, confidence, cwe_id, description, evidence, created_at
                     FROM passive_scan_alerts
                     WHERE project_id=?1
                     ORDER BY id DESC",
                )
                .map_err(storage_error)?;

            let rows = stmt
                .query_map(params![project_id.get()], |row| {
                    Ok(PassiveScanAlert {
                        id: row.get(0)?,
                        project_id,
                        exchange_id: ExchangeId(row.get(1)?),
                        rule_id: row.get(2)?,
                        name: row.get(3)?,
                        severity: parse_severity(&row.get::<_, String>(4)?),
                        confidence: row.get(5)?,
                        cwe_id: row.get(6)?,
                        description: row.get(7)?,
                        evidence: row.get(8)?,
                        created_at: row.get(9)?,
                    })
                })
                .map_err(storage_error)?;

            rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)
        })
        .await
    }

    pub async fn delete_passive_scan_alert(
        &self,
        project_id: ProjectId,
        alert_id: i64,
    ) -> DomainResult<()> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM passive_scan_alerts WHERE project_id=?1 AND id=?2",
                    params![project_id.get(), alert_id],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Err(DomainError::not_found("alert"));
            }
            Ok(())
        })
        .await
    }
}

fn compute_dedup_key(project_id: ProjectId, exchange_id: ExchangeId, rule_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(project_id.get().to_le_bytes());
    hasher.update(exchange_id.get().to_le_bytes());
    hasher.update(rule_id.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn severity_to_string(severity: RuleSeverity) -> String {
    match severity {
        RuleSeverity::Info => "info".to_string(),
        RuleSeverity::Low => "low".to_string(),
        RuleSeverity::Medium => "medium".to_string(),
        RuleSeverity::High => "high".to_string(),
        RuleSeverity::Critical => "critical".to_string(),
    }
}

fn parse_severity(s: &str) -> RuleSeverity {
    match s {
        "info" => RuleSeverity::Info,
        "low" => RuleSeverity::Low,
        "medium" => RuleSeverity::Medium,
        "high" => RuleSeverity::High,
        "critical" => RuleSeverity::Critical,
        _ => RuleSeverity::Info,
    }
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

#[derive(Debug, Clone)]
pub struct PassiveScanAlert {
    pub id: i64,
    pub project_id: ProjectId,
    pub exchange_id: ExchangeId,
    pub rule_id: String,
    pub name: String,
    pub severity: RuleSeverity,
    pub confidence: u8,
    pub cwe_id: Option<u32>,
    pub description: String,
    pub evidence: String,
    pub created_at: String,
}
