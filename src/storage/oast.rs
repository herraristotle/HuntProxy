//! OAST session, label, and interaction persistence (project-scoped).

use crate::domain::{DomainError, DomainResult, ErrorCode};
use crate::storage::projects::{now_rfc3339, parse_time};
use crate::storage::Db;
use rusqlite::{params, OptionalExtension, Row};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OastSessionRow {
    pub id: i64,
    pub project_id: i64,
    pub provider_kind: String,
    pub correlation_id: Option<String>,
    pub secret: Option<String>,
    pub server: String,
    pub domain: Option<String>,
    pub rsa_private_key_pem: Option<String>,
    pub rsa_public_key_pem: Option<String>,
    pub provider_meta: Option<String>,
    pub provider_token: Option<String>,
    pub label: Option<String>,
    pub purpose: Option<String>,
    pub watch: bool,
    pub status: String,
    pub created_at: OffsetDateTime,
    pub last_polled_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OastInteractionRow {
    pub id: i64,
    pub session_id: i64,
    pub protocol: String,
    pub unique_id: String,
    pub full_id: String,
    pub remote_address: String,
    pub raw_request: String,
    pub raw_response: String,
    pub timestamp: OffsetDateTime,
    pub received_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OastLabelRow {
    pub id: i64,
    pub session_id: i64,
    pub label: String,
    pub case_index: Option<i64>,
    pub created_at: OffsetDateTime,
}

/// Global provider registry row (daemon infrastructure, not project data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OastProviderRow {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub server: String,
    pub domain: Option<String>,
    pub token: Option<String>,
    pub enabled: bool,
    pub is_default: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Default)]
pub struct NewOastSession {
    pub project_id: i64,
    pub provider_kind: String,
    pub correlation_id: Option<String>,
    pub secret: Option<String>,
    pub server: String,
    pub domain: Option<String>,
    pub rsa_private_key_pem: Option<String>,
    pub rsa_public_key_pem: Option<String>,
    pub provider_meta: Option<String>,
    pub provider_token: Option<String>,
    pub label: Option<String>,
    pub purpose: Option<String>,
    pub watch: bool,
}

#[derive(Debug, Clone, Default)]
pub struct NewOastInteraction {
    pub session_id: i64,
    pub project_id: i64,
    pub protocol: String,
    pub unique_id: String,
    pub full_id: String,
    pub remote_address: String,
    pub raw_request: String,
    pub raw_response: String,
    pub timestamp: String,
}

impl Db {
    pub async fn insert_oast_session(&self, new: NewOastSession) -> DomainResult<i64> {
        let project_id = new.project_id;
        let provider_kind = new.provider_kind.clone();
        let correlation_id = new.correlation_id.clone();
        let secret = new.secret.clone();
        let server = new.server.clone();
        let domain = new.domain.clone();
        let rsa_private_key_pem = new.rsa_private_key_pem.clone();
        let rsa_public_key_pem = new.rsa_public_key_pem.clone();
        let provider_meta = new.provider_meta.clone();
        let provider_token = new.provider_token.clone();
        let label = new.label.clone();
        let purpose = new.purpose.clone();
        let watch = i64::from(new.watch);
        let created_at = now_rfc3339();
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO oast_sessions
                 (project_id, provider_kind, correlation_id, secret, server, domain,
                  rsa_private_key_pem, rsa_public_key_pem, provider_meta, provider_token,
                  label, purpose, watch, status, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'active', ?14)",
                params![
                    project_id,
                    provider_kind,
                    correlation_id,
                    secret,
                    server,
                    domain,
                    rsa_private_key_pem,
                    rsa_public_key_pem,
                    provider_meta,
                    provider_token,
                    label,
                    purpose,
                    watch,
                    created_at
                ],
            )
            .map_err(storage_error)?;
            Ok(conn.last_insert_rowid())
        })
        .await
    }

    pub async fn get_oast_session(
        &self,
        project_id: i64,
        session_id: i64,
    ) -> DomainResult<OastSessionRow> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT id, project_id, provider_kind, correlation_id, secret, server, domain,
                        rsa_private_key_pem, rsa_public_key_pem, provider_meta, label, purpose,
                        watch, status, created_at, last_polled_at, provider_token
                 FROM oast_sessions WHERE project_id=?1 AND id=?2",
                params![project_id, session_id],
                read_session_row,
            )
            .optional()
            .map_err(storage_error)?
            .ok_or_else(|| not_found(format!("oast session {session_id}")))
        })
        .await
    }

    pub async fn get_oast_session_any_project(
        &self,
        session_id: i64,
    ) -> DomainResult<OastSessionRow> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT id, project_id, provider_kind, correlation_id, secret, server, domain,
                        rsa_private_key_pem, rsa_public_key_pem, provider_meta, label, purpose,
                        watch, status, created_at, last_polled_at, provider_token
                 FROM oast_sessions WHERE id=?1",
                params![session_id],
                read_session_row,
            )
            .optional()
            .map_err(storage_error)?
            .ok_or_else(|| not_found(format!("oast session {session_id}")))
        })
        .await
    }

    pub async fn list_oast_sessions(
        &self,
        project_id: i64,
    ) -> DomainResult<Vec<(OastSessionRow, i64)>> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT s.id, s.project_id, s.provider_kind, s.correlation_id, s.secret,
                            s.server, s.domain, s.rsa_private_key_pem, s.rsa_public_key_pem,
                            s.provider_meta, s.label, s.purpose, s.watch, s.status,
                            s.created_at, s.last_polled_at, s.provider_token,
                            (SELECT COUNT(*) FROM oast_interactions i WHERE i.session_id = s.id)
                     FROM oast_sessions s
                     WHERE s.project_id=?1
                     ORDER BY s.id DESC",
                )
                .map_err(storage_error)?;
            let rows = stmt
                .query_map(params![project_id], |row| {
                    Ok((read_session_row(row)?, row.get(17)?))
                })
                .map_err(storage_error)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_error)
        })
        .await
    }

    /// Active sessions the background poller should visit (all projects).
    pub async fn list_oast_watch_sessions(&self) -> DomainResult<Vec<OastSessionRow>> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, project_id, provider_kind, correlation_id, secret, server, domain,
                            rsa_private_key_pem, rsa_public_key_pem, provider_meta, label, purpose,
                            watch, status, created_at, last_polled_at, provider_token
                     FROM oast_sessions
                     WHERE watch=1 AND status='active'
                     ORDER BY id",
                )
                .map_err(storage_error)?;
            let rows = stmt
                .query_map([], read_session_row)
                .map_err(storage_error)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_error)
        })
        .await
    }

    pub async fn touch_oast_session_polled(&self, session_id: i64, at: &str) -> DomainResult<()> {
        let at = at.to_string();
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE oast_sessions SET last_polled_at=?2 WHERE id=?1",
                params![session_id, at],
            )
            .map_err(storage_error)?;
            Ok(())
        })
        .await
    }

    pub async fn set_oast_session_status(&self, session_id: i64, status: &str) -> DomainResult<()> {
        let status = status.to_string();
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE oast_sessions SET status=?2 WHERE id=?1",
                params![session_id, status],
            )
            .map_err(storage_error)?;
            Ok(())
        })
        .await
    }

    /// Persist an interaction. Returns false when the unique constraint
    /// deduplicated it (already seen this poll cycle or earlier).
    pub async fn insert_oast_interaction(&self, new: NewOastInteraction) -> DomainResult<bool> {
        let session_id = new.session_id;
        let project_id = new.project_id;
        let protocol = new.protocol.clone();
        let unique_id = new.unique_id.clone();
        let full_id = new.full_id.clone();
        let remote_address = new.remote_address.clone();
        let raw_request = new.raw_request.clone();
        let raw_response = new.raw_response.clone();
        let timestamp = new.timestamp.clone();
        let received_at = now_rfc3339();
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "INSERT OR IGNORE INTO oast_interactions
                     (session_id, project_id, protocol, unique_id, full_id, remote_address,
                      raw_request, raw_response, timestamp, received_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        session_id,
                        project_id,
                        protocol,
                        unique_id,
                        full_id,
                        remote_address,
                        raw_request,
                        raw_response,
                        timestamp,
                        received_at
                    ],
                )
                .map_err(storage_error)?;
            Ok(changed > 0)
        })
        .await
    }

    pub async fn list_oast_interactions(
        &self,
        project_id: i64,
        session_id: i64,
        label: Option<String>,
        limit: i64,
        offset: i64,
    ) -> DomainResult<(Vec<OastInteractionRow>, i64)> {
        self.with_conn(move |conn| {
            // Sessions are project-pinned; a cross-project read must 404 before
            // any interaction is returned.
            let owns: Option<i64> = conn
                .query_row(
                    "SELECT id FROM oast_sessions WHERE project_id=?1 AND id=?2",
                    params![project_id, session_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(storage_error)?;
            if owns.is_none() {
                return Err(not_found(format!("oast session {session_id}")));
            }
            let like = label.as_ref().map(|l| {
                // Escape LIKE metacharacters in the user label so `%`/`_`
                // never widen the filter into a prefix-scan.
                let escaped = l
                    .replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_");
                format!("{escaped}%")
            });
            let total: i64 = match &like {
                Some(pattern) => conn.query_row(
                    "SELECT COUNT(*) FROM oast_interactions
                     WHERE session_id=?1 AND full_id LIKE ?2 ESCAPE '\\'",
                    params![session_id, pattern],
                    |row| row.get(0),
                ),
                None => conn.query_row(
                    "SELECT COUNT(*) FROM oast_interactions WHERE session_id=?1",
                    params![session_id],
                    |row| row.get(0),
                ),
            }
            .map_err(storage_error)?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, session_id, protocol, unique_id, full_id, remote_address,
                            raw_request, raw_response, timestamp, received_at
                     FROM oast_interactions
                     WHERE session_id=?1 AND (?2 IS NULL OR full_id LIKE ?2 ESCAPE '\\')
                     ORDER BY id LIMIT ?3 OFFSET ?4",
                )
                .map_err(storage_error)?;
            let rows = stmt
                .query_map(
                    params![session_id, like, limit, offset],
                    read_interaction_row,
                )
                .map_err(storage_error)?;
            let items = rows
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_error)?;
            Ok((items, total))
        })
        .await
    }

    pub async fn insert_oast_label(
        &self,
        session_id: i64,
        label: &str,
        case_index: Option<i64>,
    ) -> DomainResult<i64> {
        let label = label.to_string();
        let created_at = now_rfc3339();
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO oast_labels (session_id, label, case_index, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![session_id, label, case_index, created_at],
            )
            .map_err(storage_error)?;
            Ok(conn.last_insert_rowid())
        })
        .await
    }

    /// Label → fuzz case map for one project-scoped session. Single query so
    /// `fuzz_manage oast_poll` grouping stays cheap.
    pub async fn list_oast_label_case_map(
        &self,
        project_id: i64,
        session_id: i64,
    ) -> DomainResult<Vec<(String, Option<i64>)>> {
        self.with_conn(move |conn| {
            let owns: Option<i64> = conn
                .query_row(
                    "SELECT id FROM oast_sessions WHERE project_id=?1 AND id=?2",
                    params![project_id, session_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(storage_error)?;
            if owns.is_none() {
                return Err(not_found(format!("oast session {session_id}")));
            }
            let mut stmt = conn
                .prepare(
                    "SELECT label, case_index FROM oast_labels
                     WHERE session_id=?1 ORDER BY id",
                )
                .map_err(storage_error)?;
            let rows = stmt
                .query_map(params![session_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?))
                })
                .map_err(storage_error)?;
            let items = rows
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_error)?;
            Ok(items)
        })
        .await
    }

    pub async fn get_oast_label(
        &self,
        session_id: i64,
        label: &str,
    ) -> DomainResult<Option<OastLabelRow>> {
        let label = label.to_string();
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT id, session_id, label, case_index, created_at
                 FROM oast_labels WHERE session_id=?1 AND label=?2",
                params![session_id, label],
                read_label_row,
            )
            .optional()
            .map_err(storage_error)
        })
        .await
    }

    // --- Provider registry (global; see SPEC-oast.md provider section) ---

    pub async fn list_oast_providers(&self) -> DomainResult<Vec<OastProviderRow>> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, kind, server, domain, token, enabled, is_default,
                            created_at, updated_at
                     FROM oast_providers
                     ORDER BY is_default DESC, id",
                )
                .map_err(storage_error)?;
            let rows = stmt
                .query_map([], read_provider_row)
                .map_err(storage_error)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_error)
        })
        .await
    }

    pub async fn get_oast_provider(&self, provider_id: i64) -> DomainResult<OastProviderRow> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT id, name, kind, server, domain, token, enabled, is_default,
                        created_at, updated_at
                 FROM oast_providers WHERE id=?1",
                params![provider_id],
                read_provider_row,
            )
            .optional()
            .map_err(storage_error)?
            .ok_or_else(|| not_found(format!("oast provider {provider_id}")))
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_oast_provider(
        &self,
        name: String,
        kind: String,
        server: String,
        domain: Option<String>,
        token: Option<String>,
        enabled: bool,
    ) -> DomainResult<i64> {
        let now = now_rfc3339();
        self.with_conn(move |conn| {
            let defaults: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM oast_providers WHERE is_default=1",
                    [],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            let is_default = i64::from(defaults == 0);
            conn.execute(
                "INSERT INTO oast_providers
                 (name, kind, server, domain, token, enabled, is_default, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    name,
                    kind,
                    server,
                    domain,
                    token,
                    i64::from(enabled),
                    is_default,
                    now,
                    now
                ],
            )
            .map_err(storage_error)?;
            Ok(conn.last_insert_rowid())
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_oast_provider(
        &self,
        provider_id: i64,
        name: String,
        kind: String,
        server: String,
        domain: Option<String>,
        token: Option<String>,
        enabled: bool,
    ) -> DomainResult<()> {
        let now = now_rfc3339();
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE oast_providers
                     SET name=?2, kind=?3, server=?4, domain=?5, token=?6, enabled=?7,
                         is_default=CASE WHEN ?7=0 THEN 0 ELSE is_default END,
                         updated_at=?8
                     WHERE id=?1",
                    params![
                        provider_id,
                        name,
                        kind,
                        server,
                        domain,
                        token,
                        i64::from(enabled),
                        now
                    ],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Err(not_found(format!("oast provider {provider_id}")));
            }
            Ok(())
        })
        .await
    }

    pub async fn set_oast_provider_default(&self, provider_id: i64) -> DomainResult<()> {
        self.with_conn(move |conn| {
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM oast_providers WHERE id=?1 AND enabled=1",
                    params![provider_id],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            if exists == 0 {
                return Err(not_found(format!("enabled oast provider {provider_id}")));
            }
            conn.execute(
                "UPDATE oast_providers SET is_default=0 WHERE is_default=1",
                [],
            )
            .map_err(storage_error)?;
            conn.execute(
                "UPDATE oast_providers SET is_default=1 WHERE id=?1",
                params![provider_id],
            )
            .map_err(storage_error)?;
            Ok(())
        })
        .await
    }

    pub async fn delete_oast_provider(&self, provider_id: i64) -> DomainResult<bool> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM oast_providers WHERE id=?1",
                    params![provider_id],
                )
                .map_err(storage_error)?;
            Ok(changed > 0)
        })
        .await
    }

    /// Insert-or-refresh the provider row seeded from `[oast]` config
    /// (name "config"). Preserves the user's default choice on update.
    pub async fn upsert_config_oast_provider(
        &self,
        kind: String,
        server: String,
        domain: Option<String>,
        token: Option<String>,
    ) -> DomainResult<i64> {
        let now = now_rfc3339();
        self.with_conn(move |conn| {
            // Bootstrap-only seeding: the `[oast]` config section creates the
            // `config` row on first resolve. Once the row exists the
            // registry owns it (oast_providers update/enable/disable) —
            // re-upserting on every resolve would silently re-enable a row
            // the operator disabled and stomp registry-managed fields.
            let existing: Option<i64> = conn
                .query_row(
                    "SELECT id FROM oast_providers WHERE name='config'",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(storage_error)?;
            if let Some(id) = existing {
                return Ok(id);
            }
            let defaults: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM oast_providers WHERE is_default=1",
                    [],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            conn.execute(
                "INSERT INTO oast_providers
                 (name, kind, server, domain, token, enabled, is_default, created_at, updated_at)
                 VALUES ('config', ?1, ?2, ?3, ?4, 1, ?5, ?6, ?6)",
                params![kind, server, domain, token, i64::from(defaults == 0), now],
            )
            .map_err(storage_error)?;
            let id: i64 = conn
                .query_row(
                    "SELECT id FROM oast_providers WHERE name='config'",
                    [],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            Ok(id)
        })
        .await
    }
}

fn read_provider_row(row: &Row<'_>) -> rusqlite::Result<OastProviderRow> {
    Ok(OastProviderRow {
        id: row.get(0)?,
        name: row.get(1)?,
        kind: row.get(2)?,
        server: row.get(3)?,
        domain: row.get(4)?,
        token: row.get(5)?,
        enabled: row.get::<_, i64>(6)? != 0,
        is_default: row.get::<_, i64>(7)? != 0,
        created_at: parse_time(&row.get::<_, String>(8)?),
        updated_at: parse_time(&row.get::<_, String>(9)?),
    })
}

fn read_session_row(row: &Row<'_>) -> rusqlite::Result<OastSessionRow> {
    Ok(OastSessionRow {
        id: row.get(0)?,
        project_id: row.get(1)?,
        provider_kind: row.get(2)?,
        correlation_id: row.get(3)?,
        secret: row.get(4)?,
        server: row.get(5)?,
        domain: row.get(6)?,
        rsa_private_key_pem: row.get(7)?,
        rsa_public_key_pem: row.get(8)?,
        provider_meta: row.get(9)?,
        label: row.get(10)?,
        purpose: row.get(11)?,
        watch: row.get::<_, i64>(12)? != 0,
        status: row.get(13)?,
        created_at: parse_time(&row.get::<_, String>(14)?),
        last_polled_at: row.get::<_, Option<String>>(15)?.map(|s| parse_time(&s)),
        provider_token: row.get(16)?,
    })
}

fn read_interaction_row(row: &Row<'_>) -> rusqlite::Result<OastInteractionRow> {
    Ok(OastInteractionRow {
        id: row.get(0)?,
        session_id: row.get(1)?,
        protocol: row.get(2)?,
        unique_id: row.get(3)?,
        full_id: row.get(4)?,
        remote_address: row.get(5)?,
        raw_request: row.get(6)?,
        raw_response: row.get(7)?,
        timestamp: parse_time(&row.get::<_, String>(8)?),
        received_at: parse_time(&row.get::<_, String>(9)?),
    })
}

fn read_label_row(row: &Row<'_>) -> rusqlite::Result<OastLabelRow> {
    Ok(OastLabelRow {
        id: row.get(0)?,
        session_id: row.get(1)?,
        label: row.get(2)?,
        case_index: row.get(3)?,
        created_at: parse_time(&row.get::<_, String>(4)?),
    })
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

fn not_found(message: String) -> DomainError {
    DomainError::new(ErrorCode::NotFound, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn seed_project(db: &Db) -> i64 {
        let now = now_rfc3339();
        db.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO projects (name, created_at, updated_at, scope_json, limits_json)
                 VALUES ('oast', ?1, ?1, '{}', '{}')",
                params![now],
            )
            .map_err(storage_error)?;
            Ok(conn.last_insert_rowid())
        })
        .await
        .unwrap()
    }

    fn new_session(project_id: i64) -> NewOastSession {
        NewOastSession {
            project_id,
            provider_kind: "interactsh".into(),
            correlation_id: Some("abcdefghij0123456789".into()),
            secret: Some("550e8400-e29b-41d4-a716-446655440000".into()),
            server: "https://oast.example.com".into(),
            domain: Some("oast.example.com".into()),
            rsa_private_key_pem: Some("PRIVATE".into()),
            rsa_public_key_pem: Some("PUBLIC".into()),
            provider_meta: None,
            provider_token: None,
            label: None,
            purpose: Some("ssrf".into()),
            watch: true,
        }
    }

    #[tokio::test]
    async fn session_round_trip_is_project_scoped() {
        let db = Db::open_in_memory().await.unwrap();
        let project = seed_project(&db).await;
        let id = db.insert_oast_session(new_session(project)).await.unwrap();

        let loaded = db.get_oast_session(project, id).await.unwrap();
        assert_eq!(loaded.provider_kind, "interactsh");
        assert!(loaded.watch);
        assert_eq!(loaded.status, "active");
        assert_eq!(
            loaded.correlation_id.as_deref(),
            Some("abcdefghij0123456789")
        );

        let err = db.get_oast_session(project + 99, id).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn watch_sessions_only_return_active_watched_rows() {
        let db = Db::open_in_memory().await.unwrap();
        let project = seed_project(&db).await;
        let a = db.insert_oast_session(new_session(project)).await.unwrap();
        let mut off = new_session(project);
        off.watch = false;
        off.correlation_id = Some("abcdefghij9999999999".into());
        db.insert_oast_session(off).await.unwrap();

        let watch = db.list_oast_watch_sessions().await.unwrap();
        assert_eq!(watch.len(), 1);
        assert_eq!(watch[0].id, a);

        db.set_oast_session_status(a, "stopped").await.unwrap();
        assert!(db.list_oast_watch_sessions().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn interactions_dedupe_and_page_with_label_filter() {
        let db = Db::open_in_memory().await.unwrap();
        let project = seed_project(&db).await;
        let session = db.insert_oast_session(new_session(project)).await.unwrap();

        let interaction = |full_id: &str, ts: &str| NewOastInteraction {
            session_id: session,
            project_id: project,
            protocol: "http".into(),
            unique_id: full_id.into(),
            full_id: full_id.into(),
            remote_address: "203.0.113.9".into(),
            raw_request: "GET / HTTP/1.1".into(),
            raw_response: String::new(),
            timestamp: ts.into(),
        };
        assert!(db
            .insert_oast_interaction(interaction("cidlabelaaaa", "2026-10-11T00:00:00Z"))
            .await
            .unwrap());
        assert!(!db
            .insert_oast_interaction(interaction("cidlabelaaaa", "2026-10-11T00:00:00Z"))
            .await
            .unwrap());
        assert!(db
            .insert_oast_interaction(interaction("cidlabelbbbb", "2026-10-11T00:00:01Z"))
            .await
            .unwrap());

        let (all, total) = db
            .list_oast_interactions(project, session, None, 10, 0)
            .await
            .unwrap();
        assert_eq!(total, 2);
        assert_eq!(all.len(), 2);

        let (page, total) = db
            .list_oast_interactions(project, session, Some("cidlabelaaaa".into()), 10, 0)
            .await
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(page[0].full_id, "cidlabelaaaa");

        let err = db
            .list_oast_interactions(project + 1, session, None, 10, 0)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn labels_are_unique_per_session() {
        let db = Db::open_in_memory().await.unwrap();
        let project = seed_project(&db).await;
        let session = db.insert_oast_session(new_session(project)).await.unwrap();

        db.insert_oast_label(session, "cidlabelaaaa", Some(7))
            .await
            .unwrap();
        let dup = db.insert_oast_label(session, "cidlabelaaaa", Some(8)).await;
        assert!(dup.is_err());

        let label = db
            .get_oast_label(session, "cidlabelaaaa")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(label.case_index, Some(7));
        assert!(db
            .get_oast_label(session, "nomatch")
            .await
            .unwrap()
            .is_none());
    }
}
