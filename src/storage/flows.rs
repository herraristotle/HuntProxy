//! Flow definition persistence (project-scoped, edition-1 JSON).

use crate::domain::*;
use crate::storage::projects::{now_rfc3339, parse_time};
use crate::storage::Db;
use rusqlite::params;

impl Db {
    pub async fn list_flows(&self, project_id: ProjectId) -> DomainResult<Vec<Flow>> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, description, kind, edition, definition_json, enabled,
                            created_at, updated_at
                     FROM flows WHERE project_id=?1 ORDER BY name",
                )
                .map_err(storage_error)?;
            let rows = stmt
                .query_map(params![project_id.get()], |row| {
                    read_flow_row(project_id, row)
                })
                .map_err(storage_error)?;
            rows.collect::<rusqlite::Result<Vec<Flow>>>()
                .map_err(storage_error)
        })
        .await
    }

    pub async fn get_flow(&self, project_id: ProjectId, flow_id: FlowId) -> DomainResult<Flow> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, description, kind, edition, definition_json, enabled,
                            created_at, updated_at
                     FROM flows WHERE project_id=?1 AND id=?2",
                )
                .map_err(storage_error)?;
            let mut rows = stmt
                .query_map(params![project_id.get(), flow_id.get()], |row| {
                    read_flow_row(project_id, row)
                })
                .map_err(storage_error)?;
            rows.next()
                .transpose()
                .map_err(storage_error)?
                .ok_or_else(|| DomainError::not_found("flow"))
        })
        .await
    }

    pub async fn create_flow(
        &self,
        project_id: ProjectId,
        definition: FlowDefinition,
    ) -> DomainResult<Flow> {
        definition.validate()?;
        let name = definition.name.trim().to_string();
        let kind = definition.kind;
        let edition = definition.edition;
        let description = definition.description.clone();
        let definition_json = serde_json::to_string(&definition)
            .map_err(|error| DomainError::invalid(format!("flow definition: {error}")))?;
        let timestamp = now_rfc3339();
        self.with_conn(move |conn| {
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM flows WHERE project_id=?1 AND name=?2)",
                    params![project_id.get(), name],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            if exists {
                return Err(DomainError::conflict(format!(
                    "flow named `{name}` already exists"
                )));
            }
            conn.execute(
                "INSERT INTO flows
                 (project_id, name, description, kind, edition, definition_json,
                  enabled, created_at, updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,1,?7,?7)",
                params![
                    project_id.get(),
                    name,
                    description,
                    kind.as_str(),
                    i64::from(edition),
                    definition_json,
                    timestamp
                ],
            )
            .map_err(storage_error)?;
            Ok(Flow {
                id: FlowId(conn.last_insert_rowid()),
                project_id,
                name,
                description,
                kind,
                edition,
                enabled: true,
                definition,
                created_at: parse_time(&timestamp),
                updated_at: parse_time(&timestamp),
            })
        })
        .await
    }

    pub async fn update_flow(
        &self,
        project_id: ProjectId,
        flow_id: FlowId,
        definition: FlowDefinition,
        enabled: Option<bool>,
    ) -> DomainResult<Flow> {
        definition.validate()?;
        let name = definition.name.trim().to_string();
        let kind = definition.kind;
        let edition = definition.edition;
        let description = definition.description.clone();
        let definition_json = serde_json::to_string(&definition)
            .map_err(|error| DomainError::invalid(format!("flow definition: {error}")))?;
        let timestamp = now_rfc3339();
        self.with_conn(move |conn| {
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM flows
                         WHERE project_id=?1 AND name=?2 AND id!=?3
                     )",
                    params![project_id.get(), name, flow_id.get()],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            if exists {
                return Err(DomainError::conflict(format!(
                    "flow named `{name}` already exists"
                )));
            }
            let changed = conn
                .execute(
                    "UPDATE flows
                     SET name=?3, description=?4, kind=?5, edition=?6, definition_json=?7,
                         enabled=COALESCE(?8, enabled), updated_at=?9
                     WHERE project_id=?1 AND id=?2",
                    params![
                        project_id.get(),
                        flow_id.get(),
                        name,
                        description,
                        kind.as_str(),
                        i64::from(edition),
                        definition_json,
                        enabled.map(i64::from),
                        timestamp
                    ],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Err(DomainError::not_found("flow"));
            }
            Ok(())
        })
        .await?;
        self.get_flow(project_id, flow_id).await
    }

    pub async fn delete_flow(&self, project_id: ProjectId, flow_id: FlowId) -> DomainResult<()> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM flows WHERE project_id=?1 AND id=?2",
                    params![project_id.get(), flow_id.get()],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Err(DomainError::not_found("flow"));
            }
            Ok(())
        })
        .await
    }

    /// Enables or disables a flow without touching its definition.
    pub async fn set_flow_enabled(
        &self,
        project_id: ProjectId,
        flow_id: FlowId,
        enabled: bool,
    ) -> DomainResult<()> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE flows SET enabled=?3, updated_at=?4
                     WHERE project_id=?1 AND id=?2",
                    params![
                        project_id.get(),
                        flow_id.get(),
                        i64::from(enabled),
                        now_rfc3339()
                    ],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Err(DomainError::not_found("flow"));
            }
            Ok(())
        })
        .await
    }
}

fn read_flow_row(project_id: ProjectId, row: &rusqlite::Row<'_>) -> rusqlite::Result<Flow> {
    let id: i64 = row.get(0)?;
    let name: String = row.get(1)?;
    let description: String = row.get(2)?;
    let kind: String = row.get(3)?;
    let edition: i64 = row.get(4)?;
    let definition_json: String = row.get(5)?;
    let enabled: i64 = row.get(6)?;
    let created_at: String = row.get(7)?;
    let updated_at: String = row.get(8)?;
    let definition: FlowDefinition = serde_json::from_str(&definition_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let kind = FlowKind::parse(&kind).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(error.to_string())),
        )
    })?;
    Ok(Flow {
        id: FlowId(id),
        project_id,
        name,
        description,
        kind,
        edition: u8::try_from(edition).unwrap_or(0),
        enabled: enabled != 0,
        definition,
        created_at: parse_time(&created_at),
        updated_at: parse_time(&updated_at),
    })
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::Internal, error.to_string())
}
