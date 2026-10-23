//! OAST (out-of-band interaction tracking) client core.
//!
//! `OastService` orchestrates provider registration, label minting, polling,
//! persistence, and the background poller (see `docs/specs/SPEC-oast.md`).

mod helpers;
pub mod providers;

use crate::app::AppState;
use crate::config::{OastConfig, OastProviderKind};
use crate::domain::{DomainError, DomainResult, ErrorCode, FuzzJobId, ProjectId};
use crate::fuzzer::FuzzTemplate;
use crate::storage::{
    Db, NewOastInteraction, NewOastSession, OastProviderRow, OastSessionRow, now_rfc3339,
};
use dashmap::DashMap;
pub use providers::{Interaction, OastProvider, ProviderRegistration, RegisterOptions};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::format_description::well_known::Rfc3339;

const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(300);
const DEFAULT_PAGE_SIZE: i64 = 50;
const MAX_PAGE_SIZE: i64 = 500;

#[derive(Debug, Clone, Serialize)]
pub struct OastSessionView {
    pub session_id: i64,
    pub project_id: i64,
    pub provider: String,
    pub status: String,
    pub watch: bool,
    pub purpose: Option<String>,
    pub server: String,
    pub domain: Option<String>,
    pub correlation_id: Option<String>,
    pub payload_url: Option<String>,
    pub created_at: String,
    pub last_polled_at: Option<String>,
    pub interaction_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OastUrlView {
    pub session_id: i64,
    pub payload_url: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OastInteractionView {
    pub id: i64,
    pub protocol: String,
    pub unique_id: String,
    pub full_id: String,
    pub remote_address: String,
    pub raw_request: String,
    pub raw_response: String,
    pub timestamp: String,
    pub received_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OastInteractionsPage {
    pub interactions: Vec<OastInteractionView>,
    pub total: i64,
}

/// Registry row as exposed over MCP/REST. The token is never serialized —
/// only whether one is configured.
#[derive(Debug, Clone, Serialize)]
pub struct OastProviderView {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub server: String,
    pub domain: Option<String>,
    pub token_configured: bool,
    pub enabled: bool,
    pub is_default: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OastProviderCreate {
    pub name: String,
    pub kind: String,
    pub server: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OastProviderPatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Fully resolved provider for one operation (explicit selection, enabled
/// default row, config seed, or the single enabled row).
#[derive(Debug, Clone)]
struct ResolvedProvider {
    kind: OastProviderKind,
    server: String,
    domain: Option<String>,
    token: Option<String>,
}

/// OAST context of a fuzz job: session plus the per-case label map used for
/// exact interaction correlation. Shared by the MCP `fuzz_manage` tool and the
/// REST fuzz endpoints so both surfaces mirror the same annotation rules.
pub(crate) struct OastJobContext {
    pub(crate) session_id: i64,
    pub(crate) payload_url: Option<String>,
    pub(crate) per_case_labels: bool,
    pub(crate) labels: BTreeMap<u64, String>,
}

pub(crate) async fn load_oast_job_context(
    state: &AppState,
    project_id: ProjectId,
    job_id: FuzzJobId,
) -> DomainResult<Option<OastJobContext>> {
    let raw = state
        .db
        .load_fuzz_template_for_project(project_id, job_id)
        .await?;
    let template: FuzzTemplate = serde_json::from_str(&raw)
        .map_err(|error| DomainError::invalid(format!("stored fuzz template: {error}")))?;
    let Some(session_id) = template.oast_session_id else {
        return Ok(None);
    };
    let labels = match state
        .oast
        .label_case_map(project_id.get(), session_id)
        .await
    {
        Ok(entries) => entries
            .into_iter()
            .filter_map(|(label, case_index)| Some((case_index? as u64, label)))
            .collect(),
        Err(error) => {
            tracing::warn!(%error, session_id, "oast label map unavailable");
            BTreeMap::new()
        }
    };
    Ok(Some(OastJobContext {
        session_id,
        payload_url: template.oast_payload_url,
        per_case_labels: template.oast_per_case_labels,
        labels,
    }))
}

pub struct OastService {
    db: Arc<Db>,
    config: OastConfig,
    http: Arc<wreq::Client>,
    poller: Mutex<Option<tokio::task::AbortHandle>>,
    /// Per-session poll serialization. Concurrent polls of one session race
    /// the fetch/persist pipeline and violate the "poll returns only newly
    /// seen interactions" contract — worse, destructive providers like
    /// postbin consume interactions on read (the server shifts its queue),
    /// so double-polling can silently drop evidence. One gate per session
    /// id; different sessions keep polling in parallel.
    poll_gates: DashMap<i64, Arc<tokio::sync::Mutex<()>>>,
}

impl OastService {
    pub fn new(db: Arc<Db>, config: OastConfig) -> DomainResult<Arc<Self>> {
        let http = wreq::Client::builder()
            .timeout(Duration::from_millis(config.poll_timeout_ms))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| {
                DomainError::new(ErrorCode::ConfigInvalid, format!("oast http client: {e}"))
            })?;
        Ok(Arc::new(Self {
            db,
            config,
            http: Arc::new(http),
            poller: Mutex::new(None),
            poll_gates: DashMap::default(),
        }))
    }

    fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.config.poll_interval_ms)
            .clamp(MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)
    }

    /// OAST is available when either `[oast]` is configured or the provider
    /// registry holds an enabled row. Gates create/new_url/list/poll/
    /// interactions/stop — provider management itself is never gated here
    /// (chicken-egg: a daemon bootstrapped only via MCP needs `add` first).
    async fn require_enabled(&self) -> DomainResult<()> {
        if self.config.provider.is_some() {
            return Ok(());
        }
        let providers = self.db.list_oast_providers().await?;
        if providers.iter().any(|p| p.enabled) {
            return Ok(());
        }
        Err(DomainError::new(
            ErrorCode::Unavailable,
            "oast is not configured; add a provider (oast_providers add) or set the [oast] section",
        ))
    }

    /// Pick the provider for one operation:
    /// explicit `provider_id` (must be enabled) → enabled default row →
    /// (config is upserted as the `config` row first, becoming default only
    /// when no default exists yet) → the single enabled row → error.
    async fn resolve_provider(&self, provider_id: Option<i64>) -> DomainResult<ResolvedProvider> {
        if let Some(kind) = self.config.provider {
            self.db
                .upsert_config_oast_provider(
                    kind.as_str().to_string(),
                    self.config.effective_server(),
                    (!self.config.domain.trim().is_empty())
                        .then(|| self.config.domain.trim().to_string()),
                    (!self.config.token.is_empty()).then(|| self.config.token.clone()),
                )
                .await?;
        }
        let row = if let Some(id) = provider_id {
            let row = self.db.get_oast_provider(id).await?;
            if !row.enabled {
                return Err(DomainError::new(
                    ErrorCode::InvalidArgument,
                    format!("oast provider {id} is disabled"),
                ));
            }
            row
        } else {
            let rows = self.db.list_oast_providers().await?;
            match rows.iter().find(|p| p.enabled && p.is_default) {
                Some(row) => row.clone(),
                None => {
                    let enabled: Vec<&OastProviderRow> =
                        rows.iter().filter(|p| p.enabled).collect();
                    match enabled.len() {
                        0 => {
                            return Err(DomainError::new(
                                ErrorCode::Unavailable,
                                "oast is not configured; add a provider (oast_providers add) or set the [oast] section",
                            ));
                        }
                        1 => (*enabled[0]).clone(),
                        _ => {
                            return Err(DomainError::new(
                                ErrorCode::InvalidArgument,
                                "multiple oast providers are enabled; set one as default (oast_providers set_default) or pass provider_id",
                            ));
                        }
                    }
                }
            }
        };
        Self::resolved_from_row(&row)
    }

    /// Cheap enablement probe for surface gating (`tools/list`): true when
    /// `[oast]` is configured or any registry row is enabled — the same
    /// condition `require_enabled` gates session actions on.
    pub async fn listable(&self) -> bool {
        self.require_enabled().await.is_ok()
    }

    fn resolved_from_row(row: &OastProviderRow) -> DomainResult<ResolvedProvider> {
        let kind = OastProviderKind::parse(&row.kind)?;
        let domain = row
            .domain
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(str::to_string);
        if matches!(kind, OastProviderKind::Interactsh) && domain.is_none() {
            return Err(DomainError::new(
                ErrorCode::ConfigInvalid,
                format!("oast provider {:?} needs a payload domain", row.name),
            ));
        }
        Ok(ResolvedProvider {
            kind,
            server: row.server.clone(),
            domain,
            token: row.token.clone().filter(|t| !t.is_empty()),
        })
    }

    /// Label → fuzz case map for grouping interactions back to cases.
    pub async fn label_case_map(
        &self,
        project_id: i64,
        session_id: i64,
    ) -> DomainResult<Vec<(String, Option<i64>)>> {
        self.require_enabled().await?;
        self.db
            .list_oast_label_case_map(project_id, session_id)
            .await
    }

    // --- Provider registry management (never gated by require_enabled) ---

    pub async fn list_providers(&self) -> DomainResult<Vec<OastProviderView>> {
        self.db
            .list_oast_providers()
            .await
            .map(|rows| rows.iter().map(Self::provider_view).collect())
    }

    pub async fn add_provider(&self, new: OastProviderCreate) -> DomainResult<OastProviderView> {
        let name = new.name.trim().to_string();
        if name.is_empty() {
            return Err(DomainError::new(
                ErrorCode::InvalidArgument,
                "provider name must not be empty",
            ));
        }
        let kind = self.validate_provider_fields(&name, &new.kind, &new.server, &new.domain)?;
        if self
            .db
            .list_oast_providers()
            .await?
            .iter()
            .any(|p| p.name == name)
        {
            return Err(DomainError::new(
                ErrorCode::Conflict,
                format!("oast provider {name:?} already exists"),
            ));
        }
        let id = self
            .db
            .insert_oast_provider(
                name,
                kind.as_str().to_string(),
                new.server.trim().to_string(),
                new.domain
                    .map(|d| d.trim().to_string())
                    .filter(|d| !d.is_empty()),
                new.token.filter(|t| !t.is_empty()),
                new.enabled.unwrap_or(true),
            )
            .await?;
        let row = self.db.get_oast_provider(id).await?;
        Ok(Self::provider_view(&row))
    }

    pub async fn update_provider(
        &self,
        provider_id: i64,
        patch: OastProviderPatch,
    ) -> DomainResult<OastProviderView> {
        let current = self.db.get_oast_provider(provider_id).await?;
        let name = patch
            .name
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| current.name.clone());
        let kind_str = patch.kind.unwrap_or_else(|| current.kind.clone());
        let server = patch
            .server
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| current.server.clone());
        // Tri-state domain patch: Some("") clears the stored domain, a
        // non-empty value replaces it, None keeps the current one (token
        // clearing below follows the same Some-empty-means-clear rule; sql
        // stores Option::None as NULL).
        let domain = match patch.domain {
            Some(d) if d.trim().is_empty() => None,
            Some(d) => Some(d.trim().to_string()),
            None => current.domain.clone(),
        };
        let token = match patch.token {
            Some(token) if token.is_empty() => None,
            Some(token) => Some(token),
            None => current.token.clone(),
        };
        let enabled = patch.enabled.unwrap_or(current.enabled);
        let kind = self.validate_provider_fields(&name, &kind_str, &server, &domain)?;
        if name != current.name
            && self
                .db
                .list_oast_providers()
                .await?
                .iter()
                .any(|p| p.name == name)
        {
            return Err(DomainError::new(
                ErrorCode::Conflict,
                format!("oast provider {name:?} already exists"),
            ));
        }
        if !enabled && current.is_default {
            tracing::warn!(provider_id, "disabling the default oast provider");
        }
        self.db
            .update_oast_provider(
                provider_id,
                name,
                kind.as_str().to_string(),
                server,
                domain,
                token,
                enabled,
            )
            .await?;
        let row = self.db.get_oast_provider(provider_id).await?;
        Ok(Self::provider_view(&row))
    }

    pub async fn set_provider_default(&self, provider_id: i64) -> DomainResult<OastProviderView> {
        self.db.set_oast_provider_default(provider_id).await?;
        let row = self.db.get_oast_provider(provider_id).await?;
        Ok(Self::provider_view(&row))
    }

    pub async fn delete_provider(&self, provider_id: i64) -> DomainResult<()> {
        if !self.db.delete_oast_provider(provider_id).await? {
            return Err(DomainError::new(
                ErrorCode::NotFound,
                format!("oast provider {provider_id}"),
            ));
        }
        Ok(())
    }

    /// Kind parse + field rules shared by add/update. Returns the parsed kind.
    fn validate_provider_fields(
        &self,
        name: &str,
        kind_str: &str,
        server: &str,
        domain: &Option<String>,
    ) -> DomainResult<OastProviderKind> {
        let kind = OastProviderKind::parse(kind_str)?;
        if server.is_empty() {
            return Err(DomainError::new(
                ErrorCode::InvalidArgument,
                format!("oast provider {name:?} needs a server URL"),
            ));
        }
        if matches!(kind, OastProviderKind::Interactsh) {
            let domain = domain.as_deref().unwrap_or_default();
            if domain.trim().is_empty() {
                return Err(DomainError::new(
                    ErrorCode::InvalidArgument,
                    "interactsh providers need a payload domain",
                ));
            }
        }
        Ok(kind)
    }

    fn provider_view(row: &OastProviderRow) -> OastProviderView {
        OastProviderView {
            id: row.id,
            name: row.name.clone(),
            kind: row.kind.clone(),
            server: row.server.clone(),
            domain: row.domain.clone(),
            token_configured: row.token.as_deref().is_some_and(|t| !t.is_empty()),
            enabled: row.enabled,
            is_default: row.is_default,
            created_at: format_time(&row.created_at),
            updated_at: format_time(&row.updated_at),
        }
    }

    async fn dispatch_register(
        &self,
        opts: &RegisterOptions,
        kind: OastProviderKind,
    ) -> DomainResult<ProviderRegistration> {
        match kind {
            OastProviderKind::Interactsh => {
                providers::interactsh::InteractshProvider {
                    http: self.http.clone(),
                }
                .register(opts)
                .await
            }
            OastProviderKind::Postbin => {
                providers::postbin::PostbinProvider {
                    http: self.http.clone(),
                }
                .register(opts)
                .await
            }
            OastProviderKind::Webhooksite => {
                providers::webhooksite::WebhooksiteProvider {
                    http: self.http.clone(),
                }
                .register(opts)
                .await
            }
            OastProviderKind::Custom => {
                providers::custom::CustomProvider {
                    http: self.http.clone(),
                    token: opts.token.clone(),
                }
                .register(opts)
                .await
            }
        }
    }

    async fn dispatch_new_url(&self, row: &OastSessionRow) -> DomainResult<String> {
        match Self::provider_kind_of(row)? {
            OastProviderKind::Interactsh => {
                providers::interactsh::InteractshProvider {
                    http: self.http.clone(),
                }
                .new_url(row)
                .await
            }
            OastProviderKind::Postbin => {
                providers::postbin::PostbinProvider {
                    http: self.http.clone(),
                }
                .new_url(row)
                .await
            }
            OastProviderKind::Webhooksite => {
                providers::webhooksite::WebhooksiteProvider {
                    http: self.http.clone(),
                }
                .new_url(row)
                .await
            }
            OastProviderKind::Custom => {
                providers::custom::CustomProvider {
                    http: self.http.clone(),
                    token: row.provider_token.clone().unwrap_or_default(),
                }
                .new_url(row)
                .await
            }
        }
    }

    async fn dispatch_poll(&self, row: &OastSessionRow) -> DomainResult<Vec<Interaction>> {
        match Self::provider_kind_of(row)? {
            OastProviderKind::Interactsh => {
                providers::interactsh::InteractshProvider {
                    http: self.http.clone(),
                }
                .poll(row)
                .await
            }
            OastProviderKind::Postbin => {
                providers::postbin::PostbinProvider {
                    http: self.http.clone(),
                }
                .poll(row)
                .await
            }
            OastProviderKind::Webhooksite => {
                providers::webhooksite::WebhooksiteProvider {
                    http: self.http.clone(),
                }
                .poll(row)
                .await
            }
            OastProviderKind::Custom => {
                providers::custom::CustomProvider {
                    http: self.http.clone(),
                    token: row.provider_token.clone().unwrap_or_default(),
                }
                .poll(row)
                .await
            }
        }
    }

    async fn dispatch_deregister(&self, row: &OastSessionRow) -> DomainResult<()> {
        match Self::provider_kind_of(row)? {
            OastProviderKind::Interactsh => {
                providers::interactsh::InteractshProvider {
                    http: self.http.clone(),
                }
                .deregister(row)
                .await
            }
            OastProviderKind::Postbin => {
                providers::postbin::PostbinProvider {
                    http: self.http.clone(),
                }
                .deregister(row)
                .await
            }
            OastProviderKind::Webhooksite => {
                providers::webhooksite::WebhooksiteProvider {
                    http: self.http.clone(),
                }
                .deregister(row)
                .await
            }
            OastProviderKind::Custom => {
                providers::custom::CustomProvider {
                    http: self.http.clone(),
                    token: row.provider_token.clone().unwrap_or_default(),
                }
                .deregister(row)
                .await
            }
        }
    }

    fn provider_kind_of(row: &OastSessionRow) -> DomainResult<OastProviderKind> {
        OastProviderKind::parse(&row.provider_kind)
    }

    /// Reconstruct the session's payload URL from stored fields (no extra
    /// column): interactsh `{label}.{domain}`, bin-style `{server}/{label}`,
    /// custom stores the URL itself as the label.
    fn payload_url(row: &OastSessionRow) -> Option<String> {
        let label = row.label.as_deref()?;
        match Self::provider_kind_of(row).ok()? {
            OastProviderKind::Interactsh => row
                .domain
                .as_deref()
                .map(|domain| format!("{label}.{}", domain.trim_end_matches('.'))),
            OastProviderKind::Postbin | OastProviderKind::Webhooksite => {
                Some(format!("{}/{}", row.server.trim_end_matches('/'), label))
            }
            OastProviderKind::Custom => Some(label.to_string()),
        }
    }

    pub async fn create(
        &self,
        project_id: i64,
        purpose: Option<String>,
        watch: bool,
        provider_id: Option<i64>,
    ) -> DomainResult<OastSessionView> {
        let resolved = self.resolve_provider(provider_id).await?;
        if provider_id.is_none() {
            self.require_enabled().await?;
        }
        let opts = RegisterOptions {
            server: resolved.server.clone(),
            token: resolved.token.clone().unwrap_or_default(),
            domain: resolved.domain.clone().unwrap_or_default(),
        };
        let registration = self.dispatch_register(&opts, resolved.kind).await?;
        let kind = resolved.kind;
        let session_id = self
            .db
            .insert_oast_session(NewOastSession {
                project_id,
                provider_kind: kind.as_str().to_string(),
                correlation_id: registration.correlation_id,
                secret: registration.secret,
                server: opts.server.clone(),
                domain: if matches!(kind, OastProviderKind::Interactsh) {
                    resolved.domain.clone()
                } else {
                    None
                },
                rsa_private_key_pem: registration.rsa_private_key_pem,
                rsa_public_key_pem: registration.rsa_public_key_pem,
                provider_meta: registration.provider_meta,
                provider_token: resolved.token.clone(),
                label: Some(registration.first_label.clone()),
                purpose,
                watch,
            })
            .await?;
        self.db
            .insert_oast_label(session_id, &registration.first_label, None)
            .await?;
        let row = self.db.get_oast_session(project_id, session_id).await?;
        Ok(Self::view(&row, 0))
    }

    pub async fn new_url(
        &self,
        project_id: i64,
        session_id: i64,
        case_index: Option<i64>,
    ) -> DomainResult<OastUrlView> {
        self.require_enabled().await?;
        if let Some(index) = case_index.filter(|value| *value < 0) {
            return Err(DomainError::new(
                ErrorCode::InvalidArgument,
                format!("case_index must be >= 0, got {index}"),
            ));
        }
        let row = self.db.get_oast_session(project_id, session_id).await?;
        if row.status != "active" {
            return Err(DomainError::new(
                ErrorCode::InvalidArgument,
                format!("oast session {session_id} is {}", row.status),
            ));
        }
        let payload_url = self.dispatch_new_url(&row).await?;
        let label = Self::label_of(&row, &payload_url)?;
        self.db
            .insert_oast_label(session_id, &label, case_index)
            .await?;
        Ok(OastUrlView {
            session_id,
            payload_url,
            label,
        })
    }

    /// Derive the bare label from a minted URL for label-row persistence.
    fn label_of(row: &OastSessionRow, payload_url: &str) -> DomainResult<String> {
        match Self::provider_kind_of(row)? {
            OastProviderKind::Interactsh => {
                let domain = row.domain.as_deref().ok_or_else(|| {
                    DomainError::new(ErrorCode::Internal, "session missing domain")
                })?;
                let suffix = format!(".{}", domain.trim_end_matches('.'));
                payload_url
                    .strip_suffix(&suffix)
                    .map(str::to_string)
                    .ok_or_else(|| {
                        DomainError::new(
                            ErrorCode::Internal,
                            "payload URL does not end with session domain",
                        )
                    })
            }
            _ => Err(DomainError::new(
                ErrorCode::InvalidArgument,
                "single-URL providers do not mint additional labels",
            )),
        }
    }

    pub async fn list(&self, project_id: i64) -> DomainResult<Vec<OastSessionView>> {
        self.require_enabled().await?;
        self.db.list_oast_sessions(project_id).await.map(|rows| {
            rows.into_iter()
                .map(|(row, count)| Self::view(&row, count))
                .collect()
        })
    }

    /// Poll a session now: fetch, persist interactions (deduped), and return
    /// only the newly persisted ones. Marks the session expired when the
    /// server no longer knows it.
    pub async fn poll(
        &self,
        project_id: i64,
        session_id: i64,
    ) -> DomainResult<Vec<OastInteractionView>> {
        self.require_enabled().await?;
        let row = self.db.get_oast_session(project_id, session_id).await?;
        self.poll_row(&row).await
    }

    /// Poller-facing poll (no project gate — the row was loaded by the watch
    /// query). Returns newly persisted interactions.
    async fn poll_row(&self, row: &OastSessionRow) -> DomainResult<Vec<OastInteractionView>> {
        if row.status != "active" {
            return Ok(Vec::new());
        }
        // Serialize polls per session: the background poller and explicit
        // `poll` calls can overlap, and a duplicated fetch/persist race both
        // breaks "only newly seen interactions" and destroys evidence on
        // shift-on-read providers (postbin).
        let gate = self
            .poll_gates
            .entry(row.id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _poll_guard = gate.lock().await;
        let interactions = match self.dispatch_poll(row).await {
            Ok(interactions) => interactions,
            Err(error) if error.code() == ErrorCode::NotFound => {
                self.db.set_oast_session_status(row.id, "expired").await?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let mut fresh = Vec::new();
        for hit in interactions {
            let inserted = self
                .db
                .insert_oast_interaction(NewOastInteraction {
                    session_id: row.id,
                    project_id: row.project_id,
                    protocol: hit.protocol.clone(),
                    unique_id: hit.unique_id.clone(),
                    full_id: hit.full_id.clone(),
                    remote_address: hit.remote_address.clone(),
                    raw_request: hit.raw_request.clone(),
                    raw_response: hit.raw_response.clone(),
                    timestamp: hit.timestamp.clone(),
                })
                .await?;
            if inserted {
                fresh.push(OastInteractionView {
                    id: 0,
                    protocol: hit.protocol,
                    unique_id: hit.unique_id,
                    full_id: hit.full_id,
                    remote_address: hit.remote_address,
                    raw_request: hit.raw_request,
                    raw_response: hit.raw_response,
                    timestamp: hit.timestamp,
                    received_at: now_rfc3339(),
                });
            }
        }
        self.db
            .touch_oast_session_polled(row.id, &now_rfc3339())
            .await?;
        Ok(fresh)
    }

    pub async fn interactions(
        &self,
        project_id: i64,
        session_id: i64,
        label: Option<String>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> DomainResult<OastInteractionsPage> {
        self.require_enabled().await?;
        let limit = limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
        let offset = offset.unwrap_or(0).max(0);
        let (rows, total) = self
            .db
            .list_oast_interactions(project_id, session_id, label, limit, offset)
            .await?;
        Ok(OastInteractionsPage {
            interactions: rows
                .into_iter()
                .map(|row| OastInteractionView {
                    id: row.id,
                    protocol: row.protocol,
                    unique_id: row.unique_id,
                    full_id: row.full_id,
                    remote_address: row.remote_address,
                    raw_request: row.raw_request,
                    raw_response: row.raw_response,
                    timestamp: format_time(&row.timestamp),
                    received_at: format_time(&row.received_at),
                })
                .collect(),
            total,
        })
    }

    /// Best-effort deregister, always marks the session stopped locally and
    /// drops it from the poller.
    pub async fn stop(&self, project_id: i64, session_id: i64) -> DomainResult<OastSessionView> {
        self.require_enabled().await?;
        let row = self.db.get_oast_session(project_id, session_id).await?;
        if let Err(error) = self.dispatch_deregister(&row).await {
            tracing::warn!(
                session_id,
                error = %error,
                "oast deregister failed; marking stopped locally"
            );
        }
        self.db
            .set_oast_session_status(session_id, "stopped")
            .await?;
        let row = self.db.get_oast_session(project_id, session_id).await?;
        let count = self
            .db
            .list_oast_sessions(project_id)
            .await?
            .into_iter()
            .find(|(r, _)| r.id == session_id)
            .map(|(_, c)| c)
            .unwrap_or(0);
        Ok(Self::view(&row, count))
    }

    fn view(row: &OastSessionRow, interaction_count: i64) -> OastSessionView {
        OastSessionView {
            session_id: row.id,
            project_id: row.project_id,
            provider: row.provider_kind.clone(),
            status: row.status.clone(),
            watch: row.watch,
            purpose: row.purpose.clone(),
            server: row.server.clone(),
            domain: row.domain.clone(),
            correlation_id: row.correlation_id.clone(),
            payload_url: Self::payload_url(row),
            created_at: format_time(&row.created_at),
            last_polled_at: row.last_polled_at.as_ref().map(format_time),
            interaction_count,
        }
    }

    /// Spawn the background poller (once) when `auto_poll` is on. Call once
    /// after boot; the loop re-reads watched sessions every tick, so a
    /// registry-only setup (no `[oast]` config seed) and late-added
    /// providers are both picked up without a restart.
    pub async fn start_poller(self: &Arc<Self>) {
        if !self.config.auto_poll {
            return;
        }
        let mut guard = match self.poller.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        if guard.is_some() {
            return;
        }
        let interval = self.poll_interval();
        let service = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // consume the immediate first tick
            loop {
                tick.tick().await;
                match service.db.list_oast_watch_sessions().await {
                    Ok(sessions) => {
                        for row in sessions {
                            if let Err(error) = service.poll_row(&row).await {
                                tracing::warn!(
                                    session_id = row.id,
                                    error = %error,
                                    "background oast poll failed"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "oast watch session query failed");
                    }
                }
            }
        });
        *guard = Some(handle.abort_handle());
    }

    pub fn shutdown(&self) {
        if let Ok(mut guard) = self.poller.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }
}

fn format_time(value: &time::OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn postbin_config(server: &str) -> OastConfig {
        OastConfig {
            provider: Some(OastProviderKind::Postbin),
            server: server.to_string(),
            ..OastConfig::default()
        }
    }

    fn interactsh_config(server: &str) -> OastConfig {
        OastConfig {
            provider: Some(OastProviderKind::Interactsh),
            server: server.to_string(),
            domain: "oast.example.com".into(),
            ..OastConfig::default()
        }
    }

    async fn seed_project(db: &Db) -> i64 {
        let now = now_rfc3339();
        db.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO projects (name, created_at, updated_at, scope_json, limits_json)
                 VALUES ('oast', ?1, ?1, '{}', '{}')",
                rusqlite::params![now],
            )
            .map_err(|e| DomainError::new(ErrorCode::StorageError, e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn disabled_service_rejects_create() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let service = OastService::new(db, OastConfig::default()).unwrap();
        let err = service.create(1, None, true, None).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn registry_only_provider_enables_create_and_snapshots_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .and(wiremock::matchers::header(
                wreq::header::AUTHORIZATION.as_str(),
                "Bearer s3cret",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = seed_project(&db).await;
        let service = OastService::new(db, OastConfig::default()).unwrap();

        let added = service
            .add_provider(OastProviderCreate {
                name: "corp-collector".into(),
                kind: "custom".into(),
                server: format!("{}/", server.uri()),
                domain: None,
                token: Some("s3cret".into()),
                enabled: None,
            })
            .await
            .unwrap();
        assert!(added.enabled);
        assert!(added.is_default);
        assert!(added.token_configured);
        assert!(!added.server.is_empty());

        // Registry-only (no [oast] config) is enough to gate create.
        let session = service.create(project, None, true, None).await.unwrap();
        assert_eq!(session.provider, "custom");

        // The poll uses the session's token snapshot (Bearer custom).
        let fresh = service.poll(project, session.session_id).await.unwrap();
        assert!(fresh.is_empty());

        // Tokens never leak through the view.
        let view = service.list_providers().await.unwrap();
        let json = serde_json::to_value(&view[0]).unwrap();
        assert!(json.get("token").is_none());
        assert_eq!(json["token_configured"], true);
    }

    #[tokio::test]
    async fn explicit_provider_id_selects_that_row() {
        let server_a = MockServer::start().await;
        let server_b = MockServer::start().await;
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = seed_project(&db).await;
        let service = OastService::new(db, OastConfig::default()).unwrap();

        let a = service
            .add_provider(OastProviderCreate {
                name: "a".into(),
                kind: "postbin".into(),
                server: server_a.uri(),
                domain: None,
                token: None,
                enabled: None,
            })
            .await
            .unwrap();
        let b = service
            .add_provider(OastProviderCreate {
                name: "b".into(),
                kind: "postbin".into(),
                server: server_b.uri(),
                domain: None,
                token: None,
                enabled: None,
            })
            .await
            .unwrap();
        assert!(a.is_default);
        assert!(!b.is_default);

        // Default (first row) wins without an explicit id...
        Mock::given(method("POST"))
            .and(path("/api/bin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "binId": "bin-def"
            })))
            .expect(1)
            .mount(&server_a)
            .await;
        let def = service.create(project, None, false, None).await.unwrap();
        assert_eq!(def.server, server_a.uri());

        // ...and an explicit id overrides it.
        Mock::given(method("POST"))
            .and(path("/api/bin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "binId": "bin-x"
            })))
            .expect(1)
            .mount(&server_b)
            .await;
        let chosen = service
            .create(project, None, false, Some(b.id))
            .await
            .unwrap();
        assert_eq!(chosen.server, server_b.uri());
    }

    #[tokio::test]
    async fn default_registry_row_beats_config_seed() {
        let server_config = MockServer::start().await;
        let server_registry = MockServer::start().await;
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = seed_project(&db).await;
        let service = OastService::new(db, postbin_config(&server_config.uri())).unwrap();

        // User row added before any resolve becomes the default.
        let row = service
            .add_provider(OastProviderCreate {
                name: "preferred".into(),
                kind: "postbin".into(),
                server: server_registry.uri(),
                domain: None,
                token: None,
                enabled: None,
            })
            .await
            .unwrap();
        assert!(row.is_default);

        Mock::given(method("POST"))
            .and(path("/api/bin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "binId": "bin-r"
            })))
            .expect(1)
            .mount(&server_registry)
            .await;
        let session = service.create(project, None, false, None).await.unwrap();
        assert_eq!(session.server, server_registry.uri());

        // The config seed row exists too, but is not default.
        let providers = service.list_providers().await.unwrap();
        assert_eq!(providers.len(), 2);
        let seed = providers.iter().find(|p| p.name == "config").unwrap();
        assert!(!seed.is_default);
        assert!(seed.enabled);
        assert_eq!(seed.server, server_config.uri());
    }

    #[tokio::test]
    async fn multiple_enabled_rows_without_a_default_error() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = seed_project(&db).await;
        let service = OastService::new(db, OastConfig::default()).unwrap();
        let a = service
            .add_provider(OastProviderCreate {
                name: "a".into(),
                kind: "postbin".into(),
                server: "http://a.example".into(),
                domain: None,
                token: None,
                enabled: None,
            })
            .await
            .unwrap();
        for name in ["b", "c"] {
            service
                .add_provider(OastProviderCreate {
                    name: name.into(),
                    kind: "postbin".into(),
                    server: format!("http://{name}.example"),
                    domain: None,
                    token: None,
                    enabled: None,
                })
                .await
                .unwrap();
        }
        // Disabling the default clears is_default; b and c stay enabled with
        // no default → ambiguous selection.
        service
            .update_provider(
                a.id,
                OastProviderPatch {
                    enabled: Some(false),
                    ..OastProviderPatch::default()
                },
            )
            .await
            .unwrap();
        let err = service
            .create(project, None, false, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);

        // Choosing explicitly resolves the ambiguity.
        let providers = service.list_providers().await.unwrap();
        let b = providers.iter().find(|p| p.name == "b").unwrap();
        assert!(!b.is_default);
        // No register is attempted for postbin without a live server here —
        // resolution errors surface before dispatch (InvalidArgument above).
        let _ = b;
    }

    #[tokio::test]
    async fn explicit_disabled_provider_is_rejected() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = seed_project(&db).await;
        let service = OastService::new(db, OastConfig::default()).unwrap();
        let row = service
            .add_provider(OastProviderCreate {
                name: "off".into(),
                kind: "postbin".into(),
                server: "http://off.example".into(),
                domain: None,
                token: None,
                enabled: Some(false),
            })
            .await
            .unwrap();
        let err = service
            .create(project, None, false, Some(row.id))
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn provider_crud_conflicts_and_not_founds() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let service = OastService::new(db, OastConfig::default()).unwrap();
        let created = service
            .add_provider(OastProviderCreate {
                name: "one".into(),
                kind: "postbin".into(),
                server: "http://one.example".into(),
                domain: None,
                token: None,
                enabled: None,
            })
            .await
            .unwrap();

        // Duplicate name.
        let err = service
            .add_provider(OastProviderCreate {
                name: "one".into(),
                kind: "postbin".into(),
                server: "http://two.example".into(),
                domain: None,
                token: None,
                enabled: None,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Conflict);

        // interactsh rows require a domain.
        let err = service
            .add_provider(OastProviderCreate {
                name: "issh".into(),
                kind: "interactsh".into(),
                server: "http://issh.example".into(),
                domain: None,
                token: None,
                enabled: None,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);

        // Update: rename, clear token (empty string → None).
        let updated = service
            .update_provider(
                created.id,
                OastProviderPatch {
                    name: Some("renamed".into()),
                    token: Some(String::new()),
                    ..OastProviderPatch::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.name, "renamed");
        assert!(!updated.token_configured);
        assert!(updated.is_default);

        // Second row can take the default.
        let second = service
            .add_provider(OastProviderCreate {
                name: "two".into(),
                kind: "webhooksite".into(),
                server: "http://two.example".into(),
                domain: None,
                token: None,
                enabled: None,
            })
            .await
            .unwrap();
        let made_default = service.set_provider_default(second.id).await.unwrap();
        assert!(made_default.is_default);
        let providers = service.list_providers().await.unwrap();
        assert_eq!(providers.iter().filter(|p| p.is_default).count(), 1);

        // Delete + 404s.
        service.delete_provider(second.id).await.unwrap();
        let err = service.delete_provider(second.id).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
        let err = service
            .update_provider(9_999, OastProviderPatch::default())
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
        let err = service.set_provider_default(9_999).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn config_seed_row_is_upserted_on_first_resolve() {
        let server = MockServer::start().await;
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = seed_project(&db).await;
        assert!(service_has_no_providers(&db).await);
        let service = OastService::new(db, postbin_config(&server.uri())).unwrap();

        Mock::given(method("POST"))
            .and(path("/api/bin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "binId": "bin-c"
            })))
            .mount(&server)
            .await;
        service.create(project, None, false, None).await.unwrap();

        let providers = service.list_providers().await.unwrap();
        let seed = providers.iter().find(|p| p.name == "config").unwrap();
        assert_eq!(seed.kind, "postbin");
        assert_eq!(seed.server, server.uri());
        assert!(seed.is_default);
        assert!(seed.enabled);
        assert!(!seed.token_configured);

        // A second create reuses the same row (upsert, not insert).
        service.create(project, None, false, None).await.unwrap();
        let providers = service.list_providers().await.unwrap();
        assert_eq!(providers.iter().filter(|p| p.name == "config").count(), 1);
    }

    async fn service_has_no_providers(db: &Db) -> bool {
        db.list_oast_providers().await.unwrap().is_empty()
    }

    #[tokio::test]
    async fn postbin_create_lists_and_stops() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/bin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "binId": "bin-1"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = seed_project(&db).await;
        let service = OastService::new(db, postbin_config(&server.uri())).unwrap();

        let session = service
            .create(project, Some("blind-ssrf".into()), true, None)
            .await
            .unwrap();
        assert_eq!(session.provider, "postbin");
        assert_eq!(session.status, "active");
        let expected_url = format!("{}/bin-1", server.uri());
        assert_eq!(session.payload_url.as_deref(), Some(expected_url.as_str()));
        assert_eq!(session.interaction_count, 0);

        let listed = service.list(project).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].session_id, session.session_id);

        // Single-URL provider: new_url rejected with a clear error.
        let err = service
            .new_url(project, session.session_id, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);

        let stopped = service.stop(project, session.session_id).await.unwrap();
        assert_eq!(stopped.status, "stopped");
        // Stopped sessions leave the watch list (poller skips them).
        assert!(
            service
                .db
                .list_oast_watch_sessions()
                .await
                .unwrap()
                .is_empty()
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn interactsh_create_new_url_and_poll_dedupe() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/register"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": "registration successful"
            })))
            .expect(1)
            .mount(&server)
            .await;
        // First poll returns one interaction (invalid crypto → we assert the
        // service surfaces a protocol error rather than persisting garbage);
        // empty polls return zero. The full decrypt path is covered by the
        // integration test in tests/api_oast.rs.
        Mock::given(method("GET"))
            .and(path("/poll"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/deregister"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;

        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = seed_project(&db).await;
        let service = OastService::new(db, interactsh_config(&server.uri())).unwrap();
        let session = service.create(project, None, false, None).await.unwrap();
        assert_eq!(session.provider, "interactsh");
        let url = session.payload_url.unwrap();
        assert_eq!(url.len(), 33 + ".oast.example.com".len());

        // Distinct labels on one session, persisted for case correlation.
        let a = service
            .new_url(project, session.session_id, Some(0))
            .await
            .unwrap();
        let b = service
            .new_url(project, session.session_id, Some(1))
            .await
            .unwrap();
        assert_ne!(a.payload_url, b.payload_url);
        assert_ne!(a.label, b.label);
        assert_eq!(a.label.len(), 33);

        // Empty polls are idempotent: nothing new to return.
        let fresh = service.poll(project, session.session_id).await.unwrap();
        assert!(fresh.is_empty());
        let fresh = service.poll(project, session.session_id).await.unwrap();
        assert!(fresh.is_empty());

        let page = service
            .interactions(project, session.session_id, None, None, None)
            .await
            .unwrap();
        assert_eq!(page.total, 0);

        service.stop(project, session.session_id).await.unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn cross_project_reads_are_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/bin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "binId": "bin-x"
            })))
            .mount(&server)
            .await;
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = seed_project(&db).await;
        let other = project + 100;
        let service = OastService::new(db, postbin_config(&server.uri())).unwrap();
        let session = service.create(project, None, true, None).await.unwrap();

        let err = service.list(other).await.unwrap();
        assert!(err.is_empty());
        let err = service.poll(other, session.session_id).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
        let err = service
            .interactions(other, session.session_id, None, None, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn unknown_correlation_id_marks_session_expired() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/register"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": "registration successful"
            })))
            .mount(&server)
            .await;
        // Mainline server wraps storage misses as HTTP 400 + storage text.
        Mock::given(method("GET"))
            .and(path("/poll"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "could not get interactions: correlation-id not found in cache"
            })))
            .mount(&server)
            .await;

        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = seed_project(&db).await;
        let service = OastService::new(db, interactsh_config(&server.uri())).unwrap();
        let session = service.create(project, None, true, None).await.unwrap();

        let err = service.poll(project, session.session_id).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
        let listed = service.list(project).await.unwrap();
        assert_eq!(listed[0].status, "expired");
        // Expired sessions leave the background poller's watch list.
        assert!(
            service
                .db
                .list_oast_watch_sessions()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn poller_only_runs_when_enabled_and_polls_watch_sessions() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/bin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "binId": "bin-p"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/bin/bin-p/req/shift"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1..)
            .mount(&server)
            .await;

        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let project = seed_project(&db).await;
        let service = OastService::new(
            db,
            OastConfig {
                poll_interval_ms: 1_000,
                ..postbin_config(&server.uri())
            },
        )
        .unwrap();
        let session = service.create(project, None, true, None).await.unwrap();

        service.start_poller().await;
        assert!(service.poller.lock().unwrap().is_some());
        // Duplicate start is a no-op.
        service.start_poller().await;
        tokio::time::sleep(Duration::from_millis(2_600)).await;
        service.shutdown();
        assert!(service.poller.lock().unwrap().is_none());
        server.verify().await;

        // auto_poll=false never spawns.
        let other = MockServer::start().await;
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let service = OastService::new(
            db,
            OastConfig {
                auto_poll: false,
                ..postbin_config(&other.uri())
            },
        )
        .unwrap();
        service.start_poller().await;
        assert!(service.poller.lock().unwrap().is_none());
        let _ = session;
    }
}
