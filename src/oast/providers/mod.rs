//! OAST provider registry: shared types + the provider trait.
//!
//! Implementations live in sibling modules; the service dispatches on
//! `OastProviderKind` inside one async fn (native async-fn-in-trait, no dyn).

use crate::config::OastProviderKind;
use crate::domain::{DomainError, DomainResult, ErrorCode};
use crate::storage::OastSessionRow;
use serde::{Deserialize, Serialize};

pub mod custom;
pub mod interactsh;
pub mod postbin;
pub mod webhooksite;

#[cfg(test)]
mod tests;

/// One captured out-of-band interaction, normalized across providers
/// (mirrors QuickSSRF's `shared` Interaction shape minus session plumbing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interaction {
    pub protocol: String,
    pub unique_id: String,
    pub full_id: String,
    pub remote_address: String,
    pub raw_request: String,
    pub raw_response: String,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct RegisterOptions {
    /// Resolved provider origin (config value or provider default).
    pub server: String,
    /// Optional auth token (interactsh server token or custom Bearer).
    pub token: String,
    /// Payload domain (interactsh only).
    pub domain: String,
}

/// Everything the service needs to persist a new session, regardless of
/// provider. Provider-specific columns stay `None` for bin-style providers.
#[derive(Debug, Clone, Default)]
pub struct ProviderRegistration {
    /// First payload URL minted for this session.
    pub payload_url: String,
    /// Provider-level unique id (correlation id, bin id, token id, or URL).
    pub unique_id: String,
    pub correlation_id: Option<String>,
    pub secret: Option<String>,
    pub rsa_private_key_pem: Option<String>,
    pub rsa_public_key_pem: Option<String>,
    /// JSON blob for provider-specific metadata (binId, tokenId, ...).
    pub provider_meta: Option<String>,
    /// First full label (interactsh: 33-char `{cid}{nonce}`), else same as
    /// `unique_id` — stored in `oast_labels` for correlation.
    pub first_label: String,
}

/// Crate-internal dispatch: the service `match`es the concrete provider and
/// awaits inside one async fn — futures are never boxed or spawned as trait
/// objects, so the missing auto-trait bounds are irrelevant here.
#[allow(async_fn_in_trait)]
pub trait OastProvider {
    fn kind(&self) -> OastProviderKind;
    async fn register(&self, opts: &RegisterOptions) -> DomainResult<ProviderRegistration>;
    /// Mint an additional payload URL on an existing session (interactsh).
    async fn new_url(&self, session: &OastSessionRow) -> DomainResult<String>;
    async fn poll(&self, session: &OastSessionRow) -> DomainResult<Vec<Interaction>>;
    async fn deregister(&self, session: &OastSessionRow) -> DomainResult<()>;
}

/// Error for single-URL providers when `new_url` is requested.
pub(crate) fn unsupported_new_url(kind: OastProviderKind) -> DomainError {
    DomainError::new(
        ErrorCode::InvalidArgument,
        format!(
            "provider {} issues a single session URL; create a new session instead",
            kind.as_str()
        ),
    )
}

pub(crate) fn provider_error(message: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::Unavailable, message)
}

pub(crate) fn protocol_error(message: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::ProtocolError, message)
}
