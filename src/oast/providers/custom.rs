//! Custom provider: user-supplied poll URL returning interactions as JSON.
//! Port of `quickssrf/packages/backend/src/providers/custom/client.ts`.

use super::{
    provider_error, unsupported_new_url, Interaction, OastProvider, ProviderRegistration,
    RegisterOptions,
};
use crate::config::OastProviderKind;
use crate::domain::DomainResult;
use crate::storage::OastSessionRow;
use serde::Deserialize;
use std::sync::Arc;

pub struct CustomProvider {
    pub http: Arc<wreq::Client>,
    pub token: String,
}

#[derive(Deserialize, Default)]
struct CustomEvent {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    #[serde(rename = "rawRequest")]
    raw_request: Option<String>,
    #[serde(default)]
    #[serde(rename = "rawResponse")]
    raw_response: Option<String>,
    #[serde(default)]
    timestamp: Option<serde_json::Value>,
}

impl OastProvider for CustomProvider {
    fn kind(&self) -> OastProviderKind {
        OastProviderKind::Custom
    }

    async fn register(&self, opts: &RegisterOptions) -> DomainResult<ProviderRegistration> {
        Ok(ProviderRegistration {
            payload_url: opts.server.trim_end_matches('/').to_string(),
            unique_id: opts.server.clone(),
            correlation_id: None,
            secret: None,
            rsa_private_key_pem: None,
            rsa_public_key_pem: None,
            provider_meta: None,
            first_label: opts.server.clone(),
        })
    }

    async fn new_url(&self, _session: &OastSessionRow) -> DomainResult<String> {
        Err(unsupported_new_url(self.kind()))
    }

    async fn poll(&self, session: &OastSessionRow) -> DomainResult<Vec<Interaction>> {
        let mut request = self.http.get(&session.server);
        if !self.token.is_empty() {
            request = request.header(
                wreq::header::AUTHORIZATION,
                format!("Bearer {}", self.token),
            );
        }
        let response = request
            .send()
            .await
            .map_err(|e| provider_error(format!("custom poll: {e}")))?;
        if !response.status().is_success() {
            return Err(provider_error(format!(
                "custom poll: HTTP {}",
                response.status()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| provider_error(format!("custom poll body: {e}")))?;
        let body: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| provider_error(format!("custom poll json: {e}")))?;

        // Accept a bare array or {data|requests|events: []} (QuickSSRF parity).
        let events = if let Some(array) = body.as_array() {
            array.clone()
        } else {
            ["data", "requests", "events"]
                .iter()
                .find_map(|key| body.get(key).and_then(|v| v.as_array()))
                .cloned()
                .unwrap_or_default()
        };

        let mut synthetic = 0usize;
        Ok(events
            .into_iter()
            .map(|value| {
                let event: CustomEvent = serde_json::from_value(value.clone())
                    .unwrap_or_else(|_| CustomEvent::default());
                let id = event.id.filter(|s| !s.is_empty()).unwrap_or_else(|| {
                    synthetic += 1;
                    format!("custom-{synthetic}")
                });
                Interaction {
                    protocol: event
                        .protocol
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| "http".into()),
                    unique_id: id.clone(),
                    full_id: id,
                    remote_address: event.source.unwrap_or_default(),
                    raw_request: event.raw_request.unwrap_or_else(|| value.to_string()),
                    raw_response: event.raw_response.unwrap_or_default(),
                    timestamp: normalize_timestamp(event.timestamp),
                }
            })
            .collect())
    }

    async fn deregister(&self, _session: &OastSessionRow) -> DomainResult<()> {
        Ok(())
    }
}

/// JS `new Date(x)` semantics: numbers are epoch **milliseconds**, strings pass
/// through. Missing or invalid values use a **stable epoch sentinel** rather
/// than the wall clock — a now()-fallback would make repeated polls of one
/// server event crop up as fresh rows under the (session, full_id, timestamp)
/// dedupe key.
fn normalize_timestamp(value: Option<serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::Number(n)) => n
            .as_i64()
            .and_then(|ms| {
                time::OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000).ok()
            })
            .and_then(|ts| {
                ts.format(&time::format_description::well_known::Rfc3339)
                    .ok()
            })
            .unwrap_or_else(|| "1970-01-01T00:00:00Z".into()),
        Some(serde_json::Value::String(s)) if !s.is_empty() => s,
        _ => "1970-01-01T00:00:00Z".to_string(),
    }
}
