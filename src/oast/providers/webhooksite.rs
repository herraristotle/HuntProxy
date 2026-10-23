//! Webhook.site provider: token-based request log with full-list polling.
//! Port of `quickssrf/packages/backend/src/providers/webhooksite/client.ts`.

use super::{
    Interaction, OastProvider, ProviderRegistration, RegisterOptions, provider_error,
    unsupported_new_url,
};
use crate::config::OastProviderKind;
use crate::domain::DomainResult;
use crate::storage::OastSessionRow;
use serde::Deserialize;
use std::sync::Arc;

pub struct WebhooksiteProvider {
    pub http: Arc<wreq::Client>,
}

#[derive(Deserialize)]
struct TokenCreated {
    uuid: String,
}

#[derive(Deserialize)]
struct WebhookRequest {
    uuid: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    created_at: String,
    #[serde(default)]
    url: String,
}

#[derive(Deserialize)]
struct WebhookResponse {
    #[serde(default)]
    data: Vec<WebhookRequest>,
}

impl WebhooksiteProvider {
    fn url(server: &str, path: &str) -> String {
        format!("{}/{}", server.trim_end_matches('/'), path)
    }

    fn token_id(session: &OastSessionRow) -> DomainResult<String> {
        let meta: serde_json::Value = session
            .provider_meta
            .as_deref()
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or(serde_json::Value::Null);
        meta.get("tokenId")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| provider_error("webhook.site session missing tokenId"))
    }
}

impl OastProvider for WebhooksiteProvider {
    fn kind(&self) -> OastProviderKind {
        OastProviderKind::Webhooksite
    }

    async fn register(&self, opts: &RegisterOptions) -> DomainResult<ProviderRegistration> {
        let response = self
            .http
            .post(Self::url(&opts.server, "token"))
            .header(wreq::header::CONTENT_TYPE, "application/json")
            .send()
            .await
            .map_err(|e| provider_error(format!("webhook.site register: {e}")))?;
        if !response.status().is_success() {
            return Err(provider_error(format!(
                "webhook.site register: HTTP {}",
                response.status()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| provider_error(format!("webhook.site register body: {e}")))?;
        let created: TokenCreated = serde_json::from_slice(&bytes)
            .map_err(|e| provider_error(format!("webhook.site register json: {e}")))?;
        let url = format!("{}/{}", opts.server.trim_end_matches('/'), created.uuid);
        Ok(ProviderRegistration {
            payload_url: url,
            unique_id: created.uuid.clone(),
            correlation_id: None,
            secret: None,
            rsa_private_key_pem: None,
            rsa_public_key_pem: None,
            provider_meta: Some(serde_json::json!({ "tokenId": created.uuid }).to_string()),
            first_label: created.uuid,
        })
    }

    async fn new_url(&self, _session: &OastSessionRow) -> DomainResult<String> {
        Err(unsupported_new_url(self.kind()))
    }

    async fn poll(&self, session: &OastSessionRow) -> DomainResult<Vec<Interaction>> {
        let token_id = Self::token_id(session)?;
        let url = Self::url(&session.server, &format!("token/{token_id}/requests"));
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| provider_error(format!("webhook.site poll: {e}")))?;
        if !response.status().is_success() {
            return Err(provider_error(format!(
                "webhook.site poll: HTTP {}",
                response.status()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| provider_error(format!("webhook.site poll body: {e}")))?;
        let body: WebhookResponse = serde_json::from_slice(&bytes)
            .map_err(|e| provider_error(format!("webhook.site poll json: {e}")))?;
        // The store's UNIQUE(session_id, full_id, timestamp, protocol) dedupes
        // repeated full-list reads across polls.
        Ok(body
            .data
            .into_iter()
            .map(|req| {
                // `url` is the callback URL webhook.site recorded for the
                // request; fall back to `uuid` when the server omits it.
                let full_id = if req.url.is_empty() {
                    req.uuid.clone()
                } else {
                    req.url
                };
                Interaction {
                    protocol: "http".into(),
                    unique_id: req.uuid,
                    full_id,
                    remote_address: req.ip,
                    raw_request: if req.content.is_empty() {
                        format!("{} / HTTP/1.1", req.method)
                    } else {
                        req.content
                    },
                    raw_response: String::new(),
                    timestamp: req.created_at,
                }
            })
            .collect())
    }

    async fn deregister(&self, _session: &OastSessionRow) -> DomainResult<()> {
        Ok(())
    }
}
