//! PostBin provider: destructive one-request-per-poll bin service.
//! Port of `quickssrf/packages/backend/src/providers/postbin/client.ts`.

use super::{
    provider_error, unsupported_new_url, Interaction, OastProvider, ProviderRegistration,
    RegisterOptions,
};
use crate::config::OastProviderKind;
use crate::domain::DomainResult;
use crate::storage::OastSessionRow;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

pub struct PostbinProvider {
    pub http: Arc<wreq::Client>,
}

#[derive(Deserialize)]
struct BinCreated {
    #[serde(rename = "binId")]
    bin_id: String,
}

#[derive(Deserialize)]
struct PostbinRequest {
    #[serde(default)]
    body: serde_json::Value,
    #[serde(default)]
    headers: HashMap<String, String>,
    method: String,
    #[serde(default)]
    querystring: Option<String>,
    inserted: i64,
}

impl PostbinProvider {
    fn url(server: &str, path: &str) -> String {
        format!("{}/{}", server.trim_end_matches('/'), path)
    }

    fn bin_id(session: &OastSessionRow) -> DomainResult<String> {
        let meta: serde_json::Value = session
            .provider_meta
            .as_deref()
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or(serde_json::Value::Null);
        meta.get("binId")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| provider_error("postbin session missing binId"))
    }

    fn source_ip(headers: &HashMap<String, String>) -> String {
        for key in ["x-real-ip", "cf-connecting-ip", "x-forwarded-for"] {
            if let Some(value) = headers.get(key) {
                return value.clone();
            }
            for (name, value) in headers {
                if name.eq_ignore_ascii_case(key) {
                    return value.clone();
                }
            }
        }
        String::new()
    }

    fn raw_request(bin_id: &str, req: &PostbinRequest) -> String {
        let query = req.querystring.as_deref().unwrap_or("");
        let query = if query.is_empty() {
            String::new()
        } else {
            format!("?{query}")
        };
        let mut out = format!("{} /{bin_id}{query} HTTP/1.1", req.method);
        let mut names: Vec<&String> = req.headers.keys().collect();
        names.sort();
        for name in names {
            out.push('\n');
            out.push_str(name);
            out.push_str(": ");
            out.push_str(&req.headers[name]);
        }
        let body = match &req.body {
            serde_json::Value::Null => String::new(),
            serde_json::Value::String(s) => s.clone(),
            other => serde_json::to_string_pretty(other).unwrap_or_default(),
        };
        if !body.is_empty() {
            out.push_str("\n\n");
            out.push_str(&body);
        }
        out
    }
}

impl OastProvider for PostbinProvider {
    fn kind(&self) -> OastProviderKind {
        OastProviderKind::Postbin
    }

    async fn register(&self, opts: &RegisterOptions) -> DomainResult<ProviderRegistration> {
        let response = self
            .http
            .post(Self::url(&opts.server, "api/bin"))
            .send()
            .await
            .map_err(|e| provider_error(format!("postbin register: {e}")))?;
        if !response.status().is_success() {
            return Err(provider_error(format!(
                "postbin register: HTTP {}",
                response.status()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| provider_error(format!("postbin register body: {e}")))?;
        let created: BinCreated = serde_json::from_slice(&bytes)
            .map_err(|e| provider_error(format!("postbin register json: {e}")))?;
        let url = format!("{}/{}", opts.server.trim_end_matches('/'), created.bin_id);
        Ok(ProviderRegistration {
            payload_url: url,
            unique_id: created.bin_id.clone(),
            correlation_id: None,
            secret: None,
            rsa_private_key_pem: None,
            rsa_public_key_pem: None,
            provider_meta: Some(serde_json::json!({ "binId": created.bin_id }).to_string()),
            first_label: created.bin_id,
        })
    }

    async fn new_url(&self, _session: &OastSessionRow) -> DomainResult<String> {
        Err(unsupported_new_url(self.kind()))
    }

    async fn poll(&self, session: &OastSessionRow) -> DomainResult<Vec<Interaction>> {
        let bin_id = Self::bin_id(session)?;
        let url = Self::url(&session.server, &format!("api/bin/{bin_id}/req/shift"));
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| provider_error(format!("postbin poll: {e}")))?;
        let status = response.status();
        if status.as_u16() == 204 || status.as_u16() == 404 {
            return Ok(Vec::new());
        }
        if !status.is_success() {
            return Err(provider_error(format!("postbin poll: HTTP {status}")));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| provider_error(format!("postbin poll body: {e}")))?;
        let req: PostbinRequest = serde_json::from_slice(&bytes)
            .map_err(|e| provider_error(format!("postbin poll json: {e}")))?;

        let timestamp = millis_to_rfc3339(req.inserted);
        Ok(vec![Interaction {
            protocol: "http".into(),
            unique_id: bin_id.clone(),
            full_id: format!("{bin_id}-{}", req.inserted),
            remote_address: Self::source_ip(&req.headers),
            raw_request: Self::raw_request(&bin_id, &req),
            raw_response: String::new(),
            timestamp,
        }])
    }

    async fn deregister(&self, _session: &OastSessionRow) -> DomainResult<()> {
        Ok(())
    }
}

fn millis_to_rfc3339(ms: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
        .map(|ts| {
            ts.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
        })
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}
