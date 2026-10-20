//! Mainline interactsh protocol provider (self-hosted server).

use super::{
    protocol_error, provider_error, Interaction, OastProvider, ProviderRegistration,
    RegisterOptions,
};
use crate::config::OastProviderKind;
use crate::domain::DomainResult;
use crate::oast::helpers;
use crate::storage::OastSessionRow;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub struct InteractshProvider {
    pub http: Arc<wreq::Client>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct RegisterRequest {
    public_key: String,
    secret_key: String,
    correlation_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct DeregisterRequest {
    correlation_id: String,
    secret_key: String,
}

#[derive(Deserialize)]
struct PollResponse {
    #[serde(default)]
    data: Option<Vec<String>>,
    #[serde(default)]
    aes_key: Option<String>,
    // Mainline server parity (`pkg/server/http_server.go:500`): `-auth`
    // servers return token-element interactions in `extra` and root-TLD
    // interactions in `tlddata` — both are plaintext interaction JSON
    // strings, same shape as decoded `data[]`. Dropping either silently
    // loses evidence on auth-mode servers.
    #[serde(default)]
    extra: Option<Vec<String>>,
    #[serde(default)]
    tlddata: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawInteraction {
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    unique_id: String,
    #[serde(default)]
    full_id: String,
    #[serde(default)]
    remote_address: String,
    #[serde(default)]
    raw_request: String,
    #[serde(default)]
    raw_response: String,
    #[serde(default)]
    timestamp: String,
}

#[derive(Deserialize)]
struct RegisterResponse {
    #[serde(default)]
    message: String,
}

impl InteractshProvider {
    fn url(server: &str, path: &str) -> String {
        format!("{}/{}", server.trim_end_matches('/'), path)
    }

    fn auth_header(&self, builder: wreq::RequestBuilder, token: &str) -> wreq::RequestBuilder {
        if token.is_empty() {
            builder
        } else {
            // interactsh `-auth` expects the raw token, never `Bearer ...`.
            builder.header(wreq::header::AUTHORIZATION, token)
        }
    }

    /// Transport error Display text embeds the full request URL, and the
    /// interactsh poll URL carries the correlation secret as
    /// `?secret=<uuid>`. Replace every `secret=` value with a redaction
    /// marker so the secret can never reach logs or surfaced errors.
    fn redact_query_secret(text: String) -> String {
        const KEY: &str = "secret=";
        let mut out = String::with_capacity(text.len());
        let mut rest = text.as_str();
        while let Some(pos) = rest.find(KEY) {
            out.push_str(&rest[..pos + KEY.len()]);
            let after = &rest[pos + KEY.len()..];
            let end = after
                .find(['&', ')', ' ', '\n', '\t'])
                .unwrap_or(after.len());
            out.push_str("REDACTED");
            rest = &after[end..];
        }
        out.push_str(rest);
        out
    }

    async fn post_json(
        &self,
        url: &str,
        token: &str,
        body: &[u8],
        what: &str,
    ) -> DomainResult<String> {
        let response = self
            .auth_header(
                self.http
                    .post(url)
                    .header(wreq::header::CONTENT_TYPE, "application/json"),
                token,
            )
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| provider_error(format!("{what}: {e}")))?;
        if !response.status().is_success() {
            return Err(provider_error(format!(
                "{what}: HTTP {}",
                response.status()
            )));
        }
        Ok(response.text().await.unwrap_or_default())
    }

    fn check_register_response(&self, body: String) -> DomainResult<()> {
        // Go-client parity (`pkg/client/client.go:665-670`): an empty message
        // is "could not get register response"; anything other than
        // "registration successful" is a failed registration, not a 200-OK
        // that silently lies about the server state.
        let parsed: RegisterResponse = serde_json::from_str(body.trim())
            .map_err(|e| protocol_error(format!("register json: {e}")))?;
        if parsed.message.is_empty() {
            return Err(protocol_error("could not get register response"));
        }
        if parsed.message != "registration successful" {
            return Err(protocol_error(format!(
                "register rejected: {}",
                parsed.message
            )));
        }
        Ok(())
    }

    fn raw_to_interaction(raw: &[u8], session: &OastSessionRow) -> DomainResult<Interaction> {
        let to: RawInteraction = serde_json::from_slice(raw)
            .map_err(|e| protocol_error(format!("interaction json: {e}")))?;
        Ok(Interaction {
            protocol: to.protocol,
            unique_id: to.unique_id,
            // Server decrypts to `{full-id}` = the full label + payload domain.
            // The correlation key we persist (what `oast_labels` and the fuzz
            // `case_index` map key on) is the label itself — trim the domain
            // suffix so one interaction maps to exactly one label.
            full_id: Self::normalize_full_id(&to.full_id, session.domain.as_deref()),
            remote_address: to.remote_address,
            raw_request: to.raw_request,
            raw_response: to.raw_response,
            timestamp: to.timestamp,
        })
    }

    fn normalize_full_id(full_id: &str, domain: Option<&str>) -> String {
        if let Some(domain) = domain {
            let suffix = format!(".{}", domain.trim_end_matches('.'));
            if let Some(label) = full_id.strip_suffix(&suffix) {
                return label.to_string();
            }
        }
        // Labels never contain `.` (xid + zbase32 alphabet), so stripping
        // everything after the first dot is safe even without a domain.
        full_id.split('.').next().unwrap_or(full_id).to_string()
    }
}

impl OastProvider for InteractshProvider {
    fn kind(&self) -> OastProviderKind {
        OastProviderKind::Interactsh
    }

    async fn register(&self, opts: &RegisterOptions) -> DomainResult<ProviderRegistration> {
        // RSA-2048 keygen is 100ms+ of CPU; keep it off the async worker
        // threads (house rule: no blocking calls inside async fns).
        let (private_pem, public_b64) = tokio::task::spawn_blocking(helpers::generate_rsa_keypair)
            .await
            .map_err(|e| provider_error(format!("interactsh keygen join: {e}")))??;
        let correlation_id = helpers::anonymous_correlation_id();
        let secret = uuid::Uuid::new_v4().to_string();
        let first_label = helpers::mint_label(&correlation_id);
        let payload_url = format!("{}.{}", first_label, opts.domain.trim_end_matches('.'));

        let body = serde_json::to_vec(&RegisterRequest {
            public_key: public_b64.clone(),
            secret_key: secret.clone(),
            correlation_id: correlation_id.clone(),
        })
        .map_err(|e| provider_error(format!("register encode: {e}")))?;
        let body_text = self
            .post_json(
                &Self::url(&opts.server, "register"),
                &opts.token,
                &body,
                "interactsh register",
            )
            .await?;
        self.check_register_response(body_text)?;

        Ok(ProviderRegistration {
            payload_url,
            unique_id: correlation_id.clone(),
            correlation_id: Some(correlation_id),
            secret: Some(secret),
            rsa_private_key_pem: Some(private_pem),
            rsa_public_key_pem: Some(public_b64),
            provider_meta: None,
            first_label,
        })
    }

    async fn new_url(&self, session: &OastSessionRow) -> DomainResult<String> {
        let correlation_id = session
            .correlation_id
            .as_deref()
            .ok_or_else(|| protocol_error("session missing correlation id"))?;
        let domain = session
            .domain
            .as_deref()
            .ok_or_else(|| protocol_error("session missing payload domain"))?;
        let label = helpers::mint_label(correlation_id);
        Ok(format!("{label}.{}", domain.trim_end_matches('.')))
    }

    async fn poll(&self, session: &OastSessionRow) -> DomainResult<Vec<Interaction>> {
        let correlation_id = session
            .correlation_id
            .as_deref()
            .ok_or_else(|| protocol_error("session missing correlation id"))?;
        let secret = session
            .secret
            .as_deref()
            .ok_or_else(|| protocol_error("session missing correlation secret"))?;

        let url = format!(
            "{}?id={}&secret={}",
            Self::url(&session.server, "poll"),
            urlencode(correlation_id),
            urlencode(secret)
        );
        let response = self
            .auth_header(
                self.http.get(&url),
                session.provider_token.as_deref().unwrap_or(""),
            )
            .send()
            .await
            .map_err(|e| {
                provider_error(Self::redact_query_secret(format!("interactsh poll: {e}")))
            })?;
        let status = response.status();
        if !status.is_success() {
            // The server wraps storage misses as HTTP 400 with the storage
            // error text ("...correlation-id...cache"). Surface that as
            // NotFound so the service can mark the session expired.
            if status.as_u16() == 400 {
                let body = response.text().await.unwrap_or_default();
                let snippet: String = body.chars().take(512).collect();
                if snippet.to_ascii_lowercase().contains("correlation") {
                    return Err(crate::domain::DomainError::new(
                        crate::domain::ErrorCode::NotFound,
                        "oast session no longer known to the server (expired or evicted)",
                    ));
                }
                return Err(provider_error("interactsh poll: HTTP 400"));
            }
            return Err(provider_error(format!("interactsh poll: HTTP {status}")));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| provider_error(format!("interactsh poll body: {e}")))?;
        let poll: PollResponse = serde_json::from_slice(&bytes)
            .map_err(|e| protocol_error(format!("interactsh poll json: {e}")))?;

        // 1) encrypted interaction blobs (mainline `data[]`)
        let mut interactions: Vec<Interaction> = Vec::new();
        if let Some(data) = poll.data.filter(|d| !d.is_empty()) {
            let aes_key_b64 = poll
                .aes_key
                .as_deref()
                .ok_or_else(|| protocol_error("poll response missing aes_key"))?;
            let private_pem = session
                .rsa_private_key_pem
                .as_deref()
                .ok_or_else(|| protocol_error("session missing rsa private key"))?;
            let key = helpers::unwrap_aes_key(private_pem, aes_key_b64)?;

            for entry in &data {
                let blob = base64::engine::general_purpose::STANDARD
                    .decode(entry.trim())
                    .map_err(|e| protocol_error(format!("interaction base64: {e}")))?;
                let plain = helpers::aes_ctr_decrypt(&key, &blob)?;
                interactions.push(Self::raw_to_interaction(plain.as_slice(), session)?);
            }
        }

        // 2) `extra` / `tlddata` — plaintext interaction JSON sent by `-auth`
        // servers and for root-TLD captures (`pkg/server/http_server.go:500`).
        for plain_json in poll
            .extra
            .unwrap_or_default()
            .into_iter()
            .chain(poll.tlddata.unwrap_or_default())
        {
            if plain_json.trim().is_empty() {
                continue;
            }
            interactions.push(Self::raw_to_interaction(plain_json.as_bytes(), session)?);
        }
        Ok(interactions)
    }

    async fn deregister(&self, session: &OastSessionRow) -> DomainResult<()> {
        let correlation_id = session
            .correlation_id
            .as_deref()
            .ok_or_else(|| protocol_error("session missing correlation id"))?;
        let secret = session
            .secret
            .as_deref()
            .ok_or_else(|| protocol_error("session missing correlation secret"))?;
        let body = serde_json::to_vec(&DeregisterRequest {
            correlation_id: correlation_id.to_string(),
            secret_key: secret.to_string(),
        })
        .map_err(|e| provider_error(format!("deregister encode: {e}")))?;
        // The service marks the session stopped regardless of this result.
        self.post_json(
            &Self::url(&session.server, "deregister"),
            session.provider_token.as_deref().unwrap_or(""),
            &body,
            "interactsh deregister",
        )
        .await
        .map(|_| ())
    }
}

/// Percent-encode for query strings (correlation ids are alphanumeric but the
/// secret is a UUID; both are safe either way — keep one code path).
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
