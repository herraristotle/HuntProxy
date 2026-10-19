//! Provider unit tests against local wiremock servers (no live network).

use super::custom::CustomProvider;
use super::interactsh::InteractshProvider;
use super::postbin::PostbinProvider;
use super::webhooksite::WebhooksiteProvider;
use super::{OastProvider, RegisterOptions};
use crate::config::OastProviderKind;
use crate::storage::OastSessionRow;
use base64::Engine as _;
use time::OffsetDateTime;
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn http_client() -> std::sync::Arc<wreq::Client> {
    std::sync::Arc::new(wreq::Client::builder().build().unwrap())
}

fn session(kind: &str, server: &str) -> OastSessionRow {
    OastSessionRow {
        id: 1,
        project_id: 1,
        provider_kind: kind.into(),
        correlation_id: None,
        secret: None,
        server: server.into(),
        domain: None,
        rsa_private_key_pem: None,
        rsa_public_key_pem: None,
        provider_meta: None,
        provider_token: None,
        label: None,
        purpose: None,
        watch: true,
        status: "active".into(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        last_polled_at: None,
    }
}

fn opts(server: &str) -> RegisterOptions {
    RegisterOptions {
        server: server.into(),
        token: String::new(),
        domain: "oast.example.com".into(),
    }
}

#[tokio::test]
async fn postbin_register_and_shift_poll() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/bin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "binId": "bin-42"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/bin/bin-42/req/shift"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "body": {"secret": "yes"},
            "headers": {"X-Forwarded-For": "198.51.100.7", "Host": "www.postb.in"},
            "method": "GET",
            "querystring": "a=1",
            "inserted": 1727000000123i64
        })))
        .mount(&server)
        .await;

    let provider = PostbinProvider {
        http: http_client(),
    };
    assert_eq!(provider.kind(), OastProviderKind::Postbin);

    let reg = provider.register(&opts(&server.uri())).await.unwrap();
    assert_eq!(reg.unique_id, "bin-42");
    assert_eq!(reg.payload_url, format!("{}/bin-42", server.uri()));
    assert_eq!(reg.first_label, "bin-42");
    let mut row = session("postbin", &server.uri());
    row.provider_meta = reg.provider_meta;

    let interactions = provider.poll(&row).await.unwrap();
    assert_eq!(interactions.len(), 1);
    let hit = &interactions[0];
    assert_eq!(hit.remote_address, "198.51.100.7");
    assert_eq!(hit.full_id, "bin-42-1727000000123");
    assert!(hit.raw_request.starts_with("GET /bin-42?a=1 HTTP/1.1"));
    assert!(hit.raw_request.contains("X-Forwarded-For: 198.51.100.7"));
    assert!(hit.raw_request.contains("\"secret\": \"yes\""));
    assert!(hit.timestamp.starts_with("2024-"));

    let err = provider.new_url(&row).await.unwrap_err();
    match &err {
        crate::domain::DomainError::App { message, .. } => {
            assert!(message.contains("single session URL"), "message: {message}");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test]
async fn webhooksite_register_and_list_poll() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": "tok-9"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/token/tok-9/requests"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{
                "uuid": "req-1",
                "type": "request",
                "method": "GET",
                "ip": "203.0.113.5",
                "content": "GET /hit HTTP/1.1",
                "created_at": "2026-10-11T00:00:01.000Z",
                "url": "https://webhook.site/tok-9?u=req-1"
            }]
        })))
        .mount(&server)
        .await;

    let provider = WebhooksiteProvider {
        http: http_client(),
    };
    let reg = provider.register(&opts(&server.uri())).await.unwrap();
    assert_eq!(reg.unique_id, "tok-9");
    assert_eq!(reg.payload_url, format!("{}/tok-9", server.uri()));

    let mut row = session("webhooksite", &server.uri());
    row.provider_meta = reg.provider_meta;
    let interactions = provider.poll(&row).await.unwrap();
    assert_eq!(interactions.len(), 1);
    assert_eq!(interactions[0].unique_id, "req-1");
    assert_eq!(interactions[0].remote_address, "203.0.113.5");
    assert_eq!(
        interactions[0].full_id,
        "https://webhook.site/tok-9?u=req-1"
    );
    assert_eq!(interactions[0].timestamp, "2026-10-11T00:00:01.000Z");
}

#[tokio::test]
async fn custom_register_passthrough_and_event_shapes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/events"))
        .and(header("authorization", "Bearer sekret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [
                {"id": "e1", "protocol": "dns", "source": "192.0.2.10",
                 "rawRequest": "A oast.test", "timestamp": 1727000000000i64},
                {"rawResponse": "HTTP/1.1 200"}
            ]
        })))
        .mount(&server)
        .await;

    let provider = CustomProvider {
        http: http_client(),
        token: "sekret".into(),
    };
    let poll_url = format!("{}/events", server.uri());
    let reg = provider
        .register(&RegisterOptions {
            server: poll_url.clone(),
            token: "sekret".into(),
            domain: String::new(),
        })
        .await
        .unwrap();
    assert_eq!(reg.payload_url, poll_url);
    assert_eq!(reg.first_label, poll_url);

    let row = session("custom", &poll_url);
    let interactions = provider.poll(&row).await.unwrap();
    assert_eq!(interactions.len(), 2);
    assert_eq!(interactions[0].protocol, "dns");
    assert_eq!(interactions[0].remote_address, "192.0.2.10");
    assert_eq!(interactions[0].full_id, "e1");
    assert!(interactions[0].timestamp.starts_with("2024-"));
    assert_eq!(interactions[1].protocol, "http");
    assert_eq!(interactions[1].full_id, "custom-1");
    assert!(!interactions[1].timestamp.is_empty());
}

#[tokio::test]
async fn custom_accepts_bare_array_without_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!([{"id": "x", "timestamp": "2026-01-02T03:04:05Z"}]),
            ),
        )
        .mount(&server)
        .await;
    let provider = CustomProvider {
        http: http_client(),
        token: String::new(),
    };
    let row = session("custom", &server.uri());
    let interactions = provider.poll(&row).await.unwrap();
    assert_eq!(interactions.len(), 1);
    assert_eq!(interactions[0].timestamp, "2026-01-02T03:04:05Z");
}

#[tokio::test]
async fn interactsh_register_sends_mainline_shape_and_auth_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/register"))
        .and(header("authorization", "srv-token"))
        .and(body_string_contains("\"public-key\""))
        .and(body_string_contains("\"correlation-id\""))
        .and(body_string_contains("\"secret-key\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "domains": ["oast.example.com"]
        })))
        .mount(&server)
        .await;

    let provider = InteractshProvider {
        http: http_client(),
    };
    let reg = provider
        .register(&RegisterOptions {
            server: server.uri(),
            token: "srv-token".into(),
            domain: "oast.example.com".into(),
        })
        .await
        .unwrap();

    // Correlation id: 20 chars of the xid alphabet.
    let cid = reg.correlation_id.as_deref().unwrap();
    assert_eq!(cid.len(), 20);
    assert!(cid
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='v').contains(&c)));
    // Secret is a UUID v4 string.
    assert_eq!(
        reg.secret.as_deref().unwrap().len(),
        "550e8400-e29b-41d4-a716-446655440000".len()
    );
    // Public key payload decodes to a PEM PUBLIC KEY block.
    let pem = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(reg.rsa_public_key_pem.as_deref().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    // First payload URL = label + configured domain.
    assert_eq!(reg.first_label.len(), 33);
    assert!(reg.payload_url.ends_with(".oast.example.com"));
    assert_eq!(reg.payload_url.len(), 33 + ".oast.example.com".len());

    // Empty poll data → no interactions, no decryption attempted. The mock
    // asserts the exact `id`/`secret` query pair produced by register.
    Mock::given(method("GET"))
        .and(path("/poll"))
        .and(query_param("id", cid))
        .and(query_param("secret", reg.secret.as_deref().unwrap()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
        .expect(1)
        .mount(&server)
        .await;
    let mut row = session("interactsh", &server.uri());
    row.correlation_id = reg.correlation_id.clone();
    row.secret = reg.secret.clone();
    row.rsa_private_key_pem = reg.rsa_private_key_pem.clone();
    row.domain = Some("oast.example.com".into());
    let interactions = provider.poll(&row).await.unwrap();
    assert!(interactions.is_empty());
}

#[tokio::test]
async fn interactsh_new_url_mints_distinct_labels_on_one_session() {
    let provider = InteractshProvider {
        http: http_client(),
    };
    let mut row = session("interactsh", "https://oast.example.com");
    row.correlation_id = Some("abcdefghij0123456789".into());
    row.domain = Some("oast.example.com".into());
    let a = provider.new_url(&row).await.unwrap();
    let b = provider.new_url(&row).await.unwrap();
    assert_ne!(a, b);
    assert_eq!(a.len(), 33 + ".oast.example.com".len());
    assert!(a.starts_with("abcdefghij0123456789"));
    assert!(a.ends_with(".oast.example.com"));
}
