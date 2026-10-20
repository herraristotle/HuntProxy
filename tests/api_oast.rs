//! OAST integration: register → new_url → poll against a mock interactsh
//! server, per `docs/specs/SPEC-oast.md`. The encrypted poll fixture is
//! generated in-test with the exact parameters `src/oast/helpers.rs`
//! decrypts with (RSA-OAEP-SHA256 aes_key unwrap, AES-256-CTR with a
//! leading 16-byte IV), so this exercises the full decrypt path the
//! service-level unit tests stub out.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ctr::cipher::{KeyIvInit, StreamCipher};
use huntproxy::app::bootstrap_state;
use huntproxy::config::{Config, OastConfig, OastProviderKind};
use rand::RngCore;
use rand0::rngs::OsRng;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha256;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

const POLL_DOMAIN: &str = "oast.test";

#[derive(Clone, Default)]
struct Capture {
    /// `POST /register` body (carries the public key the server will use).
    registration: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    /// Label minted by `new_url` (what the fixture's `full-id` must trim to).
    label: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

fn oast_config(server: &str) -> OastConfig {
    OastConfig {
        provider: Some(OastProviderKind::Interactsh),
        server: server.to_string(),
        domain: POLL_DOMAIN.to_string(),
        token: String::new(),
        poll_timeout_ms: 10_000,
        auto_poll: false,
        poll_interval_ms: 1_000,
    }
}

async fn test_state(
    oast: OastConfig,
) -> (
    TempDir,
    std::sync::Arc<huntproxy::app::AppState>,
    huntproxy::domain::ProjectId,
) {
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        data_dir: directory.path().to_path_buf(),
        spool_dir: directory.path().join("spool"),
        export_dir: directory.path().join("exports"),
        runtime_dir: directory.path().join("runtime"),
        plugin_dir: directory.path().join("plugins"),
        browser_worker_path: Some(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("browser-worker")
                .join("index.js"),
        ),
        oast,
        ..Config::default()
    };
    let state = bootstrap_state(config).await.unwrap();
    let project = state
        .db
        .create_project(huntproxy::domain::CreateProjectRequest {
            name: "OAST integration".into(),
            target_url: "https://example.com/".into(),
            advanced: None,
        })
        .await
        .unwrap();
    (directory, state, project.id)
}

/// Mount `POST /register` (capturing the public key) and `GET /poll`
/// (encrypting a live fixture from the captured key + minted label).
async fn mount_provider_mocks(server: &MockServer, capture: &Capture) {
    let registration = capture.registration.clone();
    Mock::given(method("POST"))
        .and(path("/register"))
        .respond_with(move |req: &Request| {
            let slot = registration.clone();
            async move {
                if let Some(body) = &req.body {
                    *slot.lock().expect("register body") =
                        Some(String::from_utf8_lossy(body).into_owned());
                }
                // Mainline contract: a 200 that does not say "registration
                // successful" is a failed registration.
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "message": "registration successful" }))
            }
        })
        .expect(1)
        .mount(server)
        .await;

    let registration = capture.registration.clone();
    let label_slot = capture.label.clone();
    Mock::given(method("GET"))
        .and(path("/poll"))
        .respond_with(move |_req: &Request| {
            let registration = registration.clone();
            let label_slot = label_slot.clone();
            async move {
                let body = registration
                    .lock()
                    .expect("register body")
                    .clone()
                    .expect("register ran before poll");
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
                let public_key_b64 = parsed["public-key"].as_str().unwrap().to_string();
                let pem = String::from_utf8(B64.decode(public_key_b64).unwrap()).unwrap();
                let public = RsaPublicKey::from_public_key_pem(&pem).unwrap();
                let label = label_slot
                    .lock()
                    .expect("label")
                    .clone()
                    .expect("new_url ran before poll");

                let mut aes_key = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut aes_key);
                let wrapped = public
                    .encrypt(&mut OsRng, Oaep::new::<Sha256>(), &aes_key)
                    .unwrap();
                let interaction = serde_json::json!({
                    "protocol": "dns",
                    "unique-id": format!("{label}.{POLL_DOMAIN}"),
                    "full-id": format!("{label}.{POLL_DOMAIN}"),
                    "remote-address": "10.0.0.7:53",
                    "raw-request": ";; QUESTION\nexample.com. IN TXT",
                    "raw-response": "",
                    "timestamp": "2026-10-16T00:00:00Z"
                });
                let mut plaintext = serde_json::to_vec(&interaction).unwrap();
                let iv: [u8; 16] = rand::random();
                let mut cipher = Aes256Ctr::new(&aes_key, &iv);
                cipher.apply_keystream(&mut plaintext);
                let mut blob = iv.to_vec();
                blob.extend_from_slice(&plaintext);
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": [B64.encode(&blob)],
                    "aes_key": B64.encode(&wrapped)
                }))
            }
        })
        .mount(server)
        .await;
}

#[tokio::test]
async fn oast_register_new_url_poll_decrypts_dedupes_and_correlates() {
    let server = MockServer::start().await;
    let capture = Capture::default();
    mount_provider_mocks(&server, &capture).await;

    let (_dir, state, project) = test_state(oast_config(&server.uri())).await;

    // No pollution: the config seed resolves the interactsh provider.
    let session = state
        .oast
        .create(project, Some("integration".into()), true, None)
        .await
        .unwrap();
    assert_eq!(session.provider, "interactsh");
    assert_eq!(session.status, "active");

    let url = state
        .oast
        .new_url(project, session.session_id, Some(3))
        .await
        .unwrap();
    assert!(
        url.payload_url.ends_with(&format!(".{POLL_DOMAIN}")),
        "payload url on the provider domain: {}",
        url.payload_url
    );
    assert!(
        url.payload_url == format!("{}.{}", url.label, POLL_DOMAIN),
        "payload url is label-at-domain: {}",
        url.payload_url
    );
    *capture.label.lock().expect("label slot") = Some(url.label.clone());

    // Distinct case indexes mint distinct labels.
    let second = state
        .oast
        .new_url(project, session.session_id, Some(4))
        .await
        .unwrap();
    assert_ne!(second.label, url.label);

    let fresh = state.oast.poll(project, session.session_id).await.unwrap();
    assert_eq!(
        fresh.len(),
        1,
        "first poll publishes the decryptable interaction"
    );
    let hit = &fresh[0];
    assert_eq!(hit.protocol, "dns");
    // The provider trims the payload domain so full_id equals the minted
    // label — the exact key `mcp oast_poll` correlates on.
    assert_eq!(hit.full_id, url.label);
    assert_eq!(hit.raw_request, ";; QUESTION\nexample.com. IN TXT");

    // Re-polling the same server response dedupes at the store: nothing new.
    let second_poll = state.oast.poll(project, session.session_id).await.unwrap();
    assert!(
        second_poll.is_empty(),
        "dedupe across polls must hold: {second_poll:?}"
    );

    // Persistence + exact-label filtering.
    let page = state
        .oast
        .interactions(
            project,
            session.session_id,
            Some(url.label.clone()),
            Some(50),
            Some(0),
        )
        .await
        .unwrap();
    assert_eq!(page.total, 1);
    let page_other_label = state
        .oast
        .interactions(
            project,
            session.session_id,
            Some(second.label.clone()),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        page_other_label.total, 0,
        "interactions belong to one label"
    );

    // Cross-project reads are rejected (project scoping).
    let other = state
        .db
        .create_project(huntproxy::domain::CreateProjectRequest {
            name: "other".into(),
            target_url: "https://example.net/".into(),
            advanced: None,
        })
        .await
        .unwrap();
    assert!(state.oast.poll(other.id, session.session_id).await.is_err());
    assert!(state
        .oast
        .interactions(other.id, session.session_id, None, None, None)
        .await
        .is_err());
}
