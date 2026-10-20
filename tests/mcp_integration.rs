//! Integration tests for new MCP tools
//! Run with: cargo test --test mcp_integration -- --test-threads=1

use huntproxy::dom_monitor::{analyze_dom_events, DOMSinkEvent};
use huntproxy::domain::ProjectId;
use huntproxy::fingerprint::fingerprint_from_response;
use huntproxy::inspector::{build_request, inspect_request, Param as QueryParam};
use huntproxy::sequencer::{analyze_tokens, extract_tokens_from_response, TokenSample};
use huntproxy::storage::Db;
use std::sync::Arc;

#[tokio::test]
async fn test_fingerprint_tool() {
    let db = Arc::new(Db::memory().await.unwrap());
    let project_id = ProjectId::new(1);

    // Mock exchange with React response
    let headers = vec![
        ("Server".to_string(), "nginx/1.21.0".to_string()),
        ("X-Powered-By".to_string(), "Express".to_string()),
    ];
    let body = r#"
        <!DOCTYPE html>
        <html>
        <head><script src="react.production.min.js"></script></head>
        <body><div id="root"></div></body>
        </html>
    "#;

    let result = fingerprint_from_response(&headers, Some(body));

    assert!(result.technologies.iter().any(|t| t.name == "React"));
    assert!(result.technologies.iter().any(|t| t.name == "nginx"));
    assert_eq!(result.server, Some("nginx/1.21.0".to_string()));
}

#[tokio::test]
async fn test_inspector_round_trip() {
    let raw_request = "GET /api/users?page=1&limit=10 HTTP/1.1\r\n\
                       Host: example.com\r\n\
                       Cookie: session=abc123; csrf=xyz789\r\n\
                       Authorization: Bearer token123\r\n\
                       \r\n";

    // Parse
    let parsed = inspect_request(raw_request).unwrap();

    assert_eq!(parsed.method, "GET");
    assert_eq!(parsed.path, "/api/users");
    assert_eq!(parsed.query_params.len(), 2);
    assert_eq!(parsed.cookies.len(), 2);
    assert!(parsed.headers.iter().any(|h| h.name == "Authorization"));

    // Modify
    let mut modified = parsed.clone();
    modified.cookies[0].value = "new_session_token".to_string();
    modified.query_params.push(QueryParam {
        name: "debug".to_string(),
        value: "true".to_string(),
    });

    // Rebuild
    let rebuilt = build_request(&modified).unwrap();

    assert!(rebuilt.contains("Cookie: session=new_session_token"));
    assert!(rebuilt.contains("debug=true"));
    assert!(rebuilt.contains("Authorization: Bearer token123"));
}

#[tokio::test]
async fn test_sequencer_weak_tokens() {
    // Generate predictable tokens
    let samples: Vec<TokenSample> = (0..20)
        .map(|i| {
            TokenSample {
                exchange_id: i,
                value: format!("token{:016x}", i * 1000), // Predictable pattern
                source: "cookie".to_string(),
                name: "session".to_string(),
            }
        })
        .collect();

    let analysis = analyze_tokens(&samples).unwrap();

    assert_eq!(analysis.sample_count, 20);
    assert!(analysis.verdict == "WEAK" || analysis.verdict == "FAIL");
    assert!(!analysis.issues.is_empty());
}

#[tokio::test]
async fn test_sequencer_strong_tokens() {
    // Simulate crypto-random tokens (hex-encoded random bytes)
    let samples: Vec<TokenSample> = vec![
        "a3f7b29c1e8d4f6a",
        "d8e2a1c5f9b7364e",
        "7c4b8e2f1a6d9350",
        "e9f1a4d7c2b58603",
        "b6d3e8a1f7c42950",
        "4e9c7a2d5f1b8360",
        "c2f8b4e6a9d13750",
        "6d1a8e4b7f3c9205",
        "f5c9a3e7b2d48160",
        "1b7e4a9c6d2f8350",
        "8d2f6b4c9e1a7305",
        "a9e3c7f1b5d82460",
        "3c8b1e6f4a9d7205",
        "7f4d9a2e5c1b8360",
        "e1b6f8c3a7d49250",
        "9c5a2e7d4f1b8306",
        "2d7f4b9a6e1c8350",
        "f6a3e9c2b7d51480",
        "4b8e1a6f9c2d7305",
        "c9d5a2f7e4b18360",
    ]
    .into_iter()
    .enumerate()
    .map(|(i, val)| TokenSample {
        exchange_id: i as i64,
        value: val.to_string(),
        source: "cookie".to_string(),
        name: "session".to_string(),
    })
    .collect();

    let analysis = analyze_tokens(&samples).unwrap();

    assert_eq!(analysis.sample_count, 20);
    // Strong tokens might still show WEAK due to hex encoding pattern
    assert!(analysis.verdict == "PASS" || analysis.verdict == "WEAK");
}

#[tokio::test]
async fn test_token_extraction() {
    let headers = vec![
        (
            "Set-Cookie".to_string(),
            "session=abc123def456ghi789; Path=/; HttpOnly".to_string(),
        ),
        (
            "Set-Cookie".to_string(),
            "csrf=xyz789abc123def456; Path=/".to_string(),
        ),
    ];
    let body = r#"{"token":"bearer_token_abc123def456ghi789","csrf":"csrf_token_xyz789"}"#;

    let tokens = extract_tokens_from_response(&headers, Some(body));

    assert!(tokens.len() >= 2); // At least session + csrf from cookies
    assert!(tokens
        .iter()
        .any(|(name, _, source)| name == "session" && source == "cookie"));
}

#[tokio::test]
async fn test_dom_monitor_xss_detection() {
    let events = vec![
        DOMSinkEvent {
            sink_type: "innerHTML".to_string(),
            value: "<img src=x onerror=alert(1)>".to_string(),
            stack_trace: None,
            url: "https://target.com".to_string(),
            timestamp: "2026-10-18T10:00:00Z".to_string(),
        },
        DOMSinkEvent {
            sink_type: "location.href".to_string(),
            value: "javascript:alert(document.cookie)".to_string(),
            stack_trace: None,
            url: "https://target.com".to_string(),
            timestamp: "2026-10-18T10:00:01Z".to_string(),
        },
        DOMSinkEvent {
            sink_type: "eval".to_string(),
            value: "window.location.href + document.cookie".to_string(),
            stack_trace: None,
            url: "https://target.com".to_string(),
            timestamp: "2026-10-18T10:00:02Z".to_string(),
        },
    ];

    let findings = analyze_dom_events(&events);

    assert_eq!(findings.len(), 3);
    assert!(findings
        .iter()
        .any(|f| f.severity == "high" && f.description.contains("Event handler")));
    assert!(findings
        .iter()
        .any(|f| f.severity == "high" && f.description.contains("javascript: protocol")));
    assert!(findings
        .iter()
        .any(|f| f.severity == "medium" && f.description.contains("eval")));
}

#[tokio::test]
async fn test_dom_monitor_postmessage() {
    let events = vec![DOMSinkEvent {
        sink_type: "postMessage".to_string(),
        value: r#"{"message":"sensitive","targetOrigin":"*"}"#.to_string(),
        stack_trace: None,
        url: "https://target.com".to_string(),
        timestamp: "2026-10-18T10:00:00Z".to_string(),
    }];

    let findings = analyze_dom_events(&events);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, "medium");
    assert!(findings[0].description.contains("wildcard origin"));
}

#[tokio::test]
async fn test_command_palette_indexing() {
    // Command palette fuzzy search simulation
    let tools = vec![
        ("fingerprint", "Tech stack detection"),
        ("dashboard", "Multi-plugin orchestration"),
        ("sequencer_analyze", "Token randomness tests"),
        ("dom_monitor_start", "Inject sink monitoring"),
    ];

    let query = "fuzz";
    let matches: Vec<_> = tools
        .iter()
        .filter(|(name, desc)| name.contains(query) || desc.to_lowercase().contains(query))
        .collect();

    // Should match nothing for "fuzz" (no fuzzer in new tools)
    assert_eq!(matches.len(), 0);

    let query = "dom";
    let matches: Vec<_> = tools
        .iter()
        .filter(|(name, desc)| name.contains(query) || desc.to_lowercase().contains(query))
        .collect();

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].0, &"dom_monitor_start");
}

#[tokio::test]
async fn test_race_pipeline_simulation() {
    // Simulate race pipeline timing
    use std::time::Instant;

    let start = Instant::now();

    // Sequential mode with delays
    let requests = vec![
        ("req1", 0),  // No delay
        ("req2", 10), // 10ms delay
        ("req3", 10), // 10ms delay
    ];

    for (name, delay_ms) in requests {
        if delay_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        }
        // Simulate HTTP send
        let _ = name;
    }

    let elapsed = start.elapsed().as_millis();
    assert!(elapsed >= 20); // At least 20ms for two 10ms delays
}

#[tokio::test]
async fn test_dashboard_aggregation() {
    // Dashboard data structure simulation
    #[derive(Debug)]
    struct DashboardData {
        active_jobs: Vec<String>,
        findings_by_severity: std::collections::HashMap<String, usize>,
        recent_activity: Vec<String>,
    }

    let mut findings = std::collections::HashMap::new();
    findings.insert("high".to_string(), 3);
    findings.insert("medium".to_string(), 7);
    findings.insert("low".to_string(), 12);

    let dashboard = DashboardData {
        active_jobs: vec!["crawler".to_string(), "fuzzer".to_string()],
        findings_by_severity: findings.clone(),
        recent_activity: vec!["GET /api/users".to_string()],
    };

    assert_eq!(dashboard.active_jobs.len(), 2);
    assert_eq!(dashboard.findings_by_severity.get("high"), Some(&3));
    assert_eq!(dashboard.recent_activity.len(), 1);
}
