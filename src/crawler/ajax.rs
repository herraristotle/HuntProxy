//! AJAX and SPA endpoint discovery for modern web applications.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AjaxEndpoint {
    pub url: String,
    pub method: String,
    pub source: AjaxSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AjaxSource {
    FetchCall,
    XhrCall,
    AxiosCall,
    JqueryAjax,
    ApiRoute,
    GraphqlEndpoint,
}

/// Extract AJAX endpoints from JavaScript code and HTML.
pub fn extract_ajax_endpoints(base_url: &str, content: &str) -> Vec<AjaxEndpoint> {
    let Ok(base) = Url::parse(base_url) else {
        return Vec::new();
    };

    let mut endpoints = Vec::new();
    let mut seen = HashSet::new();

    // Fetch API calls: fetch('url'), fetch(`url`)
    let fetch_patterns = [
        r#"fetch\s*\(\s*['"`]([^'"`]+)['"`]"#,
        r#"fetch\s*\(\s*`([^`]+)`"#,
    ];

    for pattern in &fetch_patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(content) {
                if let Some(url) = cap.get(1) {
                    let url_str = url.as_str();
                    // Classify before dedup: a fetch('/graphql') would otherwise
                    // occupy the URL and the later API-route pass could not tag it.
                    let source = if url_str.contains("graphql") {
                        AjaxSource::GraphqlEndpoint
                    } else {
                        AjaxSource::FetchCall
                    };
                    if let Some(endpoint) = resolve_endpoint(&base, url_str, source, &mut seen) {
                        endpoints.push(endpoint);
                    }
                }
            }
        }
    }

    // XMLHttpRequest: xhr.open('METHOD', 'url')
    let xhr_pattern = r#"\.open\s*\(\s*['"](\w+)['"]\s*,\s*['"`]([^'"`]+)['"`]"#;
    if let Ok(re) = Regex::new(xhr_pattern) {
        for cap in re.captures_iter(content) {
            if let (Some(method), Some(url)) = (cap.get(1), cap.get(2)) {
                let method_str = method.as_str().to_uppercase();
                let url_str = url.as_str();
                if let Some(mut endpoint) =
                    resolve_endpoint(&base, url_str, AjaxSource::XhrCall, &mut seen)
                {
                    endpoint.method = method_str;
                    endpoints.push(endpoint);
                }
            }
        }
    }

    // Axios calls: axios.get('url'), axios.post('url'), axios({url: 'url'})
    let axios_patterns = [
        r#"axios\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]"#,
        r#"axios\s*\(\s*\{\s*url\s*:\s*['"`]([^'"`]+)['"`]"#,
    ];

    for pattern in &axios_patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(content) {
                let method = cap
                    .get(1)
                    .map(|m| m.as_str().to_uppercase())
                    .unwrap_or_else(|| "GET".to_string());
                let url_idx = if pattern.contains("axios\\.(") { 2 } else { 1 };

                if let Some(url) = cap.get(url_idx) {
                    let url_str = url.as_str();
                    if let Some(mut endpoint) =
                        resolve_endpoint(&base, url_str, AjaxSource::AxiosCall, &mut seen)
                    {
                        endpoint.method = method;
                        endpoints.push(endpoint);
                    }
                }
            }
        }
    }

    // jQuery AJAX: $.ajax({url: 'url'}), $.get('url'), $.post('url')
    let jquery_patterns = [
        r#"\$\.(get|post)\s*\(\s*['"`]([^'"`]+)['"`]"#,
        r#"\$\.ajax\s*\(\s*\{\s*url\s*:\s*['"`]([^'"`]+)['"`]"#,
    ];

    for pattern in &jquery_patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(content) {
                let method = cap
                    .get(1)
                    .map(|m| m.as_str().to_uppercase())
                    .unwrap_or_else(|| "GET".to_string());
                let url_idx = if pattern.contains("\\.(get|post)") {
                    2
                } else {
                    1
                };

                if let Some(url) = cap.get(url_idx) {
                    let url_str = url.as_str();
                    if let Some(mut endpoint) =
                        resolve_endpoint(&base, url_str, AjaxSource::JqueryAjax, &mut seen)
                    {
                        endpoint.method = method;
                        endpoints.push(endpoint);
                    }
                }
            }
        }
    }

    // API route patterns: /api/, /v1/, /graphql
    let api_pattern = r#"['"`](/(?:api|v\d+|graphql|rest)[^'"`]*?)['"`]"#;
    if let Ok(re) = Regex::new(api_pattern) {
        for cap in re.captures_iter(content) {
            if let Some(url) = cap.get(1) {
                let url_str = url.as_str();
                let source = if url_str.contains("graphql") {
                    AjaxSource::GraphqlEndpoint
                } else {
                    AjaxSource::ApiRoute
                };

                if let Some(endpoint) = resolve_endpoint(&base, url_str, source, &mut seen) {
                    endpoints.push(endpoint);
                }
            }
        }
    }

    // SPA route definitions: { path: '/route' }
    let spa_route_pattern = r#"(?:path|route)\s*:\s*['"`]([^'"`]+)['"`]"#;
    if let Ok(re) = Regex::new(spa_route_pattern) {
        for cap in re.captures_iter(content) {
            if let Some(url) = cap.get(1) {
                let url_str = url.as_str();
                // Only include if it looks like a backend route (starts with /)
                if url_str.starts_with('/') && !url_str.contains('*') && !url_str.contains(':') {
                    if let Some(endpoint) =
                        resolve_endpoint(&base, url_str, AjaxSource::ApiRoute, &mut seen)
                    {
                        endpoints.push(endpoint);
                    }
                }
            }
        }
    }

    endpoints
}

fn resolve_endpoint(
    base: &Url,
    url_str: &str,
    source: AjaxSource,
    seen: &mut HashSet<String>,
) -> Option<AjaxEndpoint> {
    // Skip template variables and obvious non-URLs
    if url_str.contains("${") || url_str.contains("{{") || url_str.starts_with("data:") {
        return None;
    }

    // Try to resolve as absolute or relative URL
    let resolved = if url_str.starts_with("http://") || url_str.starts_with("https://") {
        Url::parse(url_str).ok()?
    } else if url_str.starts_with('/') {
        base.join(url_str).ok()?
    } else {
        // Relative path
        base.join(url_str).ok()?
    };

    let url_string = resolved.to_string();

    // Deduplicate
    if seen.contains(&url_string) {
        return None;
    }
    seen.insert(url_string.clone());

    Some(AjaxEndpoint {
        url: url_string,
        method: "GET".to_string(),
        source,
    })
}

/// Extract API endpoints from common JavaScript frameworks' route definitions.
pub fn extract_framework_routes(content: &str) -> Vec<String> {
    let mut routes = Vec::new();
    let mut seen = HashSet::new();

    // Express.js routes: app.get('/path', ...), router.post('/path', ...)
    let express_pattern =
        r#"(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]"#;
    if let Ok(re) = Regex::new(express_pattern) {
        for cap in re.captures_iter(content) {
            if let Some(route) = cap.get(2) {
                let route_str = route.as_str();
                if !seen.contains(route_str) {
                    seen.insert(route_str.to_string());
                    routes.push(route_str.to_string());
                }
            }
        }
    }

    // FastAPI/Flask: @app.get('/path'), @app.post('/path')
    let python_pattern = r#"@app\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]"#;
    if let Ok(re) = Regex::new(python_pattern) {
        for cap in re.captures_iter(content) {
            if let Some(route) = cap.get(2) {
                let route_str = route.as_str();
                if !seen.contains(route_str) {
                    seen.insert(route_str.to_string());
                    routes.push(route_str.to_string());
                }
            }
        }
    }

    routes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_fetch_calls() {
        let js = r#"
            fetch('/api/users');
            fetch(`/api/posts/${id}`);
            fetch("https://example.com/api/data");
        "#;

        let endpoints = extract_ajax_endpoints("https://example.com", js);
        assert!(endpoints.iter().any(|e| e.url.contains("/api/users")));
        assert!(endpoints.iter().any(|e| e.source == AjaxSource::FetchCall));
    }

    #[test]
    fn extract_xhr_with_method() {
        let js = r#"
            xhr.open('POST', '/api/submit');
            xhr.open("GET", "/api/fetch");
        "#;

        let endpoints = extract_ajax_endpoints("https://example.com", js);
        let post_endpoint = endpoints
            .iter()
            .find(|e| e.url.contains("/api/submit"))
            .unwrap();
        assert_eq!(post_endpoint.method, "POST");
        assert_eq!(post_endpoint.source, AjaxSource::XhrCall);
    }

    #[test]
    fn extract_axios_calls() {
        let js = r#"
            axios.get('/api/users');
            axios.post('/api/create');
            axios({url: '/api/data'});
        "#;

        let endpoints = extract_ajax_endpoints("https://example.com", js);
        assert!(
            endpoints
                .iter()
                .any(|e| e.url.contains("/api/users") && e.method == "GET")
        );
        assert!(
            endpoints
                .iter()
                .any(|e| e.url.contains("/api/create") && e.method == "POST")
        );
    }

    #[test]
    fn extract_graphql_endpoint() {
        let js = r#"
            fetch('/graphql', {method: 'POST'});
        "#;

        let endpoints = extract_ajax_endpoints("https://example.com", js);
        let graphql = endpoints
            .iter()
            .find(|e| e.url.contains("/graphql"))
            .unwrap();
        assert_eq!(graphql.source, AjaxSource::GraphqlEndpoint);
    }

    #[test]
    fn skip_template_variables() {
        let js = r#"
            fetch(`/api/users/${userId}`);
            fetch('{{apiUrl}}');
        "#;

        let endpoints = extract_ajax_endpoints("https://example.com", js);
        // Should skip template variables
        assert!(endpoints.is_empty());
    }

    #[test]
    fn extract_express_routes() {
        let js = r#"
            app.get('/users', handler);
            router.post('/api/create', handler);
        "#;

        let routes = extract_framework_routes(js);
        assert!(routes.contains(&"/users".to_string()));
        assert!(routes.contains(&"/api/create".to_string()));
    }
}
