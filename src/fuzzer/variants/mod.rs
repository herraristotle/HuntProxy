//! Automatic parameter extraction and injection point detection.
//!
//! Variants parse requests to find all injectable locations (URL params,
//! JSON fields, XML nodes, cookies, headers, path segments, multipart fields)
//! without manual insertion point specification.

mod json;
mod multipart;
mod xml;

pub use json::JsonVariant;
pub use multipart::MultipartVariant;
pub use xml::XmlVariant;

use serde::{Deserialize, Serialize};

/// Auto-detected injection point with type information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionPoint {
    pub name: String,
    pub variant_type: VariantType,
    pub location: String,
    pub original_value: String,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VariantType {
    /// URL query parameter: /api?id=123
    UrlQuery,
    /// JSON field: {"user": "admin"}
    Json,
    /// XML node: <user>admin</user>
    Xml,
    /// Cookie value: session=abc123
    Cookie,
    /// Header value: X-Api-Key: secret
    Header,
    /// Path segment: /api/users/{id}/profile
    UrlPath,
    /// Multipart form field
    Multipart,
    /// GraphQL variable
    GraphQl,
    /// OData filter expression
    OData,
}

/// Extract all injection points from a request.
pub fn extract_injection_points(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Vec<InjectionPoint> {
    let mut points = Vec::new();

    // Extract URL query params
    if let Some((_, query)) = url.split_once('?') {
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                points.push(InjectionPoint {
                    name: urlencoding::decode(key).unwrap_or_default().to_string(),
                    variant_type: VariantType::UrlQuery,
                    location: format!("query:{}", key),
                    original_value: urlencoding::decode(value).unwrap_or_default().to_string(),
                    content_type: None,
                });
            }
        }
    }

    // Extract path segments (look for numeric IDs or UUIDs)
    let path_parts: Vec<&str> = url
        .split('?')
        .next()
        .unwrap_or("")
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .skip(1) // Skip host
        .collect();

    for (index, segment) in path_parts.iter().enumerate() {
        // Detect numeric IDs or UUIDs
        if segment.parse::<i64>().is_ok()
            || segment.parse::<uuid::Uuid>().is_ok()
            || (segment.len() > 8 && segment.chars().all(|c| c.is_alphanumeric() || c == '-'))
        {
            points.push(InjectionPoint {
                name: format!("path_segment_{}", index),
                variant_type: VariantType::UrlPath,
                location: format!("path:{}", index),
                original_value: segment.to_string(),
                content_type: None,
            });
        }
    }

    // Extract cookies
    for (key, value) in headers {
        if key.to_lowercase() == "cookie" {
            for cookie in value.split(';') {
                if let Some((name, val)) = cookie.trim().split_once('=') {
                    points.push(InjectionPoint {
                        name: name.to_string(),
                        variant_type: VariantType::Cookie,
                        location: format!("cookie:{}", name),
                        original_value: val.to_string(),
                        content_type: None,
                    });
                }
            }
        }
    }

    // Extract interesting headers (API keys, tokens, custom headers)
    let injectable_headers = [
        "authorization",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-request-id",
        "referer",
        "user-agent",
    ];

    for (key, value) in headers {
        let key_lower = key.to_lowercase();
        if injectable_headers.contains(&key_lower.as_str()) || key_lower.starts_with("x-") {
            points.push(InjectionPoint {
                name: key.clone(),
                variant_type: VariantType::Header,
                location: format!("header:{}", key),
                original_value: value.clone(),
                content_type: None,
            });
        }
    }

    // Extract body-based injection points if present
    if let Some(body_bytes) = body {
        let content_type = headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-type")
            .map(|(_, v)| v.to_lowercase());

        if let Some(ct) = &content_type {
            if ct.contains("application/json") {
                points.extend(JsonVariant::extract(body_bytes));
            } else if ct.contains("application/xml") || ct.contains("text/xml") {
                points.extend(XmlVariant::extract(body_bytes));
            } else if ct.contains("multipart/form-data") {
                if let Some(boundary) = extract_boundary(ct) {
                    points.extend(MultipartVariant::extract(body_bytes, &boundary));
                }
            } else if ct.contains("application/graphql") || (ct.contains("application/json") && is_graphql_query(body_bytes)) {
                points.extend(extract_graphql_variables(body_bytes));
            }
        }
    }

    points
}

fn extract_boundary(content_type: &str) -> Option<String> {
    content_type
        .split(';')
        .find_map(|part| part.trim().strip_prefix("boundary="))
        .map(|b| b.trim_matches('"').to_string())
}

fn is_graphql_query(body: &[u8]) -> bool {
    if let Ok(text) = std::str::from_utf8(body) {
        text.contains("query") || text.contains("mutation")
    } else {
        false
    }
}

fn extract_graphql_variables(body: &[u8]) -> Vec<InjectionPoint> {
    let Ok(text) = std::str::from_utf8(body) else {
        return Vec::new();
    };

    let Ok(json): Result<serde_json::Value, _> = serde_json::from_str(text) else {
        return Vec::new();
    };

    let Some(variables) = json.get("variables").and_then(|v| v.as_object()) else {
        return Vec::new();
    };

    variables
        .iter()
        .filter_map(|(key, value)| {
            Some(InjectionPoint {
                name: key.clone(),
                variant_type: VariantType::GraphQl,
                location: format!("graphql:{}", key),
                original_value: value.to_string(),
                content_type: Some("application/graphql".to_string()),
            })
        })
        .collect()
}

/// Apply payload to specific injection point, returning modified request.
pub fn apply_payload(
    point: &InjectionPoint,
    payload: &str,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<Vec<u8>>,
) -> (String, Vec<(String, String)>, Option<Vec<u8>>) {
    match point.variant_type {
        VariantType::UrlQuery => {
            let new_url = replace_url_param(url, &point.name, payload);
            (new_url, headers.to_vec(), body)
        }
        VariantType::UrlPath => {
            let new_url = replace_path_segment(url, &point.location, payload);
            (new_url, headers.to_vec(), body)
        }
        VariantType::Cookie => {
            let new_headers = replace_cookie(headers, &point.name, payload);
            (url.to_string(), new_headers, body)
        }
        VariantType::Header => {
            let new_headers = replace_header(headers, &point.name, payload);
            (url.to_string(), new_headers, body)
        }
        VariantType::Json => {
            let new_body = JsonVariant::apply(body.as_deref().unwrap_or(&[]), &point.location, payload);
            (url.to_string(), headers.to_vec(), Some(new_body))
        }
        VariantType::Xml => {
            let new_body = XmlVariant::apply(body.as_deref().unwrap_or(&[]), &point.location, payload);
            (url.to_string(), headers.to_vec(), Some(new_body))
        }
        VariantType::Multipart => {
            let new_body = body; // Multipart more complex, placeholder
            (url.to_string(), headers.to_vec(), new_body)
        }
        VariantType::GraphQl => {
            let new_body = replace_graphql_variable(body.as_deref().unwrap_or(&[]), &point.name, payload);
            (url.to_string(), headers.to_vec(), Some(new_body))
        }
        VariantType::OData => {
            // OData filters in URL query
            let new_url = replace_url_param(url, &point.name, payload);
            (new_url, headers.to_vec(), body)
        }
    }
}

fn replace_url_param(url: &str, param_name: &str, new_value: &str) -> String {
    let encoded_value = urlencoding::encode(new_value);
    if let Some((base, query)) = url.split_once('?') {
        let new_query = query
            .split('&')
            .map(|pair| {
                if let Some((key, _)) = pair.split_once('=') {
                    let decoded_key = urlencoding::decode(key).unwrap_or_default();
                    if decoded_key == param_name {
                        return format!("{}={}", key, encoded_value);
                    }
                }
                pair.to_string()
            })
            .collect::<Vec<_>>()
            .join("&");
        format!("{}?{}", base, new_query)
    } else {
        url.to_string()
    }
}

fn replace_path_segment(url: &str, location: &str, new_value: &str) -> String {
    // location format: "path:2"
    let index: usize = location.strip_prefix("path:").and_then(|s| s.parse().ok()).unwrap_or(0);

    let (base, query) = url.split_once('?').unwrap_or((url, ""));
    let mut parts: Vec<&str> = base.split('/').collect();

    if index + 1 < parts.len() {
        parts[index + 1] = new_value;
    }

    let new_path = parts.join("/");
    if query.is_empty() {
        new_path
    } else {
        format!("{}?{}", new_path, query)
    }
}

fn replace_cookie(headers: &[(String, String)], cookie_name: &str, new_value: &str) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            if k.to_lowercase() == "cookie" {
                let new_cookie = v
                    .split(';')
                    .map(|part| {
                        if let Some((name, _)) = part.trim().split_once('=') {
                            if name == cookie_name {
                                return format!("{}={}", name, new_value);
                            }
                        }
                        part.to_string()
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                (k.clone(), new_cookie)
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

fn replace_header(headers: &[(String, String)], header_name: &str, new_value: &str) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            if k.eq_ignore_ascii_case(header_name) {
                (k.clone(), new_value.to_string())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

fn replace_graphql_variable(body: &[u8], var_name: &str, new_value: &str) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(body) else {
        return body.to_vec();
    };

    let Ok(mut json): Result<serde_json::Value, _> = serde_json::from_str(text) else {
        return body.to_vec();
    };

    if let Some(variables) = json.get_mut("variables").and_then(|v| v.as_object_mut()) {
        variables.insert(var_name.to_string(), serde_json::Value::String(new_value.to_string()));
    }

    serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec())
}
