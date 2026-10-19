//! Structured HTTP request/response editing for AI agents.
//! Parse headers/params/cookies into editable structures, rebuild HTTP after edits.

use crate::domain::{DomainError, DomainResult};
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<Header>,
    pub query_params: Vec<Param>,
    pub cookies: Vec<Cookie>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredResponse {
    pub status: u16,
    pub headers: Vec<Header>,
    pub cookies: Vec<Cookie>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
}

/// Parse raw HTTP request into structured components
pub fn parse_request(raw: &str) -> DomainResult<StructuredRequest> {
    let mut lines = raw.lines();

    // Parse request line
    let request_line = lines
        .next()
        .ok_or_else(|| DomainError::invalid("empty request"))?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(DomainError::invalid("invalid request line"));
    }

    let method = parts[0].to_string();
    let url_raw = parts[1];

    // Parse URL and query params
    let (path, query) = match url_raw.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q)),
        None => (url_raw.to_string(), None),
    };

    let mut query_params = Vec::new();
    if let Some(q) = query {
        for pair in q.split('&') {
            if let Some((name, value)) = pair.split_once('=') {
                query_params.push(Param {
                    name: percent_decode_str(name).decode_utf8()?.into_owned(),
                    value: percent_decode_str(value).decode_utf8()?.into_owned(),
                });
            } else {
                query_params.push(Param {
                    name: percent_decode_str(pair).decode_utf8()?.into_owned(),
                    value: String::new(),
                });
            }
        }
    }

    // Parse headers
    let mut headers = Vec::new();
    let mut cookies = Vec::new();
    let mut host = None;
    let mut body_start = 0;

    for (idx, line) in lines.enumerate() {
        if line.is_empty() {
            body_start = idx + 2; // +2 for request line + blank line
            break;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();

            if name.eq_ignore_ascii_case("cookie") {
                // Parse cookies
                for cookie_pair in value.split(';') {
                    if let Some((cname, cvalue)) = cookie_pair.trim().split_once('=') {
                        cookies.push(Cookie {
                            name: cname.trim().to_string(),
                            value: cvalue.trim().to_string(),
                        });
                    }
                }
            } else {
                if name.eq_ignore_ascii_case("host") {
                    host = Some(value.clone());
                }
                headers.push(Header { name, value });
            }
        }
    }

    // Build full URL
    let url = if path.starts_with("http://") || path.starts_with("https://") {
        path
    } else if let Some(h) = host {
        format!("https://{}{}", h, path)
    } else {
        path
    };

    // Extract body
    let body = if body_start > 0 {
        let all_lines: Vec<&str> = raw.lines().collect();
        if body_start < all_lines.len() {
            Some(all_lines[body_start..].join("\n"))
        } else {
            None
        }
    } else {
        None
    };

    Ok(StructuredRequest {
        method,
        url,
        headers,
        query_params,
        cookies,
        body,
    })
}

/// Rebuild raw HTTP request from structured components
pub fn build_request(req: &StructuredRequest) -> DomainResult<String> {
    let mut output = String::new();

    // Parse URL to get path and host
    let url = url::Url::parse(&req.url)
        .map_err(|e| DomainError::invalid(format!("invalid URL: {}", e)))?;

    let path_and_query = if let Some(q) = url.query() {
        format!("{}?{}", url.path(), q)
    } else {
        url.path().to_string()
    };

    // Request line with rebuilt query params
    let final_query = if req.query_params.is_empty() {
        String::new()
    } else {
        let params: Vec<String> = req
            .query_params
            .iter()
            .map(|p| {
                format!(
                    "{}={}",
                    utf8_percent_encode(&p.name, NON_ALPHANUMERIC),
                    utf8_percent_encode(&p.value, NON_ALPHANUMERIC)
                )
            })
            .collect();
        format!("?{}", params.join("&"))
    };

    let path_part = url.path();
    output.push_str(&format!(
        "{} {}{} HTTP/1.1\r\n",
        req.method, path_part, final_query
    ));

    // Host header (ensure it exists)
    let mut has_host = false;
    for h in &req.headers {
        if h.name.eq_ignore_ascii_case("host") {
            has_host = true;
            break;
        }
    }
    if !has_host {
        if let Some(host) = url.host_str() {
            output.push_str(&format!("Host: {}\r\n", host));
        }
    }

    // Headers (except Cookie, we rebuild it)
    for h in &req.headers {
        if !h.name.eq_ignore_ascii_case("cookie") {
            output.push_str(&format!("{}: {}\r\n", h.name, h.value));
        }
    }

    // Cookie header (rebuilt from cookies list)
    if !req.cookies.is_empty() {
        let cookie_str: Vec<String> = req
            .cookies
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        output.push_str(&format!("Cookie: {}\r\n", cookie_str.join("; ")));
    }

    // Body
    output.push_str("\r\n");
    if let Some(body) = &req.body {
        output.push_str(body);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request() {
        let raw = "GET /api/users?page=1&limit=10 HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   Cookie: session=abc123; token=xyz\r\n\
                   User-Agent: test\r\n\
                   \r\n";

        let parsed = parse_request(raw).unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.query_params.len(), 2);
        assert_eq!(parsed.cookies.len(), 2);
        assert_eq!(parsed.cookies[0].name, "session");
    }

    #[test]
    fn test_build_request() {
        let req = StructuredRequest {
            method: "POST".to_string(),
            url: "https://example.com/api/login".to_string(),
            headers: vec![Header {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            }],
            query_params: vec![],
            cookies: vec![Cookie {
                name: "csrf".to_string(),
                value: "token123".to_string(),
            }],
            body: Some(r#"{"user":"admin"}"#.to_string()),
        };

        let rebuilt = build_request(&req).unwrap();
        assert!(rebuilt.contains("POST /api/login HTTP/1.1"));
        assert!(rebuilt.contains("Cookie: csrf=token123"));
        assert!(rebuilt.contains(r#"{"user":"admin"}"#));
    }
}
