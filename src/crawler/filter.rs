//! In-memory evaluation of HuntProxy's native query DSL against candidate
//! URLs during crawling. Same grammar and operators as History search;
//! only URL-context fields are evaluable at link-discovery time.

use regex::Regex;
use url::Url;

use crate::domain::{DomainError, DomainResult, ErrorCode};
use crate::history::{parse_text_query, validate_filter, FilterNode};

/// Fields evaluable against a candidate URL + method (no response yet).
const URL_FIELDS: &[&str] = &["host", "authority", "path", "query", "method"];

fn invalid(msg: String) -> DomainError {
    DomainError::new(ErrorCode::InvalidArgument, msg)
}

/// Parse a native-DSL filter string and reject any term on a field that
/// cannot be evaluated at link-discovery time (response fields, etc.).
pub fn parse_crawl_filter(text: &str) -> DomainResult<Option<FilterNode>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let filter = parse_text_query(trimmed)?;
    validate_filter(&filter)?;
    check_url_only(&filter)?;
    Ok(Some(filter))
}

fn check_url_only(node: &FilterNode) -> DomainResult<()> {
    match node {
        FilterNode::And { and } => {
            for child in and {
                check_url_only(child)?;
            }
            Ok(())
        }
        FilterNode::Or { or } => {
            for child in or {
                check_url_only(child)?;
            }
            Ok(())
        }
        FilterNode::Not { not } => check_url_only(not),
        FilterNode::Term { field, .. } => {
            if URL_FIELDS.contains(&field.as_str()) {
                Ok(())
            } else {
                Err(invalid(format!(
                    "crawl filter field `{field}` is not evaluable at link-discovery time (supported: {})",
                    URL_FIELDS.join(", ")
                )))
            }
        }
    }
}

/// Evaluate a parsed filter against a candidate URL and method.
pub fn filter_matches_url(filter: &FilterNode, url: &Url, method: &str) -> bool {
    match filter {
        FilterNode::And { and } => and.iter().all(|n| filter_matches_url(n, url, method)),
        FilterNode::Or { or } => or.iter().any(|n| filter_matches_url(n, url, method)),
        FilterNode::Not { not } => !filter_matches_url(not, url, method),
        FilterNode::Term {
            field,
            op,
            value,
            subfield,
        } => {
            if subfield.is_some() {
                return false;
            }
            match field.as_str() {
                "host" => term_matches(op, value, url.host_str().unwrap_or_default()),
                "authority" => term_matches(op, value, url.host_str().unwrap_or_default()),
                "path" => term_matches(op, value, url.path()),
                // `query:id=*5` is a glob on the query string: literal parts with
                // `*` standing for any run of characters.
                "query" => {
                    let actual = url.query().unwrap_or_default();
                    let pattern = value_str(value);
                    if op == "eq" && pattern.contains('*') {
                        glob_matches(&pattern, actual)
                    } else {
                        term_matches(op, value, actual)
                    }
                }
                "method" => term_matches(op, value, method),
                _ => false,
            }
        }
    }
}

fn term_matches(op: &str, value: &serde_json::Value, actual: &str) -> bool {
    match op {
        "eq" => value_str(value) == actual,
        "ne" => value_str(value) != actual,
        "contains" => actual.contains(&value_str(value)),
        "starts_with" => actual.starts_with(&value_str(value)),
        "ends_with" => actual.ends_with(&value_str(value)),
        "regex" => match compile_regex(value) {
            Some(re) => re.is_match(actual),
            None => false,
        },
        "nregex" => match compile_regex(value) {
            Some(re) => !re.is_match(actual),
            None => true,
        },
        "in" => match value {
            serde_json::Value::Array(items) => items.iter().any(|i| value_str(i) == actual),
            _ => false,
        },
        "exists" => match value {
            serde_json::Value::Bool(true) => !actual.is_empty(),
            serde_json::Value::Bool(false) => actual.is_empty(),
            _ => false,
        },
        _ => false,
    }
}

fn value_str(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `*` glob match against a whole string; every other character is literal.
fn glob_matches(pattern: &str, actual: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == actual;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let first = parts[0];
    let last = parts[parts.len() - 1];
    if first.len() + last.len() > actual.len()
        || !actual.starts_with(first)
        || !actual.ends_with(last)
    {
        return false;
    }
    let mut rest = &actual[first.len()..actual.len() - last.len()];
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(index) => rest = &rest[index + part.len()..],
            None => return false,
        }
    }
    true
}

fn compile_regex(value: &serde_json::Value) -> Option<Regex> {
    let pattern = value_str(value);
    Regex::new(&pattern).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(text: &str) -> FilterNode {
        parse_crawl_filter(text).unwrap().unwrap()
    }

    #[test]
    fn eq_and_contains() {
        let f = filter("path:~/api/");
        let url = Url::parse("https://example.com/api/users").unwrap();
        assert!(filter_matches_url(&f, &url, "GET"));
        let url2 = Url::parse("https://example.com/static/app.js").unwrap();
        assert!(!filter_matches_url(&f, &url2, "GET"));
    }

    #[test]
    fn method_and_and() {
        let f = filter("method:POST AND path:/submit");
        let url = Url::parse("https://x.test/submit").unwrap();
        assert!(filter_matches_url(&f, &url, "POST"));
        assert!(!filter_matches_url(&f, &url, "GET"));
    }

    #[test]
    fn not_or() {
        let f = filter("NOT path:/health OR method:OPTIONS");
        let url = Url::parse("https://x.test/health").unwrap();
        assert!(!filter_matches_url(&f, &url, "GET"));
        assert!(filter_matches_url(&f, &url, "OPTIONS"));
    }

    #[test]
    fn eq_exact() {
        let f = filter("host:example.com");
        let url = Url::parse("https://example.com/a").unwrap();
        assert!(filter_matches_url(&f, &url, "GET"));
        let url2 = Url::parse("https://other.com/a").unwrap();
        assert!(!filter_matches_url(&f, &url2, "GET"));
    }

    #[test]
    fn rejects_response_fields() {
        assert!(parse_crawl_filter("status:200").is_err());
        assert!(parse_crawl_filter("mime:json").is_err());
    }

    #[test]
    fn empty_filter_is_none() {
        assert!(parse_crawl_filter("").unwrap().is_none());
        assert!(parse_crawl_filter("   ").unwrap().is_none());
    }

    #[test]
    fn query_and_starts_with() {
        let f = filter("query:id=*5");
        let url = Url::parse("https://x.test/p?id=15").unwrap();
        assert!(filter_matches_url(&f, &url, "GET"));
        let url2 = Url::parse("https://x.test/p?id=20").unwrap();
        assert!(!filter_matches_url(&f, &url2, "GET"));
    }

    #[test]
    fn regex_op() {
        let f = filter("path=~^/v[0-9]+/");
        let url = Url::parse("https://x.test/v2/users").unwrap();
        assert!(filter_matches_url(&f, &url, "GET"));
        let url2 = Url::parse("https://x.test/users").unwrap();
        assert!(!filter_matches_url(&f, &url2, "GET"));
    }
}
