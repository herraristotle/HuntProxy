//! History filtering, pagination, summaries, diffs.

use crate::domain::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterNode {
    And {
        and: Vec<FilterNode>,
    },
    Or {
        or: Vec<FilterNode>,
    },
    Not {
        not: Box<FilterNode>,
    },
    Term {
        field: String,
        op: String,
        value: serde_json::Value,
        /// Header name for `header[...]` / `req_header[...]` / `resp_header[...]` terms.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subfield: Option<String>,
    },
}

const ALLOWED_FIELDS: &[&str] = &[
    "exchange_id",
    "host",
    "authority",
    "path",
    "method",
    "protocol",
    "status",
    "mime",
    "source",
    "label",
    "request_size",
    "response_size",
    "duration",
    "title",
    "page_title",
    "display_title",
    "parent",
    "browser_session",
    "capture_session",
    "reply_tab",
    "fuzz_job",
    "request_hash",
    "response_hash",
    "time",
    "error",
    "request",
    "response",
    "header",
    "req_header",
    "resp_header",
];

const HEADER_FIELDS: &[&str] = &["header", "req_header", "resp_header"];

const ALLOWED_OPS: &[&str] = &[
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "contains",
    "starts_with",
    "ends_with",
    "exists",
    "regex",
    "nregex",
];

const MAX_TERMS: usize = 32;
const MAX_DEPTH: usize = 6;
const MAX_INPUT_LEN: usize = 2048;
const MAX_REGEX_LEN: usize = 512;
const MAX_IN_LIST: usize = 64;
const MAX_HEADER_NAME_LEN: usize = 256;

pub fn validate_filter(node: &FilterNode) -> DomainResult<()> {
    validate_filter_depth(node, 0, &mut 0)
}

/// Full request search includes decoded body bytes and is intentionally
/// treated as expensive by API callers (for example, they skip an exact
/// second-pass count). Keep this structural check next to the filter model so
/// every adapter can make the same decision without inspecting generated SQL.
pub fn uses_request_body_search(node: &FilterNode) -> bool {
    match node {
        FilterNode::And { and } => and.iter().any(uses_request_body_search),
        FilterNode::Or { or } => or.iter().any(uses_request_body_search),
        FilterNode::Not { not } => uses_request_body_search(not),
        FilterNode::Term { field, .. } => field == "request",
    }
}

/// `response:~text` may decode and scan every candidate response body, so it
/// is expensive for the same reason `request:~text` is (see
/// [`uses_request_body_search`]).
pub fn uses_response_body_search(node: &FilterNode) -> bool {
    match node {
        FilterNode::And { and } => and.iter().any(uses_response_body_search),
        FilterNode::Or { or } => or.iter().any(uses_response_body_search),
        FilterNode::Not { not } => uses_response_body_search(not),
        FilterNode::Term { field, .. } => field == "response",
    }
}

fn validate_filter_depth(node: &FilterNode, depth: usize, terms: &mut usize) -> DomainResult<()> {
    if depth > MAX_DEPTH {
        return Err(DomainError::invalid("filter nesting too deep"));
    }
    match node {
        FilterNode::And { and } | FilterNode::Or { or: and } => {
            for c in and {
                validate_filter_depth(c, depth + 1, terms)?;
            }
        }
        FilterNode::Not { not } => validate_filter_depth(not, depth + 1, terms)?,
        FilterNode::Term {
            field,
            op,
            value,
            subfield,
        } => {
            *terms += 1;
            if *terms > MAX_TERMS {
                return Err(DomainError::invalid("too many filter terms"));
            }
            if !ALLOWED_FIELDS.contains(&field.as_str()) {
                return Err(DomainError::invalid(format!(
                    "unknown filter field: {field}"
                )));
            }
            if !ALLOWED_OPS.contains(&op.as_str()) {
                return Err(DomainError::invalid(format!(
                    "unknown filter operator: {op}"
                )));
            }
            if HEADER_FIELDS.contains(&field.as_str()) {
                if let Some(name) = subfield {
                    if name.is_empty() {
                        return Err(DomainError::invalid("empty header name"));
                    }
                    if name.len() > MAX_HEADER_NAME_LEN {
                        return Err(DomainError::invalid(format!(
                            "header name too long (max {MAX_HEADER_NAME_LEN} bytes)"
                        )));
                    }
                }
            } else if subfield.is_some() {
                return Err(DomainError::invalid(format!(
                    "field {field} does not support a [name] scope"
                )));
            }
            match op.as_str() {
                "regex" | "nregex" => {
                    let pattern = value
                        .as_str()
                        .ok_or_else(|| DomainError::invalid("regex requires a string pattern"))?;
                    validate_regex_pattern(pattern)?;
                }
                "in" => {
                    let list = value
                        .as_array()
                        .ok_or_else(|| DomainError::invalid("in operator requires an array"))?;
                    if list.is_empty() {
                        return Err(DomainError::invalid("in operator requires a value"));
                    }
                    if list.len() > MAX_IN_LIST {
                        return Err(DomainError::invalid(format!(
                            "in list too long (max {MAX_IN_LIST} values)"
                        )));
                    }
                }
                "exists" => {
                    if !value.is_boolean() {
                        return Err(DomainError::invalid("exists requires a boolean"));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn validate_regex_pattern(pattern: &str) -> DomainResult<()> {
    if pattern.len() > MAX_REGEX_LEN {
        return Err(DomainError::invalid(format!(
            "regex pattern too long (max {MAX_REGEX_LEN} bytes)"
        )));
    }
    regex::Regex::new(pattern)
        .map_err(|error| DomainError::invalid(format!("invalid regex pattern: {error}")))?;
    Ok(())
}

/// Compile filter AST to parameterized SQL WHERE clause (without leading WHERE).
pub fn filter_to_sql(node: &FilterNode) -> DomainResult<(String, Vec<String>)> {
    validate_filter(node)?;
    let mut binds = Vec::new();
    let sql = compile_node(node, &mut binds)?;
    Ok((sql, binds))
}

fn compile_node(node: &FilterNode, binds: &mut Vec<String>) -> DomainResult<String> {
    match node {
        FilterNode::And { and } => {
            if and.is_empty() {
                return Ok("1=1".into());
            }
            let parts: DomainResult<Vec<_>> = and.iter().map(|n| compile_node(n, binds)).collect();
            Ok(format!("({})", parts?.join(" AND ")))
        }
        FilterNode::Or { or } => {
            if or.is_empty() {
                return Ok("1=0".into());
            }
            let parts: DomainResult<Vec<_>> = or.iter().map(|n| compile_node(n, binds)).collect();
            Ok(format!("({})", parts?.join(" OR ")))
        }
        FilterNode::Not { not } => Ok(format!("NOT ({})", compile_node(not, binds)?)),
        FilterNode::Term {
            field,
            op,
            value,
            subfield,
        } => compile_term(field, subfield.as_deref(), op, value, binds),
    }
}

fn col(field: &str) -> DomainResult<&'static str> {
    Ok(match field {
        "exchange_id" => "exchange_id",
        "host" => "host",
        "authority" => "authority",
        "path" => "path",
        "method" => "method",
        "protocol" => "protocol",
        "status" => "status_code",
        "mime" => "mime",
        "source" => "source",
        "request_size" => "request_length",
        "response_size" => "response_length",
        "duration" => "duration_ms",
        "title" => "COALESCE(display_title, page_title)",
        "page_title" => "page_title",
        "display_title" => "display_title",
        "parent" => "parent_exchange_id",
        "browser_session" => "browser_session_id",
        "capture_session" => "capture_session_id",
        "reply_tab" => "reply_tab_id",
        "fuzz_job" => "fuzz_job_id",
        "request_hash" => "request_body_hash",
        "response_hash" => "response_body_hash",
        "time" => "started_at",
        "error" => "error_message",
        "label" => "exchange_id", // special-cased
        other => {
            return Err(DomainError::invalid(format!("unsupported field {other}")));
        }
    })
}

fn compile_term(
    field: &str,
    subfield: Option<&str>,
    op: &str,
    value: &serde_json::Value,
    binds: &mut Vec<String>,
) -> DomainResult<String> {
    if HEADER_FIELDS.contains(&field) {
        return compile_header_term(field, subfield, op, value, binds);
    }
    if field == "label" {
        return compile_label_term(op, value, binds);
    }
    if field == "request" {
        return compile_request_term("request", op, value, binds);
    }
    if field == "response" {
        return compile_request_term("response", op, value, binds);
    }
    let c = col(field)?;
    match op {
        "eq" => {
            binds.push(value_as_string(value)?);
            Ok(format!("{c}=?{}", binds.len()))
        }
        // `IS NOT` keeps rows whose column is NULL (for example failed
        // exchanges with no status); plain `!=` would silently drop them.
        "ne" => {
            binds.push(value_as_string(value)?);
            Ok(format!("{c} IS NOT ?{}", binds.len()))
        }
        "gt" => {
            binds.push(value_as_string(value)?);
            Ok(format!("{c}>?{}", binds.len()))
        }
        "gte" => {
            binds.push(value_as_string(value)?);
            Ok(format!("{c}>=?{}", binds.len()))
        }
        "lt" => {
            binds.push(value_as_string(value)?);
            Ok(format!("{c}<?{}", binds.len()))
        }
        "lte" => {
            binds.push(value_as_string(value)?);
            Ok(format!("{c}<=?{}", binds.len()))
        }
        "contains" => {
            binds.push(format!("%{}%", escape_like(&value_as_string(value)?)));
            Ok(format!("{c} LIKE ?{} ESCAPE '\\'", binds.len()))
        }
        "starts_with" => {
            binds.push(format!("{}%", escape_like(&value_as_string(value)?)));
            Ok(format!("{c} LIKE ?{} ESCAPE '\\'", binds.len()))
        }
        "ends_with" => {
            binds.push(format!("%{}", escape_like(&value_as_string(value)?)));
            Ok(format!("{c} LIKE ?{} ESCAPE '\\'", binds.len()))
        }
        "in" => {
            let arr = value
                .as_array()
                .ok_or_else(|| DomainError::invalid("in operator requires array"))?;
            if arr.is_empty() {
                return Ok("1=0".into());
            }
            let mut placeholders = Vec::new();
            for v in arr {
                binds.push(value_as_string(v)?);
                placeholders.push(format!("?{}", binds.len()));
            }
            Ok(format!("{c} IN ({})", placeholders.join(",")))
        }
        "exists" => {
            let exists = value.as_bool().unwrap_or(true);
            if exists {
                Ok(format!("{c} IS NOT NULL"))
            } else {
                Ok(format!("{c} IS NULL"))
            }
        }
        // The registered `regexp` function returns false for NULL inputs, so
        // `NOT (col REGEXP ...)` keeps NULL rows - matching `ne` semantics.
        "regex" => {
            binds.push(value_as_string(value)?);
            Ok(format!("{c} REGEXP ?{}", binds.len()))
        }
        "nregex" => {
            binds.push(value_as_string(value)?);
            Ok(format!("NOT ({c} REGEXP ?{})", binds.len()))
        }
        other => Err(DomainError::invalid(format!("unsupported op {other}"))),
    }
}

/// `request` and `response` scan the message target (request only), the
/// message headers, and the decoded body. Only `contains` and `regex` are
/// supported; anything else would need an index we do not have.
fn compile_request_term(
    field: &str,
    op: &str,
    value: &serde_json::Value,
    binds: &mut Vec<String>,
) -> DomainResult<String> {
    let (side, body_column, body_fn, target_op) = match (field, op) {
        (field @ ("request" | "response"), "contains") => {
            let side = if field == "request" {
                "request"
            } else {
                "response"
            };
            let value = value_as_string(value)?;
            binds.push(format!("%{}%", escape_like(&value)));
            binds.push(value);
            (
                side,
                format!("{field}_body_id"),
                "huntproxy_body_contains",
                "LIKE ESCAPE",
            )
        }
        (field @ ("request" | "response"), "regex") => {
            let side = if field == "request" {
                "request"
            } else {
                "response"
            };
            let value = value_as_string(value)?;
            binds.push(value.clone());
            binds.push(value);
            (
                side,
                format!("{field}_body_id"),
                "huntproxy_body_regex",
                "REGEXP",
            )
        }
        _ => {
            return Err(DomainError::invalid(format!(
                "{field} supports only the contains and regex operators; use {field}:~text"
            )))
        }
    };
    let pattern_index = binds.len() - 1;
    let body_index = binds.len();
    // `target_op` carries the comparison plus its operands: LIKE needs the
    // ESCAPE clause, REGEXP does not.
    let target = match target_op {
        "LIKE ESCAPE" => format!("LIKE ?{pattern_index} ESCAPE '\\'"),
        _ => format!("REGEXP ?{pattern_index}"),
    };
    let mut clauses: Vec<String> = Vec::new();
    if field == "request" {
        for column in ["method", "scheme", "authority", "path"] {
            clauses.push(format!("{column} {target}"));
        }
        clauses.push(format!("COALESCE(query, '') {target}"));
    }
    clauses.push(format!(
        "EXISTS (SELECT 1 FROM message_headers mh \
         WHERE mh.project_id=exchanges.project_id \
           AND mh.exchange_id=exchanges.exchange_id \
           AND mh.side='{side}' \
           AND (mh.name {target} OR CAST(mh.value AS TEXT) {target}))"
    ));
    clauses.push(format!(
        "EXISTS (SELECT 1 FROM bodies b \
         WHERE b.id=exchanges.{body_column} \
           AND {body_fn}(b.codec, b.content, ?{body_index}))"
    ));
    Ok(format!("({})", clauses.join(" OR ")))
}

/// `header`, `req_header` and `resp_header` scan `message_headers` only -
/// never bodies - which makes them the cheap way to look for a specific
/// header. With a `[name]` scope the name must match (case-insensitively) and
/// the operator applies to the value; without one the operator applies to
/// either the name or the value.
fn compile_header_term(
    field: &str,
    subfield: Option<&str>,
    op: &str,
    value: &serde_json::Value,
    binds: &mut Vec<String>,
) -> DomainResult<String> {
    let side = match field {
        "req_header" => Some("'request'"),
        "resp_header" => Some("'response'"),
        _ => None,
    };
    let mut prefix = String::from(
        "EXISTS (SELECT 1 FROM message_headers mh \
         WHERE mh.project_id=exchanges.project_id \
           AND mh.exchange_id=exchanges.exchange_id",
    );
    if let Some(side) = side {
        prefix.push_str(&format!(" AND mh.side={side}"));
    }
    if let Some(name) = subfield {
        binds.push(name.to_string());
        prefix.push_str(&format!(" AND mh.name=?{} COLLATE NOCASE", binds.len()));
    }
    let (positive_op, negate) = match op {
        "ne" => ("eq", true),
        "nregex" => ("regex", true),
        other => (other, false),
    };
    let condition = match positive_op {
        "exists" => "1=1".to_string(),
        "eq" => {
            binds.push(value_as_string(value)?);
            let n = binds.len();
            if subfield.is_some() {
                format!("CAST(mh.value AS TEXT)=?{n}")
            } else {
                format!("(mh.name=?{n} COLLATE NOCASE OR CAST(mh.value AS TEXT)=?{n})")
            }
        }
        "contains" | "starts_with" | "ends_with" => {
            let raw = escape_like(&value_as_string(value)?);
            let pattern = match positive_op {
                "contains" => format!("%{raw}%"),
                "starts_with" => format!("{raw}%"),
                _ => format!("%{raw}"),
            };
            binds.push(pattern);
            let n = binds.len();
            if subfield.is_some() {
                format!("CAST(mh.value AS TEXT) LIKE ?{n} ESCAPE '\\'")
            } else {
                format!(
                    "(mh.name LIKE ?{n} ESCAPE '\\' \
                     OR CAST(mh.value AS TEXT) LIKE ?{n} ESCAPE '\\')"
                )
            }
        }
        "in" => {
            let arr = value
                .as_array()
                .ok_or_else(|| DomainError::invalid("in operator requires array"))?;
            if arr.is_empty() {
                return Ok("1=0".into());
            }
            let mut placeholders = Vec::with_capacity(arr.len());
            for v in arr {
                binds.push(value_as_string(v)?);
                placeholders.push(format!("?{}", binds.len()));
            }
            let list = placeholders.join(",");
            if subfield.is_some() {
                format!("CAST(mh.value AS TEXT) IN ({list})")
            } else {
                format!("(mh.name IN ({list}) OR CAST(mh.value AS TEXT) IN ({list}))")
            }
        }
        "regex" => {
            let pattern = value_as_string(value)?;
            validate_regex_pattern(&pattern)?;
            binds.push(pattern);
            let n = binds.len();
            if subfield.is_some() {
                format!("CAST(mh.value AS TEXT) REGEXP ?{n}")
            } else {
                format!("(mh.name REGEXP ?{n} OR CAST(mh.value AS TEXT) REGEXP ?{n})")
            }
        }
        other => {
            return Err(DomainError::invalid(format!(
                "operator {other} is not supported for {field}"
            )))
        }
    };
    let clause = format!("{prefix} AND {condition})");
    Ok(if negate {
        format!("NOT ({clause})")
    } else {
        clause
    })
}

fn compile_label_term(
    op: &str,
    value: &serde_json::Value,
    binds: &mut Vec<String>,
) -> DomainResult<String> {
    let prefix = "EXISTS (SELECT 1 FROM exchange_labels el JOIN labels l ON l.id=el.label_id AND l.project_id=el.project_id WHERE el.project_id=exchanges.project_id AND el.exchange_id=exchanges.exchange_id";
    match op {
        "eq" | "ne" => {
            binds.push(value_as_string(value)?);
            let exists = format!("{prefix} AND l.name=?{})", binds.len());
            Ok(if op == "ne" {
                format!("NOT ({exists})")
            } else {
                exists
            })
        }
        "contains" | "starts_with" | "ends_with" => {
            let value = escape_like(&value_as_string(value)?);
            let pattern = match op {
                "contains" => format!("%{value}%"),
                "starts_with" => format!("{value}%"),
                _ => format!("%{value}"),
            };
            binds.push(pattern);
            Ok(format!(
                "{prefix} AND l.name LIKE ?{} ESCAPE '\\')",
                binds.len()
            ))
        }
        "in" => {
            let values = value
                .as_array()
                .ok_or_else(|| DomainError::invalid("in operator requires array"))?;
            if values.is_empty() {
                return Ok("1=0".into());
            }
            let mut placeholders = Vec::with_capacity(values.len());
            for value in values {
                binds.push(value_as_string(value)?);
                placeholders.push(format!("?{}", binds.len()));
            }
            Ok(format!(
                "{prefix} AND l.name IN ({}))",
                placeholders.join(",")
            ))
        }
        "exists" => {
            let clause = format!("{prefix})");
            Ok(if value.as_bool().unwrap_or(true) {
                clause
            } else {
                format!("NOT ({clause})")
            })
        }
        _ => Err(DomainError::invalid(format!(
            "operator {op} is not supported for label"
        ))),
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn value_as_string(v: &serde_json::Value) -> DomainResult<String> {
    match v {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Null => Ok(String::new()),
        _ => Err(DomainError::invalid("unsupported filter value type")),
    }
}

/// Small text syntax: `host:example.com method:GET status>=400`.
/// Bare words search common summary fields; `field:~value` means contains,
/// `field=~pattern` is a regex (`(?i)` for case-insensitivity),
/// `field:[a,b]` matches a list, `has(field)` / `missing(field)` test for
/// presence, and `header["Name"]:value` scopes to one header name.
/// `AND`, `OR`, `NOT`, parentheses, and quoted values are supported.
pub fn parse_text_query(input: &str) -> DomainResult<FilterNode> {
    if input.len() > MAX_INPUT_LEN {
        return Err(DomainError::invalid("filter text too long"));
    }
    let input = input.trim();
    if input.is_empty() {
        return Ok(FilterNode::And { and: vec![] });
    }
    QueryParser::new(tokenize_query(input)?).parse()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum QueryToken {
    Text(String),
    LeftParen,
    RightParen,
}

fn tokenize_query(input: &str) -> DomainResult<Vec<QueryToken>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    // Bracket groups (`label:[a, "b c"]`, `header["X-Name"]`) keep quotes and
    // whitespace verbatim and stay part of the current token, so
    // `header["X-Name"]:value` remains a single term.
    let mut in_bracket = false;
    let mut bracket_quoted = false;
    let flush = |current: &mut String, tokens: &mut Vec<QueryToken>| {
        if !current.is_empty() {
            tokens.push(QueryToken::Text(std::mem::take(current)));
        }
    };
    for character in input.chars() {
        if in_bracket {
            current.push(character);
            if character == '"' {
                bracket_quoted = !bracket_quoted;
            } else if character == ']' && !bracket_quoted {
                in_bracket = false;
            }
            continue;
        }
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            continue;
        }
        if !quoted {
            match character {
                '(' => {
                    flush(&mut current, &mut tokens);
                    tokens.push(QueryToken::LeftParen);
                    continue;
                }
                ')' => {
                    flush(&mut current, &mut tokens);
                    tokens.push(QueryToken::RightParen);
                    continue;
                }
                '[' => {
                    current.push('[');
                    in_bracket = true;
                    bracket_quoted = false;
                    continue;
                }
                character if character.is_whitespace() => {
                    flush(&mut current, &mut tokens);
                    continue;
                }
                _ => {}
            }
        }
        current.push(character);
    }
    if in_bracket {
        return Err(DomainError::invalid("unterminated [ in history filter"));
    }
    if quoted {
        return Err(DomainError::invalid("unterminated quote in history filter"));
    }
    if escaped {
        current.push('\\');
    }
    flush(&mut current, &mut tokens);
    Ok(tokens)
}

struct QueryParser {
    tokens: Vec<QueryToken>,
    position: usize,
}

impl QueryParser {
    fn new(tokens: Vec<QueryToken>) -> Self {
        Self {
            tokens,
            position: 0,
        }
    }

    fn parse(mut self) -> DomainResult<FilterNode> {
        let node = self.parse_or()?;
        if self.position != self.tokens.len() {
            return Err(DomainError::invalid("unexpected token in history filter"));
        }
        Ok(node)
    }

    fn parse_or(&mut self) -> DomainResult<FilterNode> {
        let mut nodes = vec![self.parse_and()?];
        while self.consume_keyword("OR") {
            nodes.push(self.parse_and()?);
        }
        Ok(if nodes.len() == 1 {
            nodes.remove(0)
        } else {
            FilterNode::Or { or: nodes }
        })
    }

    fn parse_and(&mut self) -> DomainResult<FilterNode> {
        let mut nodes = vec![self.parse_not()?];
        loop {
            if self.peek_keyword("OR") || matches!(self.peek(), None | Some(QueryToken::RightParen))
            {
                break;
            }
            let _ = self.consume_keyword("AND");
            nodes.push(self.parse_not()?);
        }
        Ok(if nodes.len() == 1 {
            nodes.remove(0)
        } else {
            FilterNode::And { and: nodes }
        })
    }

    fn parse_not(&mut self) -> DomainResult<FilterNode> {
        if self.consume_keyword("NOT") {
            return Ok(FilterNode::Not {
                not: Box::new(self.parse_not()?),
            });
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> DomainResult<FilterNode> {
        match self.next() {
            Some(QueryToken::Text(text)) => {
                let is_exists = text.eq_ignore_ascii_case("has");
                let is_missing = text.eq_ignore_ascii_case("missing");
                if (is_exists || is_missing) && matches!(self.peek(), Some(QueryToken::LeftParen)) {
                    self.position += 1; // consume '('
                    let field = match self.next() {
                        Some(QueryToken::Text(field)) => field,
                        _ => {
                            return Err(DomainError::invalid(
                                "expected a field name after has(/missing(",
                            ))
                        }
                    };
                    match self.next() {
                        Some(QueryToken::RightParen) => {}
                        _ => {
                            return Err(DomainError::invalid(
                                "missing closing parenthesis after has(/missing(",
                            ))
                        }
                    }
                    let term = make_term(&field, "exists", serde_json::json!(is_exists)).map_err(
                        |error| DomainError::invalid(format!("filter parse error: {error}")),
                    )?;
                    return Ok(term);
                }
                parse_one_term(&text).map_err(|error| {
                    DomainError::invalid(format!("filter parse error at `{text}`: {error}"))
                })
            }
            Some(QueryToken::LeftParen) => {
                let node = self.parse_or()?;
                match self.next() {
                    Some(QueryToken::RightParen) => Ok(node),
                    _ => Err(DomainError::invalid(
                        "missing closing parenthesis in history filter",
                    )),
                }
            }
            Some(QueryToken::RightParen) => {
                Err(DomainError::invalid("unexpected closing parenthesis"))
            }
            None => Err(DomainError::invalid("missing term in history filter")),
        }
    }

    fn peek(&self) -> Option<&QueryToken> {
        self.tokens.get(self.position)
    }

    fn next(&mut self) -> Option<QueryToken> {
        let token = self.tokens.get(self.position).cloned();
        self.position += usize::from(token.is_some());
        token
    }

    fn peek_keyword(&self, expected: &str) -> bool {
        matches!(self.peek(), Some(QueryToken::Text(text)) if text.eq_ignore_ascii_case(expected))
    }

    fn consume_keyword(&mut self, expected: &str) -> bool {
        if self.peek_keyword(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }
}

/// First `:` that is not inside a quoted bracket group (for example the
/// colon in `header["a:b"]:value`).
fn find_value_colon(part: &str) -> Option<usize> {
    let mut quoted = false;
    for (index, character) in part.char_indices() {
        match character {
            '"' => quoted = !quoted,
            ':' if !quoted => return Some(index),
            _ => {}
        }
    }
    None
}

fn parse_one_term(part: &str) -> Result<FilterNode, String> {
    // Comparison and regex operators only apply before the value colon so a
    // value like `path:/a>=b` keeps going through the field:value branch.
    let colon = find_value_colon(part);
    let head = colon.map_or(part, |index| &part[..index]);
    for (symbol, op) in [
        (">=", "gte"),
        ("<=", "lte"),
        ("!=~", "nregex"),
        ("!=", "ne"),
        ("=~", "regex"),
        (">", "gt"),
        ("<", "lt"),
    ] {
        if let Some(index) = head.find(symbol) {
            let value = &part[index + symbol.len()..];
            if op == "regex" || op == "nregex" {
                return make_term(&part[..index], op, serde_json::json!(value));
            }
            return term(&part[..index], op, value);
        }
    }
    if let Some(colon_index) = colon {
        let field = &part[..colon_index];
        let rest = &part[colon_index + 1..];
        if rest.starts_with('[') {
            if !rest.ends_with(']') || rest.len() < 2 {
                return Err("unterminated [ list; use for example status:[404,403]".into());
            }
            return parse_in_list(field, &rest[1..rest.len() - 1]);
        }
        if let Some(value) = rest.strip_prefix('~') {
            return term(field, "contains", value);
        }
        if let Some(v) = rest.strip_prefix('*') {
            if let Some(v) = v.strip_suffix('*') {
                return term(field, "contains", v);
            }
            return term(field, "ends_with", v);
        }
        if let Some(v) = rest.strip_suffix('*') {
            return term(field, "starts_with", v);
        }
        if rest.starts_with(['>', '<']) || rest.starts_with("!=") || rest.starts_with("=~") {
            return Err(
                "comparison and regex operators are written without a colon, \
                 for example status!=404"
                    .into(),
            );
        }
        return term(field, "eq", rest);
    }
    if part.contains('[') {
        return Err("header scope and lists need a value operator, \
            for example header[\"Server\"]:nginx or status:[404,403]"
            .into());
    }
    Ok(FilterNode::Or {
        or: ["host", "authority", "path", "mime", "title", "error"]
            .into_iter()
            .map(|field| term(field, "contains", part).expect("bare fan-out fields are valid"))
            .collect(),
    })
}

fn parse_in_list(field: &str, inner: &str) -> Result<FilterNode, String> {
    let mut items: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in inner.chars() {
        if escaped {
            escaped = false;
            current.push(character);
            continue;
        }
        if character == '\\' {
            escaped = true;
            current.push(character);
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            current.push(character);
            continue;
        }
        if character == ',' && !quoted {
            items.push(std::mem::take(&mut current));
            continue;
        }
        current.push(character);
    }
    if quoted || escaped {
        return Err("unterminated quote in list".into());
    }
    items.push(current);
    let mut values = Vec::with_capacity(items.len());
    for item in items {
        let item = item.trim();
        if item.is_empty() {
            return Err("empty value in list".into());
        }
        if item.starts_with('"') {
            if item.len() < 2 || !item.ends_with('"') {
                return Err("unterminated quote in list".into());
            }
            let unquoted: String = serde_json::from_str(item)
                .map_err(|error| format!("invalid quoted list value: {error}"))?;
            values.push(serde_json::json!(unquoted));
        } else {
            values.push(serde_json::json!(item));
        }
    }
    make_term(field, "in", serde_json::json!(values))
}

/// Splits `header["Content-Type"]` into its base field and header name.
fn split_field(field: &str) -> Result<(String, Option<String>), String> {
    let Some(open) = field.find('[') else {
        return Ok((field.to_string(), None));
    };
    if !field.ends_with(']') {
        return Err("unterminated [ in field name".into());
    }
    let base = &field[..open];
    if base.is_empty() {
        return Err("missing field name before [".into());
    }
    if !HEADER_FIELDS.contains(&base) {
        return Err(format!("field {base} does not support a [name] scope"));
    }
    let raw = &field[open + 1..field.len() - 1];
    let name = if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        serde_json::from_str::<String>(raw)
            .map_err(|error| format!("invalid quoted header name: {error}"))?
    } else {
        raw.to_string()
    };
    if name.is_empty() {
        return Err("empty header name".into());
    }
    if name.len() > MAX_HEADER_NAME_LEN {
        return Err(format!(
            "header name too long (max {MAX_HEADER_NAME_LEN} bytes)"
        ));
    }
    Ok((base.to_string(), Some(name)))
}

fn make_term(field: &str, op: &str, value: serde_json::Value) -> Result<FilterNode, String> {
    let (field, subfield) = split_field(field)?;
    Ok(FilterNode::Term {
        field,
        op: op.to_string(),
        value,
        subfield,
    })
}

fn term(field: &str, op: &str, value: &str) -> Result<FilterNode, String> {
    let value = if let Ok(n) = value.parse::<i64>() {
        serde_json::json!(n)
    } else {
        serde_json::json!(value)
    };
    make_term(field, op, value)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDiff {
    pub status_changed: bool,
    pub parent_status: Option<u16>,
    pub child_status: Option<u16>,
    pub length_delta: Option<i64>,
    pub mime_changed: bool,
    pub body_hash_equal: Option<bool>,
    pub header_added: Vec<String>,
    pub header_removed: Vec<String>,
    pub header_changed: Vec<String>,
    pub text_diff: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub fn diff_exchanges(
    parent_status: Option<u16>,
    child_status: Option<u16>,
    parent_len: Option<i64>,
    child_len: Option<i64>,
    parent_mime: Option<&str>,
    child_mime: Option<&str>,
    parent_hash: Option<&str>,
    child_hash: Option<&str>,
    parent_headers: &[(String, String)],
    child_headers: &[(String, String)],
    parent_body_text: Option<&str>,
    child_body_text: Option<&str>,
) -> ResponseDiff {
    let mut parent_map: std::collections::BTreeMap<String, String> = parent_headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    let child_map: std::collections::BTreeMap<String, String> = child_headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();

    let mut header_added = Vec::new();
    let mut header_removed = Vec::new();
    let mut header_changed = Vec::new();
    for (k, v) in &child_map {
        match parent_map.remove(k) {
            None => header_added.push(k.clone()),
            Some(pv) if pv != *v => header_changed.push(k.clone()),
            _ => {}
        }
    }
    for k in parent_map.keys() {
        header_removed.push(k.clone());
    }

    let text_diff = match (parent_body_text, child_body_text) {
        (Some(a), Some(b)) if a.len() < 64 * 1024 && b.len() < 64 * 1024 => {
            Some(bounded_line_diff(a, b, 50))
        }
        _ => None,
    };

    ResponseDiff {
        status_changed: parent_status != child_status,
        parent_status,
        child_status,
        length_delta: match (parent_len, child_len) {
            (Some(a), Some(b)) => Some(b - a),
            _ => None,
        },
        mime_changed: parent_mime != child_mime,
        body_hash_equal: match (parent_hash, child_hash) {
            (Some(a), Some(b)) => Some(a == b),
            _ => None,
        },
        header_added,
        header_removed,
        header_changed,
        text_diff,
    }
}

fn bounded_line_diff(a: &str, b: &str, max_lines: usize) -> String {
    let al: Vec<&str> = a.lines().collect();
    let bl: Vec<&str> = b.lines().collect();
    let mut out = String::new();
    let max = al.len().max(bl.len()).min(max_lines);
    for i in 0..max {
        let left = al.get(i).copied().unwrap_or("");
        let right = bl.get(i).copied().unwrap_or("");
        if left != right {
            out.push_str(&format!("- {left}\n+ {right}\n"));
        }
    }
    if al.len().max(bl.len()) > max_lines {
        out.push_str(&format!("... truncated after {max_lines} lines\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_query_and_sql() {
        let n = parse_text_query("host:example.com method:GET status>=400").unwrap();
        validate_filter(&n).unwrap();
        let (sql, binds) = filter_to_sql(&n).unwrap();
        assert!(sql.contains("host"));
        assert!(sql.contains("method"));
        assert_eq!(binds.len(), 3);
    }

    #[test]
    fn lineage_ids_and_body_hashes_are_filterable() {
        let filter = parse_text_query(
            "exchange_id:3011 capture_session:42 request_hash:abc response_hash:~def",
        )
        .unwrap();
        let (sql, binds) = filter_to_sql(&filter).unwrap();
        assert!(sql.contains("exchange_id="));
        assert!(sql.contains("capture_session_id="));
        assert!(sql.contains("request_body_hash="));
        assert!(sql.contains("response_body_hash LIKE"));
        assert_eq!(binds, vec!["3011", "42", "abc", "%def%"]);
    }

    #[test]
    fn bare_text_and_tilde_are_contains_searches() {
        let bare = parse_text_query("javascript").unwrap();
        let (sql, binds) = filter_to_sql(&bare).unwrap();
        assert!(sql.contains(" OR "));
        assert!(binds.iter().all(|value| value == "%javascript%"));

        let path = parse_text_query("path:~.js").unwrap();
        let (_, binds) = filter_to_sql(&path).unwrap();
        assert_eq!(binds, vec!["%.js%"]);
    }

    #[test]
    fn request_contains_supports_boolean_or_quotes_and_method() {
        let filter = parse_text_query(
            r#"(request:~"this" OR request:~"that" OR request:~":smtg") method:PUT"#,
        )
        .unwrap();
        let (sql, binds) = filter_to_sql(&filter).unwrap();
        assert!(sql.contains("huntproxy_body_contains"));
        assert!(sql.contains(" OR "));
        assert!(sql.contains(" AND "));
        assert!(sql.contains("method="));
        assert!(binds.iter().any(|value| value == ":smtg"));
        assert!(binds.iter().any(|value| value == "PUT"));
        assert!(uses_request_body_search(&filter));
    }

    #[test]
    fn only_request_terms_are_classified_as_full_body_searches() {
        let ordinary = parse_text_query("host:example.com method:POST").unwrap();
        assert!(!uses_request_body_search(&ordinary));

        let nested = parse_text_query("NOT (status:404 OR request:~needle)").unwrap();
        assert!(uses_request_body_search(&nested));
    }

    #[test]
    fn malformed_boolean_queries_are_rejected() {
        assert!(parse_text_query("method:PUT OR").is_err());
        assert!(parse_text_query("(method:PUT").is_err());
        assert!(parse_text_query(r#"request:~"unfinished"#).is_err());
    }

    #[test]
    fn rejects_unknown_field() {
        let n = FilterNode::Term {
            field: "drop_table".into(),
            op: "eq".into(),
            value: serde_json::json!("x"),
            subfield: None,
        };
        assert!(validate_filter(&n).is_err());
    }

    #[test]
    fn sql_injection_stays_bound() {
        // Text query splits on whitespace; injection payload is a single token.
        let n = parse_text_query("host:a';DROP_TABLE_projects;--").unwrap();
        let (sql, binds) = filter_to_sql(&n).unwrap();
        assert!(!sql.to_lowercase().contains("drop"));
        assert!(binds[0].contains("DROP"));
    }

    fn as_term(node: &FilterNode) -> (&str, Option<&str>, &str, &serde_json::Value) {
        match node {
            FilterNode::Term {
                field,
                op,
                value,
                subfield,
            } => (field, subfield.as_deref(), op, value),
            other => panic!("expected a term, got {other:?}"),
        }
    }

    #[test]
    fn response_search_scans_response_headers_and_body() {
        let filter = parse_text_query(r#"response:~"set-cookie""#).unwrap();
        assert!(uses_response_body_search(&filter));
        assert!(!uses_request_body_search(&filter));
        let (sql, binds) = filter_to_sql(&filter).unwrap();
        assert!(sql.contains("huntproxy_body_contains"));
        assert!(sql.contains("side='response'"));
        assert!(!sql.contains("side='request'"));
        assert!(binds.iter().any(|value| value == "%set-cookie%"));

        let regex = parse_text_query(r"response=~server:\d+").unwrap();
        let (sql, binds) = filter_to_sql(&regex).unwrap();
        assert!(sql.contains("huntproxy_body_regex"));
        assert!(sql.contains("REGEXP"));
        assert!(binds.iter().any(|value| value == "server:\\d+"));
    }

    #[test]
    fn request_regex_uses_body_regex_function() {
        let filter = parse_text_query(r#"request=~"^PUT /admin""#).unwrap();
        let (sql, binds) = filter_to_sql(&filter).unwrap();
        assert!(sql.contains("huntproxy_body_regex"));
        assert!(sql.contains("path REGEXP"));
        assert!(binds.iter().any(|value| value == "^PUT /admin"));
    }

    #[test]
    fn regex_operator_ordering_and_validation() {
        // `!=~` must win over `!=` or the value would come out as `~foo`.
        let node = parse_one_term("path!=~foo").unwrap();
        let (field, _, op, value) = as_term(&node);
        assert_eq!((field, op, value.as_str()), ("path", "nregex", Some("foo")));

        let node = parse_one_term("path=~foo").unwrap();
        let (_, _, op, value) = as_term(&node);
        assert_eq!((op, value.as_str()), ("regex", Some("foo")));

        // Values after the field colon are not scanned for operators.
        let node = parse_one_term("path:/a>=b").unwrap();
        let (_, _, op, value) = as_term(&node);
        assert_eq!((op, value.as_str()), ("eq", Some("/a>=b")));

        let filter = parse_text_query(r#"path=~"(?i)^/api/\d+$""#).unwrap();
        filter_to_sql(&filter).unwrap();

        // Parses fine, but the regex itself is invalid.
        let bad = parse_text_query("path=~+").unwrap();
        assert!(filter_to_sql(&bad).is_err());

        // Unbalanced parens are a parse error, not a validation error.
        assert!(parse_text_query("path=~(").is_err());

        let long = parse_text_query(&format!("path=~{}", "a".repeat(MAX_REGEX_LEN + 1))).unwrap();
        assert!(filter_to_sql(&long).is_err());
    }

    #[test]
    fn in_lists_and_quoted_elements() {
        let node = parse_one_term("status:[404,403]").unwrap();
        let (field, _, op, value) = as_term(&node);
        assert_eq!((field, op), ("status", "in"));
        assert_eq!(value, &serde_json::json!(["404", "403"]));

        let node = parse_one_term(r#"path:["/a,b",/c]"#).unwrap();
        let (_, _, _, value) = as_term(&node);
        assert_eq!(value, &serde_json::json!(["/a,b", "/c"]));

        let filter = parse_text_query("status:[404,403] method:GET").unwrap();
        let (sql, binds) = filter_to_sql(&filter).unwrap();
        assert!(sql.contains("status_code IN (?1,?2)"));
        assert!(binds.iter().any(|value| value == "404"));

        assert!(parse_one_term("status:[]").is_err());
        assert!(parse_one_term("status:[a,]").is_err());
        assert!(parse_one_term("[a,b]").is_err());
        assert!(parse_one_term("status:[a,b").is_err());
        assert!(parse_text_query("status:[a,").is_err());

        let long = parse_text_query(&format!(
            "status:[{}]",
            (0..MAX_IN_LIST + 1)
                .map(|index| index.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ))
        .unwrap();
        assert!(filter_to_sql(&long).is_err());
    }

    #[test]
    fn has_and_missing_test_presence() {
        let node = parse_text_query("has(error)").unwrap();
        let (field, _, op, value) = as_term(&node);
        assert_eq!((field, op), ("error", "exists"));
        assert_eq!(value, &serde_json::json!(true));

        let node = parse_text_query("missing(error)").unwrap();
        let (field, _, op, value) = as_term(&node);
        assert_eq!((field, op), ("error", "exists"));
        assert_eq!(value, &serde_json::json!(false));

        let filter = parse_text_query("has(label) NOT has(error)").unwrap();
        let (sql, _) = filter_to_sql(&filter).unwrap();
        assert!(sql.contains("IS NOT NULL"));
        assert!(sql.contains("NOT ("));

        // Unknown fields are still rejected inside has().
        let bad = parse_text_query("has(drop_table)").unwrap();
        assert!(validate_filter(&bad).is_err());

        // A bare `has`/`missing` word stays a plain full-text search.
        let bare = parse_text_query("has").unwrap();
        let (_, binds) = filter_to_sql(&bare).unwrap();
        assert!(binds.iter().all(|value| value == "%has%"));

        // has() with a bracketed header scope.
        let node = parse_text_query(r#"has(header["Set-Cookie"])"#).unwrap();
        let (field, sub, op, _) = as_term(&node);
        assert_eq!((field, sub, op), ("header", Some("Set-Cookie"), "exists"));
    }

    #[test]
    fn header_terms_are_scoped_and_cheap() {
        let node = parse_one_term(r#"header["Content-Type"]:~json"#).unwrap();
        let (field, sub, op, value) = as_term(&node);
        assert_eq!(
            (field, sub, op),
            ("header", Some("Content-Type"), "contains")
        );
        assert_eq!(value, &serde_json::json!("json"));

        let filter = parse_text_query(r#"req_header["X-Forwarded-For"]:~127"#).unwrap();
        let (sql, binds) = filter_to_sql(&filter).unwrap();
        assert!(sql.contains("side='request'"));
        assert!(sql.contains("COLLATE NOCASE"));
        assert!(!sql.contains("bodies"));
        assert!(!sql.contains("huntproxy_body"));
        assert!(binds.iter().any(|value| value == "%127%"));

        let filter = parse_text_query(r#"resp_header["Server"]:nginx"#).unwrap();
        let (sql, _) = filter_to_sql(&filter).unwrap();
        assert!(sql.contains("side='response'"));
        assert!(sql.contains("CAST(mh.value AS TEXT)=?"));

        // Bare header search matches name or value, any side.
        let filter = parse_text_query(r#"header:~"content-length""#).unwrap();
        let (sql, _) = filter_to_sql(&filter).unwrap();
        assert!(sql.contains("mh.name LIKE"));
        assert!(!sql.contains("mh.side="));

        // Negated header terms exclude exchanges that carry the value.
        let filter = parse_text_query(r#"header["Server"]!=nginx"#).unwrap();
        let (sql, _) = filter_to_sql(&filter).unwrap();
        assert!(sql.starts_with("NOT (EXISTS"));

        // Quoted header names may contain a colon.
        let node = parse_one_term(r#"header["a:b"]:v"#).unwrap();
        let (_, sub, _, _) = as_term(&node);
        assert_eq!(sub, Some("a:b"));

        // [name] scope only makes sense with a value operator.
        assert!(parse_one_term(r#"host["x"]:y"#).is_err());
        assert!(parse_one_term(r#"header[""]:x"#).is_err());
        // Comparison operators are not allowed after the value colon.
        assert!(parse_one_term("status:!=404").is_err());
        let filter = parse_text_query("header:~x").unwrap();
        filter_to_sql(&filter).unwrap();
    }

    #[test]
    fn ne_keeps_null_columns() {
        let filter = parse_text_query("status!=404").unwrap();
        let (sql, binds) = filter_to_sql(&filter).unwrap();
        assert!(sql.contains("status_code IS NOT ?"));
        assert!(!sql.contains("status_code!=?"));
        assert_eq!(binds, vec!["404"]);
    }

    #[test]
    fn value_colon_keeps_comparison_operators_working() {
        let filter = parse_text_query("status>=400 duration>50 time>=2026-01-01T00:00:00").unwrap();
        let (sql, binds) = filter_to_sql(&filter).unwrap();
        assert!(sql.contains("status_code>="));
        assert!(sql.contains("duration_ms>"));
        assert!(sql.contains("started_at>="));
        assert_eq!(binds, vec!["400", "50", "2026-01-01T00:00:00"]);
    }
}
