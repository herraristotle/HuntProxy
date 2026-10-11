//! Import-time translator from the bounded HTTPQL subset observed in Caido
//! workflow store exports into HuntProxy's native query language.
//!
//! HuntProxy has exactly one query language — the same one the History
//! search bar uses — and flows evaluate it through the same compiler.
//! HTTPQL exists here only as a *source* format: `translate_httpql_to_dsl`
//! parses an HTTPQL query (the fields and operators actually seen in the
//! `workflows/` store), builds our `FilterNode` AST directly, prints it
//! back to query text, and refuses the import when the round-trip would
//! change meaning (for example a regex containing `>=`, which our parser
//! would read as a comparison operator).
//!
//! Supported HTTPQL surface: `req.raw`, `req.query`, `req.path`,
//! `req.host`, `req.method`, `resp.raw`, `resp.mime`, `resp.status`; the
//! `cont`, `ncont`, `eq`, `neq`, `like`, `regex`, `gt`, `gte`, `lt`, `lte`
//! operators; and `and` / `or` / `not` (case-insensitive) with parentheses.
//! Anything else is a precise import error, never a guess.

use regex::Regex;

use crate::domain::{DomainError, DomainResult, ErrorCode};
use crate::history::{filter_to_sql, parse_text_query, FilterNode};

/// Cap on the raw query text we will even try to parse.
pub const MAX_HTTPQL_QUERY: usize = 2048;
/// Cap on any single regular expression a `regex:` operator may use.
pub const MAX_HTTPQL_REGEX: usize = 512;
/// Cap on nesting depth of parenthesised groups in the source query.
pub const MAX_HTTPQL_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    ReqRaw,
    ReqQuery,
    ReqPath,
    ReqHost,
    ReqMethod,
    RespRaw,
    RespMime,
    RespStatus,
}

impl Field {
    fn parse(text: &str) -> DomainResult<Self> {
        Ok(match text {
            "req.raw" => Self::ReqRaw,
            "req.query" => Self::ReqQuery,
            "req.path" => Self::ReqPath,
            "req.host" => Self::ReqHost,
            "req.method" => Self::ReqMethod,
            "resp.raw" => Self::RespRaw,
            "resp.mime" => Self::RespMime,
            "resp.status" => Self::RespStatus,
            other => {
                return Err(invalid(format!(
                    "unsupported httpql field `{other}` (supported: req.raw, req.query, req.path, req.host, req.method, resp.raw, resp.mime, resp.status)"
                )))
            }
        })
    }

    /// Corresponding HuntProxy query-language field name.
    fn dsl_name(self) -> &'static str {
        match self {
            Self::ReqRaw => "request",
            Self::ReqQuery => "query",
            Self::ReqPath => "path",
            Self::ReqHost => "host",
            Self::ReqMethod => "method",
            Self::RespRaw => "response",
            Self::RespMime => "mime",
            Self::RespStatus => "status",
        }
    }

    fn is_numeric(self) -> bool {
        matches!(self, Self::RespStatus)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Cont,
    Ncont,
    Eq,
    Neq,
    Like,
    Regex,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl Op {
    fn parse(text: &str) -> DomainResult<Self> {
        Ok(match text {
            "cont" => Self::Cont,
            "ncont" => Self::Ncont,
            "eq" => Self::Eq,
            "neq" => Self::Neq,
            "like" => Self::Like,
            "regex" => Self::Regex,
            "gt" => Self::Gt,
            "gte" => Self::Gte,
            "lt" => Self::Lt,
            "lte" => Self::Lte,
            other => {
                return Err(invalid(format!(
                    "unsupported httpql operator `{other}` (supported: cont, ncont, eq, neq, like, regex, gt, gte, lt, lte)"
                )))
            }
        })
    }
}

/// Literal operand of a comparison: a plain string, a regex source (validated
/// to compile, stored as text), or a number (used only against numeric fields
/// such as `resp.status`).
#[derive(Debug, Clone)]
enum Literal {
    Text(String),
    Pattern(String),
    Number(f64),
}

#[derive(Debug, Clone)]
enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Cmp {
        field: Field,
        op: Op,
        literal: Literal,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Ident,
    Str,
    Regex,
    Num,
    Colon,
    Dot,
    LParen,
    RParen,
}

/// A lexed token: kind plus owned text (string literals are unescaped).
struct Lexeme {
    kind: Tok,
    text: String,
}

fn invalid(message: String) -> DomainError {
    DomainError::new(ErrorCode::InvalidArgument, message)
}

/// Lexical scan: splits the query into lexemes with owned text.
fn lex(query: &str) -> DomainResult<Vec<Lexeme>> {
    let bytes = query.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b' ' | b'\t' | b'\r' | b'\n' => {
                i += 1;
            }
            b':' => {
                out.push(Lexeme {
                    kind: Tok::Colon,
                    text: ":".into(),
                });
                i += 1;
            }
            b'.' => {
                out.push(Lexeme {
                    kind: Tok::Dot,
                    text: ".".into(),
                });
                i += 1;
            }
            b'(' => {
                out.push(Lexeme {
                    kind: Tok::LParen,
                    text: "(".into(),
                });
                i += 1;
            }
            b')' => {
                out.push(Lexeme {
                    kind: Tok::RParen,
                    text: ")".into(),
                });
                i += 1;
            }
            b'"' => {
                let start = i + 1;
                let mut j = start;
                let mut escaped = false;
                while j < bytes.len() {
                    if escaped {
                        escaped = false;
                        j += 1;
                        continue;
                    }
                    match bytes[j] {
                        b'\\' => escaped = true,
                        b'"' => break,
                        _ => j += 1,
                    }
                }
                if j >= bytes.len() {
                    return Err(invalid(
                        "unterminated string literal in httpql query".into(),
                    ));
                }
                let raw = &query[start..j];
                let unescaped = raw.replace("\\\"", "\"").replace("\\\\", "\\");
                out.push(Lexeme {
                    kind: Tok::Str,
                    text: unescaped,
                });
                i = j + 1;
            }
            b'/' => {
                let start = i + 1;
                let mut j = start;
                let mut escaped = false;
                while j < bytes.len() {
                    if escaped {
                        escaped = false;
                        j += 1;
                        continue;
                    }
                    match bytes[j] {
                        b'\\' => escaped = true,
                        b'/' => break,
                        _ => j += 1,
                    }
                }
                if j >= bytes.len() {
                    return Err(invalid("unterminated regex literal in httpql query".into()));
                }
                out.push(Lexeme {
                    kind: Tok::Regex,
                    text: query[start..j].to_string(),
                });
                i = j + 1;
            }
            b'0'..=b'9' => {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_digit() || bytes[i] == b'.' || bytes[i] == b'-')
                {
                    i += 1;
                }
                out.push(Lexeme {
                    kind: Tok::Num,
                    text: query[start..i].to_string(),
                });
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'-' => {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric()
                        || bytes[i] == b'_'
                        || bytes[i] == b'-'
                        || bytes[i] == b'*')
                {
                    i += 1;
                }
                out.push(Lexeme {
                    kind: Tok::Ident,
                    text: query[start..i].to_string(),
                });
            }
            other => {
                return Err(invalid(format!(
                    "unexpected character `{}` in httpql query",
                    other as char
                )))
            }
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<Lexeme>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<(Tok, &str)> {
        self.toks.get(self.pos).map(|l| (l.kind, l.text.as_str()))
    }

    fn next(&mut self) -> Option<(Tok, String)> {
        let lexeme = self.toks.get(self.pos).map(|l| (l.kind, l.text.clone()));
        if lexeme.is_some() {
            self.pos += 1;
        }
        lexeme
    }

    fn expect(&mut self, want: Tok) -> DomainResult<String> {
        match self.next() {
            Some((tok, text)) if tok == want => Ok(text),
            Some((tok, text)) => Err(invalid(format!(
                "expected {want:?} in httpql query, found {tok:?} `{text}`"
            ))),
            None => Err(invalid(format!(
                "expected {want:?} in httpql query, found end of input"
            ))),
        }
    }

    fn parse_expr(&mut self, depth: usize) -> DomainResult<Expr> {
        let mut lhs = self.parse_and(depth)?;
        loop {
            let save = self.pos;
            match self.peek() {
                Some((Tok::Ident, word)) if word.eq_ignore_ascii_case("or") => {
                    self.pos += 1;
                    let rhs = self.parse_and(depth)?;
                    lhs = Expr::Or(Box::new(lhs), Box::new(rhs));
                }
                _ => {
                    self.pos = save;
                    return Ok(lhs);
                }
            }
        }
    }

    fn parse_and(&mut self, depth: usize) -> DomainResult<Expr> {
        let mut lhs = self.parse_not(depth)?;
        loop {
            let save = self.pos;
            match self.peek() {
                Some((Tok::Ident, word)) if word.eq_ignore_ascii_case("and") => {
                    self.pos += 1;
                    let rhs = self.parse_not(depth)?;
                    lhs = Expr::And(Box::new(lhs), Box::new(rhs));
                }
                _ => {
                    self.pos = save;
                    return Ok(lhs);
                }
            }
        }
    }

    fn parse_not(&mut self, depth: usize) -> DomainResult<Expr> {
        match self.peek() {
            Some((Tok::Ident, word)) if word.eq_ignore_ascii_case("not") => {
                self.pos += 1;
                let inner = self.parse_not(depth)?;
                Ok(Expr::Not(Box::new(inner)))
            }
            _ => self.parse_atom(depth),
        }
    }

    fn parse_atom(&mut self, depth: usize) -> DomainResult<Expr> {
        if depth > MAX_HTTPQL_DEPTH {
            return Err(invalid(format!(
                "httpql query nests deeper than {MAX_HTTPQL_DEPTH}"
            )));
        }
        match self.peek() {
            Some((Tok::LParen, _)) => {
                self.pos += 1;
                let inner = self.parse_expr(depth + 1)?;
                self.expect(Tok::RParen)?;
                Ok(inner)
            }
            Some((Tok::Ident, _)) => self.parse_cmp(),
            Some((tok, slice)) => Err(invalid(format!(
                "unexpected {tok:?} `{slice}` in httpql query"
            ))),
            None => Err(invalid("unexpected end of httpql query".into())),
        }
    }

    fn parse_cmp(&mut self) -> DomainResult<Expr> {
        let field_tok = self.expect(Tok::Ident)?;
        let field = Field::parse(&field_tok)?;
        self.expect(Tok::Dot)?;
        let op_tok = self.expect(Tok::Ident)?;
        let op = Op::parse(&op_tok)?;
        self.expect(Tok::Colon)?;
        let literal = match self.next() {
            Some((Tok::Str, text)) => Literal::Text(text),
            Some((Tok::Regex, pattern)) => {
                if pattern.len() > MAX_HTTPQL_REGEX {
                    return Err(invalid(format!(
                        "httpql regex longer than {MAX_HTTPQL_REGEX} bytes"
                    )));
                }
                // Validate at import time with the same regex engine the
                // runtime uses, so a pattern Caido accepted but Rust rejects
                // fails the import, not the flow.
                Regex::new(&pattern)
                    .map_err(|e| invalid(format!("invalid httpql regex /{pattern}/: {e}")))?;
                Literal::Pattern(pattern)
            }
            Some((Tok::Num, text)) => {
                let n: f64 = text
                    .parse()
                    .map_err(|_| invalid(format!("invalid httpql number `{text}`")))?;
                Literal::Number(n)
            }
            Some((tok, text)) => {
                return Err(invalid(format!(
                    "expected string, regex, or number after `{field_tok}.{op_tok}:`, found {tok:?} `{text}`"
                )))
            }
            None => {
                return Err(invalid(
                    "expected a literal after `:` in httpql query".into(),
                ))
            }
        };
        // Numeric fields compare only against numbers with the ordering
        // operators; text fields only against strings and regexes. Reject
        // mismatches up front so translation stays total.
        match (field.is_numeric(), &literal) {
            (true, Literal::Number(_)) => {
                if !matches!(op, Op::Eq | Op::Neq | Op::Gt | Op::Gte | Op::Lt | Op::Lte) {
                    return Err(invalid(format!(
                        "operator `{op_tok}` is not supported against numeric field `{field_tok}`"
                    )));
                }
            }
            (true, _) => {
                return Err(invalid(format!(
                    "field `{field_tok}` is numeric but compared against a text or regex literal"
                )))
            }
            (false, Literal::Text(_) | Literal::Pattern(_)) => {}
            (false, Literal::Number(_)) => {
                return Err(invalid(format!(
                    "field `{field_tok}` is text but compared against a number"
                )))
            }
        }
        Ok(Expr::Cmp { field, op, literal })
    }
}

/// Translate an HTTPQL query into HuntProxy query-language text.
///
/// The returned text is proven safe to store: it parses back through
/// [`parse_text_query`] into the same filter this translator built, and it
/// compiles through [`filter_to_sql`] (the exact runtime path the
/// `flow/query-match` node uses).
pub fn translate_httpql_to_dsl(query: &str) -> DomainResult<String> {
    if query.len() > MAX_HTTPQL_QUERY {
        return Err(invalid(format!(
            "httpql query longer than {MAX_HTTPQL_QUERY} bytes"
        )));
    }
    let toks = lex(query)?;
    if toks.is_empty() {
        return Err(invalid("httpql query is empty".into()));
    }
    let mut parser = Parser { toks, pos: 0 };
    let expr = parser.parse_expr(0)?;
    if parser.pos != parser.toks.len() {
        let (tok, text) = (
            parser.toks[parser.pos].kind,
            parser.toks[parser.pos].text.clone(),
        );
        return Err(invalid(format!(
            "trailing {tok:?} `{text}` in httpql query"
        )));
    }
    let filter = httpql_to_filter(&expr)?;
    let text = filter_to_dsl(&filter)?;
    let reparsed = parse_text_query(&text)?;
    let original = serde_json::to_value(&filter)
        .map_err(|e| invalid(format!("internal: cannot compare translated filter: {e}")))?;
    let round_trip = serde_json::to_value(&reparsed)
        .map_err(|e| invalid(format!("internal: cannot compare reparsed filter: {e}")))?;
    if original != round_trip {
        return Err(invalid(format!(
            "translated query `{text}` does not round-trip through the HuntProxy query parser unchanged; \
             this happens when a regex contains comparison operators such as >= or a value starts with >, <, ~, or * - \
             simplify the pattern to avoid those sequences"
        )));
    }
    // Prove the runtime compiler accepts the filter (field allowlist, op
    // allowlist, depth and term caps, body-search plumbing).
    filter_to_sql(&reparsed)?;
    Ok(text)
}

fn httpql_to_filter(expr: &Expr) -> DomainResult<FilterNode> {
    Ok(match expr {
        Expr::And(a, b) => FilterNode::And {
            and: vec![httpql_to_filter(a)?, httpql_to_filter(b)?],
        },
        Expr::Or(a, b) => FilterNode::Or {
            or: vec![httpql_to_filter(a)?, httpql_to_filter(b)?],
        },
        Expr::Not(inner) => FilterNode::Not {
            not: Box::new(httpql_to_filter(inner)?),
        },
        Expr::Cmp { field, op, literal } => cmp_to_filter(*field, *op, literal)?,
    })
}

fn term_node(field: &str, op: &str, value: serde_json::Value) -> FilterNode {
    FilterNode::Term {
        field: field.to_string(),
        op: op.to_string(),
        value,
        subfield: None,
    }
}

/// Text-term values are built exactly like the query parser's `term()`:
/// a value that parses as an integer becomes a JSON number, everything else
/// stays a string. Keeping the two in lockstep is what lets the round-trip
/// comparison prove the translation is faithful.
fn text_value(raw: &str) -> serde_json::Value {
    if let Ok(n) = raw.parse::<i64>() {
        serde_json::json!(n)
    } else {
        serde_json::json!(raw)
    }
}

fn cmp_to_filter(field: Field, op: Op, literal: &Literal) -> DomainResult<FilterNode> {
    let name = field.dsl_name();
    if field.is_numeric() {
        let Literal::Number(n) = literal else {
            return Err(invalid(format!(
                "internal: numeric field `{name}` compared against a non-number"
            )));
        };
        if n.fract() != 0.0 || n.abs() >= 1e15 {
            return Err(invalid(format!(
                "httpql number `{n}` is not an integer; status comparisons must use whole numbers"
            )));
        }
        let op_name = match op {
            Op::Eq => "eq",
            Op::Neq => "ne",
            Op::Gt => "gt",
            Op::Gte => "gte",
            Op::Lt => "lt",
            Op::Lte => "lte",
            other => {
                return Err(invalid(format!(
                    "internal: operator {other:?} not handled for numeric field"
                )))
            }
        };
        return Ok(term_node(name, op_name, serde_json::json!(*n as i64)));
    }
    match (op, literal) {
        (Op::Cont, Literal::Text(value)) => Ok(term_node(name, "contains", text_value(value))),
        (Op::Ncont, Literal::Text(value)) => Ok(FilterNode::Not {
            not: Box::new(term_node(name, "contains", text_value(value))),
        }),
        (Op::Eq, Literal::Text(value)) => Ok(term_node(name, "eq", text_value(value))),
        (Op::Neq, Literal::Text(value)) => Ok(term_node(name, "ne", text_value(value))),
        (Op::Regex, Literal::Pattern(pattern)) => {
            Ok(term_node(name, "regex", serde_json::json!(pattern)))
        }
        (Op::Like, Literal::Text(pattern)) => desugar_like(name, pattern),
        other => Err(invalid(format!(
            "unsupported httpql comparison against field `{name}` ({other:?})"
        ))),
    }
}

/// Desugar a SQL `LIKE` pattern into native query-language operators.
/// `%` and `_` are the only wildcards; patterns that do not reduce to a
/// single contains / starts_with / ends_with become a `(?i)` regex, which
/// matches SQLite's case-insensitive LIKE behaviour.
fn desugar_like(field: &str, pattern: &str) -> DomainResult<FilterNode> {
    let underscore = pattern.contains('_');
    let pcts = pattern.matches('%').count();
    if underscore || pcts > 2 {
        return Ok(like_to_regex_term(field, pattern));
    }
    if pcts == 0 {
        return Ok(term_node(field, "eq", text_value(pattern)));
    }
    if pcts == 1 {
        let (prefix, suffix) = pattern
            .split_once('%')
            .expect("one percent is present when the count is 1");
        if suffix.is_empty() {
            return Ok(term_node(field, "starts_with", text_value(prefix)));
        }
        if prefix.is_empty() {
            return Ok(term_node(field, "ends_with", text_value(suffix)));
        }
        return Ok(FilterNode::And {
            and: vec![
                term_node(field, "starts_with", text_value(prefix)),
                term_node(field, "ends_with", text_value(suffix)),
            ],
        });
    }
    // Two percent signs and no underscore: only the `%x%` shape reduces to
    // a single contains; anything else needs the regex fallback.
    if pattern.starts_with('%') && pattern.ends_with('%') {
        let inner = &pattern[1..pattern.len() - 1];
        if !inner.contains('%') {
            return Ok(term_node(field, "contains", text_value(inner)));
        }
    }
    Ok(like_to_regex_term(field, pattern))
}

fn like_to_regex_term(field: &str, pattern: &str) -> FilterNode {
    let mut out = String::with_capacity(pattern.len() * 2 + 4);
    out.push_str("(?i)");
    for ch in pattern.chars() {
        match ch {
            '%' => out.push_str(".*"),
            '_' => out.push('.'),
            other => {
                if "\\.+*?()|[]{}^$".contains(other) {
                    out.push('\\');
                }
                out.push(other);
            }
        }
    }
    term_node(field, "regex", serde_json::json!(out))
}

/// Print a filter back into query-language text. Terms are emitted bare;
/// compound children are parenthesised so precedence survives the trip.
fn filter_to_dsl(node: &FilterNode) -> DomainResult<String> {
    Ok(match node {
        FilterNode::And { and } => {
            let parts: DomainResult<Vec<_>> = and.iter().map(child_dsl).collect();
            parts?.join(" AND ")
        }
        FilterNode::Or { or } => {
            let parts: DomainResult<Vec<_>> = or.iter().map(child_dsl).collect();
            parts?.join(" OR ")
        }
        FilterNode::Not { not } => format!("NOT {}", child_dsl(not)?),
        FilterNode::Term {
            field,
            op,
            value,
            subfield,
        } => {
            if subfield.is_some() {
                return Err(invalid(
                    "internal: header terms are not produced by httpql translation".into(),
                ));
            }
            term_dsl(field, op, value)?
        }
    })
}

fn child_dsl(node: &FilterNode) -> DomainResult<String> {
    match node {
        FilterNode::Term { .. } => filter_to_dsl(node),
        other => Ok(format!("({})", filter_to_dsl(other)?)),
    }
}

fn term_dsl(field: &str, op: &str, value: &serde_json::Value) -> DomainResult<String> {
    match op {
        "eq" => Ok(format!("{field}:{}", dsl_value(value)?)),
        "ne" => Ok(format!("{field}!={}", dsl_value(value)?)),
        "contains" => Ok(format!("{field}:~{}", dsl_quoted(value)?)),
        "starts_with" => Ok(format!("{field}:{}*", dsl_quoted(value)?)),
        "ends_with" => Ok(format!("{field}:*{}", dsl_quoted(value)?)),
        "regex" => Ok(format!("{field}=~{}", dsl_quoted(value)?)),
        "nregex" => Ok(format!("{field}!=~{}", dsl_quoted(value)?)),
        "gt" => Ok(format!("{field}>{}", number_text(value)?)),
        "gte" => Ok(format!("{field}>={}", number_text(value)?)),
        "lt" => Ok(format!("{field}<{}", number_text(value)?)),
        "lte" => Ok(format!("{field}<={}", number_text(value)?)),
        other => Err(invalid(format!(
            "internal: no query emission for operator `{other}`"
        ))),
    }
}

fn dsl_quoted(value: &serde_json::Value) -> DomainResult<String> {
    let text = match value {
        serde_json::Value::String(text) => text.clone(),
        // Text-term values that parse as integers are stored as numbers
        // (mirroring the query parser); quote them back as their digits.
        serde_json::Value::Number(number) => number.to_string(),
        _ => {
            return Err(invalid(
                "internal: expected a string or number value".into(),
            ))
        }
    };
    Ok(format!("\"{}\"", dsl_escape(&text)))
}

fn dsl_value(value: &serde_json::Value) -> DomainResult<String> {
    match value {
        serde_json::Value::String(_) => dsl_quoted(value),
        _ => number_text(value),
    }
}

fn number_text(value: &serde_json::Value) -> DomainResult<String> {
    if let Some(n) = value.as_i64() {
        return Ok(n.to_string());
    }
    if let Some(n) = value.as_f64() {
        if n.fract() == 0.0 && n.abs() < 1e15 {
            return Ok((n as i64).to_string());
        }
        return Ok(format!("{n}"));
    }
    Err(invalid("internal: expected a number".into()))
}

/// Escape a value for a double-quoted query-language string: the tokenizer
/// treats `\` as an escape and `"` as the terminator.
fn dsl_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' | '"' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn translate(query: &str) -> String {
        translate_httpql_to_dsl(query).unwrap()
    }

    #[test]
    fn translates_cont_and_ncont() {
        assert_eq!(translate("req.query.cont:\"code=\""), "query:~\"code=\"");
        assert_eq!(translate("req.query.ncont:\"nope\""), "NOT query:~\"nope\"");
    }

    #[test]
    fn translates_and_or_not_and_parens() {
        assert_eq!(
            translate(
                "(req.query.cont:\"code=\" AND req.query.cont:\"state=\") OR req.query.cont:\"zzz\""
            ),
            "(query:~\"code=\" AND query:~\"state=\") OR query:~\"zzz\""
        );
        assert_eq!(
            translate("NOT req.query.cont:\"zzz\""),
            "NOT query:~\"zzz\""
        );
        assert_eq!(
            translate("req.query.ncont:\"zzz\" and req.query.cont:\"code=\""),
            "(NOT query:~\"zzz\") AND query:~\"code=\""
        );
    }

    #[test]
    fn translates_regex_with_quotes_colons_and_flags() {
        // The emitted text must parse back into a regex term carrying the
        // original pattern byte-for-byte; exact-string assertions would only
        // re-test the escaper against itself.
        let text = translate("req.query.regex:/(?i)(https?|ftp|file)(:\\/\\/|%3A%2F%2F)/");
        match parse_text_query(&text).unwrap() {
            FilterNode::Term {
                field,
                op,
                value,
                subfield,
            } => {
                assert_eq!(field, "query");
                assert_eq!(op, "regex");
                assert_eq!(
                    value.as_str().unwrap(),
                    "(?i)(https?|ftp|file)(:\\/\\/|%3A%2F%2F)"
                );
                assert!(subfield.is_none());
            }
            other => panic!("expected a term, got {other:?}"),
        }
        let text = translate("resp.raw.regex:/\"access_token\"\\s*:\\s*\"([^\"]+)\"/");
        match parse_text_query(&text).unwrap() {
            FilterNode::Term {
                field, op, value, ..
            } => {
                assert_eq!(field, "response");
                assert_eq!(op, "regex");
                assert_eq!(
                    value.as_str().unwrap(),
                    "\\\"access_token\\\"\\\\s*:\\\\s*\\\"([^\\\"]+)\\\""
                );
            }
            other => panic!("expected a term, got {other:?}"),
        }
    }

    #[test]
    fn translates_raw_fields_to_full_text_search() {
        assert_eq!(
            translate("req.raw.cont:\"Sec-Fetch-Mode: navigate\""),
            "request:~\"Sec-Fetch-Mode: navigate\""
        );
        assert_eq!(
            translate("resp.mime.eq:\"application/json\""),
            "mime:\"application/json\""
        );
        assert_eq!(
            translate("req.host.eq:\"example.com\""),
            "host:\"example.com\""
        );
        assert_eq!(translate("req.method.eq:\"POST\""), "method:\"POST\"");
        assert_eq!(translate("req.path.cont:\"/api/\""), "path:~\"/api/\"");
    }

    #[test]
    fn translates_status_comparisons_numerically() {
        assert_eq!(translate("resp.status.gte:200"), "status>=200");
        assert_eq!(translate("resp.status.lt:300"), "status<300");
        assert_eq!(translate("resp.status.eq:404"), "status:404");
        assert_eq!(translate("resp.status.neq:204"), "status!=204");
    }

    #[test]
    fn desugars_like_wildcards() {
        assert_eq!(translate("req.query.like:\"code=%\""), "query:\"code=\"*");
        assert_eq!(translate("req.query.like:\"%token\""), "query:\"*token\"");
        assert_eq!(translate("req.query.like:\"%code=%\""), "query:~\"code=\"");
        assert_eq!(
            translate("req.query.like:\"code=%next\""),
            "query:\"code=\"* AND query:\"*next\""
        );
        // No wildcard: exact match. Underscore or several %: (?i) regex.
        assert_eq!(translate("req.query.like:\"code=1\""), "query:\"code=1\"");
        assert_eq!(
            translate("req.query.like:\"code=a__\""),
            "query=~\"(?i)code=a..\""
        );
        assert_eq!(
            translate("req.query.like:\"%a%b%\""),
            "query=~\"(?i).*a.*b.*\""
        );
    }

    #[test]
    fn escapes_values_for_the_dsl_tokenizer() {
        // Quotes and backslashes inside values survive the round-trip.
        assert_eq!(
            translate("req.query.cont:\"a\\\"b\\\\c\""),
            "query:~\"a\\\"b\\\\c\""
        );
    }

    #[test]
    fn rejects_unsupported_fields_and_ops() {
        assert!(translate_httpql_to_dsl("req.headers.cont:\"x\"").is_err());
        assert!(translate_httpql_to_dsl("req.query.explode:\"x\"").is_err());
        assert!(translate_httpql_to_dsl("req.query").is_err());
        assert!(translate_httpql_to_dsl("").is_err());
        assert!(translate_httpql_to_dsl("req.query.cont:\"x\" trailing").is_err());
        // like/regex against the numeric status field.
        assert!(translate_httpql_to_dsl("resp.status.like:\"2%\"").is_err());
        assert!(translate_httpql_to_dsl("resp.status.regex:/2../").is_err());
        // Number against a text field.
        assert!(translate_httpql_to_dsl("req.query.eq:5").is_err());
    }

    #[test]
    fn rejects_unbalanced_and_oversized() {
        assert!(translate_httpql_to_dsl("(req.query.cont:\"x\"").is_err());
        let long = "a".repeat(MAX_HTTPQL_QUERY + 1);
        assert!(translate_httpql_to_dsl(&format!("req.query.cont:\"{long}\"")).is_err());
    }

    #[test]
    fn refuses_regex_that_would_not_round_trip() {
        // `>=` inside the pattern is read as the gte operator by our
        // parser; the translator detects the mismatch and refuses.
        let err = translate_httpql_to_dsl("req.raw.regex:/a>=b/").unwrap_err();
        assert!(err.to_string().contains("round-trip"), "{err}");
        // Values starting with ~ or * would flip eq into contains / ends_with.
        let err = translate_httpql_to_dsl("req.query.eq:\"~x\"").unwrap_err();
        assert!(err.to_string().contains("round-trip"), "{err}");
    }

    #[test]
    fn round_trips_real_store_queries() {
        // Queries observed across the 21 httpql-matches nodes in the store.
        let samples = [
            "req.raw.cont:\"Sec-Fetch-Mode: navigate\"",
            "req.query.cont:\"state=\" AND req.query.cont:\"code=\" AND NOT req.query.cont:\"code_challenge\"",
            "resp.raw.regex:/\"access_token\"\\s*:/",
            "req.host.eq:\"accounts.google.com\" AND req.path.cont:\"/o/oauth2\"",
            "resp.status.gte:300 AND resp.status.lt:400",
            "req.method.eq:\"POST\" AND req.query.cont:\"redirect_uri=\"",
            "resp.mime.eq:\"application/json\" AND resp.raw.cont:\"id_token\"",
            "req.query.like:\"code=%\" AND req.query.ncont:\"code_challenge\"",
            "req.path.eq:\"/.well-known/openid-configuration\"",
            "req.raw.cont:\"Cookie:\" AND req.raw.cont:\"session=\" AND req.path.cont:\"/admin\"",
        ];
        for sample in samples {
            translate_httpql_to_dsl(sample).unwrap_or_else(|e| panic!("{sample}: {e}"));
        }
    }
}
