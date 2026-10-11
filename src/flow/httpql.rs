//! Bounded HTTPQL subset evaluator for `flow/httpql-match` nodes.
//!
//! This implements only the surface actually observed in real Caido workflow
//! exports (the `workflows/` store): the fields below, the `cont`, `ncont`,
//! `eq`, `neq`, `like`, `regex`, `gt`, `gte`, `lt`, `lte` operators, `and` /
//! `or` / `not` (case-insensitive keywords), and parentheses. Anything else
//! is rejected with a precise error rather than guessed at.

use regex::Regex;
use std::collections::BTreeSet;

use crate::domain::{DomainError, DomainResult, ErrorCode};

/// Cap on the raw query text we will even try to parse.
pub const MAX_HTTPQL_QUERY: usize = 2048;
/// Cap on any single regular expression a `regex:` operator may use.
pub const MAX_HTTPQL_REGEX: usize = 512;
/// Cap on nesting depth of parenthesised groups.
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

/// Literal operand of a comparison: a plain string, a compiled regex, or a
/// number (used only against numeric fields such as `resp.status`).
#[derive(Debug, Clone)]
enum Literal {
    Text(String),
    Pattern(Regex),
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
                let compiled = Regex::new(&pattern).map_err(|e| {
                    invalid(format!("invalid httpql regex /{pattern}/: {e}"))
                })?;
                Literal::Pattern(compiled)
            }
            Some((Tok::Num, text)) => {
                let n: f64 = text
                    .parse()
                    .map_err(|_| invalid(format!("invalid httpql number `{text}`")))?;
                Literal::Number(n)
            }
            Some((tok, text)) => Err(invalid(format!(
                "expected string, regex, or number after `{field_tok}.{op_tok}:`, found {tok:?} `{text}`"
            ))),
            None => {
                return Err(invalid(
                    "expected a literal after `:` in httpql query".into(),
                ))
            }
        };
        // Numeric fields cannot be compared against text literals and vice
        // versa; reject the mismatch up front so evaluation stays total.
        match (field.is_numeric(), &literal) {
            (true, Literal::Text(_) | Literal::Pattern(_))
                if !matches!(op, Op::Like | Op::Regex) =>
            {
                return Err(invalid(format!(
                    "field `{field_tok}` is numeric but compared against a text literal"
                )))
            }
            (true, _) => {}
            (false, Literal::Number(_)) => {
                return Err(invalid(format!(
                    "field `{field_tok}` is text but compared against a number"
                )))
            }
            (false, _) => {}
        }
        Ok(Expr::Cmp { field, op, literal })
    }
}

/// Parse an HTTPQL query into an evaluable tree.
pub fn parse_httpql(query: &str) -> DomainResult<HttpqlQuery> {
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
    Ok(HttpqlQuery { expr })
}

/// A parsed, ready-to-evaluate HTTPQL query.
#[derive(Debug)]
pub struct HttpqlQuery {
    expr: Expr,
}

/// Fields a parsed query touches. Callers use this to load only the context
/// the query actually needs (raw request/response text is expensive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpqlNeeds {
    pub req_raw: bool,
    pub resp_raw: bool,
}

impl HttpqlQuery {
    pub fn needs(&self) -> HttpqlNeeds {
        let mut needs = HttpqlNeeds {
            req_raw: false,
            resp_raw: false,
        };
        walk(&self.expr, &mut needs);
        fn walk(expr: &Expr, needs: &mut HttpqlNeeds) {
            match expr {
                Expr::And(a, b) | Expr::Or(a, b) => {
                    walk(a, needs);
                    walk(b, needs);
                }
                Expr::Not(inner) => walk(inner, needs),
                Expr::Cmp { field, .. } => match field {
                    Field::ReqRaw => needs.req_raw = true,
                    Field::RespRaw => needs.resp_raw = true,
                    _ => {}
                },
            }
        }
        needs
    }

    /// Evaluate the query against a context. Every field the query does not
    /// touch is treated as empty (text) or absent (numeric).
    pub fn evaluate(&self, ctx: &HttpqlContext<'_>) -> bool {
        eval(&self.expr, ctx)
    }
}

/// Values the evaluator reads. Text fields default to empty string; the
/// numeric `resp.status` field defaults to absent (`None`).
pub struct HttpqlContext<'a> {
    pub req_raw: &'a str,
    pub req_query: &'a str,
    pub req_path: &'a str,
    pub req_host: &'a str,
    pub req_method: &'a str,
    pub resp_raw: &'a str,
    pub resp_mime: &'a str,
    pub resp_status: Option<u16>,
}

impl Default for HttpqlContext<'_> {
    fn default() -> Self {
        Self {
            req_raw: "",
            req_query: "",
            req_path: "",
            req_host: "",
            req_method: "",
            resp_raw: "",
            resp_mime: "",
            resp_status: None,
        }
    }
}

fn field_text<'a>(field: Field, ctx: &'a HttpqlContext<'_>) -> &'a str {
    match field {
        Field::ReqRaw => ctx.req_raw,
        Field::ReqQuery => ctx.req_query,
        Field::ReqPath => ctx.req_path,
        Field::ReqHost => ctx.req_host,
        Field::ReqMethod => ctx.req_method,
        Field::RespRaw => ctx.resp_raw,
        Field::RespMime => ctx.resp_mime,
        Field::RespStatus => "",
    }
}

fn like_to_regex(pattern: &str) -> Regex {
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
    // The pattern was built from a caller string; quoting the wildcards above
    // means this only fails on pathological sizes, which we already cap.
    Regex::new(&out).unwrap_or_else(|_| Regex::new("(?i)a^").expect("sentinel regex"))
}

fn eval(expr: &Expr, ctx: &HttpqlContext<'_>) -> bool {
    match expr {
        Expr::And(a, b) => eval(a, ctx) && eval(b, ctx),
        Expr::Or(a, b) => eval(a, ctx) || eval(b, ctx),
        Expr::Not(inner) => !eval(inner, ctx),
        Expr::Cmp { field, op, literal } => eval_cmp(*field, *op, literal, ctx),
    }
}

fn eval_cmp(field: Field, op: Op, literal: &Literal, ctx: &HttpqlContext<'_>) -> bool {
    if field.is_numeric() {
        let Some(status) = ctx.resp_status else {
            // A numeric comparison against an absent value is false for all
            // ops except neq, which is vacuously true.
            return matches!(op, Op::Neq);
        };
        let Some(target) = literal_number(literal) else {
            return false;
        };
        let actual = f64::from(status);
        return match op {
            Op::Eq => actual == target,
            Op::Neq => actual != target,
            Op::Gt => actual > target,
            Op::Gte => actual >= target,
            Op::Lt => actual < target,
            Op::Lte => actual <= target,
            _ => false,
        };
    }
    let text = field_text(field, ctx);
    match (op, literal) {
        (Op::Cont, Literal::Text(needle)) => text.contains(needle.as_str()),
        (Op::Ncont, Literal::Text(needle)) => !text.contains(needle.as_str()),
        (Op::Eq, Literal::Text(needle)) => text == needle.as_str(),
        (Op::Neq, Literal::Text(needle)) => text != needle.as_str(),
        (Op::Like, Literal::Text(pattern)) => like_to_regex(pattern).is_match(text),
        (Op::Regex, Literal::Pattern(re)) => re.is_match(text),
        // eq/neq against a regex or number on a text field: treat as never
        // matching (the parser already rejects numeric literals here).
        _ => false,
    }
}

fn literal_number(literal: &Literal) -> Option<f64> {
    match literal {
        Literal::Number(n) => Some(*n),
        _ => None,
    }
}

/// Collect the distinct field names a query mentions (used by the converter
/// to refuse queries that would need context we cannot supply).
pub fn referenced_fields(query: &HttpqlQuery) -> BTreeSet<&'static str> {
    let mut out = BTreeSet::new();
    collect(&query.expr, &mut out);
    fn collect<'a>(expr: &'a Expr, out: &mut BTreeSet<&'static str>) {
        match expr {
            Expr::And(a, b) | Expr::Or(a, b) => {
                collect(a, out);
                collect(b, out);
            }
            Expr::Not(inner) => collect(inner, out),
            Expr::Cmp { field, .. } => {
                let name: &'static str = match field {
                    Field::ReqRaw => "req.raw",
                    Field::ReqQuery => "req.query",
                    Field::ReqPath => "req.path",
                    Field::ReqHost => "req.host",
                    Field::ReqMethod => "req.method",
                    Field::RespRaw => "resp.raw",
                    Field::RespMime => "resp.mime",
                    Field::RespStatus => "resp.status",
                };
                out.insert(name);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with(query: &str) -> HttpqlContext<'static> {
        HttpqlContext {
            req_raw: "GET /a?x=1 HTTP/1.1\r\nSec-Fetch-Mode: navigate\r\n",
            req_query: query,
            req_path: "/a",
            req_host: "example.com",
            req_method: "GET",
            resp_raw: "HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"abc\"}",
            resp_mime: "application/json",
            resp_status: Some(200),
        }
    }

    fn evaluate(query: &str, ctx: &HttpqlContext<'_>) -> bool {
        parse_httpql(query).unwrap().evaluate(ctx)
    }

    #[test]
    fn matches_cont_and_ncont() {
        let ctx = ctx_with("code=1&state=2");
        assert!(evaluate("req.query.cont:\"code=\"", &ctx));
        assert!(evaluate("req.query.ncont:\"nope\"", &ctx));
        assert!(!evaluate("req.query.cont:\"nope\"", &ctx));
    }

    #[test]
    fn and_or_not_and_parens() {
        let ctx = ctx_with("code=1&state=2");
        assert!(evaluate(
            "(req.query.cont:\"code=\" AND req.query.cont:\"state=\") OR req.query.cont:\"zzz\"",
            &ctx
        ));
        assert!(!evaluate(
            "req.query.cont:\"code=\" AND req.query.cont:\"zzz\"",
            &ctx
        ));
        assert!(evaluate("NOT req.query.cont:\"zzz\"", &ctx));
        assert!(evaluate(
            "req.query.ncont:\"zzz\" and req.query.cont:\"code=\"",
            &ctx
        ));
    }

    #[test]
    fn regex_with_inline_flags() {
        let ctx = ctx_with("url=https%3A%2F%2Fevil");
        assert!(evaluate(
            "req.query.regex:/(?i)(https?|ftp|file)(:\\/\\/|%3A%2F%2F)/",
            &ctx
        ));
        assert!(!evaluate("req.query.regex:/nope/", &ctx));
    }

    #[test]
    fn raw_fields_match_header_and_body_text() {
        let ctx = HttpqlContext::default();
        assert!(evaluate("req.raw.cont:\"Sec-Fetch-Mode: navigate\"", &ctx));
        assert!(evaluate(
            "resp.raw.regex:/\"access_token\"\\s*:\\s*\"([^\"]+)\"/",
            &ctx
        ));
    }

    #[test]
    fn status_compares_numerically() {
        let ctx = ctx_with("");
        assert!(evaluate("resp.status.gte:200", &ctx));
        assert!(evaluate("resp.status.lt:300", &ctx));
        assert!(!evaluate("resp.status.eq:404", &ctx));
    }

    #[test]
    fn like_wildcards() {
        let ctx = ctx_with("code=abc&state=xyz");
        assert!(evaluate("req.query.like:\"code=%\"", &ctx));
        assert!(!evaluate("req.query.like:\"nope=%\"", &ctx));
        assert!(evaluate("req.query.like:\"code=a__\"", &ctx));
    }

    #[test]
    fn rejects_unsupported_fields_and_ops() {
        assert!(parse_httpql("req.headers.cont:\"x\"").is_err());
        assert!(parse_httpql("req.query.explode:\"x\"").is_err());
        assert!(parse_httpql("req.query").is_err());
        assert!(parse_httpql("").is_err());
        assert!(parse_httpql("req.query.cont:\"x\" trailing").is_err());
    }

    #[test]
    fn rejects_unbalanced_and_oversized() {
        assert!(parse_httpql("(req.query.cont:\"x\"").is_err());
        let long = "a".repeat(MAX_HTTPQL_QUERY + 1);
        assert!(parse_httpql(&format!("req.query.cont:\"{long}\"")).is_err());
    }

    #[test]
    fn needs_reports_raw_sides() {
        let q = parse_httpql("req.raw.cont:\"a\" OR resp.raw.cont:\"b\"").unwrap();
        let needs = q.needs();
        assert!(needs.req_raw && needs.resp_raw);
        let q2 = parse_httpql("req.query.cont:\"a\"").unwrap();
        assert!(!q2.needs().req_raw && !q2.needs().resp_raw);
    }

    #[test]
    fn referenced_fields_lists_mentions() {
        let q = parse_httpql("req.query.cont:\"a\" OR resp.status.eq:500").unwrap();
        let fields = referenced_fields(&q);
        assert!(fields.contains("req.query"));
        assert!(fields.contains("resp.status"));
    }
}
