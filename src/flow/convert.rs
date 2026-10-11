//! One-way importer: Caido workflow definitions (the `workflows/` store
//! format, edition 2) into HuntProxy flow definitions (edition 1).
//!
//! The mapping is deliberately strict. Every Caido `definition_id` is either
//! mapped to a HuntProxy node type (possibly with synthesised JavaScript for
//! the codec nodes) or the import is refused with an error that names the
//! offending node. Nothing is silently dropped or approximated.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::domain::{
    DomainError, DomainResult, ErrorCode, FlowDefinition, FlowDisplay, FlowEdge, FlowGraph,
    FlowKind, FlowNode, FlowPort, FlowProperty, FLOW_EDITION,
};

use crate::history::parse_text_query;

fn invalid(message: String) -> DomainError {
    DomainError::new(ErrorCode::InvalidArgument, message)
}

/// Pure-JS base64 used by the synthesised codec snippets (QuickJS has no
/// `btoa`/`atob`).
const JS_BASE64_SNIPPET: &str = r#"
const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64encode(bytes, pad) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    let n = (bytes[i] << 16) | ((bytes[i + 1] || 0) << 8) | (bytes[i + 2] || 0);
    out += ALPHA[(n >> 18) & 63] + ALPHA[(n >> 12) & 63];
    out += i + 1 < bytes.length ? ALPHA[(n >> 6) & 63] : (pad ? "=" : "");
    out += i + 2 < bytes.length ? ALPHA[n & 63] : (pad ? "=" : "");
  }
  return out;
}
function b64decode(text) {
  const clean = text.replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/");
  const bytes = [];
  let buffer = 0, bits = 0;
  for (const ch of clean) {
    const v = ALPHA.indexOf(ch);
    if (v < 0) continue;
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return bytes;
}
function utf8bytes(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
      const lo = str.charCodeAt(++i);
      const cp = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00);
      out.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 63),
        0x80 | ((cp >> 6) & 63),
        0x80 | (cp & 63)
      );
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
  }
  return out;
}
function utf8string(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; ) {
    const b = bytes[i++];
    let cp;
    if (b < 0x80) cp = b;
    else if ((b & 0xe0) === 0xc0) cp = ((b & 0x1f) << 6) | (bytes[i++] & 0x3f);
    else if ((b & 0xf0) === 0xe0)
      cp = ((b & 0x0f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f);
    else
      cp =
        ((b & 0x07) << 18) |
        ((bytes[i++] & 0x3f) << 12) |
        ((bytes[i++] & 0x3f) << 6) |
        (bytes[i++] & 0x3f);
    if (cp < 0x10000) out += String.fromCharCode(cp);
    else {
      cp -= 0x10000;
      out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
    }
  }
  return out;
}
"#;

/// What a Caido `definition_id` maps to: our node type, or `None` when the
/// node is a terminal that has no HuntProxy counterpart and is dropped.
fn map_definition(def_id: &str, alias: &str) -> DomainResult<Option<&'static str>> {
    Ok(match def_id {
        "caido/on-intercept-response" | "caido/on-intercept-request" => {
            Some("flow/on-intercept-response")
        }
        "caido/convert-start" | "caido/active-start" => Some("flow/manual-start"),
        "caido/passive-end" | "caido/convert-end" | "caido/active-end" => None,
        "caido/if-else" => Some("flow/if-else"),
        "caido/color-set" => Some("flow/set-color"),
        "caido/finding-create" => Some("flow/report-finding"),
        "caido/code-js" => Some("flow/js"),
        "caido/httpql-matches" => Some("flow/query-match"),
        "caido/in-scope" => Some("flow/in-scope"),
        "caido/base64-encode" | "caido/base64-decode" | "caido/url-encode" | "caido/url-decode" => {
            Some("flow/js")
        }
        "caido/http-code-js" => Some("flow/js"),
        other => {
            return Err(invalid(format!(
                "node `{alias}` uses unsupported Caido definition `{other}`"
            )))
        }
    })
}

/// Output port names that differ between Caido and HuntProxy for a given
/// Caido `definition_id`.
fn map_output_name(caido_def_id: &str, output: &str, _alias: &str) -> DomainResult<String> {
    Ok(match (caido_def_id, output) {
        ("caido/code-js" | "caido/http-code-js", "data") => "output".to_string(),
        (
            "caido/base64-encode" | "caido/base64-decode" | "caido/url-encode" | "caido/url-decode",
            "data",
        ) => "output".to_string(),
        ("caido/convert-start", "data") => "input".to_string(),
        ("caido/active-start", "request" | "response") => "input".to_string(),
        // Passive triggers expose a single `exchange` summary object; Caido
        // scripts that consumed `request`/`response` now read it from the
        // shaped `input.request` / `input.response` handles.
        ("caido/on-intercept-request" | "caido/on-intercept-response", "request" | "response") => {
            "exchange".to_string()
        }
        _ => output.to_string(),
    })
}

fn parse_ref(data: &str) -> DomainResult<(String, String)> {
    let rest = data
        .strip_prefix('$')
        .ok_or_else(|| invalid(format!("reference `{data}` must start with `$`")))?;
    let (alias, output) = rest
        .split_once('.')
        .ok_or_else(|| invalid(format!("reference `{data}` must be `$alias.output`")))?;
    if alias.is_empty() || output.is_empty() {
        return Err(invalid(format!("malformed reference `{data}`")));
    }
    Ok((alias.to_string(), output.to_string()))
}

fn map_kind(raw: &str) -> DomainResult<FlowKind> {
    Ok(match raw {
        "passive" => FlowKind::Passive,
        "active" => FlowKind::Active,
        "convert" => FlowKind::Convert,
        other => {
            return Err(invalid(format!(
                "unsupported Caido workflow kind `{other}` (supported: passive, active, convert)"
            )))
        }
    })
}

fn codec_snippet(caido_def_id: &str, inputs: &[(String, Value)]) -> DomainResult<String> {
    let const_str = |name: &str| -> Option<String> {
        inputs
            .iter()
            .find(|(alias, _)| alias == name)
            .and_then(|(_, value)| value.get("data"))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let const_bool = |name: &str| -> Option<bool> {
        inputs
            .iter()
            .find(|(alias, _)| alias == name)
            .and_then(|(_, value)| value.get("data"))
            .and_then(Value::as_bool)
    };
    Ok(match caido_def_id {
        "caido/base64-encode" => {
            let url_safe = const_str("format").as_deref() == Some("URL_SAFE");
            let pad = const_bool("pad").unwrap_or(true);
            format!(
                "{JS_BASE64_SNIPPET}\nfunction run(input) {{\n  const text = typeof input === \"string\" ? input : JSON.stringify(input);\n  let out = b64encode(utf8bytes(text), {pad});\n  {url_safe_swap}\n  return out;\n}}",
                url_safe_swap = if url_safe {
                    "out = out.replace(/\\+/g, \"-\").replace(/\\//g, \"_\");"
                } else {
                    ""
                }
            )
        }
        "caido/base64-decode" => {
            format!(
                "{JS_BASE64_SNIPPET}\nfunction run(input) {{\n  return utf8string(b64decode(String(input)));\n}}"
            )
        }
        "caido/url-encode" => {
            "function run(input) {\n  const text = typeof input === \"string\" ? input : JSON.stringify(input);\n  return encodeURIComponent(text);\n}".to_string()
        }
        "caido/url-decode" => {
            "function run(input) {\n  return decodeURIComponent(String(input));\n}".to_string()
        }
        other => {
            return Err(invalid(format!(
                "internal: no codec snippet for `{other}`"
            )))
        }
    })
}

/// Convert a Caido workflow definition (JSON text) into a HuntProxy flow
/// definition. The result satisfies the structural flow schema; callers should
/// additionally run `validate_flow` before storing it.
pub fn import_caido_definition(raw: &str) -> DomainResult<FlowDefinition> {
    let root: Value = serde_json::from_str(raw)
        .map_err(|e| invalid(format!("definition is not valid JSON: {e}")))?;

    let edition = root
        .get("edition")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("definition is missing `edition`".into()))?;
    if edition != 2 {
        return Err(invalid(format!(
            "unsupported Caido definition edition {edition}; this importer supports edition 2"
        )));
    }

    let kind = map_kind(
        root.get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("definition is missing `kind`".into()))?,
    )?;
    let name = root
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let description = root
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let graph = root
        .get("graph")
        .ok_or_else(|| invalid("definition is missing `graph`".into()))?;
    let caido_nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("definition graph is missing `nodes`".into()))?;
    let caido_edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    // Pass 1: identity mapping. Every kept node gets an alias and a Caido
    // definition id so pass 2 can resolve references regardless of array
    // order (Caido exports freely use forward references).
    let mut id_to_alias: BTreeMap<u64, String> = BTreeMap::new();
    let mut alias_to_def_id: BTreeMap<String, String> = BTreeMap::new();
    let mut dropped_ids: BTreeSet<u64> = BTreeSet::new();
    let mut seen_aliases: BTreeSet<String> = BTreeSet::new();

    for node in caido_nodes {
        let id = node
            .get("id")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("node is missing numeric `id`".into()))?;
        let raw_alias = node
            .get("alias")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut alias = if raw_alias.is_empty() {
            format!("node_{id}")
        } else {
            raw_alias
        };
        // Our alias charset is [A-Za-z0-9_-]; Caido aliases already conform,
        // but guard against a hostile export anyway.
        alias = alias
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        if !seen_aliases.insert(alias.clone()) {
            return Err(invalid(format!("duplicate node alias `{alias}`")));
        }
        let def_id = node
            .get("definition_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("node `{alias}` is missing `definition_id`")))?
            .to_string();

        match map_definition(&def_id, &alias)? {
            Some(_) => {
                id_to_alias.insert(id, alias.clone());
                alias_to_def_id.insert(alias, def_id);
            }
            None => {
                dropped_ids.insert(id);
            }
        }
    }

    // Pass 2: build node bodies and rewrite input references.
    let mut nodes: Vec<FlowNode> = Vec::new();
    for node in caido_nodes {
        let id = node
            .get("id")
            .and_then(Value::as_u64)
            .expect("pass 1 validated ids");
        let Some(alias) = id_to_alias.get(&id) else {
            continue; // dropped terminal
        };
        let def_id = alias_to_def_id
            .get(alias)
            .expect("pass 1 recorded def ids")
            .clone();
        let target_type = map_definition(&def_id, alias)?.expect("kept node");

        let raw_inputs: Vec<(String, Value)> = node
            .get("inputs")
            .and_then(Value::as_array)
            .map(|inputs| {
                inputs
                    .iter()
                    .filter_map(|input| {
                        let alias = input.get("alias")?.as_str()?.to_string();
                        let value = input.get("value")?.clone();
                        Some((alias, value))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let display = node.get("display").and_then(|d| {
            Some(FlowDisplay {
                x: d.get("x")?.as_i64()?,
                y: d.get("y")?.as_i64()?,
            })
        });

        let mut inputs: BTreeMap<String, FlowProperty> = BTreeMap::new();
        match def_id.as_str() {
            "caido/on-intercept-response"
            | "caido/on-intercept-request"
            | "caido/convert-start"
            | "caido/active-start"
            | "caido/in-scope" => {}
            "caido/if-else" => {
                let condition = raw_inputs
                    .iter()
                    .find(|(in_alias, _)| in_alias == "condition")
                    .ok_or_else(|| {
                        invalid(format!(
                            "node `{alias}` is missing required input `condition`"
                        ))
                    })?;
                let condition_property = convert_value(&condition.1, &alias_to_def_id, alias)?;
                inputs.insert("left".into(), condition_property);
                inputs.insert(
                    "right".into(),
                    FlowProperty::Const {
                        value: Value::Bool(true),
                    },
                );
                inputs.insert(
                    "op".into(),
                    FlowProperty::Const {
                        value: Value::String("eq".into()),
                    },
                );
            }
            "caido/color-set" => {
                for (in_alias, value) in &raw_inputs {
                    if in_alias == "color" {
                        inputs.insert(
                            "color".into(),
                            convert_value(value, &alias_to_def_id, alias)?,
                        );
                    }
                    // `request` input dropped: set-color defaults to the
                    // triggering exchange.
                }
                if !inputs.contains_key("color") {
                    return Err(invalid(format!(
                        "node `{alias}` is missing required input `color`"
                    )));
                }
            }
            "caido/finding-create" => {
                for (in_alias, value) in &raw_inputs {
                    match in_alias.as_str() {
                        "title" | "description" => {
                            inputs.insert(
                                in_alias.clone(),
                                convert_value(value, &alias_to_def_id, alias)?,
                            );
                        }
                        // `reporter`, `dedupe_key`, `request` dropped: no
                        // HuntProxy equivalent; findings attach to the
                        // triggering exchange by default.
                        _ => {}
                    }
                }
                for required in ["title", "description"] {
                    if !inputs.contains_key(required) {
                        return Err(invalid(format!(
                            "node `{alias}` is missing required input `{required}`"
                        )));
                    }
                }
            }
            "caido/code-js" => {
                for (in_alias, value) in &raw_inputs {
                    match in_alias.as_str() {
                        "code" => {
                            inputs.insert(
                                "code".into(),
                                convert_value(value, &alias_to_def_id, alias)?,
                            );
                        }
                        "data" => {
                            inputs.insert(
                                "input".into(),
                                convert_value(value, &alias_to_def_id, alias)?,
                            );
                        }
                        _ => {}
                    }
                }
                if !inputs.contains_key("code") {
                    return Err(invalid(format!(
                        "node `{alias}` is missing required input `code`"
                    )));
                }
            }
            "caido/http-code-js" => {
                // The script receives the shaped exchange summary as `input`,
                // whose `.request` / `.response` handles replace Caido's
                // per-input wiring, so a ref to either collapses into `input`.
                let mut input_prop: Option<FlowProperty> = None;
                for (in_alias, value) in &raw_inputs {
                    match in_alias.as_str() {
                        "code" => {
                            inputs.insert(
                                "code".into(),
                                convert_value(value, &alias_to_def_id, alias)?,
                            );
                        }
                        "request" | "response" => {
                            if input_prop.is_none() {
                                input_prop = Some(convert_value(value, &alias_to_def_id, alias)?);
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(property) = input_prop {
                    inputs.insert("input".into(), property);
                }
                if !inputs.contains_key("code") {
                    return Err(invalid(format!(
                        "node `{alias}` is missing required input `code`"
                    )));
                }
            }
            "caido/httpql-matches" => {
                for (in_alias, value) in &raw_inputs {
                    if in_alias == "query" {
                        let query = value.get("data").and_then(Value::as_str).ok_or_else(|| {
                            invalid(format!("node `{alias}` input `query` must be a string"))
                        })?;
                        // The importer accepts only HuntProxy's own query
                        // language; there is no HTTPQL dialect. A query that
                        // does not parse or names an unknown field is refused
                        // rather than guessed at.
                        let filter = parse_text_query(query).map_err(|error| {
                            invalid(format!(
                                "node `{alias}` query is not valid HuntProxy syntax: {error}"
                            ))
                        })?;
                        crate::history::validate_filter(&filter).map_err(|error| {
                            invalid(format!(
                                "node `{alias}` query is not valid HuntProxy syntax: {error}"
                            ))
                        })?;
                        inputs.insert(
                            "query".into(),
                            FlowProperty::Const {
                                value: Value::String(query.to_string()),
                            },
                        );
                    }
                    // `request` / `response` dropped: query-match defaults to
                    // the triggering exchange.
                }
                if !inputs.contains_key("query") {
                    return Err(invalid(format!(
                        "node `{alias}` is missing required input `query`"
                    )));
                }
            }
            "caido/base64-encode"
            | "caido/base64-decode"
            | "caido/url-encode"
            | "caido/url-decode" => {
                let snippet = codec_snippet(&def_id, &raw_inputs)?;
                inputs.insert(
                    "code".into(),
                    FlowProperty::Const {
                        value: Value::String(snippet),
                    },
                );
                if let Some((_, value)) = raw_inputs.iter().find(|(in_alias, _)| in_alias == "data")
                {
                    inputs.insert(
                        "input".into(),
                        convert_value(value, &alias_to_def_id, alias)?,
                    );
                }
            }
            other => {
                return Err(invalid(format!(
                    "internal: unhandled Caido definition `{other}`"
                )))
            }
        }

        nodes.push(FlowNode {
            node_type: target_type.to_string(),
            alias: alias.clone(),
            display,
            inputs,
        });
    }

    // Pass 3: rewrite edges.
    let mut edges: Vec<FlowEdge> = Vec::new();
    for edge in &caido_edges {
        let source_id = edge
            .get("source")
            .and_then(|s| s.get("node_id"))
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("edge is missing `source.node_id`".into()))?;
        let target_id = edge
            .get("target")
            .and_then(|s| s.get("node_id"))
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("edge is missing `target.node_id`".into()))?;
        let source_port = edge
            .get("source")
            .and_then(|s| s.get("exec_alias"))
            .and_then(Value::as_str)
            .unwrap_or("exec");
        let target_port = edge
            .get("target")
            .and_then(|s| s.get("exec_alias"))
            .and_then(Value::as_str)
            .unwrap_or("exec");

        // Edges touching dropped end nodes are dropped with them.
        if dropped_ids.contains(&source_id) || dropped_ids.contains(&target_id) {
            continue;
        }
        let source_alias = id_to_alias.get(&source_id).ok_or_else(|| {
            invalid(format!(
                "edge references unknown source node id {source_id}"
            ))
        })?;
        let target_alias = id_to_alias.get(&target_id).ok_or_else(|| {
            invalid(format!(
                "edge references unknown target node id {target_id}"
            ))
        })?;

        // Caido uses one `exec` alias everywhere. HuntProxy trigger nodes
        // continue on `exec` (the interpreter seeds the start node with
        // that port); action and condition nodes continue on `ok`.
        // `httpql-matches` occasionally uses a `true` branch port in store
        // samples; fail loudly rather than silently rewiring it.
        let source_def = alias_to_def_id.get(source_alias).map(String::as_str);
        let mapped_source_port = match (source_port, source_def) {
            (
                "exec",
                Some(
                    "caido/convert-start"
                    | "caido/active-start"
                    | "caido/on-intercept-request"
                    | "caido/on-intercept-response",
                ),
            ) => "exec",
            ("exec", _) => "ok",
            (port, Some("caido/httpql-matches")) => {
                return Err(invalid(format!(
                    "edge from node `{source_alias}` uses exec port `{port}`, but HuntProxy's `flow/query-match` only emits `ok`; split the branch into an explicit `flow/if-else` on the `matches` output"
                )))
            }
            (port, _) => port,
        };
        edges.push(FlowEdge {
            source: FlowPort {
                node: source_alias.clone(),
                port: mapped_source_port.to_string(),
            },
            target: FlowPort {
                node: target_alias.clone(),
                port: target_port.to_string(),
            },
        });
    }

    Ok(FlowDefinition {
        edition: FLOW_EDITION,
        kind,
        name,
        description,
        graph: FlowGraph { nodes, edges },
    })
}

/// Convert a single Caido input value into a `FlowProperty`, resolving `$ref`
/// targets through the alias→definition-id map built in pass 1.
fn convert_value(
    value: &Value,
    alias_to_def_id: &BTreeMap<String, String>,
    _current_alias: &str,
) -> DomainResult<FlowProperty> {
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("node input value is missing `kind`".into()))?;
    let data = value
        .get("data")
        .ok_or_else(|| invalid("node input value is missing `data`".into()))?;
    Ok(match kind {
        "ref" => {
            let text = data
                .as_str()
                .ok_or_else(|| invalid("ref value `data` must be a string".into()))?;
            let (alias, output) = parse_ref(text)?;
            let source_def_id = alias_to_def_id.get(&alias).ok_or_else(|| {
                invalid(format!(
                    "reference to unknown node `{alias}` (forward references to dropped terminals are not supported)"
                ))
            })?;
            let mapped = map_output_name(source_def_id, &output, &alias)?;
            FlowProperty::Ref {
                node: alias,
                output: mapped,
            }
        }
        "string" | "bool" | "number" | "json" => FlowProperty::Const {
            value: data.clone(),
        },
        other => {
            return Err(invalid(format!(
            "unsupported input value kind `{other}` (supported: ref, string, bool, number, json)"
        )))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal passive workflow: trigger -> httpql match -> if-else ->
    /// set-color on the true branch.
    const PASSIVE_SAMPLE: &str = r##"{
      "description": "color navigations",
      "edition": 2,
      "kind": "passive",
      "name": "Color navigations",
      "graph": {
        "edges": [
          {"source": {"exec_alias": "exec", "node_id": 0}, "target": {"exec_alias": "exec", "node_id": 2}},
          {"source": {"exec_alias": "exec", "node_id": 2}, "target": {"exec_alias": "exec", "node_id": 3}},
          {"source": {"exec_alias": "true", "node_id": 3}, "target": {"exec_alias": "exec", "node_id": 4}},
          {"source": {"exec_alias": "exec", "node_id": 4}, "target": {"exec_alias": "exec", "node_id": 1}}
        ],
        "nodes": [
          {"alias": "on_intercept", "definition_id": "caido/on-intercept-request", "id": 0, "inputs": [], "display": {"x": 0, "y": 0}},
          {"alias": "passive_end", "definition_id": "caido/passive-end", "id": 1, "inputs": [], "display": {"x": 0, "y": 300}},
          {"alias": "match", "definition_id": "caido/httpql-matches", "id": 2,
           "inputs": [
             {"alias": "query", "value": {"data": "request:~\"Sec-Fetch-Mode: navigate\"", "kind": "string"}},
             {"alias": "request", "value": {"data": "$on_intercept.request", "kind": "ref"}}
           ], "display": {"x": 0, "y": 100}},
          {"alias": "branch", "definition_id": "caido/if-else", "id": 3,
           "inputs": [{"alias": "condition", "value": {"data": "$match.matches", "kind": "ref"}}], "display": {"x": 0, "y": 200}},
          {"alias": "color", "definition_id": "caido/color-set", "id": 4,
           "inputs": [
             {"alias": "color", "value": {"data": "#D99E4A", "kind": "string"}},
             {"alias": "request", "value": {"data": "$on_intercept.request", "kind": "ref"}}
           ], "display": {"x": 0, "y": 250}}
        ]
      }
    }"##;

    #[test]
    fn converts_passive_workflow() {
        let def = import_caido_definition(PASSIVE_SAMPLE).unwrap();
        assert_eq!(def.edition, FLOW_EDITION);
        assert_eq!(def.kind, FlowKind::Passive);
        assert_eq!(def.name, "Color navigations");
        // passive-end dropped; 4 nodes remain.
        assert_eq!(def.graph.nodes.len(), 4);
        let types: Vec<&str> = def
            .graph
            .nodes
            .iter()
            .map(|n| n.node_type.as_str())
            .collect();
        assert!(types.contains(&"flow/on-intercept-response"));
        assert!(types.contains(&"flow/query-match"));
        assert!(types.contains(&"flow/if-else"));
        assert!(types.contains(&"flow/set-color"));
        // The httpql-matches query is stored verbatim: it must already be in
        // HuntProxy's own query language, never HTTPQL.
        let query_node = def.graph.nodes.iter().find(|n| n.alias == "match").unwrap();
        assert_eq!(
            query_node.inputs["query"],
            FlowProperty::Const {
                value: Value::String("request:~\"Sec-Fetch-Mode: navigate\"".into())
            }
        );
        // Edge into dropped passive-end is gone; the trigger keeps its `exec`
        // source port while action nodes emit `ok`.
        assert_eq!(def.graph.edges.len(), 3);
        let branch = def
            .graph
            .nodes
            .iter()
            .find(|n| n.alias == "branch")
            .unwrap();
        assert!(matches!(branch.inputs["left"], FlowProperty::Ref { .. }));
        assert!(matches!(branch.inputs["right"], FlowProperty::Const { .. }));
        let color = def.graph.nodes.iter().find(|n| n.alias == "color").unwrap();
        assert_eq!(color.inputs.len(), 1);
        assert!(color.inputs.contains_key("color"));
    }

    #[test]
    fn converts_convert_workflow_with_codec() {
        let sample = r#"{
          "edition": 2, "kind": "convert", "name": "B64", "description": "",
          "graph": {
            "edges": [
              {"source": {"exec_alias": "exec", "node_id": 0}, "target": {"exec_alias": "exec", "node_id": 2}},
              {"source": {"exec_alias": "exec", "node_id": 2}, "target": {"exec_alias": "exec", "node_id": 1}}
            ],
            "nodes": [
              {"alias": "start", "definition_id": "caido/convert-start", "id": 0, "inputs": []},
              {"alias": "end", "definition_id": "caido/convert-end", "id": 1,
               "inputs": [{"alias": "data", "value": {"data": "$decode.data", "kind": "ref"}}]},
              {"alias": "decode", "definition_id": "caido/base64-decode", "id": 2,
               "inputs": [
                 {"alias": "format", "value": {"data": "STANDARD", "kind": "string"}},
                 {"alias": "data", "value": {"data": "$start.data", "kind": "ref"}}
               ]}
            ]
          }
        }"#;
        let def = import_caido_definition(sample).unwrap();
        assert_eq!(def.kind, FlowKind::Convert);
        assert_eq!(def.graph.nodes.len(), 2);
        let decode = def
            .graph
            .nodes
            .iter()
            .find(|n| n.alias == "decode")
            .unwrap();
        assert_eq!(decode.node_type, "flow/js");
        let code = match &decode.inputs["code"] {
            FlowProperty::Const {
                value: Value::String(s),
            } => s.clone(),
            other => panic!("expected const code, got {other:?}"),
        };
        assert!(code.contains("function run(input)"));
        // start.data ref rewired to manual-start's `input` output.
        assert!(matches!(
            decode.inputs["input"],
            FlowProperty::Ref { ref node, ref output } if node == "start" && output == "input"
        ));
    }

    #[test]
    fn imports_http_code_js() {
        let sample = r#"{
          "edition": 2, "kind": "active", "name": "CORS", "description": "",
          "graph": {
            "edges": [],
            "nodes": [
              {"alias": "start", "definition_id": "caido/active-start", "id": 0, "inputs": []},
              {"alias": "js", "definition_id": "caido/http-code-js", "id": 1,
               "inputs": [{"alias": "code", "value": {"data": "return 1;", "kind": "string"}}]}
            ]
          }
        }"#;
        let def = import_caido_definition(sample).unwrap();
        let js = def.graph.nodes.iter().find(|n| n.alias == "js").unwrap();
        assert_eq!(js.node_type, "flow/js");
        match &js.inputs["code"] {
            FlowProperty::Const {
                value: Value::String(s),
            } => assert_eq!(s, "return 1;"),
            other => panic!("expected const code, got {other:?}"),
        }
        crate::flow::validate_flow(&def).unwrap();
    }

    /// Caido wires `request`/`response` refs into the node; HuntProxy passes
    /// one `input` carrying the shaped summary, so either ref collapses there.
    #[test]
    fn collapses_request_response_refs_into_input() {
        let sample = r#"{
          "edition": 2, "kind": "passive", "name": "Header", "description": "",
          "graph": {
            "edges": [],
            "nodes": [
              {"alias": "on_intercept", "definition_id": "caido/on-intercept-response", "id": 0, "inputs": []},
              {"alias": "js", "definition_id": "caido/http-code-js", "id": 1,
               "inputs": [
                 {"alias": "code", "value": {"data": "return 1;", "kind": "string"}},
                 {"alias": "request", "value": {"data": "$on_intercept.request", "kind": "ref"}},
                 {"alias": "response", "value": {"data": "$on_intercept.response", "kind": "ref"}}
               ]}
            ]
          }
        }"#;
        let def = import_caido_definition(sample).unwrap();
        let js = def.graph.nodes.iter().find(|n| n.alias == "js").unwrap();
        assert!(
            matches!(
                js.inputs["input"],
                FlowProperty::Ref { ref node, ref output } if node == "on_intercept" && output == "exchange"
            ),
            "expected exchange ref, got {:?}",
            js.inputs["input"]
        );
        crate::flow::validate_flow(&def).unwrap();
    }

    #[test]
    fn refuses_query_outside_our_dialect() {
        let sample = r#"{
          "edition": 2, "kind": "passive", "name": "Bad", "description": "",
          "graph": {
            "edges": [],
            "nodes": [
              {"alias": "on_intercept", "definition_id": "caido/on-intercept-response", "id": 0, "inputs": []},
              {"alias": "match", "definition_id": "caido/httpql-matches", "id": 1,
               "inputs": [{"alias": "query", "value": {"data": "req.headers.cont:\"x\"", "kind": "string"}}]}
            ]
          }
        }"#;
        let err = import_caido_definition(sample).unwrap_err();
        assert!(err.to_string().contains("not valid HuntProxy syntax"));
    }

    #[test]
    fn refuses_wrong_edition_and_kind() {
        assert!(import_caido_definition(
            r#"{"edition":1,"kind":"passive","name":"x","graph":{"nodes":[]}}"#
        )
        .is_err());
        assert!(import_caido_definition(
            r#"{"edition":2,"kind":"weird","name":"x","graph":{"nodes":[]}}"#
        )
        .is_err());
        assert!(import_caido_definition("not json").is_err());
    }

    /// Real workflow store samples shipped as fixtures. Guard the converter
    /// against the exact shapes the Caido community store publishes.
    #[test]
    fn converts_real_store_samples() {
        let cases: &[(&str, &str, FlowKind)] = &[
            (
                "base64-decode",
                include_str!("../../tests/fixtures/caido/base64-decode.json"),
                FlowKind::Convert,
            ),
            (
                "color-top-level-navigation",
                include_str!("../../tests/fixtures/caido/color-top-level-navigation.json"),
                FlowKind::Passive,
            ),
            (
                "evalsso",
                include_str!("../../tests/fixtures/caido/evalsso.json"),
                FlowKind::Passive,
            ),
        ];
        for (name, raw, expect_kind) in cases {
            let def = import_caido_definition(raw).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(def.kind, *expect_kind, "{name}");
            assert!(!def.graph.nodes.is_empty(), "{name}");
            crate::flow::validate_flow(&def)
                .unwrap_or_else(|e| panic!("{name} imported but failed validation: {e}"));
            if *name == "base64-decode" {
                assert_eq!(
                    def.graph.edges.len(),
                    1,
                    "{name} edges: {:?}",
                    def.graph.edges
                );
                let edge = &def.graph.edges[0];
                assert_eq!(edge.source.node, "start", "{name}");
                assert_eq!(edge.source.port, "exec", "{name}");
                assert_eq!(edge.target.node, "base64_decode", "{name}");
                assert_eq!(edge.target.port, "exec", "{name}");
            }
        }
    }

    /// `http-code-js` shows up in the real store shapes too (every `active`
    /// workflow). Wire it to the trigger and assert the edge ports validate:
    /// the trigger's `exec` output maps to the action node's `ok` output
    /// port, while the action node's exec *input* port stays `exec`.
    #[test]
    fn imports_http_code_js_fixture_shape() {
        let sample = include_str!("../../tests/fixtures/caido/evalsso.json");
        let mut root: Value = serde_json::from_str(sample).unwrap();
        let trigger_id = root["graph"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["definition_id"] == "caido/on-intercept-response")
            .unwrap()["id"]
            .as_i64()
            .unwrap();
        let nodes = root["graph"]["nodes"].as_array_mut().unwrap();
        nodes.push(serde_json::json!({
            "alias": "js",
            "definition_id": "caido/http-code-js",
            "id": 999,
            "inputs": [
                {"alias": "code", "value": {"data": "return 1;", "kind": "string"}},
                {"alias": "request", "value": {"data": "$on_intercept_response.request", "kind": "ref"}}
            ]
        }));
        root["graph"]["edges"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "source": {"exec_alias": "exec", "node_id": trigger_id},
                "target": {"exec_alias": "exec", "node_id": 999}
            }));
        let def = import_caido_definition(&root.to_string()).unwrap();
        let js = def.graph.nodes.iter().find(|n| n.alias == "js").unwrap();
        assert_eq!(js.node_type, "flow/js");
        assert!(
            matches!(
                js.inputs["input"],
                FlowProperty::Ref { ref node, ref output } if node == "on_intercept_response" && output == "exchange"
            ),
            "expected exchange ref, got {:?}",
            js.inputs["input"]
        );
        let edge = def
            .graph
            .edges
            .iter()
            .find(|e| e.source.node == "on_intercept_response" && e.target.node == "js")
            .unwrap();
        assert_eq!(edge.source.port, "exec");
        assert_eq!(edge.target.port, "exec");
        crate::flow::validate_flow(&def).unwrap();
    }
}
