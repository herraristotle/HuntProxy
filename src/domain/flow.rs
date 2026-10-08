//! Flow (graph workflow) definitions — edition 1.
//!
//! A flow is a control-flow DAG: edges carry execution only. Data travels via
//! `{kind:"ref"}` properties that name an earlier node's output by alias.

use serde::{Deserialize, Serialize};
use time::serde::rfc3339;
use time::OffsetDateTime;

use super::{DomainError, DomainResult, FlowId, ProjectId};

pub const FLOW_EDITION: u8 = 1;
pub const MAX_FLOW_NAME: usize = 128;
pub const MAX_FLOW_DESCRIPTION: usize = 4096;
pub const MAX_FLOW_NODES: usize = 256;
pub const MAX_FLOW_EDGES: usize = 512;
pub const MAX_FLOW_INPUTS: usize = 64;
pub const MAX_FLOW_ALIAS: usize = 64;
pub const MAX_FLOW_TYPE: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowKind {
    Passive,
    Active,
    Convert,
}

impl FlowKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::Active => "active",
            Self::Convert => "convert",
        }
    }

    pub fn parse(value: &str) -> DomainResult<Self> {
        match value {
            "passive" => Ok(Self::Passive),
            "active" => Ok(Self::Active),
            "convert" => Ok(Self::Convert),
            other => Err(DomainError::invalid(format!("unknown flow kind `{other}`"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowDefinition {
    pub edition: u8,
    pub kind: FlowKind,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub graph: FlowGraph,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FlowGraph {
    #[serde(default)]
    pub nodes: Vec<FlowNode>,
    #[serde(default)]
    pub edges: Vec<FlowEdge>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowNode {
    #[serde(rename = "type")]
    pub node_type: String,
    pub alias: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<FlowDisplay>,
    #[serde(default)]
    pub inputs: std::collections::BTreeMap<String, FlowProperty>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowDisplay {
    pub x: i64,
    pub y: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowProperty {
    Const { value: serde_json::Value },
    Ref { node: String, output: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowEdge {
    pub source: FlowPort,
    pub target: FlowPort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowPort {
    pub node: String,
    pub port: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub id: FlowId,
    pub project_id: ProjectId,
    pub name: String,
    pub description: String,
    pub kind: FlowKind,
    pub edition: u8,
    pub enabled: bool,
    pub definition: FlowDefinition,
    #[serde(with = "rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub updated_at: OffsetDateTime,
}

fn valid_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_FLOW_ALIAS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

impl FlowDefinition {
    /// Structural validation: shape, sizes, aliases, and reference targets.
    /// Registry checks (known node types, port names, type compatibility)
    /// happen later at load time in the flow engine.
    pub fn validate(&self) -> DomainResult<()> {
        if self.edition != FLOW_EDITION {
            return Err(DomainError::invalid(format!(
                "unsupported flow edition {}; this build supports {FLOW_EDITION}",
                self.edition
            )));
        }
        let name = self.name.trim();
        if name.is_empty() {
            return Err(DomainError::invalid("flow name must not be empty"));
        }
        if name.len() > MAX_FLOW_NAME {
            return Err(DomainError::invalid(format!(
                "flow name too long (max {MAX_FLOW_NAME} bytes)"
            )));
        }
        if self.description.len() > MAX_FLOW_DESCRIPTION {
            return Err(DomainError::invalid(format!(
                "flow description too long (max {MAX_FLOW_DESCRIPTION} bytes)"
            )));
        }
        if self.graph.nodes.is_empty() {
            return Err(DomainError::invalid("flow must contain at least one node"));
        }
        if self.graph.nodes.len() > MAX_FLOW_NODES {
            return Err(DomainError::invalid(format!(
                "too many flow nodes (max {MAX_FLOW_NODES})"
            )));
        }
        if self.graph.edges.len() > MAX_FLOW_EDGES {
            return Err(DomainError::invalid(format!(
                "too many flow edges (max {MAX_FLOW_EDGES})"
            )));
        }

        let mut aliases: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for node in &self.graph.nodes {
            if !valid_alias(&node.alias) {
                return Err(DomainError::invalid(format!(
                    "invalid node alias `{}` (use 1-{} bytes of [A-Za-z0-9_-])",
                    node.alias, MAX_FLOW_ALIAS
                )));
            }
            if !aliases.insert(node.alias.as_str()) {
                return Err(DomainError::invalid(format!(
                    "duplicate node alias `{}`",
                    node.alias
                )));
            }
            if node.node_type.is_empty() || node.node_type.len() > MAX_FLOW_TYPE {
                return Err(DomainError::invalid(format!(
                    "invalid node type for alias `{}`",
                    node.alias
                )));
            }
            if node.inputs.len() > MAX_FLOW_INPUTS {
                return Err(DomainError::invalid(format!(
                    "too many inputs on node `{}` (max {MAX_FLOW_INPUTS})",
                    node.alias
                )));
            }
            for (input, property) in &node.inputs {
                if !valid_alias(input) {
                    return Err(DomainError::invalid(format!(
                        "invalid input name `{input}` on node `{}`",
                        node.alias
                    )));
                }
                if let FlowProperty::Ref { node: target, .. } = property {
                    if !valid_alias(target) {
                        return Err(DomainError::invalid(format!(
                            "invalid reference node `{target}` on input `{input}` of node `{}`",
                            node.alias
                        )));
                    }
                }
            }
        }

        for edge in &self.graph.edges {
            for port in [&edge.source, &edge.target] {
                if !aliases.contains(port.node.as_str()) {
                    return Err(DomainError::invalid(format!(
                        "edge references unknown node `{}`",
                        port.node
                    )));
                }
                if !valid_alias(&port.port) {
                    return Err(DomainError::invalid(format!(
                        "invalid edge port `{}`",
                        port.port
                    )));
                }
            }
            if edge.source.node == edge.target.node && edge.source.port == edge.target.port {
                return Err(DomainError::invalid(format!(
                    "self edge on node `{}`",
                    edge.source.node
                )));
            }
        }

        // Reference targets must be declared nodes; ordering ("earlier node")
        // is enforced by the engine at run/validate time.
        for node in &self.graph.nodes {
            for property in node.inputs.values() {
                if let FlowProperty::Ref { node: target, .. } = property {
                    if !aliases.contains(target.as_str()) {
                        return Err(DomainError::invalid(format!(
                            "input on node `{}` references unknown node `{target}`",
                            node.alias
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FlowDefinition {
        serde_json::from_value(serde_json::json!({
            "edition": 1,
            "kind": "passive",
            "name": "flag xff",
            "description": "probe X-Forwarded-For",
            "graph": {
                "nodes": [
                    {
                        "type": "flow/on-intercept-response",
                        "alias": "start",
                        "display": {"x": 40, "y": 80},
                        "inputs": {}
                    },
                    {
                        "type": "flow/if-else",
                        "alias": "check",
                        "inputs": {
                            "left": {"kind": "const", "value": 500},
                            "right": {"kind": "ref", "node": "start", "output": "status"}
                        }
                    }
                ],
                "edges": [
                    {"source": {"node": "start", "port": "exec"},
                     "target": {"node": "check", "port": "exec"}}
                ]
            }
        }))
        .unwrap()
    }

    #[test]
    fn definition_round_trips() {
        let definition = sample();
        definition.validate().unwrap();
        let encoded = serde_json::to_string(&definition).unwrap();
        let decoded: FlowDefinition = serde_json::from_str(&encoded).unwrap();
        assert_eq!(definition, decoded);
        // Refs serialize with the kind tag.
        assert!(encoded.contains(r#""kind":"ref""#));
        assert!(encoded.contains(r#""kind":"const""#));
    }

    #[test]
    fn rejects_bad_edition_and_empty_name() {
        let mut definition = sample();
        definition.edition = 2;
        assert!(definition.validate().is_err());

        let mut definition = sample();
        definition.name = "  ".into();
        assert!(definition.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_and_invalid_aliases() {
        let mut definition = sample();
        definition.graph.nodes[1].alias = "start".into();
        assert!(definition
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate"));

        let mut definition = sample();
        definition.graph.nodes[0].alias = "bad alias".into();
        assert!(definition
            .validate()
            .unwrap_err()
            .to_string()
            .contains("invalid node alias"));
    }

    #[test]
    fn rejects_unknown_reference_and_edge_targets() {
        let mut definition = sample();
        definition.graph.nodes[1].inputs.insert(
            "left".into(),
            FlowProperty::Ref {
                node: "ghost".into(),
                output: "x".into(),
            },
        );
        assert!(definition
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unknown node"));

        let mut definition = sample();
        definition.graph.edges[0].target.node = "ghost".into();
        assert!(definition
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unknown node"));
    }

    #[test]
    fn rejects_empty_graph_and_self_edge() {
        let mut definition = sample();
        definition.graph.nodes.clear();
        assert!(definition.validate().is_err());

        let mut definition = sample();
        let source = definition.graph.edges[0].source.clone();
        definition.graph.edges[0].target = source;
        assert!(definition
            .validate()
            .unwrap_err()
            .to_string()
            .contains("self edge"));
    }
}
