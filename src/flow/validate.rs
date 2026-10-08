//! Registry-aware flow validation: known node types, declared ports, reference
//! targets, constant shapes, trigger presence, and acyclicity.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::domain::{DomainError, DomainResult, FlowDefinition, FlowKind, FlowProperty};

use super::registry::{node_info, NodeInfo, ValueKind};

pub fn validate_flow(definition: &FlowDefinition) -> DomainResult<()> {
    definition.validate()?;

    let mut types: BTreeMap<&str, &'static NodeInfo> = BTreeMap::new();
    for node in &definition.graph.nodes {
        let info = node_info(&node.node_type).ok_or_else(|| {
            DomainError::invalid(format!(
                "node `{}` uses unknown type `{}`",
                node.alias, node.node_type
            ))
        })?;
        types.insert(node.alias.as_str(), info);
    }

    for node in &definition.graph.nodes {
        let info = types[node.alias.as_str()];
        for (name, property) in &node.inputs {
            let spec = info.input(name).ok_or_else(|| {
                DomainError::invalid(format!(
                    "node `{}` of type `{}` has no input `{name}`",
                    node.alias, node.node_type
                ))
            })?;
            match property {
                FlowProperty::Const { value } => {
                    if !spec.kind.holds(value) {
                        return Err(DomainError::invalid(format!(
                            "input `{name}` on `{}` expects {}, got {}",
                            node.alias,
                            spec.kind.as_str(),
                            json_kind(value)
                        )));
                    }
                }
                FlowProperty::Ref {
                    node: source,
                    output,
                } => {
                    let source_info = types.get(source.as_str()).copied().ok_or_else(|| {
                        DomainError::invalid(format!(
                            "input `{name}` on `{}` references unknown node `{source}`",
                            node.alias
                        ))
                    })?;
                    let source_output = source_info.output(output).ok_or_else(|| {
                        DomainError::invalid(format!(
                            "node `{source}` of type `{}` has no output `{output}`",
                            source_info.type_name
                        ))
                    })?;
                    if !spec.kind.compatible(source_output.kind) {
                        return Err(DomainError::invalid(format!(
                            "input `{name}` on `{}` expects {} but `{source}.{output}` is {}",
                            node.alias,
                            spec.kind.as_str(),
                            source_output.kind.as_str()
                        )));
                    }
                }
            }
        }
        for spec in info.inputs {
            if spec.required && !node.inputs.contains_key(spec.name) {
                return Err(DomainError::invalid(format!(
                    "node `{}` of type `{}` is missing required input `{}`",
                    node.alias, node.node_type, spec.name
                )));
            }
        }
    }

    for edge in &definition.graph.edges {
        let source = types[edge.source.node.as_str()];
        if !source.exec_out_port(&edge.source.port) {
            return Err(DomainError::invalid(format!(
                "node `{}` of type `{}` has no output exec port `{}`",
                edge.source.node, source.type_name, edge.source.port
            )));
        }
        let target = types[edge.target.node.as_str()];
        if !target.exec_in_port(&edge.target.port) {
            return Err(DomainError::invalid(format!(
                "node `{}` of type `{}` has no input exec port `{}`",
                edge.target.node, target.type_name, edge.target.port
            )));
        }
    }

    validate_triggers(definition, &types)?;
    validate_acyclic(definition)?;
    Ok(())
}

fn validate_triggers(
    definition: &FlowDefinition,
    types: &BTreeMap<&str, &'static NodeInfo>,
) -> DomainResult<()> {
    let wanted = match definition.kind {
        FlowKind::Passive => "exchange",
        FlowKind::Active => "manual",
        FlowKind::Convert => return Ok(()),
    };
    let has_trigger = types.values().any(|info| info.trigger == Some(wanted));
    if !has_trigger {
        let expected = if wanted == "exchange" {
            "flow/on-intercept-response"
        } else {
            "flow/manual-start"
        };
        return Err(DomainError::invalid(format!(
            "{} flows must contain a `{expected}` trigger node",
            definition.kind.as_str()
        )));
    }
    Ok(())
}

/// Exec edges plus reference dependencies must form a DAG.
fn validate_acyclic(definition: &FlowDefinition) -> DomainResult<()> {
    let aliases: BTreeSet<&str> = definition
        .graph
        .nodes
        .iter()
        .map(|node| node.alias.as_str())
        .collect();

    fn add_edge<'a>(
        from: &'a str,
        to: &'a str,
        adjacency: &mut BTreeMap<&'a str, Vec<&'a str>>,
        indegree: &mut BTreeMap<&'a str, usize>,
    ) {
        if from == to {
            return;
        }
        let targets = adjacency.get_mut(from).expect("alias exists");
        if !targets.contains(&to) {
            targets.push(to);
            *indegree.get_mut(to).expect("alias exists") += 1;
        }
    }

    let mut indegree: BTreeMap<&str, usize> = aliases.iter().map(|alias| (*alias, 0)).collect();
    let mut adjacency: BTreeMap<&str, Vec<&str>> =
        aliases.iter().map(|alias| (*alias, vec![])).collect();

    for edge in &definition.graph.edges {
        add_edge(
            edge.source.node.as_str(),
            edge.target.node.as_str(),
            &mut adjacency,
            &mut indegree,
        );
    }
    for node in &definition.graph.nodes {
        for property in node.inputs.values() {
            if let FlowProperty::Ref { node: source, .. } = property {
                add_edge(
                    source.as_str(),
                    node.alias.as_str(),
                    &mut adjacency,
                    &mut indegree,
                );
            }
        }
    }

    let mut queue: VecDeque<&str> = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(alias, _)| *alias)
        .collect();
    let mut visited = 0usize;
    while let Some(alias) = queue.pop_front() {
        visited += 1;
        for target in adjacency.get(alias).into_iter().flatten() {
            let degree = indegree.get_mut(target).expect("alias exists");
            *degree -= 1;
            if *degree == 0 {
                queue.push_back(target);
            }
        }
    }
    if visited != aliases.len() {
        return Err(DomainError::invalid(
            "flow graph contains a cycle; nodes must form a directed acyclic graph",
        ));
    }
    Ok(())
}

fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => ValueKind::Boolean.as_str(),
        serde_json::Value::Number(_) => ValueKind::Number.as_str(),
        serde_json::Value::String(_) => ValueKind::String.as_str(),
        serde_json::Value::Array(_) => ValueKind::Array.as_str(),
        serde_json::Value::Object(_) => ValueKind::Object.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::FlowPort;

    fn sample() -> FlowDefinition {
        serde_json::from_value(serde_json::json!({
            "edition": 1,
            "kind": "passive",
            "name": "flag xff",
            "graph": {
                "nodes": [
                    {"type": "flow/on-intercept-response", "alias": "start", "inputs": {}},
                    {"type": "flow/if-else", "alias": "check", "inputs": {
                        "left": {"kind": "const", "value": 500},
                        "right": {"kind": "ref", "node": "start", "output": "status"}
                    }},
                    {"type": "flow/set-color", "alias": "paint", "inputs": {
                        "color": {"kind": "const", "value": "red"}
                    }}
                ],
                "edges": [
                    {"source": {"node": "start", "port": "exec"},
                     "target": {"node": "check", "port": "exec"}},
                    {"source": {"node": "check", "port": "true"},
                     "target": {"node": "paint", "port": "exec"}}
                ]
            }
        }))
        .unwrap()
    }

    #[test]
    fn valid_flow_passes() {
        validate_flow(&sample()).unwrap();
    }

    #[test]
    fn rejects_unknown_node_type() {
        let mut definition = sample();
        definition.graph.nodes[1].node_type = "flow/mystery".into();
        let error = validate_flow(&definition).unwrap_err().to_string();
        assert!(error.contains("unknown type"), "{error}");
    }

    #[test]
    fn rejects_unknown_ports_and_inputs() {
        let mut definition = sample();
        definition.graph.edges[1].source.port = "maybe".into();
        let error = validate_flow(&definition).unwrap_err().to_string();
        assert!(error.contains("no output exec port"), "{error}");

        let mut definition = sample();
        definition.graph.nodes[2]
            .inputs
            .insert("shine".into(), FlowProperty::Const { value: 1.into() });
        let error = validate_flow(&definition).unwrap_err().to_string();
        assert!(error.contains("no input `shine`"), "{error}");
    }

    #[test]
    fn rejects_unknown_reference_output() {
        let mut definition = sample();
        definition.graph.nodes[1].inputs.insert(
            "right".into(),
            FlowProperty::Ref {
                node: "start".into(),
                output: "missing".into(),
            },
        );
        let error = validate_flow(&definition).unwrap_err().to_string();
        assert!(error.contains("no output `missing`"), "{error}");
    }

    #[test]
    fn rejects_missing_required_input() {
        let mut definition = sample();
        definition.graph.nodes[2].inputs.clear();
        let error = validate_flow(&definition).unwrap_err().to_string();
        assert!(error.contains("missing required input `color`"), "{error}");
    }

    #[test]
    fn rejects_wrong_kind_const() {
        let mut definition = sample();
        definition.graph.nodes[2]
            .inputs
            .insert("color".into(), FlowProperty::Const { value: 7.into() });
        let error = validate_flow(&definition).unwrap_err().to_string();
        assert!(error.contains("expects string, got number"), "{error}");
    }

    #[test]
    fn rejects_missing_trigger_for_kind() {
        let mut definition = sample();
        definition.kind = FlowKind::Active;
        let error = validate_flow(&definition).unwrap_err().to_string();
        assert!(error.contains("flow/manual-start"), "{error}");
    }

    #[test]
    fn rejects_exec_cycle() {
        let mut definition = sample();
        definition.graph.edges.push(crate::domain::FlowEdge {
            source: FlowPort {
                node: "paint".into(),
                port: "ok".into(),
            },
            target: FlowPort {
                node: "check".into(),
                port: "exec".into(),
            },
        });
        let error = validate_flow(&definition).unwrap_err().to_string();
        assert!(error.contains("cycle"), "{error}");
    }

    #[test]
    fn rejects_reference_cycle() {
        let definition: FlowDefinition = serde_json::from_value(serde_json::json!({
            "edition": 1,
            "kind": "passive",
            "name": "cycle",
            "graph": {
                "nodes": [
                    {"type": "flow/on-intercept-response", "alias": "start", "inputs": {}},
                    {"type": "flow/json-parse", "alias": "parse", "inputs": {
                        "text": {"kind": "ref", "node": "tpl", "output": "text"}
                    }},
                    {"type": "flow/template", "alias": "tpl", "inputs": {
                        "template": {"kind": "const", "value": "hi"},
                        "vars": {"kind": "ref", "node": "parse", "output": "value"}
                    }}
                ],
                "edges": [
                    {"source": {"node": "start", "port": "exec"},
                     "target": {"node": "parse", "port": "exec"}},
                    {"source": {"node": "parse", "port": "ok"},
                     "target": {"node": "tpl", "port": "exec"}}
                ]
            }
        }))
        .unwrap();
        let error = validate_flow(&definition).unwrap_err().to_string();
        assert!(error.contains("cycle"), "{error}");
    }
}
