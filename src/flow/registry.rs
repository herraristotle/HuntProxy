//! Flow node catalog: declares every built-in node's inputs, outputs, and
//! exec ports. The validator, the engine, and the UI inspector all read this.

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueKind {
    Any,
    String,
    Number,
    Boolean,
    Object,
    Array,
}

impl ValueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::String => "string",
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::Object => "object",
            Self::Array => "array",
        }
    }

    /// Static port compatibility: equal kinds, or either side is `Any`.
    pub fn compatible(self, other: Self) -> bool {
        self == other || self == Self::Any || other == Self::Any
    }

    /// Runtime check used for constant inputs.
    pub fn holds(self, value: &Value) -> bool {
        match self {
            Self::Any => true,
            Self::String => value.is_string(),
            Self::Number => value.is_number(),
            Self::Boolean => value.is_boolean(),
            Self::Object => value.is_object(),
            Self::Array => value.is_array(),
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct PortSpec {
    pub name: &'static str,
    pub kind: ValueKind,
    pub required: bool,
    pub doc: &'static str,
}

impl PortSpec {
    pub const fn input(
        name: &'static str,
        kind: ValueKind,
        required: bool,
        doc: &'static str,
    ) -> Self {
        Self {
            name,
            kind,
            required,
            doc,
        }
    }

    pub const fn output(name: &'static str, kind: ValueKind, doc: &'static str) -> Self {
        Self {
            name,
            kind,
            required: false,
            doc,
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct NodeInfo {
    pub type_name: &'static str,
    pub display: &'static str,
    pub category: &'static str,
    pub doc: &'static str,
    /// Trigger payload this node consumes: `"exchange"` or `"manual"`.
    pub trigger: Option<&'static str>,
    pub inputs: &'static [PortSpec],
    pub outputs: &'static [PortSpec],
    pub exec_in: &'static [&'static str],
    pub exec_out: &'static [&'static str],
}

impl NodeInfo {
    pub fn input(&self, name: &str) -> Option<&'static PortSpec> {
        self.inputs.iter().find(|port| port.name == name)
    }

    pub fn output(&self, name: &str) -> Option<&'static PortSpec> {
        self.outputs.iter().find(|port| port.name == name)
    }

    pub fn exec_out_port(&self, name: &str) -> bool {
        self.exec_out.contains(&name)
    }

    pub fn exec_in_port(&self, name: &str) -> bool {
        self.exec_in.contains(&name)
    }
}

const NO_INPUTS: &[PortSpec] = &[];
const NO_OUTPUTS: &[PortSpec] = &[];
const EXEC: &[&str] = &["exec"];
const OK_ERROR: &[&str] = &["ok", "error"];

const NODES: &[NodeInfo] = &[
    NodeInfo {
        type_name: "flow/on-intercept-response",
        display: "On response",
        category: "trigger",
        doc: "Starts a passive flow for each captured in-scope exchange.",
        trigger: Some("exchange"),
        inputs: NO_INPUTS,
        outputs: &[
            PortSpec::output("exchange", ValueKind::Object, "Exchange summary that fired the flow."),
            PortSpec::output("status", ValueKind::Number, "Response status code."),
            PortSpec::output("method", ValueKind::String, "Request method."),
            PortSpec::output("url", ValueKind::String, "Request URL."),
        ],
        exec_in: &[],
        exec_out: EXEC,
    },
    NodeInfo {
        type_name: "flow/manual-start",
        display: "Manual start",
        category: "trigger",
        doc: "Starts an active flow on demand with a caller-supplied input.",
        trigger: Some("manual"),
        inputs: NO_INPUTS,
        outputs: &[PortSpec::output("input", ValueKind::Any, "Payload supplied when the flow was run.")],
        exec_in: &[],
        exec_out: EXEC,
    },
    NodeInfo {
        type_name: "flow/if-else",
        display: "If / else",
        category: "logic",
        doc: "Compares left and right, then continues on the true or false port.",
        trigger: None,
        inputs: &[
            PortSpec::input("left", ValueKind::Any, true, "Left operand."),
            PortSpec::input("right", ValueKind::Any, true, "Right operand."),
            PortSpec::input(
                "op",
                ValueKind::String,
                false,
                "eq, ne, gt, gte, lt, lte, contains, startswith, endswith, or matches. Defaults to eq.",
            ),
        ],
        outputs: NO_OUTPUTS,
        exec_in: EXEC,
        exec_out: &["true", "false"],
    },
    NodeInfo {
        type_name: "flow/template",
        display: "Template",
        category: "transform",
        doc: "Renders {{key}} placeholders from vars into text.",
        trigger: None,
        inputs: &[
            PortSpec::input("template", ValueKind::String, true, "Text with {{key}} placeholders."),
            PortSpec::input("vars", ValueKind::Object, false, "Values substituted into the template."),
        ],
        outputs: &[PortSpec::output("text", ValueKind::String, "Rendered text.")],
        exec_in: EXEC,
        exec_out: OK_ERROR,
    },
    NodeInfo {
        type_name: "flow/json-parse",
        display: "Parse JSON",
        category: "transform",
        doc: "Parses a JSON string into a value.",
        trigger: None,
        inputs: &[PortSpec::input("text", ValueKind::String, true, "JSON text to parse.")],
        outputs: &[PortSpec::output("value", ValueKind::Any, "Parsed value.")],
        exec_in: EXEC,
        exec_out: OK_ERROR,
    },
    NodeInfo {
        type_name: "flow/json-select",
        display: "Select path",
        category: "transform",
        doc: "Reads a dotted path (a.b.0.c) out of a value.",
        trigger: None,
        inputs: &[
            PortSpec::input("value", ValueKind::Any, true, "Value to read from."),
            PortSpec::input("path", ValueKind::String, true, "Dotted path such as user.roles.0."),
        ],
        outputs: &[
            PortSpec::output("found", ValueKind::Boolean, "Whether the path existed."),
            PortSpec::output("value", ValueKind::Any, "Value at the path, or null."),
        ],
        exec_in: EXEC,
        exec_out: OK_ERROR,
    },
    NodeInfo {
        type_name: "flow/regex-match",
        display: "Regex match",
        category: "transform",
        doc: "Matches text against a regular expression.",
        trigger: None,
        inputs: &[
            PortSpec::input("text", ValueKind::String, true, "Text to search."),
            PortSpec::input("pattern", ValueKind::String, true, "Rust regular expression."),
            PortSpec::input("flags", ValueKind::String, false, "Optional flags: i, m, s."),
        ],
        outputs: &[
            PortSpec::output("matched", ValueKind::Boolean, "Whether the pattern matched."),
            PortSpec::output("groups", ValueKind::Array, "Capture groups, including the full match at index 0."),
        ],
        exec_in: EXEC,
        exec_out: OK_ERROR,
    },
    NodeInfo {
        type_name: "flow/http-request",
        display: "HTTP request",
        category: "network",
        doc: "Sends a request through HuntProxy's Reply pipeline and records it in History.",
        trigger: None,
        inputs: &[
            PortSpec::input("method", ValueKind::String, true, "HTTP method such as GET or POST."),
            PortSpec::input("url", ValueKind::String, true, "Absolute http(s) URL."),
            PortSpec::input("headers", ValueKind::Object, false, "Header overrides, name to value."),
            PortSpec::input("body", ValueKind::String, false, "Raw request body."),
            PortSpec::input("timeout_ms", ValueKind::Number, false, "Total timeout. Defaults to 30000."),
        ],
        outputs: &[
            PortSpec::output("status", ValueKind::Number, "Response status code."),
            PortSpec::output("body", ValueKind::String, "Response body text."),
            PortSpec::output("headers", ValueKind::Object, "Response headers."),
            PortSpec::output("exchange_id", ValueKind::Number, "Recorded exchange id, when captured."),
            PortSpec::output("duration_ms", ValueKind::Number, "Round-trip duration in milliseconds."),
        ],
        exec_in: EXEC,
        exec_out: OK_ERROR,
    },
    NodeInfo {
        type_name: "flow/js",
        display: "JavaScript",
        category: "transform",
        doc: "Runs a function run(input) in QuickJS and returns its result.",
        trigger: None,
        inputs: &[
            PortSpec::input("code", ValueKind::String, true, "Script defining function run(input)."),
            PortSpec::input("input", ValueKind::Any, false, "Argument passed to run()."),
            PortSpec::input("timeout_ms", ValueKind::Number, false, "Execution timeout. Defaults to 5000."),
        ],
        outputs: &[PortSpec::output("output", ValueKind::Any, "Value returned by run().")],
        exec_in: EXEC,
        exec_out: OK_ERROR,
    },
    NodeInfo {
        type_name: "flow/shell",
        display: "Shell",
        category: "shell",
        doc: "Runs a command directly (no shell interpretation). Subject to flows.allow_shell.",
        trigger: None,
        inputs: &[
            PortSpec::input("command", ValueKind::String, true, "Executable name or path."),
            PortSpec::input("args", ValueKind::Array, false, "Arguments passed to the executable."),
            PortSpec::input("timeout_ms", ValueKind::Number, false, "Kill timeout. Defaults to 15000."),
        ],
        outputs: &[
            PortSpec::output("stdout", ValueKind::String, "Standard output, capped."),
            PortSpec::output("stderr", ValueKind::String, "Standard error, capped."),
            PortSpec::output("code", ValueKind::Number, "Exit code, or null when killed by a signal."),
        ],
        exec_in: EXEC,
        exec_out: OK_ERROR,
    },
    NodeInfo {
        type_name: "flow/set-color",
        display: "Set color",
        category: "output",
        doc: "Colors an exchange row in History.",
        trigger: None,
        inputs: &[
            PortSpec::input("color", ValueKind::String, true, "Color name or #rrggbb value."),
            PortSpec::input("exchange_id", ValueKind::Number, false, "Exchange to color. Defaults to the triggering exchange."),
        ],
        outputs: &[PortSpec::output("exchange_id", ValueKind::Number, "Exchange that was colored.")],
        exec_in: EXEC,
        exec_out: OK_ERROR,
    },
    NodeInfo {
        type_name: "flow/report-finding",
        display: "Report finding",
        category: "output",
        doc: "Creates a finding, optionally attached to the triggering exchange.",
        trigger: None,
        inputs: &[
            PortSpec::input("title", ValueKind::String, true, "Finding title."),
            PortSpec::input("description", ValueKind::String, true, "Finding description."),
            PortSpec::input("exchange_id", ValueKind::Number, false, "Related exchange. Defaults to the triggering exchange."),
        ],
        outputs: &[PortSpec::output("finding_id", ValueKind::Number, "Created finding id.")],
        exec_in: EXEC,
        exec_out: OK_ERROR,
    },
];

pub fn node_catalog() -> &'static [NodeInfo] {
    NODES
}

pub fn node_info(type_name: &str) -> Option<&'static NodeInfo> {
    NODES.iter().find(|node| node.type_name == type_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_entries_are_consistent() {
        assert!(NODES.len() >= 12);
        let mut seen = std::collections::BTreeSet::new();
        for node in NODES {
            assert!(seen.insert(node.type_name), "duplicate {}", node.type_name);
            assert!(!node.display.is_empty());
            assert!(!node.category.is_empty());
            if node.trigger.is_some() {
                assert!(node.exec_in.is_empty(), "{} is a trigger", node.type_name);
                assert!(!node.exec_out.is_empty());
            } else {
                assert!(!node.exec_in.is_empty(), "{} needs exec in", node.type_name);
                assert!(!node.exec_out.is_empty());
            }
            let mut input_ports = std::collections::BTreeSet::new();
            for spec in node.inputs {
                assert!(
                    input_ports.insert(spec.name),
                    "{} input {}",
                    node.type_name,
                    spec.name
                );
            }
            let mut output_ports = std::collections::BTreeSet::new();
            for spec in node.outputs {
                assert!(
                    output_ports.insert(spec.name),
                    "{} output {}",
                    node.type_name,
                    spec.name
                );
            }
        }
    }

    #[test]
    fn lookup_finds_known_and_unknown_types() {
        let info = node_info("flow/if-else").expect("if-else exists");
        assert_eq!(info.inputs.len(), 3);
        assert!(node_info("flow/nope").is_none());
        assert!(node_info("start").is_none());
    }

    #[test]
    fn value_kinds_match_values() {
        assert!(ValueKind::String.holds(&Value::from("x")));
        assert!(!ValueKind::String.holds(&Value::from(1)));
        assert!(ValueKind::Number.holds(&Value::from(1.5)));
        assert!(ValueKind::Array.holds(&serde_json::json!([])));
        assert!(ValueKind::Any.compatible(ValueKind::Object));
        assert!(!ValueKind::String.compatible(ValueKind::Number));
    }
}
