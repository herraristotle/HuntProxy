//! Flow engine: node registry, validation, execution, and job orchestration.

mod interp;
mod js;
mod nodes;
mod registry;
mod runner;
mod shell;
mod validate;

pub use interp::{
    trigger_kind_for, FlowRunOptions, FlowRunOutcome, FlowStepLog, FlowTrigger, NodeExecCtx,
    NodeHandler, NodeOutcome, MAX_FLOW_STEPS,
};
pub use js::run_flow_js;
pub use nodes::BuiltInHandler;
pub use registry::{node_catalog, node_info, NodeInfo, PortSpec, ValueKind};
pub use runner::{
    FlowJobState, FlowJobView, FlowService, MAX_CONCURRENT_FLOW_JOBS, MAX_FINISHED_FLOW_JOBS,
};
pub use shell::{run_flow_shell, ShellOutput, ShellRequest};
pub use validate::validate_flow;
