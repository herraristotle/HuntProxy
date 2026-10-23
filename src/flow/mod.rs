//! Flow engine: node registry, validation, execution, and job orchestration.

mod interp;
mod js;
mod nodes;
mod registry;
mod runner;
mod shell;
mod validate;

pub use interp::{
    FlowRunOptions, FlowRunOutcome, FlowStepLog, FlowTrigger, MAX_FLOW_STEPS, NodeExecCtx,
    NodeHandler, NodeOutcome, trigger_kind_for,
};
pub use js::run_flow_js;
pub use nodes::BuiltInHandler;
pub use registry::{NodeInfo, PortSpec, ValueKind, node_catalog, node_info};
pub use runner::{
    FlowJobState, FlowJobView, FlowService, MAX_CONCURRENT_FLOW_JOBS, MAX_FINISHED_FLOW_JOBS,
};
pub use shell::{ShellOutput, ShellRequest, run_flow_shell};
pub use validate::validate_flow;
