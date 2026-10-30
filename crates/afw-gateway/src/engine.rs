//! Rule engine used by the gateway. Points to the stand-in until `afw-engine` (lot L5) is
//! merged; then this module becomes `pub use afw_engine::{...}` with no other change.

pub use crate::engine_shim::{
    CompileError, CompiledPolicy, Decision, DecisionLayer, FlowContext, Implicit,
};
