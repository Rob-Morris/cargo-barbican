//! Pure Cargo source-tool identity, approval and installed-correspondence rules.
mod evidence;
mod exception_authoring;
mod graph_protocol;
mod identity;
mod installation;
mod record;

pub use evidence::*;
pub use exception_authoring::*;
pub use graph_protocol::*;
pub use identity::*;
pub use installation::*;
pub use record::*;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ToolError(pub String);

pub(crate) fn require(condition: bool, message: &str) -> Result<(), ToolError> {
    if condition {
        Ok(())
    } else {
        Err(ToolError(message.into()))
    }
}

#[cfg(test)]
mod tests;
