//! Shared error type for core abstractions.

use thiserror::Error;

/// Errors raised by `carapace-core` itself (type-level problems); backend-
/// specific errors live in their own crates.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}
