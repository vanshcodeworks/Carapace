//! The backend abstraction: every tier (native, Wasm, microVM) implements
//! this trait. See ADR-0001 for the synchronous design.

use crate::report::{ExitReport, KillReason};
use crate::spec::SandboxSpec;

/// Errors raised by backends. Setup failures are *fatal for that run only*
/// and MUST mean the payload did not run (fail closed, threat-model §6).
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// The environment cannot isolate safely (doctor gate failed).
    #[error("environment not ready for this backend: {0}")]
    EnvironmentNotReady(String),
    /// Isolation setup failed before the payload ran.
    #[error("sandbox setup failed (payload did not run): {0}")]
    Setup(String),
    /// Supervision failed mid-run; the tree was killed.
    #[error("sandbox supervision failed (tree killed): {0}")]
    Supervision(String),
}

/// A backend knows how to turn a [`SandboxSpec`] into a running, isolated
/// process tree handle.
pub trait Backend: Send + Sync {
    /// Checks the environment gate (fail closed) and spawns the sandbox.
    fn spawn(&self, spec: &SandboxSpec) -> Result<Box<dyn SandboxHandle>, BackendError>;
}

/// A live sandbox run.
pub trait SandboxHandle: Send {
    /// Blocks until the run ends (exit, signal, limit-kill, or timeout),
    /// returning the full report. Safe to call once.
    fn wait(&mut self) -> Result<ExitReport, BackendError>;

    /// Kills the entire tree now. `wait()` afterwards returns the report
    /// with the given reason recorded.
    fn kill(&mut self, reason: KillReason);
}
