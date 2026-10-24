//! `carapace-core`: frontend-agnostic sandbox abstractions.
//!
//! Everything here must be free of platform-specific code: the same types
//! serve the CLI, the library API, and the MCP server. Linux-specific
//! machinery lives in `carapace-native` (and later `carapace-wasm`,
//! `carapace-vm`); this crate only defines *what a sandbox run is*, not *how
//! it is enforced*.
//!
//! ## Fail-closed contract
//!
//! A [`doctor::DoctorReport`] that is not [`doctor::DoctorReport::ready`]
//! means the native tier must refuse to run code. Backends must check this
//! before every spawn and abort otherwise. See docs/threat-model.md.

pub mod backend;
pub mod doctor;
pub mod error;
pub mod report;
pub mod spec;

pub use backend::{Backend, BackendError, SandboxHandle};
pub use doctor::{Check, DoctorReport, Status};
pub use error::CoreError;
pub use report::{ExitReport, KillReason};
pub use spec::{Limits, SandboxSpec};
