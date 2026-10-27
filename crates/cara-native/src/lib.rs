//! `carapace-native`: the Tier 1 backend (Linux namespaces + cgroups v2 +
//! seccomp-bpf + Landlock). Linux-only by design; other crates must treat
//! compile-failure here as "native tier unavailable", never as a fallback
//! to running unsandboxed.

#![cfg(target_os = "linux")]
// Same rule as cara-sys: every unsafe block carries a SAFETY comment.
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod backend;
pub mod bench;
pub mod cgroup;
pub mod child;
pub mod doctor;
#[cfg(test)]
mod pdeathsig_test;
pub mod seccomp_profile;
mod supervisor;

pub use backend::NativeBackend;
pub use carapace_core::{Backend, SandboxHandle};
