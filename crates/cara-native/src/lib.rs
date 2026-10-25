//! `carapace-native`: the Tier 1 backend (Linux namespaces + cgroups v2 +
//! seccomp-bpf + Landlock). Linux-only by design; other crates must treat
//! compile-failure here as "native tier unavailable", never as a fallback
//! to running unsandboxed.

#![cfg(target_os = "linux")]

pub mod backend;
pub mod bench;
pub mod cgroup;
pub mod child;
pub mod doctor;
pub mod seccomp_profile;
mod supervisor;

pub use backend::NativeBackend;
pub use carapace_core::{Backend, SandboxHandle};
