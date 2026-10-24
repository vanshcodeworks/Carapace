//! Raw Linux syscall wrappers for Carapace.
//!
//! This crate is the only place in the workspace where `unsafe` blocks that
//! issue raw syscalls live. Higher layers ([`carapace_native`]) must treat
//! this crate as plain plumbing: it makes no policy decisions and holds no
//! configuration. Every `unsafe` block carries a `SAFETY:` comment explaining
//! why the call is sound.
//!
//! Constant values cited from kernel headers were verified against the
//! development environment (Ubuntu 24.04, kernel 6.18, `linux-libc-dev`
//! 6.8 headers) — see `docs/agent/ENV.md`. Anything not verifiable is marked
//! `TODO(verify)` and must fail closed.

#![cfg(target_os = "linux")]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod fork;
pub mod landlock;
pub mod mount;
pub mod ns;
pub mod seccomp;
