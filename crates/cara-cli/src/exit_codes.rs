//! Stable exit codes for the `cara` binary. Documented in docs/cli.md and
//! part of the public interface — do not renumber. Not all are produced yet;
//! reserved values carry `#[allow(dead_code)]` until their subcommand lands.

/// Everything succeeded.
pub const OK: u8 = 0;
/// CLI usage error (clap already uses 2 for this).
#[allow(dead_code)] // reserved: stable public contract
pub const USAGE: u8 = 2;
/// Policy file invalid or requested configuration impossible.
#[allow(dead_code)] // reserved: used from milestone C5 (`cara policy`)
pub const INVALID_POLICY: u8 = 3;
/// Environment cannot run the requested tier safely (`cara doctor` gate).
pub const ENV_NOT_READY: u8 = 4;
