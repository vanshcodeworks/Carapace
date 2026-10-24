//! `carapace-vm`: Tier 3 backend (microVM — Firecracker or libkrun,
//! chosen by ADR). Planned for milestone C10; requires KVM, which the
//! development WSL2 environment lacks (see docs/agent/ENV.md), so this tier
//! is developed with clean-skip tests and a full design.

pub const MILESTONE: &str = "C10";
