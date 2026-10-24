//! `carapace-mcp`: Model Context Protocol server exposing `run_code` and
//! `explain_result` tools (milestone C7). MCP input is treated as hostile:
//! every field is validated and size-capped before it reaches a sandbox.

pub const MILESTONE: &str = "C7";
