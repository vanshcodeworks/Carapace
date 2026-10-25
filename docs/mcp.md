# MCP Server Guide

> **Status: NOT BUILT YET.** The server lands with **milestone C7 — being
> built now** (`crates/cara-mcp`, currently a scaffold). Everything on this
> page is the *design contract* the implementation must satisfy, plus the
> client configuration you will use once it exists. Do not wire clients up
> to it until the C7 milestone is announced in docs/agent/STATE.md.

## Purpose

The MCP (Model Context Protocol) server exposes Carapace to MCP clients
(Claude Desktop, Cursor, ZCode, …) as tools:

| Tool | What it does |
|---|---|
| `run_code` | Execute a program inside the Tier 1 sandbox and return the `ExitReport` |
| `explain_result` | Turn a run's report into a plain-English explanation (why it died: `timeout`, `output_overflow`, `memory_limit`, internal error) |

The point: an agent that wants to *run* code does not get a bare shell on
your machine — it gets `run(code, policy) -> result` with every limit and
isolation layer described in docs/architecture.md between it and the host.

## Transport and protocol

- **JSON-RPC 2.0 over stdio** (one JSON message per line, MCP standard
  transport for local servers).
- Standard MCP methods: `initialize`, `tools/list`, `tools/call`
  (plus the usual `notifications/initialized`, `ping`).
- The server wraps the **synchronous** core (`carapace-core`'s
  `Backend` trait, ADR-0001): an async runtime at the edge, if any, bridges
  to the sync core via `spawn_blocking`. One run at a time per sandbox;
  concurrent runs are independent sandboxes with independent cgroup leaves.
- The binary will be `cara-mcp` (crate `carapace-mcp`).

## Hostile-input rules (the non-negotiable part)

The threat model (docs/threat-model.md §2) classifies MCP requests as
**hostile input**. The server is the trust boundary between a remote LLM
and the local machine, so:

1. **Size caps on everything** before it reaches a sandbox: program path,
   arguments, code/payload, environment entries, and the policy document.
   Oversized requests are rejected with a JSON-RPC error, never truncated
   into something ambiguous.
2. **Field whitelists**: requests may set only the documented fields
   (program, args, optional policy subset, optional timeout). Unknown
   fields are rejected — the same fail-closed rule as the TOML policy
   parser. An MCP request can never *widen* a policy beyond what the local
   configuration allows; it can only narrow or use pre-configured presets.
3. **No shell interpolation by the server**: the program path must be
   absolute (the same rule as `cara run`); the server performs no PATH
   search and runs no intermediate shell of its own.
4. Environment variables for the payload are an explicit allowlist
   (`SandboxSpec.env`) — nothing is inherited from the server's own
   environment.
5. Every sandboxing property still applies unchanged (namespaces, seccomp,
   Landlock, cgroups, kill strategy); MCP adds input validation *in front
   of* the sandbox, never instead of it.

Exact caps and the full request schema will be specified in the crate docs
when C7 lands; this page will be updated with the implemented values.

## Client configuration (for when C7 lands)

Point the client at the `cara-mcp` binary. Build it once:

```sh
cargo build -p carapace-mcp
# binary at ./target/debug/cara-mcp (or $CARGO_TARGET_DIR/... )
```

### Claude Desktop

`Claude Desktop → Settings → Developer → Edit Config`:

```json
{
  "mcpServers": {
    "carapace": {
      "command": "/absolute/path/to/cara-mcp",
      "args": []
    }
  }
}
```

### Cursor

`~/.cursor/mcp.json` (or project `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "carapace": {
      "command": "/absolute/path/to/cara-mcp",
      "args": []
    }
  }
}
```

Notes:

- The path must be absolute and must exist on the *same machine* running
  the sandbox — Carapace is local-first, there is no remote mode.
- The server inherits your login environment, so the same environment
  requirements as the CLI apply: a delegated cgroup subtree (on WSL2 see
  docs/troubleshooting.md; run the client from a normal session or enable
  the linger fix).
- Run `cara doctor` once from the same account to confirm the environment
  is Tier 1 ready before connecting a client.

## Milestones

| Milestone | Scope |
|---|---|
| C7 | `cara-mcp` stdio server: `initialize` / `tools/list` / `tools/call`, `run_code` + `explain_result`, hostile-input validation, e2e test (in progress — see docs/agent/STATE.md) |
| C9 | Tier 2 (Wasm) becomes available behind the same tool surface |
| C10 | Tier 3 (microVM) where `/dev/kvm` exists |
