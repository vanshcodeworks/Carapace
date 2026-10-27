# MCP Server Guide

> **Status: BUILT (milestone C7, commit 335b8bb; session tools added in P3).**
> The server ships as `cara mcp` (and the standalone `cara-mcp` binary) in
> `crates/cara-mcp`: line-delimited JSON-RPC 2.0 over stdio, `initialize` /
> `tools/list` / `tools/call`, with the hostile-input rules below enforced
> (29 protocol unit tests + two real-sandbox e2e tests). Client
> configuration below is live.

## Purpose

The MCP (Model Context Protocol) server exposes Carapace to MCP clients
(Claude Desktop, Cursor, ZCode, …) as tools:

| Tool | What it does |
|---|---|
| `run_code` | Execute a program inside the Tier 1 sandbox and return the `ExitReport` |
| `explain_result` | Turn a run's report into a plain-English explanation (why it died: `timeout`, `output_overflow`, `memory_limit`, internal error) |
| `session_create` | Create a persistent session (a size-capped `/work` plus one cgroup for every exec) |
| `session_exec` | Run code in a fresh sandbox whose `/work` is the session's directory |
| `session_upload` | Write base64 content into the session work dir |
| `session_download` | Read a session file back as base64 |
| `session_list` | List the sessions this server created, with liveness |
| `session_close` | Stop a session and remove its work dir |

The point: an agent that wants to *run* code does not get a bare shell on
your machine — it gets `run(code, policy) -> result` with every limit and
isolation layer described in docs/architecture.md between it and the host.
Sessions extend that from one call to a workflow **without** weakening it:
files persist, processes never do (each exec gets a new PID namespace and a
new rootfs), and the session's `/work` is `MS_NOEXEC` unless the policy
explicitly opts in.

## Sessions in one paragraph

`session_create` spawns a *keeper* process from the same binary, attaches it
to a session cgroup leaf before it unshares, and mounts a size-capped tmpfs
at `/work`. `session_exec` forks a fresh sandbox from the keeper: new mount,
PID, IPC, UTS (and net, unless `network = "full"`) namespaces, the usual
rlimits + Landlock + seccomp stack, and the session tmpfs bound at `/work`.
The keeper serves one request at a time, so concurrent execs serialize. The
session dies with this server (PDEATHSIG on the keeper), and
`session_close` is the explicit teardown. Full design: ADR-0009.

### Session caps (MCP surface)

| Cap | Value | Why |
|---|---|---|
| `policy.timeout_ms` (default per exec) | ≤ 600000 | matches `run_code` |
| `policy.memory_mb` | 64 … 2048 | the keeper lives in the same cgroup |
| `policy.max_processes` | 8 … 512 | keeper + stage-1 + stage-2 + payload |
| `policy.disk_mb` | 1 … 1024 | size of the session `/work` tmpfs |
| `session_exec.code` | ≤ 65536 bytes | same as `run_code` |
| `session_upload.content_base64` | ≤ 4 MiB decoded | must also fit the 8 MiB line cap |
| `session_download` | ≤ 8 MiB | larger files stay inside the session |
| `session_exec.timeout_ms` | ≤ 600000 | per-call override |

Sessions are **server-owned**: a session id created by one `cara-mcp`
process is refused by another, and the CLI's sessions are never reachable
from MCP. A crashed or restarted server therefore leaves no live sandbox.

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
6. **Session ids are not capabilities.** The server accepts only ids it
   created in this process; anything else is a tool error before any
   filesystem or socket access. Paths in `session_upload` and
   `session_download` are relative, normalized, and re-validated by the
   keeper with `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)`.

The exact caps are listed above; the request schemas are the tool
definitions in `crates/cara-mcp/src/lib.rs`.

## Client configuration

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
| C7 | `cara-mcp` stdio server: `initialize` / `tools/list` / `tools/call`, `run_code` + `explain_result`, hostile-input validation, e2e test |
| P3 | `session_create` / `session_exec` / `session_upload` / `session_download` / `session_list` / `session_close` (ADR-0009) |
| C9 | Tier 2 (Wasm) becomes available behind the same tool surface |
| C10 | Tier 3 (microVM) where `/dev/kvm` exists |
