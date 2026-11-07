# Carapace for agents

Carapace gives an AI agent a narrow door to a real machine.

The agent writes code. It sends the code to Carapace. Carapace runs the code
inside a sandbox with limits, then returns the output and the reason the code
stopped. The agent never gets a shell on the host.

This page is for the human who operates the agent. The file to hand to the
agent itself is [AGENT_SETUP.md](../AGENT_SETUP.md).

## The short version

1. Install `cara` and `cara-mcp` with `bash scripts/install.sh`.
2. Run `cara doctor`. If it fails, fix the host first.
3. Point the MCP client at the absolute path of `cara-mcp`.
4. Let the agent call `run_code` or the session tools.
5. Keep `network = "none"` and `exec_on_write = false` for untrusted code.

## Connect an MCP client

Build once:

```sh
cargo build --release -p carapace-mcp
```

The server binary is `target/release/cara-mcp`, or
`~/.local/bin/cara-mcp` after the installer.

Claude Desktop config:

```json
{
  "mcpServers": {
    "carapace": {
      "command": "/home/YOU/.local/bin/cara-mcp",
      "args": []
    }
  }
}
```

Cursor config (`~/.cursor/mcp.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "carapace": {
      "command": "/home/YOU/.local/bin/cara-mcp",
      "args": []
    }
  }
}
```

The path must be absolute. The server runs on the same machine as the
sandbox. There is no remote mode.

Run the smoke client to prove the connection works:

```sh
python3 scripts/mcp-smoke.py "$(command -v cara-mcp)"
```

## Tools

| Tool | What it does |
|---|---|
| `run_code` | Run a short shell or Python program in a one-shot sandbox. Returns the report. |
| `explain_result` | Explain a report in plain English. |
| `session_create` | Create a session with a persistent, size-capped `/work`. |
| `session_exec` | Run code in a fresh sandbox whose `/work` is the session directory. |
| `session_upload` | Write base64 content into the session work dir. |
| `session_download` | Read a session file as base64. |
| `session_list` | List sessions created by this server, with liveness. |
| `session_close` | Stop a session and remove its work dir. |

The server treats MCP input as hostile. It caps sizes, rejects unknown
fields, requires absolute program paths, and performs no shell
interpolation. A request can narrow a policy, but it cannot widen one beyond
the local configuration.

## Sessions

A session keeps files, not processes.

```sh
id=$(cara session start --policy policy.toml)
cara session exec "$id" -- /bin/sh -c 'echo data > /work/input.txt'
cara session exec "$id" -- /bin/sh -c 'cat /work/input.txt'
cara session close "$id"
```

Each `session exec` gets a new PID namespace, a new mount namespace, and a
new root filesystem. The session's `/work` is mounted into each one. A
background process from one exec does not survive into the next.

From MCP, the flow is:

1. `session_create`
2. `session_exec` with the returned `session_id`
3. `session_upload` and `session_download` as needed
4. `session_list` to check liveness
5. `session_close` when done

Session ids are owned by the server process. A different `cara-mcp` process
refuses them. A restarted server does not resume old sessions.

## Policy recipes

### Strict, no network

This is the default. Use it for untrusted code.

```toml
preset = "strict"

[network]
mode = "none"
```

Strict limits: 10 second timeout, 256 MiB memory, 32 processes, 64 MiB
scratch, 1 MiB output, `exec_on_write = false`.

### Development, no network

Use this only when the agent needs to compile and run its own output.

```toml
preset = "dev"

[network]
mode = "none"
```

Dev limits: 60 second timeout, 1 GiB memory, 128 processes, 512 MiB
scratch, 8 MiB output, `exec_on_write = true`.

### Read-only data

```toml
preset = "strict"

[filesystem]
read_only = ["/opt/models", "/srv/datasets"]

[network]
mode = "none"
```

The paths appear at the same absolute paths inside the sandbox, read-only.

### A project directory

```toml
preset = "dev"

[limits]
timeout = "5m"
disk = "1G"

[filesystem]
read_write = ["/home/dev/project"]

[network]
mode = "none"
```

The directory is visible at the same path, read-write. Files written by the
payload are real host files. Grant this only to code you trust enough to
write in that directory.

### Network

`network = "none"` is the default and the right choice for untrusted code.
`network = "full"` shares the host network. It is a loud opt-in and should be
rare.

`network = "allowlist"` is not implemented. A policy that requests it is
refused before any sandbox starts.

## What the agent should do

Give the agent instructions like this:

> Use the Carapace MCP tools to run code. Use `run_code` for one-shot work.
> Use `session_create` and `session_exec` when files must persist. Keep the
> policy strict. If a tool returns an environment error, stop and report it.
> Do not run the code on the host.

The agent should not decide to disable the sandbox because a task is
inconvenient.

## Safety rules

- Untrusted code runs only through Carapace.
- Keep `network = "none"` unless the task truly needs the host network.
- Keep `exec_on_write = false` unless the task is compile-and-run.
- Do not run the MCP server or `cara` as root.
- Do not edit the seccomp allowlist, Landlock rules, or doctor gate to make a
  task pass.
- Treat session ids as server-owned handles, not as passwords or capabilities.
- A read-write bind is a real host directory. Grant the smallest path that
  works.

## Verify

```sh
cara doctor
cara run -- /bin/sh -c 'echo hello from carapace'
python3 scripts/mcp-smoke.py "$(command -v cara-mcp)"
```

For the full test loop:

```sh
bash scripts/check.sh
```

## Limits

- Linux x86_64 only. WSL2 works.
- No network allowlist.
- No Python or TypeScript SDK. MCP and the CLI are the interfaces.
- No prebuilt binaries yet. Build from source.
- Tier 1 shares the host kernel. A kernel exploit can escape. Tier 2 and
  Tier 3 are the answer to that, but Tier 2 is not in the CLI yet and Tier 3
  is not usable.
- The measured environment is WSL2 Ubuntu 24.04, kernel 6.18, x86_64. Other
  distros are unverified until measured. See
  [docs/agent/UNVERIFIED.md](agent/UNVERIFIED.md).

## More

- [MCP reference](mcp.md)
- [Policy reference](policy.md)
- [Threat model](threat-model.md)
- [Troubleshooting](troubleshooting.md)
- [Agent setup file](../AGENT_SETUP.md)
