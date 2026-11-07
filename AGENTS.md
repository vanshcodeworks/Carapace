# AGENTS.md

This file is for coding agents that work on the Carapace repository.

If you are an agent that was asked to set Carapace up for a user, read
[AGENT_SETUP.md](AGENT_SETUP.md) instead. It is the installation and
connection guide.

## Working rules

1. Read [CONTRIBUTING.md](CONTRIBUTING.md) and
   [docs/agent/STATE.md](docs/agent/STATE.md) before changing code.
2. Work on the `agent/work` branch. `main` is the integration branch.
3. Run `bash scripts/check.sh` before you call a change done. It runs the
   docs check, shell syntax checks, formatting, clippy, the workspace tests,
   and the runtime matrix.
4. Every security claim needs a named test. Update
   [docs/agent/CLAIMS.md](docs/agent/CLAIMS.md) when you add or change one.
5. Hostile code runs only inside the Carapace sandbox. Never run a hostile
   payload on the host to debug it.
6. New configuration must fail closed. Reject unknown fields, unknown
   values, and ambiguous input.
7. Keep the README in very simple English and free of em dash characters.
   `scripts/check-docs.py` enforces the em dash rule.
8. Do not claim support for a platform, feature, or behavior that is not
   measured. Put open items in
   [docs/agent/UNVERIFIED.md](docs/agent/UNVERIFIED.md).
9. Do not commit secrets, tokens, keys, or local machine paths.
10. Keep the license files and the repository URL consistent:
    `https://github.com/vanshcodeworks/Carapace`.

## Layout

```
crates/          Rust workspace
  cara-core      types and policy
  cara-sys       raw syscalls, all unsafe code
  cara-native    Tier 1 backend, doctor, sessions
  cara-cli       the cara binary
  cara-mcp       the MCP server
  cara-wasm      Tier 2 backend
  cara-vm        Tier 3 plan
  cara-escape-tests  hostile payload catalog and README table
docs/            public docs and agent journals
scripts/         check, install, runtime matrix, MCP smoke test
demo/            product demo
```

## Verification

```sh
bash scripts/check.sh
cargo deny check
python3 scripts/mcp-smoke.py "$(command -v cara-mcp)"
```

The strict workspace tests need `systemd-run --user --scope` and
`CARA_STRICT_ENV_TESTS=1`. `scripts/check.sh` handles the WSL cgroup bridge.

## Documentation

- [README.md](README.md): public front page
- [AGENT_SETUP.md](AGENT_SETUP.md): setup file for a user's agent
- [docs/agents.md](docs/agents.md): human guide to agent workflows
- [docs/mcp.md](docs/mcp.md): MCP contract
- [docs/agent/STATE.md](docs/agent/STATE.md): current state
- [docs/agent/LOG.md](docs/agent/LOG.md): cycle log
- [docs/agent/CLAIMS.md](docs/agent/CLAIMS.md): claim ledger
- [docs/agent/UNVERIFIED.md](docs/agent/UNVERIFIED.md): open items
