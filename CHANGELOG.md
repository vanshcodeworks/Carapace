# Changelog

All notable changes to Carapace are recorded here.

The project is alpha. There is no tagged release and no prebuilt binary yet.
Build from the `main` branch.

## Unreleased

### Audit 2026-11-18

- Removed the unsafe, non-working network allowlist implementation; the mode
  is again refused before any code runs, with a real regression test.
- Corrected Tier 3 status: experimental libkrun backend only, not usable for
  untrusted code (no rootfs, no bounded console, no kill/timeout, no CLI).
- Added runnable policy examples and fixed the missing `dev.toml` reference.
- Added `cara-mcp --version/--help`, issue templates, PATH and WSL guidance,
  a self-bridging demo, and accurate build prerequisites.

### CLI 2026-11-18

- `cara` help now includes examples and a short product description.
- Terminal output uses restrained color for status and summaries. Colors are
  disabled for pipes, `NO_COLOR`, and `TERM=dumb`; JSON stays uncolored.
- Added `cara vm` for the experimental Tier 3 backend (fails closed without
  KVM).

### Added

- `cara run`: one-shot sandbox for untrusted programs, with CPU, memory,
  process, disk, output, and wall-clock limits.
- `cara doctor`: measured host checks with exact remedies. The run path
  fails closed when a required capability is missing.
- `cara policy check` and `cara policy explain`: strict TOML policies with
  `strict`, `dev`, and `network-light` presets.
- `cara session start|exec|put|get|ls|list|close|prune`: persistent `/work`
  across execs. Each exec is a fresh sandbox with a new PID namespace.
- `cara mcp` and `cara-mcp`: MCP server over stdio with 8 tools
  (`run_code`, `explain_result`, and 6 session tools).
- Tier 1 native isolation: user, PID, mount, network, IPC, UTS, and cgroup
  namespaces; cgroup v2 limits; Landlock; seccomp allowlist; capability
  drop; `no_new_privs`; descriptor and environment allowlists.
- Tier 2 Wasm backend with policy parity tests. It is a library backend and
  is not exposed by the CLI yet.
- Tier 3 microVM design and fail-closed plan. Not usable yet.
- Escape suite with 21 hostile payloads, a 31-test red-team suite, runtime
  matrix coverage for bash, Python, Node, gcc, Rust, Go, and the JVM.
- `scripts/install.sh`: build and install `cara` and `cara-mcp` into
  `~/.local/bin`, then run the doctor gate.
- `AGENT_SETUP.md` and `docs/agents.md`: setup and usage instructions for
  AI agents and their users.
- Apache-2.0 and MIT license files.

### Security

- `exec_on_write` is off by default and off in `strict`. Writable mounts are
  `MS_NOEXEC`, so a written file cannot be executed or mapped executable
  unless the policy opts in.
- The network allowlist is not implemented. A policy that requests it is
  refused before any sandbox starts.
- MCP input is treated as hostile: size caps, field allowlists, absolute
  program paths, no shell interpolation, and server-owned session ids.

### Known limits

- Linux x86_64 only. The measured environment is WSL2 Ubuntu 24.04,
  kernel 6.18.
- No network allowlist, no SDKs, no aarch64, no prebuilt binaries.
- Tier 1 does not protect against a Linux kernel exploit.
- See `docs/agent/UNVERIFIED.md` for the full list of unproven behavior.
