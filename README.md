# Carapace

**Run untrusted code — safely, locally, in milliseconds.**

Carapace (`cara`) is a single-binary, local-first sandbox for executing
arbitrary, untrusted programs (AI-generated code first and foremost) with
hard limits on CPU, memory, processes, wall time, disk, and output, and
strict control of filesystem and network access. No daemon. No Docker.

> **Status: early development (milestone C0).** The environment gate
> (`cara doctor`) works today; sandboxed execution lands over the coming
> milestones (see docs/agent/STATE.md). Nothing is published yet, and no
> security claim is made beyond what docs/agent/CLAIMS.md maps to a test.

## Why

AI coding agents write useful programs — and occasionally destructive ones.
The primary demo: an agent writes a script that tries to `rm -rf` your home,
fork-bomb the machine, and POST your SSH keys to a URL. Carapace runs it
anyway, blocks all three, and reports exactly what was stopped and why.

Carapace is deliberately a minimal *execution primitive*, not an agent
workstation: no browser, no IDE, no containers-as-a-service — just hardened,
millisecond-scale `run(code, policy) -> result` with defense in depth:

1. **Tier 1 (native)**: user/pid/mount/net/ipc/uts/cgroup namespaces +
   cgroups v2 + seccomp-bpf + Landlock + capability drop. Runs rootless on
   any modern Linux (kernel ≥ 5.10).
2. **Tier 2 (Wasm)**: no shared kernel syscalls; fuel and memory caps.
3. **Tier 3 (microVM)**: a separate kernel per run (Firecracker/libkrun),
   where KVM is available.

What Tier 1 explicitly does **not** promise: protection against a Linux
kernel exploit (all namespaces share the host kernel) — that is what Tiers
2 and 3 are for. See [docs/threat-model.md](docs/threat-model.md) for the
honest, complete picture.

## Quick start (developers)

Linux (or WSL2) with Rust ≥ 1.85:

```sh
cargo build -p carapace-cli
./target/debug/cara doctor      # can this machine run the Tier 1 sandbox?
```

`cara doctor` measures every capability it reports (user namespaces, cgroup
v2 delegation, Landlock ABI, seccomp-bpf, …) and exits non-zero — refusing
to pretend — when the environment cannot isolate safely.

## Repository layout

```
crates/   cara-core (types) · cara-sys (raw syscalls, all unsafe confined
          here) · cara-native (Tier 1) · cara-cli (the `cara` binary)
          · cara-wasm (Tier 2) · cara-vm (Tier 3) · cara-mcp (MCP server)
          · cara-escape-tests (the hostile payload catalog)
docs/     threat model, architecture, decisions (ADRs), agent notes
runtimes/ minimal rootfs recipes per language
examples/ library API examples
```

## Documentation

- [Threat model](docs/threat-model.md) — what is defended, what is not, why
- [Agent state](docs/agent/STATE.md) — what exists today, what is verified

## License

Apache-2.0 OR MIT.
