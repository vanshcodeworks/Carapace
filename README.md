# Carapace

**Run untrusted code — safely, locally, in milliseconds.**

Carapace (`cara`) is a single-binary, local-first sandbox for executing
arbitrary, untrusted programs (AI-generated code first and foremost) with
hard limits on CPU, memory, processes, wall time, disk, and output, and
strict control of filesystem and network access. No daemon. No Docker.

> **Status: Tier 1 works end to end (milestones C0–C7).** `cara doctor`
> gates the environment, `cara run` executes with the full isolation
> stack (namespaces, cgroups, Landlock, seccomp, capability drop), the
> escape suite proves what is stopped, and `cara mcp` serves run_code to
> agents. Nothing is published yet; every claim is mapped to a test in
> docs/agent/CLAIMS.md.

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

## What Carapace stops

Every row is a test in the escape suite (crate `carapace-escape-tests`): the
payload runs through the real sandbox and the suite asserts the documented
result. This table is generated from the catalog — it cannot drift from
what is actually tested.

| Attack | Result |
|---|---|
| `fork_bomb` — Fork bomb | Capped by pids.max and killed at the timeout; peak process count stays near the cap and no stragglers survive on the host |
| `memory_hog` — Memory hog | OOM-killed at the memory limit (KillReason::MemoryLimit) with peak memory near the cap; the host is unaffected |
| `cpu_spin` — CPU spin | Killed at the wall timeout with cpu_time close to the cpu.max quota (100 percent of one core) |
| `disk_filler` — Disk filler | Writes fail with ENOSPC (8 MiB root tmpfs) or the RLIMIT_FSIZE / scratch-size cap; the host filesystem is untouched |
| `output_flood` — Output flood | Killed with KillReason::OutputOverflow at the output cap; captured output stays capped |
| `read_etc_passwd` — Read /etc/passwd | Succeeds but shows the sandbox's own passwd (carapace-sandbox-marker), never host users |
| `read_shadow` — Read /etc/shadow | The file does not exist inside the sandbox; cat fails |
| `read_home` — Read /home and /root | Neither exists inside the sandbox (No such file or directory) |
| `write_outside` — Write outside the sandbox | Both writes denied: /usr is read-only (EROFS), /etc is denied by Landlock; no host file appears |
| `write_then_exec` — Write then execute | The file is created but Landlock denies execve on writable locations: the written program never runs (Permission denied, rc=126) |
| `symlink_escape` — Symlink escape | The link resolves to the sandbox's own /etc/passwd within the Landlock scope; the host file is untouched |
| `proc_escape` — /proc inspection | /proc/1 is the sandbox's own shell and the pid space is fresh (max pid <= 10); host processes are invisible |
| `ptrace_attempt` — ptrace injection | Denied with EPERM: ptrace is not in the seccomp allowlist |
| `mount_attempt` — mount(2) attempt | Denied with EPERM: mount(2) is not in the seccomp allowlist |
| `unshare_attempt` — unshare(2) escape | Denied with EPERM: unshare(2) is not in the seccomp allowlist |
| `socket_egress` — Network egress | Denied with EPERM on socket(2): no sockets exist (empty netns plus seccomp); the connection is never made |
| `abstract_unix_escape` — Abstract Unix socket | Denied with EPERM: socket(2) itself is denied, so the abstract namespace is unreachable |
| `setuid_escalation` — setuid escalation | Every uid change fails with EPERM (no CAP_SETUID); setuid bits in the read-only /usr bind are inert: CapEff=0000000000000000 and NoNewPrivs=1 |
| `keyring_abuse` — Keyring abuse | Denied with EPERM: keyring syscalls are not in the seccomp allowlist |
| `fd_leak_scan` — FD leak scan | Exactly 0, 1, 2 plus the scanner's own transient directory fd; nothing else leaks in |
| `env_leak` — Environment leak | The child sees exactly the allowlisted variables the spec set; nothing is inherited from the host |

Additional red-team probes (tests/redteam.rs): chroot, mknod, sethostname,
/proc/sys writes, cross-hierarchy rename, zombie hoards, dual-stream
floods, slow-drip output, hostile argv — all denied or contained.

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
