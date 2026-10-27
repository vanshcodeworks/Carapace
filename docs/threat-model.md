# Carapace Threat Model

Status: v1, matches milestone C0 (doctor implemented; enforcement mechanisms land C1–C4 and this document is updated as each lands). Every claim below maps to a test or is marked `TODO(test)` and tracked in `docs/agent/CLAIMS.md`.

## 1. What Carapace is

Carapace ("cara") is a **single-binary, local-first execution sandbox for untrusted code**, aimed first at AI-agent-generated programs. It runs a program with hard limits on CPU, memory, processes, wall time, disk and output size, with filesystem access restricted to declared paths and network access off by default. It requires no daemon and no Docker.

Carapace is a **defense-in-depth execution primitive**, not a claim of invulnerability. The word "secure" is deliberately avoided without qualification throughout the documentation.

## 2. Actors and trust boundaries

| Actor | Trust | Notes |
|---|---|---|
| Invoking user (CLI/library/MCP client) | Trusted | Defines the policy; can allow paths/network. Malicious *policies* are out of scope (the user can already read/write their own machine). |
| The payload (untrusted code) | **Hostile** | Arbitrary machine code, from the moment it is exec'd until it exits. Assumed to try every escape and exhaustion technique in §5. |
| Policy/config files | Untrusted *input* | Must parse defensively; a malformed policy must fail closed, never fall back to a permissive default. |
| MCP requests | Hostile input | Validated and size-capped before reaching a sandbox. |
| Other local users of the host | Out of scope boundary | Carapace's rootless sandbox must not let the *payload* attack them either (e.g. via shared /tmp) — tested where applicable. |

Assets to protect on the host: the filesystem outside allowed paths (including `~/.ssh`, `/etc`), host processes, the network, machine resources (CPU/RAM/disk/PIDs), supervisor/host secrets (environment variables, inherited fds), and the integrity of Carapace itself (its supervisor must not be exhaustible).

## 3. Tiers and what each defends against

### Tier 1 — Native (namespaces + cgroups v2 + seccomp-bpf + Landlock)

**Defended** (each line becomes an automated escape-suite test by C6):

- **Host filesystem confidentiality/integrity**: the payload sees only a minimal root plus explicitly allowed (read-only or read-write) paths. Enforced by mount namespaces + `pivot_root` + Landlock as a second layer. Landlock additionally blocks *open_by_handle_at*-style tricks that operate through inherited mounts.
- **No write-then-exec by default**: writable areas (`/work`, `/tmp`, `/dev/shm`, `read_write` binds) are granted `RW_ALL_NO_EXEC` and mounted `noexec`; a payload cannot execute a file it just wrote — via `execve`, `mmap(PROT_EXEC)` or `dlopen` — unless the policy explicitly sets `filesystem.exec_on_write = true` (off in `strict`; `dev` opts in for compile-and-run). Escape test `write_then_exec` proves the `execve` denial, red-team `rt_mmap_exec_of_written_file_denied` proves the mapping denial, and their positive controls prove the opt-in.
- **No host `/etc/alternatives` inode**: only symlinks that resolve under `/usr` are recreated inside the sandbox; the host directory is never bind-mounted, so regular files shipped there (Ubuntu's `README`) are invisible.
- **No host `/etc` beyond two narrow runtime paths**: host `/etc/alternatives` is never mounted (only `/usr`-resolving symlinks are recreated), and the only host `/etc` bind is the canonical OpenJDK `security` directory referenced by an in-tree JVM (read-only, audited in ADR-0007 §8). Nothing else under `/etc` is reachable.
- **No network access unless allowed**: default is an empty network namespace (no interfaces, no sockets that reach anywhere). DNS, raw sockets, and abstract UNIX sockets are blocked in the default netns; seccomp denies socket creation where the policy says `mode="none"`.
- **Resource caps**: memory (`memory.max` + swap off), CPU (`cpu.max`), process count (`pids.max` — fork bombs), wall time (supervisor timeout), output volume (byte caps on stdout/stderr), disk (scratch size + `fsize` rlimit + io limits where delegated).
- **No privilege escalation**: inside the userns the payload "is root" only over namespaced resources; all capabilities are dropped before exec; `no_new_privs` blocks setuid/setgid/f(cap) transitions; setuid binaries are not mounted at all.
- **No visibility of host processes**: PID namespace shows only the payload's own tree; `/proc` is a fresh, minimal mount.
- **No syscall surface beyond an allowlist**: seccomp-bpf default-deny profile per runtime; unknown syscalls (including future kernel additions) are denied, not allowed.

**NOT defended** (explicit non-promises for Tier 1):

- **A Linux kernel 0-day/1-day exploit.** All namespaces share the host kernel. A payload that exploits the kernel *from inside* the namespaces can escape. This is the fundamental limitation of namespace sandboxes and the reason Tiers 2 and 3 exist. Landlock/seccomp reduce the attack surface (the payload cannot simply call the interesting syscalls), but this is mitigation, not a boundary.
- Side channels (Spectre-style, Rowhammer) — out of scope for v1.
- Hardware attacks, DMA — out of scope.

### Tier 2 — Wasm (milestone C9)

Adds: no shared kernel syscalls at all (the guest cannot execute host machine code), fuel metering for deterministic CPU bounds, memory caps enforced by the runtime rather than cgroups. Still bound by the correctness of the Wasmtime runtime and its WASI host functions.

### Tier 3 — microVM (milestone C10)

Adds: a separate kernel (KVM/Firecracker or libkrun). A payload kernel exploit compromises only the disposable VM kernel. Bound by VMM correctness and hardware virtualization. Not available on the dev environment (no /dev/kvm) — developed as a documented design with clean-skip tests.

## 4. Attack surface *of Carapace itself*

The sandbox is a program that runs hostile code; bugs *in Carapace* are attack surface:

1. **Policy parser** — hostile or malformed TOML must never silently produce a permissive policy. Mitigation: strict validation, deny-by-default unknown fields, fuzz targets (C8), property tests.
2. **Path handling / mount planner** — `..` traversal, symlink races, absolute-vs-relative confusion, hardlink escapes. Mitigation: property tests that no planned path escapes the sandbox root (C4/C6 tests), `O_NOFOLLOW`/resolved-at-open patterns, mount ordering rules.
3. **TOCTOU between setup and exec** — the child validates its own mounts *after* `pivot_root` and refuses to continue if they are not exactly as planned (planned C2 test).
4. **fd leaks into the child** — any fd Carapace leaves open is a read/write channel to host resources. Mitigation: `close_range` sanitization before exec + an escape test that scans `/proc/self/fd` from inside (C4).
5. **Supervisor resource exhaustion** — output caps, bounded event queues, timeouts on every wait; the supervisor must survive a payload that floods output, spawns rapidly, or holds the pipe open (C3/C6 tests).
6. **Environment variable leakage** — the child env is constructed allowlist-style, never inherited (test in C6).
7. **Kill/teardown correctness** — every sandbox must die even if it forks, daemonizes, or the parent crashes: subreaper design, pidfd-based tree kill, cgroup kill, tmpfs/mount cleanup verified by tests (C1).
8. **cgroup leaks** — cgroups are always removed, including on supervisor crash (C3 tests).

## 5. Attack classes the escape suite must cover (v1 catalog)

fork bomb; memory hog; CPU spin; disk filler; output flooding; read `/etc/passwd` and host paths; write outside sandbox; symlink escape; hardlink escape; `..` traversal; `/proc` and `/sys` probing; ptrace of host processes; mount/umount attempts; unshare/setns attempts; chroot; raw sockets; DNS/network egress; abstract UNIX sockets; setuid binaries; kernel keyring; io_uring misuse (seccomp stance verified and documented); clock manipulation; signals to host PIDs; inherited-fd reading; environment leakage; TOCTOU on mount setup; supervisor exhaustion. The catalog grows with every red-team cycle; each entry names its expected safe outcome and the reason it is safe.

## 6. Fail-closed contract

- If **any** isolation step fails (namespace creation, uid/gid map, mount, cgroup attach, capability drop, Landlock apply, seccomp install), the child aborts *before exec'ing the payload*. There is no code path from "isolation failed" to "run anyway".
- A degraded mode (e.g. "no cgroup limits available, run anyway") is opt-in via an explicit, loudly-labeled flag and is never the default. v1 ships none; if demand appears it will be an ADR.
- `cara doctor` is the pre-flight gate: backends refuse to spawn when required capabilities are missing. Tested at the backend level in C1.
- Unknown policy fields or ambiguous values are errors, not warnings.

## 7. Residual risks (honest list)

- Kernel exploits (Tier 1) — see §3; mitigated in depth by seccomp default-deny + Landlock + no capabilities + minimal attack surface (no setuid, no device nodes except safe ones).
- seccomp/Landlock/kernel bugs in the *host* kernel version the user runs; Carapace documents its tested kernel baseline (5.10+, dev on 6.18).
- Policy *misconfiguration* by the trusted user (allowing `~` read-write and having secrets there). `cara policy explain` exists to make policies legible; it cannot read minds.
- Zero-days in interpreters/runtimes mounted read-only into the sandbox (e.g. a malicious `import` chain if a writable site-packages is allowed). Runtime authoring guide documents safe recipes.
- The supervisor runs on the host; a host compromised by other means is out of scope.

## 8. Claim → mechanism → test mapping

Maintained in `docs/agent/CLAIMS.md` (generated summaries live there; the public "What Carapace stops" table is generated from the escape suite at C6). Rules: no public claim without a test name; measured numbers state the machine; `TODO(verify)` marks anything unproven.

## 9. Changes

- v1 (C0): initial model written before enforcement code; enforcement sections updated as milestones land.
