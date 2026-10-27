# Architecture

How one Carapace run works, end to end, on Tier 1 (native Linux). Details
live in the ADRs (docs/decisions/); this page is the map. Everything here
describes code that exists and is tested today unless explicitly marked
otherwise.

```
 cara run --policy p.toml -- /usr/bin/python3 ...
        │
        ▼
 Policy::parse ──► SandboxSpec            (cara-core, strict TOML, fail closed)
        │
        ▼
 NativeBackend::spawn(spec)               (cara-native)
   ├─ doctor gate: environment().ready() or refuse (exit 4)
   ├─ network allowlist? → Setup error (ADR-0004, fail closed)
   ├─ validate host layout (merged-usr: /usr/bin/sh, /usr/lib, /usr/lib64)
   ├─ prepare everything parent-side (argv/env CStrings, tmpfs sizes,
   │   seccomp filter, binds, staging dir) — the child never allocates
   ├─ fork stage-1 (PLAIN, no namespaces)          [ADR-0003]
   ├─ create cgroup leaf cara-run-<pid>-<nanos>, write limits,
   │   attach the parked stage-1
   ├─ "go" byte on the go-pipe
        │
        ▼ (inside stage-1, then stage-2 — see below)
 handshake pipes ──► supervision ──► ExitReport
```

## 1. Doctor gate

Every backend consults the environment report before spawning
(`DoctorReport::ready()`, tested by
`supervisor.rs::environment_gate_blocks_spawn_when_not_ready`). `cara
doctor` measures each capability at run time — it never assumes:

| Check id | What is measured |
|---|---|
| `kernel` | `uname(2)` |
| `platform` | distro + WSL detection (informational) |
| `userns` | fork + `unshare(CLONE_NEWUSER)` as an unprivileged user |
| `cgroup2` | `statfs` magic `0x63677270` on `/sys/fs/cgroup` |
| `cgroup-delegation` | forks a real child, creates a leaf, **moves the child into it** — `nsdelegate` forbids cross-boundary attaches, so mkdir alone proves nothing |
| `landlock` | `landlock_create_ruleset(NULL, 0, VERSION)` → ABI version |
| `seccomp` | `seccomp(SECCOMP_GET_ACTION_AVAIL, KILL_PROCESS)` |
| `pidfd` | `pidfd_open(getpid(), 0)` — missing (kernel < 5.3) degrades to a warning with a process-group-kill fallback |
| `close-range` | `close_range(4, 3, 0)` → EINVAL — missing (< 5.9) degrades to a warning with `/proc/self/fd` enumeration fallback |
| `kvm` | `/dev/kvm` presence (informational; Tier 3) |

A required check that fails blocks the run with exit code 4; the report
always includes a remedy (tested: every failing check carries one).

## 2. SandboxSpec

`Policy::to_spec()` lowers the policy into a `SandboxSpec`: program (absolute
path), args, an **allowlist-only environment** (`BTreeMap` — nothing is
inherited from the parent; policy runs default `PATH` and `HOME=/work`),
the limits, extra read-only/read-write paths, and the network mode. The
spec is platform-agnostic; enforcement is entirely in the backend.

## 3. Two-stage child (ADR-0003)

Rootless cgroup attachment has two kernel constraints: `nsdelegate` forbids
moving a task into a delegated subtree from outside it (WSL's `/non-systemd`
cgroup), and a task that already entered a user namespace can never be moved
by its parent. Hence two stages:

**Stage 1 — plain fork, parked.** The supervisor forks an ordinary child
(no namespaces) and creates the cgroup leaf while stage-1 sits parked on a
go-pipe. Attaching a plain same-uid child is legal everywhere the delegated
subtree is writable. The leaf therefore covers every process the run will
ever create — stage-1 has no descendants yet.

**Stage 1 — released.** On the `go` byte, stage-1:

1. `unshare`s all namespaces in one call — `CLONE_NEWUSER | NEWNS | NEWPID
   | NEWIPC | NEWUTS` (+ `NEWNET` unless `mode = "full"`); NEWUSER first is
   what makes the combination unprivileged-legal,
2. denies `setgroups`, writes `uid_map`/`gid_map` (`0` → parent uid/gid,
   captured *before* the fork because `getuid()` is meaningless inside the
   new userns until the map exists),
3. forks **stage 2**, then becomes a proxy: it closes every child-facing fd
   except the result pipe, sends the payload pid, waits for stage 2, and
   forwards the raw wait status. It never execs — so it must close fds
   manually (CLOEXEC would never fire); skipping this deadlocks the
   supervisor once the payload fills its stdout pipe.

**Stage 2 — pid-namespace init.** Being init of a fresh PID namespace is
the primary kill guarantee (ADR-0002): when it dies, the kernel SIGKILLs
everything left in the namespace. Stage 2 builds the sandbox filesystem:

| Step | What happens |
|---|---|
| rlimits | `RLIMIT_CORE = 0` (no core dumps) |
| `MS_REC\|MS_PRIVATE` on `/` | stop mount propagation back to the host (the classic sandbox leak) |
| new root | size-capped tmpfs (8 MiB) mounted over a parent-made `mkdtemp` staging dir (`$XDG_RUNTIME_DIR`, fallback `/tmp`), `MS_NOSUID\|MS_NODEV` |
| policy binds | extra read-only/read-write paths, same path inside and outside, bind + recursive read-only remount |
| `/usr` | host `/usr` bound recursively, remounted `RDONLY\|NODEV`; `/bin`, `/lib`, `/lib64` symlinks (merged-usr) |
| `/dev` | exactly `null`, `zero`, `urandom`, `random`, bound from the host (mknod is impossible rootless) |
| `/dev/shm` | fresh tmpfs sized like `/work` (POSIX shared memory / named semaphores) |
| `/etc` | sandbox-owned minimal `passwd`/`group` — never the host's users; plus a read-only `/etc/alternatives` bind when the host has one |
| `/work` | fresh tmpfs, size = `limits.disk`; becomes the payload's cwd |
| `/proc` | fresh procfs for *this* pid namespace |
| pivot | `pivot_root` + `umount2(MNT_DETACH)` of the old root |
| verify | fail-closed self-check: `/usr/bin/sh` present, fresh `/proc/self/status`, `/.cara-old` gone, `/home` and `/root` unresolvable, `/work` writable — the payload never starts in a half-built sandbox |
| stdio | `dup2` to fds 0/1/2 (clears CLOEXEC on exactly those) |

Both stages set `PR_SET_PDEATHSIG(SIGKILL)`: stage 2 re-arms it after
`fork(2)` clears the attribute and re-checks that stage 1 is still alive via
the host `/proc` (the sandbox procfs is not mounted yet). A supervisor or
stage-1 death therefore tears down the PID-namespace init, and the kernel
tears down every payload process with it.

Then the hardening chain, in order (tests in `hardening.rs`):

1. `close_range` — every fd above 2 closed except the exec-status write
   end; the payload inherits exactly `{0,1,2}`
   (`no_fd_leaks_into_payload`),
2. rlimits — `RLIMIT_FSIZE` = `limits.disk` (per-file cap), `RLIMIT_NOFILE`
   = 256 (`fsize_rlimit_caps_single_files`),
3. `capset` — all capabilities dropped, not even namespaced ones
   (`no_new_privs_and_zero_capabilities`),
4. `no_new_privs` — blocks setuid/setgid/fcap transitions
   (`no_new_privs_and_zero_capabilities`),
5. Landlock — deny-by-default ruleset; grants: `/usr`, `/proc`, `/etc`
   read-only (execute + read incl. directories); `/dev` file-level
   read/write/truncate only (no rights to create nodes, dirs or symlinks
   there); `/dev/shm`, `/work`, `/tmp` full read-write; plus the
   policy binds at their declared access. ABI-aware (handled-access bits
   scale with the kernel's ABI), fails closed if absent
   (`landlock_denies_writes_outside_grants`, `landlock_denies_writes_to_proc`),
6. **seccomp last** — the filter is irreversible and would otherwise bind
   the setup steps themselves (see [Syscall stance](#syscall-stance)),
7. `execve` — on failure a stage-coded error goes out on the status pipe
   and the child exits 127: no code ran unsandboxed
   (`pre_exec_failure_is_setup_error_not_a_run`, `rt_hostile_argv_fails_closed`).

Fork safety: between fork and exec only async-signal-safe raw syscalls run —
no allocation, no std formatting, no locks. Everything the child needs is
prepared parent-side in `ChildConfig`.

## 4. Handshake pipes

Two pipes with unambiguous ownership:

| Pipe | Owner | Semantics |
|---|---|---|
| status pipe | stage 2 | CLOEXEC write end. **EOF = exec happened** (the payload is running). A `ChildError {stage, errno}` (8 bytes, `#[repr(C)]`, size asserted) = pre-exec failure at a named stage → the supervisor returns a `Setup` error and the payload never ran |
| result pipe | stage 1 | Message 1: payload pid (20). Message 2: forwarded wait status (21). Stage 1 closes all other fds so the parent's EOF detection only depends on stage 2 |

After the handshake the supervisor `pidfd_open`s the payload init (ESRCH on
an instantly-exiting payload is handled as "already finished", not an
error) and starts two capped reader threads for stdout/stderr.

## 5. Supervision and kill (ADR-0002)

`wait()` polls two fds with the timeout deadline: the payload's **pidfd**
(readable on exit — no `/proc` polling) and an **overflow self-pipe** that
reader threads poke the moment a stream exceeds its cap, so a
flooding-but-otherwise-quiet payload dies in milliseconds instead of at the
wall deadline.

Kill order, belt and braces:

1. `pidfd_send_signal(SIGKILL)` to the payload init — the kernel then kills
   every remaining process in its PID namespace (primary, PID-reuse-immune),
2. SIGKILL to stage 1 (the proxy) so it can never linger,
3. `cgroup.kill` on the leaf — a third, kernel-level switch covering any
   race.

The supervisor is a child subreaper; reaping targets stage-1 and the
forwarded status specifically — never a `waitpid(-1)` sweep, because a
process hosting several sandboxes must not reap another sandbox's children
(learned empirically; ADR-0003 §4). Tests: `timeout_kills_the_tree_quickly`,
`forked_grandchildren_die_with_sandbox`, `rt_zombie_hoard_contained`,
`handle_kill_works_before_timeout`.

## 6. Resource accounting → ExitReport

After the tree dies, the supervisor reads the leaf's accounting files and
returns an `ExitReport`:

| Field | Source |
|---|---|
| `exit_code`, `signal` | forwarded wait status |
| `kill_reason` | `Timeout` · `OutputOverflow` · `MemoryLimit` (cgroup `memory.events` `oom_kill` > 0 with a SIGKILL) · `Internal(String)` |
| `wall_time` | measured from the true start of spawn (the handshake overlaps the payload's first milliseconds) |
| `stdout`, `stderr` | capped captures (per-stream cap) |
| `cpu_time` | `cpu.stat` `usage_usec` |
| `peak_memory_bytes` | `memory.peak` |
| `peak_processes` | `pids.peak` |

`cara run --json` serializes this with a stable schema (stable
`kill_reason` strings: `timeout`, `output_overflow`, `memory_limit`,
`internal: …`; lossy UTF-8 for output). Tests:
`limits.rs::resource_report_is_populated`, `memory_hog_is_oom_killed_at_limit`,
`run_ui.rs::json_has_stable_shape`.

The cgroup leaf is removed **synchronously** before the CLI exits — on the
normal `wait()` path (bounded retries; usually instant) and in the doctor's
attach probe — so a short-lived process cannot exit before cleanup; `Drop`
keeps the asynchronous remover (~10 s) as a safety net. Before creating a
leaf, `CgroupLeaf::create` sweeps empty `cara-run-*`/`cara-cgroup-probe-*`
directories whose owning PID is gone — `rmdir` only, never kill or move
processes — so a hard-killed supervisor leaves at most a transient empty
directory. `mk_staging_dir` applies the same rule to empty
`cara-staging.*` dirs older than 60s (the age guard keeps a concurrent
spawn between `mkdtemp` and mount safe). The staging dir is removed and the
config freed. Tests: `cgroup_leaves_are_always_removed`,
`run_removes_its_cgroup_leaf_before_exit`,
`doctor_removes_its_cgroup_probe_leaf_before_exit`,
`sweep_removes_only_leaves_with_dead_owners`,
`stale_staging_sweep_removes_only_old_empty_dirs`,
`no_staging_dirs_leak_on_host`.

## Syscall stance

The seccomp profile (`cara-native/src/seccomp_profile.rs`) is **default
deny**: everything a plain interpreter needs (fd/file ops, memory, fork and
plain `clone`, signals, time, futex/epoll, `getrandom`, `ioctl`,
`arch_prctl`, `prctl`) is allowlisted; everything else returns `EPERM`.
Read-only xattr syscalls (`getxattr` family, for coreutils ACL probes) and
`getpgrp` (bash job control) were added after the P2 runtime matrix; neither
crosses a privilege boundary. Deliberately absent: `mount`, `umount2`,
`ptrace`, `bpf`, `unshare`, `setns`, `reboot`, module loading,
`kexec_load`, `swapon`, keyring
syscalls, `open_by_handle_at`, `process_vm_readv`, `io_uring_setup`,
`pivot_root`, `socket`/`connect`/`bind` (unless `mode = "full"`),
`clone3`. `clone(2)` gets a dedicated BPF path: allowed without
`CLONE_NEW*` flags, denied with them. A wrong architecture is killed
(`SECCOMP_RET_KILL_PROCESS`), never allowed.

Profile development mode: `CARA_SECCOMP_LOG=1` in the *parent* environment
switches the default action to log-and-allow so a runtime's real syscall
needs show up in dmesg. Production keeps the strict default.

## Crate layout

| Crate | Role |
|---|---|
| `cara-core` | Platform-agnostic types: `SandboxSpec`, `Limits`, `Policy` (TOML, strict), `ExitReport`/`KillReason`, `DoctorReport`. No unsafe, compiles everywhere |
| `cara-sys` | Raw syscall wrappers — all `unsafe` confined here: fork/clone, namespaces, mount, seccomp BPF compiler, Landlock |
| `cara-native` | Tier 1 backend: doctor checks, backend/supervisor, two-stage child, rootfs builder, cgroup leaves, seccomp profiles, benchmark example |
| `cara-cli` | The `cara` binary: `doctor`, `run`, `policy check/explain`, stable exit codes, JSON reports |
| `cara-escape-tests` | The hostile payload catalog; every security claim maps to a test here (C6). Payloads only ever run *through* the sandbox |
| `cara-mcp` | MCP server, `run_code`/`explain_result` (C7 — being built now) |
| `cara-wasm` | Tier 2 (Wasmtime, fuel + memory caps) — planned C9 |
| `cara-vm` | Tier 3 (microVM, Firecracker/libkrun) — planned C10, needs `/dev/kvm` |

Core design decisions and their reasoning: sync core API (ADR-0001),
tree-kill strategy (ADR-0002), two-stage child + cgroup attach (ADR-0003),
network modes (ADR-0004), zygote pool for warm starts (ADR-0005 — design
accepted, implementation is C8; today's cold path is the reference).
Measured cold start on the reference dev machine (WSL2, kernel 6.18):
`/bin/true` median 6.7 ms, `python3 -c pass` median 24.9 ms (n=100, cycle 6).

## Fail-closed contract

- Any isolation failure (namespace, id maps, mount, cgroup attach, cap
  drop, Landlock, seccomp) aborts the child **before exec** — there is no
  path from "isolation failed" to "run anyway"
  (`pre_exec_failure_is_setup_error_not_a_run`).
- Unknown policy fields/units/presets are errors
  (`policy.rs::unknown_fields_are_rejected`).
- The doctor gate refuses to spawn when a required capability is missing.
- The claim → mechanism → test ledger lives in docs/agent/CLAIMS.md.
