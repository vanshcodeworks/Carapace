# ADR-0008: Syscall additions for Go and JVM — none, and why

Date: 2026-10-27 · Status: accepted · Milestone: P2 (runtime matrix) · Extends ADR-0007

## Context

The P2 runtime matrix gained two columns: Go (build and run a goroutine
program inside the sandbox) and the JVM (compile and run a threaded Java
program). Both are real workloads, not version banners. The question this
ADR answers is the one the profile process requires: **which syscalls had
to be added to the allowlist, and what attack surface does each addition
buy?**

The answer is **none**. This ADR records the measurement that justifies
that answer and reviews every syscall the runtimes attempted but the
allowlist does not contain, so a future reader does not have to guess
whether the profile was widened silently.

## Method

Environment: WSL2 kernel 6.18.54.1, Ubuntu 24.04, Go 1.22.2, OpenJDK
21.0.12.1. All runs went through the real Tier 1 sandbox (`cara run`).

1. **Strict run first.** `python3 scripts/runtime-matrix.py` with the
   production filter (default action `EPERM`) → **17 passed, 0 failed, 0
   skipped**, including `go-build-run` and `jvm-compile-run`. A missing
   syscall that a runtime cannot fall back from would have failed its
   case; this is the load-bearing evidence that no addition is required.
2. **Dev logging second.** `sudo dmesg -C` then
   `CARA_SECCOMP_LOG=1 python3 scripts/runtime-matrix.py` → 17/17 again.
   In this mode the filter's default action is `SECCOMP_RET_LOG` (allow
   and log), so every syscall **not** in the allowlist is recorded. The
   run produced **20 audit records covering 6 distinct syscalls**, with no
   rate-limit or suppressed-line messages.
3. **Mapping.** Numbers were resolved against
   `/usr/include/x86_64-linux-gnu/asm/unistd_64.h` (the same header the
   profile's `libc::SYS_*` constants come from).

`CARA_SECCOMP_LOG=1` is a development switch. It is never used by
`scripts/check.sh`, never set by the sandbox itself, and must not be used
to claim strictness: it deliberately allows what the production filter
denies.

## Observed-but-not-allowed syscalls

| Syscall | Nr. | Observed from | What it does | Attack surface if added | Decision |
|---|---|---|---|---|---|
| `socket(2)` | 41 | `bash` ×6, `javac` ×1 | Creates a socket endpoint. | A socket that cannot reach anywhere in the empty netns is still a local resource; in `network = "full"` the same call is already granted by `NETWORK_ALLOWED`. | **Not added.** Network syscalls stay policy-gated; the empty netns is the primary control and seccomp is defense in depth. The attempts (likely NSS/nscd probes) fail with `EPERM` and both runtimes continue. |
| `connect(2)` | 42 | `bash` ×6, `javac` ×1 | Connects a socket to an address. | Same as `socket`: only meaningful with a socket and a reachable address, neither of which exists in `mode = "none"`. | **Not added.** Policy-gated with `socket`; the matrix passes without it. |
| `getpeername(2)` | 52 | `bash` ×2 | Reads the peer address of a connected socket. | Information disclosure only on a socket the payload already owns; no socket can be created in `mode = "none"`. | **Not added.** No runtime needs it to complete; `mode = "full"` grants it with the rest of the network set. |
| `statfs(2)` | 137 | `javac` ×1 | Returns filesystem type, block size and free-space counters for a path. | Read-only host information (free space, inode counts) that the payload cannot otherwise see; no mutation. | **Not added.** `javac` continues without it. Free-space disclosure is not needed for compilation. |
| `fadvise64(2)` | 221 | `sort` ×1 | Advisory page-cache hint (`POSIX_FADV_*`), including `DONTNEED`. | Could evict clean page-cache pages for files the payload can open, a performance side effect on shared host cache; no data access or mutation. | **Not added.** `sort` completes without it. The hint is an optimization, not a capability. |
| `fallocate(2)` | 285 | Go linker (`link`) ×2 | Preallocates or punches blocks in a file. | Disk consumption inside writable mounts; already bounded by the tmpfs size and `RLIMIT_FSIZE`, but it also enables hole-punching on files the payload can write. | **Not added.** The Go linker falls back to ordinary writes; the case passes. |

`clone3(2)` is deliberately absent from both the allowlist and this table:
the filter returns `ENOSYS` for it unconditionally, including in log mode,
so it never executes. That decision and its rationale are in ADR-0007 §6.

## What the existing allowlist already covers

The two runtimes exercised the profile's existing thread/IPC/memory paths
without additions: `clone(2)` with thread flags (the `clone3 → ENOSYS`
fallback), `futex(2)`, `mmap`/`mprotect`/`munmap`/`mremap`/`madvise`,
`rt_sigaction`/`rt_sigprocmask`/`rt_sigreturn`, `epoll_create1`/
`epoll_ctl`/`epoll_pwait`, `eventfd2`, `pipe2`, `getrandom`, `sched_*`,
`prctl`, `set_robust_list`, `set_tid_address`, and the file/stat family.
Those were reviewed when they were added; this ADR does not re-open them.

## Decision

- **Zero syscalls added** for Go or the JVM.
- The six observed calls above remain denied in `network = "none"` and
  are not part of the base profile. `socket`/`connect`/`getpeername` are
  granted only by `network = "full"` through `NETWORK_ALLOWED`.
- A future addition requires: (a) a runtime-matrix case that fails in
  strict mode, (b) a log-mode run showing the exact syscall, (c) a row in
  this table with the attack-surface review, and (d) the failing case
  passing in strict mode afterward. "The strace looked busy" is not a
  reason to widen the profile.

## Consequences

- Go and JVM run under the same default-deny profile as every other
  runtime; the strict posture is unchanged.
- The JVM does require one **filesystem** concession (its `/etc`-packaged
  `security` directory), which is audited in ADR-0007 §8. That is a
  read-only data exposure, not a syscall grant.
- Re-trigger: any new runtime column that fails in strict mode. Run the
  method above before touching `seccomp_profile.rs`.
