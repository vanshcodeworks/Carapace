# ADR-0002: Process-tree termination strategy

Date: 2026-10-25 · Status: accepted · Milestone: C1

## Context
A sandbox payload may fork. After timeout/limit-trigger the ENTIRE tree must
die, reliably and verifiably, and the supervisor must also clean up if the
payload daemonizes (double-fork, setsid).

## Decision (belt and braces, in order)
1. **The payload runs as PID 1 of a fresh PID namespace.** When the init
   process of a PID namespace exits, the kernel SIGKILLs every remaining
   process in that namespace. Killing one process kills the tree by kernel
   guarantee — the primary mechanism.
2. The supervisor holds a **pidfd** (CLONE_PIDFD) for that init: kill via
   `pidfd_send_signal(SIGKILL)` is immune to PID reuse, and the fd polls
   readable on exit (no polling loops on /proc).
3. Parent is a **child subreaper** (PR_SET_CHILD_SUBREAPER): any payload
   process that escapes the PID namespace semantics (none known, but
   defense in depth) reparents to the supervisor, which reaps it.
4. From C3, the run's **cgroup v2 `cgroup.kill`** file provides a third,
   independent kill switch (writes SIGKILL to every process in the cgroup).

## Consequences
- We never kill "by pid number" alone; no PID-reuse race.
- Test suite proves: grandchildren die on timeout; /proc holds no leftover
  processes after wait(); supervisor survives hostile output floods.
