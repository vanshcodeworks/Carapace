# ADR-0003: Two-stage child and rootless cgroup attachment

Date: 2026-10-25 · Status: accepted · Milestone: C3

## Context
Tier 1 must run the payload inside a cgroup v2 leaf with hard limits
(memory.max, pids.max, cpu.max). Creating the leaf under the delegated
subtree works rootless, but *moving a process into it* does not always:

1. `nsdelegate` cgroup2 mounts forbid moving a task into a delegated
   subtree from outside it. WSL places `wsl.exe`-launched processes in a
   root-owned `/non-systemd` cgroup *outside* `user@<uid>.service` — so
   the supervisor cannot attach anything while it sits there. Normal
   Linux logins (pam_systemd) are already inside the user slice and work
   out of the box.
2. A child created by `clone(CLONE_NEWUSER|…)` lives in its own user
   namespace; the parent lacks CAP_SYS_ADMIN there and cannot move it at
   all (kernel attach checks), even from inside the delegated subtree.

## Decision
1. **Two-stage child.** The supervisor forks a PLAIN stage-1 (no
   namespaces). While stage-1 is parked on a go-pipe, the supervisor
   creates the limits leaf and attaches stage-1 — allowed, because
   stage-1 is an ordinary same-uid child of a supervisor that is inside
   its delegated subtree. On the go signal, stage-1 `unshare`s ALL
   namespaces in one call (the unprivileged-legal NEWUSER+rest
   combination), writes its id maps, forks stage-2, and stage-2 — pid 1
   of the new PID namespace — builds the rootfs, pivots, and execs the
   payload. Stage-1 then proxies the payload's wait status to the
   supervisor through a dedicated result pipe and exits.
2. **Two pipes, unambiguous semantics.** Stage-2 owns the exec-status
   pipe (CLOEXEC): EOF = exec happened, `ChildError` = pre-exec failure.
   Stage-1 owns the result pipe: payload-pid notice, then the forwarded
   wait status. Stage-1 closes every other child-facing fd immediately
   after forking stage-2 — it never execs, so CLOEXEC would otherwise
   never fire and the supervisor would deadlock on EOF once the payload
   fills its stdout pipe.
3. **Environment honesty.** `cara doctor` verifies the real capability
   (fork a child, create a leaf, attach, clean up) — not just a writable
   directory. On the WSL/outside-slice case it prints the exact remedy
   (`systemd-run --user --scope --quiet …`, measured ~13ms). The
   repository's `scripts/check.sh` self-bridges the same way; normal
   Linux needs nothing.
4. **Kill order** (ADR-0002 update): pidfd SIGKILL of the payload init
   (kernel kills its whole PID namespace) → SIGKILL stage-1 →
   `cgroup.kill` in the leaf. Cleanup reaps stage-1 and the (reparented)
   payload init specifically; no `waitpid(-1)` sweeps in normal
   operation (a process hosting several sandboxes must never reap
   another sandbox's children — learned empirically).
5. **Overflow self-pipe.** Output readers write one byte to a self-pipe
   the moment the byte cap is exceeded; the supervisor's poll watches the
   pidfd AND that pipe, so an overflowing-but-quiet payload is killed in
   milliseconds instead of at the wall deadline (was: a constant ~10s).

## Consequences
- Rootless cgroup limits work on any environment where the supervisor
  runs inside its delegated subtree (all standard logins; WSL via the
  documented bridge; CI containers without systemd test the doctor-gate
  skip path).
- Exit statuses survive one extra process hop (forwarded through the
  result pipe); `pidfd_open` losing the race with instantly-exiting
  payloads (ESRCH) is handled as "already finished".
- Wall-time is measured from the true start of spawn (the handshake
  overlaps the payload's first milliseconds).
