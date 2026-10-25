# ADR-0005: Zygote pool and cold/warm start strategy

Date: 2026-10-25 · Status: accepted (design; implementation in C8) · Milestone: C8

## Context
Current cold start (measured on the reference dev env, cycle 6, before
pooling): full sandbox spawn+exec of /bin/sh ≈ 20–30 ms supervised wall
time; python3 ≈ 60 ms (interpreter startup dominates). The budget users
care about: agent tool-calls that run code per turn. A pre-forked pool can
hide the namespace/mount/cgroup setup — but only the parts that are safe
to reuse.

## What can be pre-created (warm) vs must be per-run (cold)
- **Reusable per zygote**: user namespace + id maps, mount namespace with
  MS_PRIVATE, the tmpfs root skeleton (usr bind, /dev nodes, /etc, /work
  tmpfs, symlinks), Landlock ruleset (same grants every run), an empty
  seccomp state… — everything that does not depend on per-run policy.
- **Per-run only**: cgroup leaf (limits differ per policy), seccomp filter
  (policy-dependent — the filter is installed last and is irreversible),
  go/exec, output pipes, the payload itself.
- A zygote that has already applied a seccomp filter CANNOT install a
  different one later (filters stack, and the old allowlist binds it). So
  the zygote must park BEFORE the seccomp step, and pool-key on policy
  class if per-profile pools are wanted (v1: one base profile → one pool).

## Design
1. **Zygote process** (`zygote.rs` in cara-native): a stage-1-equivalent
   process that completes everything through Landlock and then blocks on a
   command socket (a pair of UNIX stream fds created before unshare; one
   end held by the supervisor). It holds: pidfd, the status/result pipes
   wiring, and its cgroup-unattached state.
2. **Pool**: supervisor keeps N warm zygotes (lazy spawn, target size 2 by
   default). `spawn()` takes a zygote from the pool, creates the cgroup
   leaf, writes the limit files, attaches the zygote pid (works: plain
   same-uid task in the delegated subtree — same as the two-stage design),
   sends `argv/env/fsize/seccomp-filter` over the command socket, and the
   zygote finishes the remaining steps (fd close, rlimits, caps,
   no_new_privs, seccomp install, execve).
3. **Per-run isolation of reused state**: the tmpfs root is shared READ-
   ONLY state; /work and /tmp must be FRESH per run — the zygote keeps a
   clean scratch subvolume? NO: tmpfs cannot be snapshotted rootlessly
   cheaply. Solution: /work is mounted per-run by the zygote just before
   exec (mount tmpfs at staging/work with the run's size cap) — the zygote
   does this on every command; remounting is cheap (~100µs).
4. **Crash containment**: a zygote that dies while parked is detected via
   pidfd poll and replaced by the pool; the run fails closed with Setup.
5. **Memory**: each parked zygote costs ~1 RSS + tmpfs skeleton (8 MiB
   cap, mostly unmapped). Default pool = 2; `CARA_POOL=0` disables it
   (pure cold path stays available and tested).

## Honesty rules for benchmarking (C8)
- Measure cold and warm paths separately, publish both with machine specs
  (docs/agent/ENV.md reference env), N=100 runs, median + p95.
- Never pool across different seccomp profiles without an ADR update.

## Consequences
- Warm start target: < 5 ms from spawn() to payload exec (verify in C8).
- The cold path stays the reference implementation; the pool is a wrapper,
  not a fork of the logic — the child steps are shared code.
- Fuzz/property tests for the command-socket protocol (C8 fuzz targets).
