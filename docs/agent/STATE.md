# STATE — agent working state (overwritten every cycle)

Last updated: cycle 2 start (2026-10-25), milestone C1 in progress.

## Current milestone
C1: rootless namespaces + supervisor (timeout, tree kill, cleanup tests).

## Done (verified green @ commit 75226dd)
- C0 COMPLETE. Environment: WSL2 Ubuntu 24.04.5, kernel 6.18, userns ✅,
  cgroup2 delegation (cpu/io/memory/pids at user@1000.service) ✅, Landlock
  ABI 7 ✅, seccomp ✅, pidfd ✅, close_range ✅, no KVM (Tier 3 stubbed).
- Workspace: 8 crates compile; fmt+clippy(-D warnings)+test --workspace all
  green via scripts/check.sh (strict env assertions on).
- `cara doctor`: 10 measured checks, JSON+human, exit 0/4. WSL quirk
  handled: non-login processes sit in root-owned /non-systemd cgroup;
  delegation root falls back to user@<uid>.service slice.
- Threat model v1, ENV.md, all agent files, README (honest), CI file.

## In progress
- C1: SandboxSpec/ExitReport/KillReason + Backend trait in cara-core;
  clone-with-namespaces child (userns maps, setgroups deny) in cara-sys;
  supervisor with pidfd wait, wall timeout, output caps, subreaper +
  pid-namespace-init kill; integration tests (exit codes, timeout kill,
  output overflow kill, fork survival, fail-closed pre-exec, ns isolation).

## Known bugs / risks
- C1 sandbox has NO filesystem isolation yet (pivot_root is C2): only
  self-written benign payloads run through it in tests; no `cara run` CLI
  exposure until C2+. Documented in child.rs docs.
- waitid(P_PIDFD) availability in libc crate unverified — fallback waitpid.

## How to run checks
From Windows: `wsl -d Ubuntu-24.04 -u dev -- bash /mnt/p/Carapace/scripts/check.sh`
Commit only when green. Never run hostile payloads outside the sandbox.

## Last verified commit
75226dd (C0 docs + Cargo.lock; code in bcecc3a)
