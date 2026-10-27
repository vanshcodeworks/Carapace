# STATE - agent working state (overwritten every cycle)

Last updated: cycle 13 (P2) - 2026-10-27.

## Done (all green via scripts/check.sh)
- C0-C12 COMPLETE at 02044f0 (see FINAL_REPORT.md).
- P2 runtime matrix (cycle 13): 15/15 through the real Tier 1 sandbox -
  bash/coreutils, Python stdlib + multiprocessing, Node JSON +
  worker_threads, gcc compile-and-run, host-built Rust binary.
- P2 fixes: policy PATH/HOME defaults; /dev/shm tmpfs; read-only
  /etc/alternatives; getpgrp + read-only xattr syscalls; Landlock RW
  includes EXECUTE; stage-2 re-arms PDEATHSIG + host /proc race check.
- Cgroup hygiene: synchronous leaf removal in wait() and doctor attach
  probe; sweep empty dead-owner leaves on create; sweep empty staging
  dirs older than 60s. Leaf/staging lists empty after a full check.
- Full workspace: 191 passed / 0 failed; clippy -D warnings clean.

## In progress
- (none)

## Known bugs / risks
- Go and JVM runtimes remain unverified (UNVERIFIED R1.2).
- Hard-killed supervisor can leave an empty leaf/staging dir; swept on
  the next run, never force-removed or killed by the sweeper.
- Microsecond PDEATHSIG interleaving is closed in code but has no
  targeted loop test (UNVERIFIED R2.10).
- mkdir_p lesson encoded: never hardcode prefix lengths; keep join
  separators (bind ENOENT debugging).

## How to run checks
wsl -d Ubuntu-24.04 -u dev -- bash /mnt/p/Carapace/scripts/check.sh
(check.sh self-bridges via systemd-run --user --scope and now runs the
runtime matrix after cargo test)
