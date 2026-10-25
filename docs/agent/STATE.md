# STATE — agent working state (overwritten every cycle)

Last updated: cycle 5 done (C4 complete @ f4b4b02), C5 in progress.

## Done (all green via scripts/check.sh)
- C0-C4 complete. 68 tests. Full Tier 1 stack now active per run:
  namespaces (7) -> private-ns rootfs/pivot -> cgroup limits ->
  fd close_range -> rlimits (fsize/nofile/core) -> capset drop ->
  no_new_privs -> Landlock (ABI-aware grants) -> seccomp allowlist ->
  exec. Payload sees fds {0,1,2}, CapEff=0, NoNewPrivs=1, EPERM on
  namespace/socket/io_uring syscalls, Landlock-denied writes outside
  /work+/tmp+/dev, kernel OOM at memory limit.

## In progress (C5 — policy + network + CLI)
- cara-core/src/policy.rs: TOML policy parse+validate, presets strict/
  dev/network-light; limits parsing (bytes "256MB", percents, durations).
- SandboxSpec gains filesystem read_only/read_write binds + network mode.
- Network: default none (netns empty — already enforced); `full` mode =
  share host netns (opt-in; requires setns from parent — ADR); allowlist
  mode deferred with ADR (design doc).
- CLI: `cara run` (file or -c code, --policy), `cara policy check|explain`,
  exit codes; JSON report output (--json).
- Tests: policy parse/validation matrix; explain output contains key
  facts; run with default policy works; unknown-field rejection.

## Known bugs / risks
- none open.
- io.max not set (optional; documented).
- allowlist network mode = C5 ADR design only.

## How to run checks
wsl -d Ubuntu-24.04 -u dev -- bash /mnt/p/Carapace/scripts/check.sh

## Last verified commit
f4b4b02
