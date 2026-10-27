# STATE - agent working state (overwritten every cycle)

Last updated: cycle 14 (P1 hardening + doctor + Go/JVM) - 2026-10-27.

## Done (all green via scripts/check.sh)
- C0-C12 COMPLETE at 02044f0 (see FINAL_REPORT.md).
- P1.1 exec-on-write is an explicit policy field:
  `SandboxSpec::exec_on_write` / `Policy::exec_on_write` /
  `[filesystem] exec_on_write`, default **false**, **false** in `strict`,
  true in `dev` (and inherited by `network-light`). Landlock grants
  `RW_ALL_NO_EXEC` unless opted in. Escape catalog `write_then_exec` (21
  entries) proves the denial; `write_then_exec_allowed_when_spec_opts_in`
  is the positive control. Runtime matrix uses `preset = "dev"` for
  gcc/Rust.
- P1.2 `/etc/alternatives` is no longer bind-mounted: the parent planner
  recreates only symlinks whose canonical target is under `/usr`. Ubuntu's
  regular `README` is not visible inside.
- P1.3 PDEATHSIG fork window is forced deterministically by a
  `cfg(test)`-only pause hook + re-executed helper test; stage-2 also
  treats `Z`/`X` as dead. Release builds cannot enable the hook.
- ADR-0007 audits every compatibility concession (alternatives, /dev/shm,
  getpgrp, xattrs, PATH/HOME, clone3, exec_on_write, OpenJDK security
  config) with risk, narrowing and test evidence.
- `cara doctor` refactored into measured `Facts::collect()` + pure
  `classify()`: AppArmor/sysctl/user-max userns, cgroup v1/hybrid,
  delegation/controllers, non-merged-/usr, Landlock/seccomp/pidfd/
  close_range. Remedies are print-only, exact, and cite verified upstream
  URLs. 21 doctor tests, including 17 simulated-environment blockers.
- README "What Carapace stops" table is pinned to the escape catalog by
  `table::tests::readme_table_matches_the_catalog`; it found and fixed 9
  already-drifted rows.
- P2 Go/JVM columns: `go-build-run` (Go 1.22.2, goroutines) and
  `jvm-compile-run` (OpenJDK 21.0.12.1, javac + thread). Runtime matrix:
  **17 passed, 0 failed, 0 skipped**. Dev logging found 20 audit records
  over 6 unlisted syscalls; **zero additions** (ADR-0008). The JVM needs
  one narrow read-only `/etc/java-*-openjdk/security` bind, audited in
  ADR-0007 §8 and unit-tested.
- Concurrency: stage-1 now closes every inherited descriptor except its
  result pipe (`close_fds_except`). The first full gate exposed a
  deadlock: long-lived parallel sandboxes held each other's pipe write
  ends and blocked in `spawn` before their timeouts started. RT22 failed
  before the fix and passes in ~1 s; the escape suite finishes 23/23 in
  ~4 s.
- Cgroup hygiene: synchronous leaf removal in wait() and doctor attach
  probe; sweep empty dead-owner leaves on create; sweep empty staging
  dirs older than 60s. Leaf/staging lists empty after a full check.
- Full workspace: 219 passed / 0 failed (22 red-team tests); clippy -D
  warnings clean; runtime matrix 17/17.

## In progress
- (none)

## Known bugs / risks
- Other distro/kernel environments remain unmeasured (UNVERIFIED R2.11);
  do not call any distro supported.
- JVM config layout variants (Fedora/Arch, other JDK vendors) untested
  (UNVERIFIED R2.12).
- Doctor remedies are simulated, not applied on real broken hosts
  (UNVERIFIED R2.13).
- Hard-killed supervisor can leave an empty leaf/staging dir; swept on
  the next run, never force-removed or killed by the sweeper.
- aarch64 seccomp table absent (filter kills by design); Landlock nested
  bind interactions untested (UNVERIFIED R1.3/R1.4).
- mkdir_p lesson encoded: never hardcode prefix lengths; keep join
  separators (bind ENOENT debugging).

## How to run checks
wsl -d Ubuntu-24.04 -u dev -- bash /mnt/p/Carapace/scripts/check.sh
(check.sh self-bridges via systemd-run --user --scope and runs the
runtime matrix after cargo test)
