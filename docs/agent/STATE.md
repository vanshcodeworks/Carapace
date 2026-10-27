# STATE - agent working state (overwritten every cycle)

Last updated: cycle 17 (P3: persistent sessions) - 2026-10-27.

## Done (all green via scripts/check.sh)
- C0-C12 COMPLETE at 02044f0 (see FINAL_REPORT.md).
- P3 sessions (first slice) COMPLETE per ADR-0009: one keeper process
  per session, a session-wide cgroup leaf, a size-capped tmpfs at
  `/work`, and a 0600 UNIX control socket. Each exec is a fresh sandbox
  (new mount/PID/IPC/UTS, net unless `full`; shared user namespace) with
  the session tmpfs bound at `/work`; each exec is a fresh sandbox, and
  only files are intended to persist (a direct background-process probe
  is still open, UNVERIFIED R2.15).
  Uploads/downloads are path-validated with `openat2`, temp-file +
  `renameat`, capped at 64 MiB (MCP download 8 MiB). CLI:
  `session start|exec|put|get|ls|list|close|prune`. MCP: 6 server-owned
  session tools (8 tools total), foreign ids refused. 13 CLI integration
  tests + `mcp_sessions_persist_files_and_close`; `docs/mcp.md` and
  ADR-0009 updated. Network allowlist and SDKs remain open (P3 rest).

- P1.1 exec-on-write is an explicit policy field:
  `SandboxSpec::exec_on_write` / `Policy::exec_on_write` /
  `[filesystem] exec_on_write`, default **false**, **false** in `strict`,
  true in `dev` (and inherited by `network-light`). Landlock grants
  `RW_ALL_NO_EXEC` unless opted in. Escape catalog `write_then_exec` (21
  entries) proves the denial; `write_then_exec_allowed_when_spec_opts_in`
  is the positive control. Runtime matrix uses `preset = "dev"` for
  gcc/Rust.
- P1.1a (cycle 16) mmap/dlopen enforcement: Landlock's `EXECUTE` right
  only covers `execve(2)`, so a written file could still be mapped
  `PROT_EXEC` or `dlopen`ed. Writable mounts (root tmpfs `/tmp`, `/work`,
  `/dev/shm`, read-write binds) are now `MS_NOEXEC` when
  `exec_on_write` is false. RT31 proves the mapping fails with EPERM,
  anonymous exec mappings still work, and `exec_on_write(true)` maps
  successfully.
- P1.2 `/etc/alternatives` is no longer bind-mounted: the parent planner
  recreates only symlinks whose canonical target is under `/usr`. Ubuntu's
  regular `README` is not visible inside.
- P1.3 PDEATHSIG fork window is forced deterministically by a
  `cfg(test)`-only pause hook + re-executed helper test; stage-2 also
  treats `Z`/`X` as dead. Release builds cannot enable the hook.
- ADR-0007 audits every compatibility concession (alternatives, /dev/shm,
  getpgrp, xattrs, PATH/HOME, clone3, exec_on_write + mmap/noexec,
  OpenJDK security config) with risk, narrowing and test evidence. Cycle
  15 strengthened the getpgrp/xattr proof; cycle 16 added the mmap
  limitation and mount-level fix.
- `cara doctor` refactored into measured `Facts::collect()` + pure
  `classify()`: AppArmor/sysctl/user-max userns, cgroup v1/hybrid,
  delegation/controllers, non-merged-/usr, Landlock/seccomp/pidfd/
  close_range. Remedies are print-only, exact, and cite verified upstream
  URLs. 21 doctor tests, including 17 simulated-environment blockers. The
  Debian `unprivileged_userns_clone` remedy now cites the Debian salsa
  patch and says the knob is Debian-specific.
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
  result pipe (`close_fds_except`). RT22 covers the deadlock: long-lived
  parallel sandboxes held each other's pipe write ends and blocked in
  `spawn` before their timeouts started. RT22 failed before the fix and
  passes in ~1 s; the escape suite finishes 23/23 in ~4 s.
- Cgroup hygiene: synchronous leaf removal in wait() and doctor attach
  probe; sweep empty dead-owner leaves on create; sweep empty staging
  dirs older than 60s. Leaf/staging lists empty after a full check.
- Cycle 15 audit: `CLAIMS.md`, `release.md`, `demo/README.md`, `ENV.md`,
  `UNVERIFIED.md` and ADR-0007 corrected where they had drifted (payload/
  test counts, cargo-deny status, musl TODO, a stray `strace` line,
  getpgrp/xattr proof rows).
- Full-network positive control added: `network_full_mode_permits_loopback_sockets`
  performs a real loopback round-trip under `mode = "full"` (0.34 s);
  `seccomp_blocks_socket_creation` remains the denial side.
- musl: `cargo build -p carapace-cli --target x86_64-unknown-linux-musl`
  succeeds; binary is `static-pie linked`. Fixed a real portability bug:
  `statfs.f_type` is signed on glibc and unsigned on musl, so the cgroup2
  comparison normalizes to u64.
- Debian 12.15 (bookworm) minbase userland measured under the same WSL2
  kernel via private mount namespace + rbind + pivot_root (a plain chroot
  cannot create userns: unshare(2) EPERM when fs->root != mnt_ns->root).
  `cara doctor` READY; dash and Python 3.11 payloads ran; `/etc/debian_version`
  correctly absent. `/usr/lib64` exists (empty) in bookworm, so the
  host-layout gate accepts it. Userland-only data point, not support.
- Cycle 16 red-team: 9 new probes RT23-RT31 (new mount API, cross-
  hierarchy hardlink and RENAME_EXCHANGE, per-run /tmp and /dev/shm,
  thread/exec inheritance of seccomp+Landlock, kernel info-leak syscalls,
  memfd+execveat, mmap(PROT_EXEC) of written files). One real finding
  (mmap/dlopen bypass) fixed with noexec mounts. `tests/redteam.rs` now
  has **31 tests**.
- Full workspace: **250 passed / 0 failed** (27 result lines; 31 red-team
  tests); clippy -D warnings clean; runtime matrix 17/17; escape suite
  23/23.

## In progress
- P3 rest: network allowlist (seccomp user-notification `connect` broker,
  IP/CIDR + port only; `network = "allowlist"` is currently refused), then
  Python/TypeScript SDKs (MCP clients + smoke tests), then P4
  (external-review brief, draft escape challenge).

## Known bugs / risks
- Alternate environments: one Debian userland data point only; no
  different kernel, Fedora/Arch/Alpine, aarch64, non-systemd or real
  non-merged-/usr host (UNVERIFIED R2.11). Do not call any distro
  supported.
- JVM config layout variants (Fedora/Arch, other JDK vendors) untested
  (UNVERIFIED R2.12).
- Doctor remedies are simulated, not applied on real broken hosts
  (UNVERIFIED R2.13).
- The debootstrap tree was not signature-verified; it is a test fixture,
  not a trusted artifact.
- Hard-killed supervisor can leave an empty leaf/staging dir; swept on
  the next run, never force-removed or killed by the sweeper.
- aarch64 seccomp table absent (filter kills by design); Landlock nested
  bind interactions untested (UNVERIFIED R1.3/R1.4).
- noexec is enforced per mount: a payload could still execute a file it
  wrote *onto an executable mount it was granted* (e.g. an executable
  read-write bind). That is the documented `exec_on_write` trade-off, not
  a bypass of the default.
- Sessions need cgroup delegation for the keeper leaf, so they do not
  exist on Tier 2. Session memory/CPU/pids caps cover the keeper *and*
  every payload; `peak_memory_bytes`/`peak_processes` in an exec report
  are session-cumulative high-water marks, not per-exec peaks.
- A CLI-started session is deliberately detached and outlives the CLI;
  its directory is reclaimed only by explicit `session prune` (the cgroup
  sweeper handles leaves by owner-pid liveness). MCP session ids are
  process-owned and die with the server (PDEATHSIG), so ids are not
  resumable across a restart.
- Session testing is single-session: concurrent execs within one session
  serialize (tested), but many simultaneous sessions on one host have not
  been stress-tested. No aarch64/alternate-kernel session run.
- Session-wide memory/CPU/output limits are not individually measured
  (R2.14); the control socket authenticates by filesystem permissions
  only, so any same-uid process can drive a session (not a privilege
  boundary, R2.16); transfer-cap boundaries and the XDG fallback path are
  untested (R3.25-R3.26).
- mkdir_p lesson encoded: never hardcode prefix lengths; keep join
  separators (bind ENOENT debugging).

## How to run checks
wsl -d Ubuntu-24.04 -u dev -- bash /mnt/p/Carapace/scripts/check.sh
(check.sh self-bridges via systemd-run --user --scope and runs the
runtime matrix after cargo test)
