# UNVERIFIED — everything still unproven, ranked by risk

Maintained per the P0 protocol. Each item states what is unproven, why it
matters, and how it could be verified. "Unproven" ≠ "false": it means no
test or measurement in this repository currently demonstrates it.

## R1 — High risk (security-relevant, unproven)

1. **No kernel-exploit boundary has ever been demonstrated.** Tier 1 shares
   the host kernel; the threat model says a kernel 0-day defeats it. No
   fuzzing of the *kernel's* namespace/seccomp/Landlock attack surface from
   inside the sandbox has been done (our fuzzers only cover our own
   parsers). Verify by: running a syscall fuzzer (e.g. a targeted syskaller
   subset) inside the sandbox against the ~140-syscall allowlist.
   TODO(verify).
2. ~~**Seccomp allowlist completeness for Go and JVM runtimes is unproven.**~~
   **DONE (cycle 14).** `scripts/runtime-matrix.py` now has `go-build-run`
   (build + goroutines) and `jvm-compile-run` (javac + threaded Java):
   **17 passed, 0 failed, 0 skipped** in strict mode on the reference env.
   Dev logging (`CARA_SECCOMP_LOG=1`) produced 20 audit records covering 6
   distinct syscalls not in the allowlist; none was required, and each is
   reviewed in ADR-0008. Zero syscalls were added. Remaining scope: other
   distro/kernel/JDK layouts (R2.11, R2.12).
3. **Landlock ruleset vs. bind-mount interaction under concurrent rule
   paths is unproven.** The rw/ro bind + Landlock grant lists are built
   from the same paths, but no test drives rename(2) BETWEEN two
   user-supplied rw binds (REFER semantics), nor bind mounts of nested
   paths (e.g. /a and /a/b both bound, one ro one rw). Verify by: P5
   red-team tests with nested policy binds.
4. **The BPF allowlist is compiled for x86_64 only.** On aarch64 the
   filter kills the process by design (fail closed), so the native tier is
   x86_64-only in practice. No aarch64 seccomp table exists. Verify by:
   cross-building + QEMU (P1) or a native ARM host.

## R2 — Medium risk (correctness/completeness, unproven)

5. **CI has never been observed running.** The workflow exists and the
   trigger now includes `agent/work`, but no GitHub Actions run of this
   repository has been seen (nothing was pushed from this environment).
   Whether hosted runners pass (userns available? cgroup v2 delegation
   absent → tests self-skip? wasm parity runs?) is unproven. Verify by:
   pushing the branch (human action).
6. **~~`cargo audit` / `cargo deny` results~~ DONE (cycle 12)**: cargo
   audit rc=0 (no advisories, 205 deps); cargo deny all four sections ok
   after writing an explicit license policy in deny.toml (permissive-only
   allow list, each entry justified; copyleft fails the check by default).
   Remaining: add `cargo deny check` to CI (currently local-only).
7. ~~**musl static build**~~ **DONE (cycle 15).** `cargo build -p
   carapace-cli --target x86_64-unknown-linux-musl` succeeds after fixing
   a signedness difference in `statfs.f_type` (signed on glibc, unsigned
   on musl). The result is `static-pie linked`; it ran `cara doctor`
   (READY) and sandboxed `/bin/sh` and `python3` payloads on a Debian 12
   (bookworm) userland under the same WSL2 kernel. Still unverified: musl
   builds of Tier 2 (`carapace-wasm`), non-x86_64 musl targets, and the
   glibc build on hosts with glibc < 2.39.
8. **Non-merged-/usr and non-systemd hosts**: doctor now detects the
   merged-usr requirement, non-systemd PID 1 and missing delegation, and
   prints exact remedies (simulated-environment tests). No real
   non-merged-/usr, Alpine/OpenRC or sysvinit host has been tested; only
   the WSL2 Ubuntu 24.04 reference env was available. The failure is
   fail-closed, but the remedy text may not match every layout. Verify by:
   booting such a host/VM and running `cara doctor`.
9. **cgroup v1 / hybrid hosts**: doctor now distinguishes v1-only, hybrid
   with required controllers, hybrid without them, and missing
   delegation; the classification and remedies are unit-tested with
   simulated facts. No real v1/hybrid host has been tested. Verify by: a
   VM with a hybrid hierarchy.
10. ~~**PDEATHSIG across the two-stage fork under every exec path**~~ **DONE
    (cycle 14).** The fork→PDEATHSIG window is now forced deterministically:
    a `cfg(test)`-only pause hook in stage-2 plus a re-executed helper test
    (`forced_pdeathsig_race_never_execs_payload`) kill stage-1 inside the
    window and assert the payload never execs. Release builds cannot enable
    the hook. RT16 still covers the end-to-end SIGKILL path.
11. **Other distro/kernel environments remain largely untested.** Every
    baseline measurement in this repository comes from one environment:
    WSL2, kernel 6.18.54.1-microsoft-standard-WSL2, Ubuntu 24.04.5,
    x86_64, systemd user slice. Cycle 15 added **one** data point: a
    Debian 12.15 (bookworm) minbase userland under the *same* WSL kernel,
    entered with `pivot_root` in a private mount namespace (a plain
    `chroot` cannot create user namespaces: `unshare(2)` returns `EPERM`
    when the caller's root is not the mount namespace root). With the
    static musl build, `cara doctor` was READY and `/bin/sh` (dash) plus
    Python payloads ran. This is userland-only: no different kernel, no
    Fedora/Arch/Alpine, no aarch64, no non-systemd or real
    non-merged-/usr host, and the debootstrap tree was not
    signature-verified. Do not treat any distro as supported until its row
    is measured. Verify by: booting each target (VM or container with
    userns/cgroup delegation) and running `scripts/check.sh`.
12. **JVM security-config layout variants are untested.** The JVM column
    passes on Ubuntu 24.04 OpenJDK 21, whose `conf/security/java.security`
    links into `/etc/java-21-openjdk/security`; the planner exposes only
    that canonical directory (ADR-0007 §8). Fedora/Arch-style JDKs that
    keep the file under `/usr` need no bind and are expected to work, but
    were not measured. Other JDK vendors/versions may ship additional
    files in the `security` directory; the bind is read-only and Landlock
    grants read-only, but the exact file set is not audited. Verify by:
    adding those images to the matrix.
13. **Doctor remedies are simulated, never applied.** Every blocker class
    (AppArmor userns, sysctl userns, cgroup v1/hybrid, missing delegation,
    non-merged-/usr, missing Landlock/seccomp/pidfd/close_range) is tested
    against synthetic `Facts` and the printed text is asserted; no real
    host in that broken state was remediated and re-measured. The
    commands and upstream URLs were verified to exist, not executed.
    Verify by: snapshot a VM, break one capability at a time, apply the
    printed remedy, and re-run `cara doctor`.
14. **Session-wide memory, CPU and output limits are not individually
    measured.** The keeper and every payload share one cgroup leaf
    (ADR-0009 §3), but the session tests cover the disk quota, the
    per-exec timeout and the policy floors only; no test drives a session
    payload into the memory cap or the CPU quota, and no test overflows
    the session output cap. Verify by: session equivalents of
    `limits.rs::memory_hog_is_oom_killed_at_limit`,
    `cpu_quota_shapes_usage`, and the output-overflow probe.
15. **Backgrounded processes across execs are not directly tested.** Each
    exec gets a new PID namespace, so namespace teardown should kill a
    background child when the exec ends; only the timeout/close/
    keeper-kill tree kills are asserted. Verify by: run
    `sh -c 'sleep 30 &'`, then assert no matching process exists in the
    session cgroup after the exec returns.
16. **The session control socket authenticates by filesystem permissions
    only** (0600 socket inside a 0700 directory); there is no
    `SO_PEERCRED` check. Any same-uid process can connect and issue
    put/get/exec. This is not a privilege boundary (same-uid processes
    can already signal or ptrace the keeper), but the MCP server-owned
    id allowlist protects the tool surface, not the socket. Verify by: a
    same-uid connection probe and an explicit threat-model note; add
    peer-credential checks if sessions ever span trust domains.
17. **Sessions require cgroup delegation and do not exist on Tier 2.**
    `SessionManager::start` needs a delegated leaf; no wasm/vm session
    equivalent is designed. Verify by: running the session suite on a
    host without delegation (expected fail-closed) and documenting the
    Tier 2 gap.
18. **Multiple simultaneous sessions are untested.** The CLI tests run
    one session at a time; three concurrent execs within one session are
    tested. No stress test covers N sessions (each with a keeper and a
    cgroup leaf) competing for memory/pids, nor `session prune` racing a
    live keeper. Verify by: a multi-session stress test.
19. **Stale CLI session directories are reclaimed only by explicit
    `session prune`.** The cgroup sweeper removes dead-owner leaves, but
    nothing automatically removes a session directory whose keeper is
    gone; `session list` marks liveness. Verify by: a documented operator
    workflow plus a long-running test, or an age-threshold reaper.


## R3 — Low risk (docs/ergonomics, unproven)

20. **docs/mcp.md client config JSON** was written from the MCP spec shape,
    not validated against current Claude Desktop / Cursor docs. Verify by:
    reading both products' current documentation (P3).
21. **Benchmark comparability** (bubblewrap/nsjail/Docker) — never run;
    docs make no comparative claims (correct). Verify by: P4 on the same
    machine with installable tools.
22. **SBOM tooling output** (`cargo cyclonedx`) — command documented, never
    run. Verify by: P8 release dry run.
23. **`cara policy explain` wording quality** — tested for required
    substrings, never reviewed by a human new to the project. Verify by:
    P6 new-user simulation.
24. **Large-tree builds on DrvFs**: all builds here used the ext4 cache
    (CARGO_TARGET_DIR); a naive `cargo build` directly on /mnt/p has never
    been timed (documented in ENV.md as the reason for the cache).
25. **Session transfer caps are code-enforced but not boundary-tested.**
    `MAX_TRANSFER_BYTES` (64 MiB) and the MCP download cap (8 MiB) are
    checked before allocation; no test uploads/downloads at or just over
    either limit. Verify by: boundary tests with a sparse/large file.
26. **The session socket fallback path is untested.** When
    `XDG_RUNTIME_DIR` is unset, sessions use
    `/tmp/cara-sessions-<uid>`; the primary path is exercised, the
    fallback's 0700 directory / 0600 socket modes only by reading code.
    Verify by: unset `XDG_RUNTIME_DIR` and run the session suite.
27. **Session CLI ergonomics and the MCP six-tool flow have not been
    reviewed by a new user.** They pass their tests, but no human
    walkthrough exists. Verify by: P6 new-user simulation.
28. **Session behavior on alternate environments is unmeasured.** All
    session tests run on the reference WSL2 kernel/Ubuntu 24.04 with
    cgroup delegation; no aarch64, no different kernel, no
    Debian/Fedora/Arch session run. This extends R2.11 to the
    keeper/tmpfs/cgroup path. Verify by: the same suite on each target.


## Verified-this-cycle (P0)

- Clean-build from wiped cache: 3m47s, workspace compiles.
- Full suite on the clean build: **183 passed, 0 failed** (26 result
  lines) — matches the FINAL_REPORT claim exactly. (An earlier "135"
  reading was my own verification script's 300 s timeout truncation, not
  a product issue.)
- Red-team suite stability: 3 consecutive runs, 22/22 each; the
  fd-leak probe's parallel-run flakiness was fixed (serialized
  measurement + documented churn slack, commit fcf5e57).
- scripts/check.sh (fmt + clippy -D warnings + tests): all green.

## Verified cycle 13 (P2 runtime matrix)

- `scripts/runtime-matrix.py`: **15 passed, 0 failed, 0 skipped** through
  the real Tier 1 sandbox on the reference WSL env: bash/coreutils,
  Python stdlib (json/re/hashlib, sqlite3, ssl context, threads,
  concurrent.futures), Python `multiprocessing.Pool`, Node JSON,
  Node `worker_threads`, gcc compile-and-run, host-built Rust binary.
- Policy-driven runs default `PATH` and `HOME=/work`; host env is still
  not inherited (`run_provides_default_path_and_home`).
- `/dev/shm` (writable, size-capped) makes POSIX semaphores and Python
  multiprocessing work; `/etc/alternatives` is visible read-only when the
  host has it.
- Read-only xattr syscalls and `getpgrp` added to the allowlist after
  `ls -l` / bash job control hit EPERM.
- RT16 (SIGKILLed supervisor) initially still orphaned payloads: stage-2
  does **not** inherit PDEATHSIG across `fork(2)`. Fixed by re-arming in
  stage-2 plus a host `/proc/<stage1_pid>` check. RT16 now leaves no
  payload processes.
- Hard-kill caveat: a SIGKILLed supervisor can leave an **empty** cgroup
  leaf and empty staging dir (no processes). Normal `cara run`/`cara
  doctor` processes now remove their run/probe leaves synchronously before
  exit (the doctor attach probe was the remaining per-invocation leak);
  `CgroupLeaf::create` sweeps empty dead-owner leaves on the next run, and
  `mk_staging_dir` sweeps empty staging dirs older than 60s. Nothing is
  ever killed or moved by either sweeper. Verified by running after a hard
  kill: both lists empty.

## Verified cycle 14 (P1 hardening + doctor + Go/JVM)

- Strict posture: `exec_on_write` is off by default and off in `strict`;
  escape test `write_then_exec` proves a written file cannot be executed,
  and its positive control proves the explicit opt-in works. `dev` opts in
  for compile-and-run (runtime matrix uses `preset = "dev"`).
- `/etc/alternatives` is no longer bind-mounted: only symlinks whose
  canonical target is under `/usr` are recreated. Ubuntu's regular
  `README` is not visible inside.
- PDEATHSIG window forced deterministically (see R2.10).
- Concurrency deadlock found by the first full gate: stage-1 inherited the
  embedder's descriptors, so long-lived parallel sandboxes held each
  other's pipe write ends and blocked in `spawn` before their timeouts
  started. Fixed by closing every fd except the result pipe in stage-1;
  RT22 (4 concurrent infinite payloads, 1 s timeout) failed before the fix
  and passes in ~1 s after. The escape suite now finishes 23/23 in ~4 s.
- `cara doctor` refactored into measured `Facts` + pure `classify`; 21
  unit tests including 17 simulated-environment blocker tests. Every
  remedy is print-only and cites an upstream URL verified with HTTP 200.
- README attack table pinned to the escape catalog by a test; it found
  and fixed 9 already-drifted rows.
- Go 1.22.2 and OpenJDK 21.0.12.1 installed; runtime matrix now **17
  passed, 0 failed, 0 skipped** including `go-build-run` and
  `jvm-compile-run`. Dev logging: 20 audit records, 6 distinct unlisted
  syscalls, **zero additions** (ADR-0008). The JVM needs one narrow
  read-only `/etc` bind (ADR-0007 §8).
- Full `scripts/check.sh`: all green (test total recorded in the cycle log).

## Verified cycle 16 (red-team: kernel surfaces, inheritance, mmap exec)

- **Landlock does not mediate `mmap(PROT_EXEC)`/`dlopen`.** Its
  `LANDLOCK_ACCESS_FS_EXECUTE` right is documented as "Execute a file" and
  is enforced on `execve(2)` only. Measured before the fix: a file written
  to `/work` mapped executable (`MAP_SHARED` and `MAP_PRIVATE`) and a
  copied `libm.so.6` loaded via `dlopen` under `exec_on_write = false`.
  Fixed by mounting every writable area (`/tmp` root tmpfs, `/work`,
  `/dev/shm`, read-write binds) `MS_NOEXEC` when the policy does not opt
  in. RT31 (`rt_mmap_exec_of_written_file_denied`) asserts EPERM on the
  file mapping, success for anonymous executable mappings (JITs), and
  success for the same mapping with `exec_on_write(true)`.
- New mount API (`open_tree`/`move_mount`/`fsopen`/`fsconfig`/`fsmount`/
  `fspick`/`mount_setattr`), cross-hierarchy `link(2)` and
  `renameat2(RENAME_EXCHANGE)`, thread/exec inheritance, per-run
  `/tmp`+`/dev/shm`, memfd+`execveat`, and the info-leak syscall set are
  all denied as designed (RT23-RT30).
- Still unverified: `noexec` semantics on filesystems other than tmpfs and
  bind mounts (e.g. a policy-granted read-write bind on a host filesystem
  that ignores `MS_NOEXEC`, such as some FUSE mounts); measured on the
  reference WSL2 kernel only. An executable *writable* bind is the
  documented `exec_on_write` trade-off, not a bypass of the default.

## Verified cycle 17 (P3 sessions)

- Sessions were exercised end to end through the real `cara` binary
  (13 integration tests) and through `cara-mcp` (one e2e test plus the
  MCP unit suite). Measured: `/work` persists across separate host
  processes and the CLI's exit; upload/download is byte-exact; `..`,
  absolute paths and symlink traversal are refused; a 1 s exec timeout
  kills the payload tree while the session survives; a 2 MiB tmpfs
  returns ENOSPC and the session stays usable; `/work` is `MS_NOEXEC` by
  default (`execve` fails, `mmap(PROT_EXEC)` returns EPERM 1) and
  `preset = "dev"` runs/maps the same file; `close` removes the socket,
  work dir and metadata; host paths and `socket(2)` stay hidden; three
  concurrent execs serialize and all complete; `close` while busy kills
  the payload; a SIGKILLed keeper takes the payload with it and `prune`
  reclaims the directory; unknown/malformed ids exit 3.
- The MCP e2e test covers create, persistence across execs,
  upload/download, list, foreign-id refusal and close.
- RT20 (`rt_zero_output_cap_kills_immediately`) was flaky for a
  test-only reason: a payload that wrote and exited in the same
  millisecond could be reaped before the overflow byte was observed, and
  the assertion measured spawn time under load. It now runs
  `sh("echo hi; sleep 30")` with a 10 s timeout and asserts
  `wall_time < 3 s`; the product's overflow kill was correct. Stable
  over three consecutive red-team runs (31/31 each).
- Full workspace: **250 passed / 0 failed** across 27 result lines
  (31 red-team, 23 escape, 41 hardening, 29 MCP unit, 13 session
  integration, 2 MCP e2e, plus the other suites); clippy
  `-D warnings` clean; runtime matrix 17/17; escape suite 23/23.
- Still unverified for sessions: per-limit memory/CPU/output behavior
  (R2.14), background-process persistence across execs (R2.15), socket
  peer authentication (R2.16), Tier 2 availability (R2.17), multi-session
  stress (R2.18), automatic stale-dir reaping (R2.19), transfer-cap
  boundaries (R3.25), the socket fallback path (R3.26), new-user
  ergonomics (R3.27), and alternate environments (R3.28).

