# LOG — append-only, one entry per cycle

## Cycle 1 — 2026-10-25 — C0 environment + scaffold
Task: environment setup, workspace scaffold, doctor, threat model, agent files.
Outcome: WSL2 Ubuntu 24.04.5 dev env fully working (userns, cgroup2
delegation cpu/io/memory/pids, Landlock ABI 7, seccomp, pidfd, close_range;
no KVM). Workspace scaffolded; `cara doctor` implemented with 10 checks;
threat-model v1; CI file; scripts/check.sh. NOT yet compiled/verified.
Commands: wsl --install Ubuntu-24.04 --no-launch; apt install (see ENV.md);
rustup; systemd Delegate drop-in + enable-linger; empirical C probes
(.wsl/probe-syscalls.c) for syscall constants; file writes.
Results: all probes green; first build pending next cycle.
Next: run scripts/check.sh, fix until green, commit C0.

## Cycle 2 — 2026-10-25 — C1 complete
Task: namespace child + supervisor + tests (QUEUE C1 items).
Outcome: DONE @ 9714750. 9 integration tests green, no leftovers. Two
empirical fixes: (a) uid_map must use uid captured pre-clone (getuid()
inside fresh userns = 65534 overflow → EPERM); (b) parent must close its
pipe write-end copies right after clone, else exec-confirmation EOF and
output readers hang forever (was: supervisor deadlock with live yes(1)).
Commands: scripts/check.sh (fmt+clippy+test), single-thread test reruns,
process autopsies via .wsl/probe-stuck.sh.
Results: cargo test -p carapace-native: 9/9 ok in 0.92s.
Next: C2 rootfs/pivot_root (child mount sequence + self-verification).

## Cycle 3 — 2026-10-25 — C2 complete
Task: child rootfs + pivot_root + fs-isolation tests.
Outcome: DONE @ 745dc0a. Rootfs: private-/tmp-then-pivot design (no host
artifacts at all — replaced mkdtemp staging which leaked dirs due to async
ns teardown + EEXIST races). Empirical lessons: empty-slice as_ptr is
dangling for mount(NULL,...) => EFAULT; MNT_DETACH is umount2-only =>
EINVAL as mount flag; uid_map needs parent-recorded ids (re-confirmed via
probes); waitpid(-1) sweeps in multi-sandbox processes steal other
sandboxes' children (removed; pidns kill suffices). python3 runs in the
sandbox (~8ms full spawn+exec wall time via examples/probe).
Commands: scripts/check.sh; .wsl/probe-pivot*.c isolations; fresh-binary
test runs via .wsl/run-tests.sh (lesson: cargo build -p cli does NOT
rebuild test binaries — caused a false-persisting bug report).
Results: 19/19 integration tests green (9 supervisor + 10 rootfs).
Next: C3 cgroup limits.

## Cycle 4 — 2026-10-25 — C3 complete
Task: cgroup v2 limits + resource report (QUEUE C3).
Outcome: DONE @ 5e23c89. Root cause chain solved with C probes: nsdelegate
forbids moving tasks into a delegated subtree from outside (WSL
/non-systemd) AND parent cannot move a userns child at all -> two-stage
child (fork plain, attach, then unshare+fork pidns-init), ADR-0003.
Doctor now tests REAL attach capability; check.sh self-bridges via
systemd-run --user --scope (13ms, WSL only). Deadlocks fixed: stage-1
holding status/stdio pipes (no CLOEXEC for non-exec'ing process); overflow
flag gated behind poll -> self-pipe (flooder test 10s -> ms; suite
11.4s -> 1.4s). pidfd/ESRCH race handled. Warnings: leaf removal is async
(kernel teardown takes seconds on 6.18-wsl).
Commands: scripts/check.sh (all green, repeated 3x stable via
.wsl/loop-sup.sh); probes in .wsl/probe-cgroup-*.
Results: 24 sandbox integration tests green; supervisor suite 1.4s.
Next: C4 seccomp+Landlock+capdrop+rlimits+fd sanitization.

## Cycle 5 — 2026-10-25 — C4 complete
Task: seccomp+Landlock+caps+rlimits+fd sanitization (QUEUE C4).
Outcome: DONE @ f4b4b02. Real bug found by tests: BPF clone-block
fall-through returned ALLOW for EVERY syscall (socket creation succeeded
inside the sandbox!) — fixed layout + added a permanent BPF
mini-interpreter unit test proving filter semantics structurally.
Landlock verified load-bearing (blocks /etc writes on writable tmpfs).
seccomp stance on io_uring: denied (test asserts exact EPERM).
Commands: scripts/check.sh; .wsl/run-hard.sh; probe-c4.sh.
Results: 68 tests green; hardening suite 10/10; python runs ~29ms under
the full stack.
Next: C5 policy TOML + network modes + cara run/policy CLI.

## Cycle 6 — 2026-10-25 — C5 complete
Task: policy + binds + network + CLI (QUEUE C5); subagent parallelization
started per user request.
Outcome: DONE @ eae8a2b. Bind debugging saga (strace-assisted): mkdtemp
staging + tmpfs-over-staging design; mkdir_p separator bug; ENOENT chain.
open_tree/move_mount path abandoned (EINVAL rootless) in favor of
before-overmount path-based binds. strace installed (ENV.md).
Subagents: escape-suite agent running; docs + MCP agents relaunched after
concurrency-limit failures (one agent at a time appears allowed).
Commands: scripts/check.sh; .wsl/run-full.sh; bind-probe/bind-strace probes.
Results: full workspace green incl. 6 CLI e2e tests.
Next: integrate subagent output (C6/C7), then C8.

## Cycle 7 — 2026-10-25 — C6 complete
Task: escape suite integration + red-team cycle 1 + README table.
Outcome: DONE @ 3ae2e4d (+ b3501b7 probes). 21 suite tests + 11 redteam
tests green bridged. Fixed agent's two test bugs: python stdout buffering
(flush=True), PEP 538 LC_CTYPE misattributed as leak (now asserts no
HOST-process env names). README table generated from catalog.
Concurrency: agents run ONE at a time; docs agent running; MCP agent
crashed mid-work twice (files in tree, WIP).
Next: cara bench subcommand (bench.rs ready), MCP integration, C8 pool.

## Cycle 7b — 2026-10-25 — C7 complete
Task: MCP server integration.
Outcome: DONE @ 335b8bb. MCP agent delivered cara-mcp (28 unit + 1 e2e
green, clippy-clean); I wired `cara mcp` into the CLI and smoke-tested
the handshake. ADR-0005 deferred by measurement (bbc0493) — cold path
already 6.7-7.0ms median; pool is a ~3ms win for a new attack surface.
Docs agent still running (owns docs/*.md, SECURITY.md, CONTRIBUTING.md).
Next: docs integration, C9 Wasm tier.

## Cycle 9 — 2026-10-25 — C8/C10/C12 complete, audit + demo green
Task: fuzz targets, audit cycle, C10/C12 agent integration, demo.
Outcome: ALL DONE. Fuzzers: policy_parse 50k, spec_limits 940k,
report_json 199k runs clean AFTER spec_limits found a REAL bug
(parse_duration wrap + 16,900-year durations; fixed with checked_mul +
90-day/1TiB caps + regression tests). Audit: undocumented_unsafe_blocks
now denied crate-wide. C10: ADR-0006 (libkrun first, sourced) + cara-vm
KVM-free logic, fails closed both branches. C12: release runbook,
release-dry-run workflow, demo. Demo: 9/9 PASS bridged (after accepting
cap-by-denial outcomes for fork/memory scenarios — the caps held by
DENIAL, which the demo now documents).
Commands: scripts/check.sh (all green), run-fuzz.sh, run-demo.sh,
wasm-dbg probes (removed).
Next: remaining C11 red-team cycles 2-3 as ongoing hardening; C9 TODOs
(fuel->cpu_time, scratch cap); publish = human action.

## Cycle 10 — 2026-10-25 — C11 red-team cycle 2
Task: fresh attack classes from public escape research (core_pattern,
process_vm_*, maskedPaths-style symlink abuse, perf_event_open) +
operational leak.
Outcome: REAL LEAK found and fixed — SIGKILLed supervisor orphaned the
sandbox (PR_SET_PDEATHSIG + getppid race check now in stage-1; RT16
reproduces and proves). RT12-15 added (all denied). 17/17 red-team
green; full workspace green. Fuzz-found policy caps regression-tested.
Commands: run-rt.sh, run-full.sh, scripts/check.sh.
Next: FINAL_REPORT; remaining backlog = wasm TODOs, libkrun boot path,
publish (human).

## Cycle 11 — 2026-10-25 — C11 red-team cycle 3
Task: concurrency, leaks, API-misuse probes.
Outcome: REAL API BUG found — double wait() re-reported success; fixed
(one-shot wait, Supervision error on second call). New probes RT17-21:
concurrent isolation (8 parallel, no cross-talk), no fd leaks over 30
runs, zero-cap kill, stdin EOF. 22/22 red-team green; full workspace
green. Consecutive clean audits: 2 (cycles 9-10); red-team cycle 3 found
one issue which was fixed and is now permanently tested.
Commands: run-rt.sh, run-full.sh, scripts/check.sh.

## Cycle 12 (P0) — 2026-10-25 — re-verify and reconcile
Task: P0 — fresh clean build, reconcile CLAIMS, CI check, UNVERIFIED.md.
Outcome: clean build from wiped cache 3m47s ✓; full suite 183 passed /
0 failed on the clean build (matches FINAL_REPORT; earlier "135" was my
verification script's timeout truncation — noted as a tooling fix:
run-full.sh timeout raised). rt fd-leak probe was flaky under parallel
load → fixed (serialized measurement + churn slack, fcf5e57), stable 3x.
CI trigger extended to agent/work; runner caveat documented in the
workflow since C0. UNVERIFIED.md written (15 items, R1-R3 ranked).
Commands: count-tests.sh (new), run-full.sh, run-rt.sh x3, check.sh.
Results: baseline green; audit/deny pending install (background).
Next: triage audit/deny output, then P1 compat matrix.

## Cycle 13 (P2) - 2026-10-27 - runtime matrix
Task: P2 - prove real runtimes (not just sh/python3) work through Tier 1,
and fix what the matrix finds.
Outcome: `scripts/runtime-matrix.py` (tracked, also run by check.sh):
15 passed / 0 failed / 0 skipped - bash/coreutils, Python stdlib
(json/re/hashlib, sqlite3, ssl, threads, concurrent.futures),
Python multiprocessing, Node JSON + worker_threads, gcc compile-and-run,
host-built Rust binary. Fixes: policy runs default PATH and HOME=/work;
writable size-capped /dev/shm (POSIX semaphores); read-only
/etc/alternatives for distro symlinks; getpgrp + read-only xattr syscalls
(bash job control, ls -l ACL probes); Landlock RW grant includes EXECUTE
(exec payload-built binaries). RT16 exposed a real remaining orphan gap:
fork(2) clears PDEATHSIG, so stage-2 now re-arms it and checks
/proc/<stage1_pid>; RT16 leaves no processes. Cgroup hygiene: leaf
removal is synchronous in wait() and in doctor's attach probe (the probe
was leaking one empty leaf per CLI invocation); create() sweeps empty
dead-owner leaves, mk_staging_dir sweeps empty staging dirs older than
60s. After a full check the leaf and staging lists are empty.
Full workspace: 191 passed / 0 failed; clippy -D warnings clean.
Commands: scripts/runtime-matrix.py, scripts/check.sh.
Next: Go/JVM matrix columns (UNVERIFIED R1.2), microsecond PDEATHSIG
loop, P1 compat matrix.

## Cycle 14 (P1) - 2026-10-27 - hardening + doctor + Go/JVM

Task: P1 - make write-then-exec an explicit policy decision, audit every
last-cycle compatibility concession, force the PDEATHSIG window; P2 -
doctor blockers with exact print-only remedies, Go/JVM matrix columns,
syscall audit.

Outcome: DONE. `exec_on_write` is a new spec/policy/TOML field, default
false, false in strict, true in dev; Landlock grants RW_ALL_NO_EXEC
unless opted in. Escape catalog is now 21 entries: `write_then_exec`
proves a written file cannot run, and
`write_then_exec_allowed_when_spec_opts_in` proves the denial is the
policy field. `/etc/alternatives`
is no longer bind-mounted - only symlinks resolving under /usr are
recreated, so Ubuntu's README is invisible. PDEATHSIG is forced with a
cfg(test)-only pause hook + re-executed helper; release builds cannot
enable it. ADR-0007 audits all compatibility changes.

Doctor is now Facts::collect() + pure classify(): AppArmor/sysctl/
user-max userns, cgroup v1/hybrid, delegation/controllers, non-merged
/usr, Landlock/seccomp/pidfd/close_range. 21 tests (17 simulated
environments); every remedy is print-only, exact, and cites an upstream
URL verified HTTP 200. README attack table is pinned to the catalog by a
test, which found and fixed 9 drifted rows.

Go 1.22.2 + OpenJDK 21.0.12.1 installed; runtime matrix gained
`go-build-run` (goroutines) and `jvm-compile-run` (javac + thread):
17 passed / 0 failed / 0 skipped. Strict mode needed **zero new
syscalls**; dev logging produced 20 audit records over 6 unlisted
syscalls (socket, connect, getpeername, statfs, fadvise64, fallocate),
each reviewed and left denied in ADR-0008. The JVM required one narrow
read-only bind of the canonical OpenJDK `security` directory that its
/usr symlink references; planner unit test covers foreign targets,
regular files and dangling links (ADR-0007 section 8).

The first full gate after these changes hung in the escape suite. Root
cause: stage-1 is a fork of the embedder and inherited every open fd,
including other concurrent sandboxes' status/result pipe write ends. With
long-lived payloads, each supervisor blocked in `spawn` on EOF before its
timeout could start. Fixed by closing every fd except the result pipe in
stage-1 (`close_fds_except`). Regression test RT22 spawns four infinite
payloads concurrently with a 1 s timeout and requires all four Timeout
reports inside a 30 s watchdog: it deadlocked (failed) before the fix and
passes in 1.1 s after. The escape suite went from hanging to 23/23 in
4.1 s.

Housekeeping: LOG.md contained an accidental second copy of cycles 1-11
(an LF-ending block inserted mid-file). It was removed; no unique entry
was lost and the remaining text is unchanged.

Full workspace: 219 passed / 0 failed (including 22 red-team tests);
clippy -D warnings clean; runtime matrix 17/17. Cgroup/staging lists
empty after the run.
Commands: scripts/check.sh, scripts/runtime-matrix.py,
CARA_SECCOMP_LOG=1 + dmesg audit.
Next: other distro/kernel environments (UNVERIFIED R2.11), JVM layout
variants (R2.12), doctor remedies on real broken hosts (R2.13); then
P3 sessions/upload/download/network allowlist/SDKs.

## Cycle 15 (audit) - 2026-10-27 - claim audit, musl build, Debian userland

Task: scheduled audit of P1/P2. Re-derive every claim from a test or a
measurement; build the musl target; exercise the runtime against a
different userland.

Outcome: audit found and fixed real drift. `CLAIMS.md` still said 20
payloads/21 suite tests/11 red-team tests/10 cara-vm tests and marked
full-network and musl as TODO; corrected to 21 payloads, 23 suite tests,
22 red-team tests, 9 cara-vm tests, and measured rows. `release.md`
claimed cargo-deny had never run (there is a committed deny.toml and
cycle 12 ran it) and carried a stale musl TODO; corrected. `demo/README`
said 20 payloads. `ENV.md` ended with a stray `strace` line.
ADR-0007 cited "seccomp_profile unit tests" for `getpgrp` and xattrs, but
those tests did not assert either: `essentials_are_allowed` now asserts
`SYS_getpgrp` plus all six read-only xattr syscalls, and
`dangerous_syscalls_are_not_allowed` asserts all six mutation xattr
syscalls are absent. Doctor's Debian remedy cited the wrong sysctl page:
`unprivileged_userns_clone` is a Debian-specific knob, now cited to the
Debian salsa patch (URL verified HTTP 200) and labelled Debian-specific.
Every `unsafe` block still carries a SAFETY comment; no unqualified
"secure" remains outside the disclaimer.

The audit's missing proof was full-network mode: only the denial side was
tested. Added `network_full_mode_permits_loopback_sockets`, an end-to-end
positive control (host listener, payload connects/sends/receives over
loopback under `mode = "full"`). It passes in 0.34 s.

musl: `cargo build -p carapace-cli --target x86_64-unknown-linux-musl`
now succeeds and produces a `static-pie linked` binary. It exposed a real
portability bug: `statfs.f_type` is signed on glibc but unsigned on musl,
so the cgroup2 magic comparison now normalizes to u64.

Alternate userland: bootstrapped Debian 12.15 (bookworm) minbase with
debootstrap and ran the static musl binary there under the same WSL2
kernel. A plain chroot cannot be used - `unshare(2)` returns EPERM when
the caller's root is not the mount-namespace root, so even an empty
chroot cannot create a user namespace. The harness enters a private mount
namespace, `--rbind`s the tree (recursive bind keeps nested /proc, /sys,
/dev), `pivot_root`s, and drops to uid 1000. Result: `cara doctor`
READY (userns, cgroup v2 + delegation, Landlock ABI 7, seccomp, merged
usr, systemd); dash and Python 3.11 payloads ran (`42`);
`/etc/debian_version` is correctly absent inside the sandbox. Debian
bookworm ships an empty `/usr/lib64` with `/lib64 -> usr/lib64`, so the
host-layout gate accepts it (an earlier suspicion that it lacked the path
was wrong). This is a userland-only data point, not a support claim; the
debootstrap tree was not signature-verified and only one release was
tested. Recorded in ENV.md and UNVERIFIED R2.11.

Full workspace: 220 passed / 0 failed (including 22 red-team tests and
the new network control); clippy -D warnings clean; runtime matrix
17/17. Escape suite 23/23 in 4.05 s. Cgroup/staging lists empty.
Commands: scripts/check.sh, cargo build --target
x86_64-unknown-linux-musl, debian-pivot-test.sh.
Next: red-team cycle 16; then P3 (sessions, upload/download, network
allowlist, SDKs) and P4 (external-review brief, escape challenge).

## Cycle 16 (red-team) - 2026-10-27 - kernel surfaces, inheritance, mmap exec

Task: scheduled red-team cycle. Probe attack classes the regular suites
do not cover; a probe that only confirms an existing test is not a
finding.

Outcome: 9 new probes, RT23-RT31, all green after one real fix.

- RT23 `rt_new_mount_api_denied`: `open_tree`, `move_mount`, `fsopen`,
  `fsconfig`, `fsmount`, `fspick`, `mount_setattr` all return EPERM even
  with deliberately invalid arguments (denial happens before argument
  validation).
- RT24 `rt_cross_hierarchy_hardlink_denied`: `link(2)` out of `/work`
  into `/etc` and from `/etc/passwd` into `/work` both fail; neither
  destination appears. Landlock REFER covers hardlinks, not just rename.
- RT25 `rt_rename_exchange_across_hierarchy_denied`:
  `renameat2(RENAME_EXCHANGE)` across `/work` -> `/etc` fails and both
  files keep their original contents (RT5 covered plain rename only).
- RT26 `rt_tmp_and_shm_are_not_shared`: a marker written to `/tmp` or
  `/dev/shm` by one sandbox is invisible to the next, and a host file in
  `/tmp` is invisible inside. Fresh per-run tmpfs mounts.
- RT27 `rt_threads_inherit_seccomp`: a payload worker thread gets the same
  EPERM for `socket(2)` as the main thread.
- RT28 `rt_exec_inherits_landlock_and_seccomp`: a payload-spawned
  `sh`/`python3` still cannot write `/etc` and cannot create a socket.
- RT29 `rt_kernel_info_leak_syscalls_denied`: `syslog`,
  `name_to_handle_at`, `open_by_handle_at`, `process_vm_readv/writev`,
  `kcmp`, `bpf`, `userfaultfd` all EPERM through the installed filter.
- RT30 `rt_memfd_execveat_denied`: `memfd_create` is allowed (ordinary
  payloads need it), but `execveat` is denied with EPERM, closing the
  anonymous-memfd exec path.
- RT31 `rt_mmap_exec_of_written_file_denied`: **found a real gap.**
  Landlock's `LANDLOCK_ACCESS_FS_EXECUTE` right is documented as "Execute
  a file" and is enforced on `execve(2)` only, not on
  `mmap(PROT_EXEC)`/`dlopen`. Measured before the fix: a file written to
  `/work` could be mapped executable (`MAP_SHARED` and `MAP_PRIVATE`),
  and a copied `libm.so.6` could be `dlopen`ed - i.e. write-then-exec
  without `execve`, despite `exec_on_write = false`.

Fix: every writable mount is now `MS_NOEXEC` when `exec_on_write` is
false - the root tmpfs (`/tmp`), `/work`, `/dev/shm`, and read-write
binds (remounted `MS_NOEXEC`). `/usr` keeps its executable read-only
bind; anonymous executable mappings remain allowed for JITs. The same
test is the positive control: with `exec_on_write(true)` the mapping
succeeds. Measured errno for `mmap(PROT_EXEC)` on a noexec mount is
**EPERM (1)**, not EACCES - the assertion uses that exact value.

Docs updated: ADR-0007 section 7 (limitation, mount fix, proof row),
`docs/policy.md` (`exec_on_write` covers execve + mmap + dlopen),
`docs/threat-model.md`, `CLAIMS.md` (31 red-team tests).

Full workspace: 229 passed / 0 failed (31 red-team tests); clippy
-D warnings clean; runtime matrix 17/17; escape suite 23/23 in ~4.4 s.
Cgroup/staging lists empty.
Commands: scripts/check.sh, .wsl/rt31-probe.sh (characterization).
Next: P3 (sessions, upload/download, network allowlist, Python/TypeScript
SDKs) and P4 (external-review brief, escape challenge).
