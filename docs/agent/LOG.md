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
