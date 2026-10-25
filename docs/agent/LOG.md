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
