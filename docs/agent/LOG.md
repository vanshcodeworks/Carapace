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
