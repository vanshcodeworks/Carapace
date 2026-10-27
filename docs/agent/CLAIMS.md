# CLAIMS — every public claim mapped to its test or measurement

Rules: a claim without a test/measurement reference is a bug in this file.
Measured numbers must state the machine (reference env: WSL2 kernel
6.18.54.1, Ubuntu 24.04, i.e. docs/agent/ENV.md). TODO(test) = claimed but
test lands at listed milestone.

| Claim | Basis | Status |
|---|---|---|
| Dev environment supports rootless Tier 1: userns, cgroup v2 (cpu/io/memory/pids delegated), Landlock ABI 7, seccomp-bpf | Empirical probes in docs/agent/ENV.md + `cara doctor` run | ✅ verified cycle 1 (doctor output) |
| `cara doctor` reports each capability by measuring it at runtime and exits 4 when Tier 1 is impossible (fail closed) | cara-native doctor tests; cara-cli tests/doctor_cli.rs | ✅ C0 |
| Landlock ABI on dev machine is exactly v7 | carapace-sys landlock strict test (`strict_env_has_landlock`) | ✅ C0 |
| seccomp-bpf available on dev machine | carapace-sys seccomp strict test | ✅ C0 |
| Kernel config: CONFIG_SECURITY_LANDLOCK=y, CONFIG_SECCOMP_FILTER=y, CONFIG_LSM includes landlock (dev machine) | /proc/config.gz read in ENV.md (manual, cycle 1) | ✅ manual; TODO(test): doctor reads /proc/config.gz where available |
| Isolation claims (fs, network, caps, limits) | escape suite | ⏳ C1–C6 (see docs/threat-model.md §8) |
| Performance claims (cold/warm start) | benches/ | ⏳ C8 (will state machine specs) |
| "What Carapace stops" README table | generated from cara-escape-tests | ⏳ C6 |

## Retractions / corrections
(none yet)

## C3 claims (added cycle 4)
| Claim | Basis | Status |
|---|---|---|
| Memory limit kills hogs at the configured cap (64MB) with OOM reason and peak recorded | limits.rs memory_hog_is_oom_killed_at_limit | verified C3 |
| pids.max caps fork bombs; no straggler processes | limits.rs fork_bomb_is_capped_by_pids_max (+ /proc scan) | verified C3 |
| cpu.max quota measurably shapes CPU (20% vs 200%) | limits.rs cpu_quota_shapes_usage | verified C3 |
| Resource report populated (cpu time, peak mem, wall) | limits.rs resource_report_is_populated | verified C3 |
| cgroup leaves always removed (async, <=10s) | limits.rs cgroup_leaves_are_always_removed | verified C3 |
| WSL: cgroup attach only works inside user slice; bridge = systemd-run --user --scope (~13ms) | .wsl probes bridge-test.sh; doctor remedy text | verified C3 |

## C4 claims (added cycle 5)
| Claim | Basis | Status |
|---|---|---|
| Payload syscall surface is allowlisted; denied syscalls return EPERM | hardening.rs socket/unshare/io_uring tests + seccomp interpreter test | verified C4 |
| clone(2) with CLONE_NEW* flags denied; plain fork works | hardening.rs + filter_semantics_interpreted | verified C4 |
| Filter semantics proven structurally (arch/allow/deny/clone paths) | carapace-sys seccomp::tests::filter_semantics_interpreted (BPF mini-interpreter) | verified C4 |
| Landlock blocks writes outside granted paths even on writable mounts | hardening.rs landlock_denies_writes_outside_grants | verified C4 |
| Payload inherits exactly fds 0,1,2 | hardening.rs no_fd_leaks_into_payload | verified C4 |
| Capabilities dropped + no_new_privs set | hardening.rs no_new_privs_and_zero_capabilities (observed in-sandbox) | verified C4 |
| Single-file size capped by RLIMIT_FSIZE | hardening.rs fsize_rlimit_caps_single_files | verified C4 |
| Normal interpreter runtimes unaffected | hardening.rs normal_python_still_works + all prior suites | verified C4 |

## C5 claims (added cycle 6)
| Claim | Basis | Status |
|---|---|---|
| Policy files reject unknown fields/units/presets (fail closed) | cara-core policy tests + cli_run policy_check_valid_and_invalid | verified C5 |
| read_write binds expose exactly the listed host dirs inside the sandbox | cli_run run_with_read_write_bind_sees_host_dir | verified C5 |
| network mode allowlist fails closed at run time (not implemented) | cli_run run_fails_closed_on_unknown_network_mode_in_policy | verified C5 |
| network mode full permits sockets; none denies (seccomp + netns) | hardening.rs socket test + seccomp_profile filter_for branch | ⏳ full-mode e2e TODO(test) C6 |
| cara run --json has a stable report schema | run_ui json tests (kill_reason strings) | verified C5 |
| cara run exit codes documented (0/2/3/4) | exit_codes.rs + cli tests | verified C5 |

## C8 pre-benchmarks (cold path, cycle 6 — reference machine WSL2 kernel 6.18.54.1, Ubuntu 24.04.5)
| Claim | Basis | Status |
|---|---|---|
| Cold start (full stack: 7 namespaces, rootfs+pivot, cgroup attach, Landlock, seccomp, exec): /bin/true median 6.71ms p95 9.27ms; /bin/sh 6.36ms p95 8.54ms; python3 -c pass 24.91ms p95 45.43ms (n=100 each) | crates/cara-native/examples/bench.rs output cycle 6 | ✅ measured cold; warm (pool) pending C8 |

## C6 claims (added cycle 6/7)
| Claim | Basis | Status |
|---|---|---|
| "What Carapace stops" README table is generated from the tested catalog | carapace-escape-tests table::markdown + README section | verified C6 |
| All 20 escape payloads exhibit their documented safe outcome through the real sandbox | tests/suite.rs 21 tests green (bridged run 4.25s) | verified C6 |
| No host env var leaks into the sandbox (PATH shared by design) | suite.rs env_leak (asserts against live host env) | verified C6 |
| setuid bits are inert: CapEff=0, NoNewPrivs=1, uid changes EPERM | suite.rs setuid_escalation | verified C6 |
| Red-team: chroot/mknod/sethostname//proc/sys/cross-hierarchy-rename denied; zombie hoards + dual floods + slow-drip contained | tests/redteam.rs 11 tests green | verified C6 |
| Cold start: /bin/true median 6.71ms p95 9.27ms (n=100, WSL2 6.18) | examples/bench.rs | verified (machine-specific) |

## C7 claims (added cycle 7)
| Claim | Basis | Status |
|---|---|---|
| MCP server speaks JSON-RPC 2.0 stdio: initialize/tools/call with correct error codes | carapace-mcp 28 unit tests + e2e + `cara mcp` handshake smoke test | verified C7 |
| run_code treats MCP input as hostile: size caps, field whitelists, NUL rejection | carapace-mcp validation unit tests | verified C7 |
| MCP refuses to run code when the doctor gate fails (fail closed) | carapace-mcp run_code doctor-gate path | verified C7 (unit-level) |
| run_code leaves zero temp files on every path (Drop guard) | agent-verified `ls /tmp/cara-mcp-*` = 0 after runs | verified C7 |

## C9 claims (added cycle 8)
| Claim | Basis | Status |
|---|---|---|
| Wasm tier enforces the same policy semantics as Tier 1 (fuel->CpuLimit, epoch->Timeout, limiter->MemoryLimit, output caps, env allowlist, no network) | carapace-wasm tests/parity.rs 9 tests green | verified C9 |
| Kill classification is state-based, not message-based (wasmtime 50 has no public Trap enum) | parity.rs + lib.rs chain-based classification | verified C9 |
| WASI capability grants: exactly one /work scratch dir, no stdin, no sockets, nothing else | parity.rs + lib.rs WasiCtxBuilder usage | verified C9 (structural) |
| Scratch dir removed on every path (Drop guard) | lib.rs ScratchGuard | verified C9 (structural) |
| TODO(wasm-tier): fuel->cpu_time estimate; scratch byte cap; shared Engine for kill() | lib.rs TODOs | ⏳ open, documented |

## C10/C12 claims (added cycle 9)
| Claim | Basis | Status |
|---|---|---|
| MicroVM tier evaluation: libkrun first (in-process, bundled kernel, directory rootfs), Firecracker second, cloud-hypervisor rejected for v1 — all versions/facts sourced | ADR-0006 with inline URLs | verified C10 (research) |
| cara-vm fails closed both with and without KVM; VmPlan mapping clamps and rejects zero budgets | cara-vm 10 unit tests | verified C10 |
| Release runbook: topological publish order core -> sys -> native -> {mcp,wasm,vm} -> cli; audit/deny/SBOM commands real | docs/release.md (agent verified against Cargo.tomls) | verified C12 (docs; musl TODO(verify)) |
| Product demo: 6 scenarios, 9 checks, all PASS on the reference env; host untouched after every scenario | demo/demo.sh run cycle 9 | verified C12 |
| Caps may hold by denial (fork denial, MemoryError) as well as by kill — both accepted and documented | demo/demo.sh checks d + f | verified C12 |

## C11 claims (added cycle 10)
| Claim | Basis | Status |
|---|---|---|
| Supervisor death by ANY route (crash/SIGKILL) destroys the sandbox tree - no orphaned payloads | redteam.rs rt_cara_binary_sigkilled_midrun_orphans_nothing + PR_SET_PDEATHSIG in stage-1, re-armed in stage-2 with a host /proc parent check | verified C11 (found + fixed this cycle); stage-2 gap re-verified P2 |
| perf_event_open, openat2 denied (EPERM); core_pattern surface closed (RLIMIT_CORE=0, /proc/sys RO) | redteam.rs RT12-RT14 | verified C11 |
| Landlock defeats symlink indirection from writable scratch into /proc/sys | redteam.rs rt_symlink_into_proc_sys_denied | verified C11 |

## C11 cycle-3 claims
| Claim | Basis | Status |
|---|---|---|
| Concurrent sandboxes are isolated (no cross-contamination of output) | redteam.rs rt_concurrent_sandboxes_isolated (8 parallel) | verified C11 |
| No descriptor/resource leaks across many sequential runs | redteam.rs rt_no_resource_leaks_over_many_runs (30 runs, fd count) | verified C11 |
| wait() is one-shot; double call errors cleanly (no silent re-report) | redteam.rs rt_double_wait_is_clean_error | verified C11 (found + fixed) |
| Zero output cap kills immediately; stdin reads EOF without hanging | redteam.rs rt_zero_output_cap_kills_immediately, rt_stdin_reads_eof | verified C11 |

## P2 claims (added cycle 13)
| Claim | Basis | Status |
|---|---|---|
| Real runtimes run end to end: bash/coreutils, Python stdlib (json/re/hashlib, sqlite3, ssl, threads, concurrent.futures), Python multiprocessing, Node JSON + worker_threads, gcc compile-and-run, host-built Rust binary, Go build+goroutines, OpenJDK javac+thread | scripts/runtime-matrix.py: 17 passed, 0 failed, 0 skipped on the reference WSL env | verified P2 |
| Policy-driven runs get a usable PATH and HOME=/work without inheriting host env | policy unit test + cli_run.rs::run_provides_default_path_and_home | verified P2 |
| POSIX shared memory / named semaphores work: /dev/shm is a writable size-capped tmpfs; Python multiprocessing.Pool works | rootfs.rs::dev_shm_is_writable, python_multiprocessing_semaphores | verified P2 |
| /etc/alternatives resolves through recreated symlinks only when the host link's canonical target is under /usr; the host directory is never bind-mounted, so regular files (Ubuntu README) are invisible | supervisor planner unit test + rootfs.rs::etc_alternatives_work_when_host_has_them | verified P1/P2 |
| bash job control and coreutils ACL probes work: getpgrp + read-only xattr syscalls are allowlisted | runtime matrix bash/coreutils cases + seccomp profile | verified P2 |
| A normal `cara run` and `cara doctor` remove their run/attach-probe cgroup leaves synchronously before the CLI exits; stale empty leaves from hard-killed supervisors are swept by owner-PID liveness on the next create, and empty staging dirs older than 60s are swept on the next spawn | cli_run.rs::run_removes_its_cgroup_leaf_before_exit + doctor_removes_its_cgroup_probe_leaf_before_exit; cgroup unit sweep test; staging unit sweep test; limits.rs::cgroup_leaves_are_always_removed | verified P2 |
| Executing a binary the payload wrote into a read-write bind works only when the policy opts in (`preset = "dev"` or `filesystem.exec_on_write = true`); strict denies it | runtime matrix gcc-compile-run + rust-binary (dev preset); escape suite write_then_exec (strict) | verified P2/P1 |

## P1 hardening claims (added cycle 14)
| Claim | Basis | Status |
|---|---|---|
| Strict denies `execve` on files written to `/work`, `/tmp`, `/dev/shm` and read-write binds; `dev` and explicit `filesystem.exec_on_write = true` opt in | escape suite `write_then_exec` (denied, rc=126) + `write_then_exec_allowed_when_spec_opts_in` (positive control); landlock `RW_ALL_NO_EXEC` unit test | verified P1 |
| `/etc/alternatives` is recreated as symlinks only when the host link resolves under `/usr`; host regular files and out-of-/usr targets are never exposed | supervisor planner unit test + rootfs `etc_alternatives_work_when_host_has_them` (asserts README invisible) | verified P1 |
| The fork->PDEATHSIG interleaving is forced deterministically: when the supervisor dies inside the window, stage-2 sees stage-1 dead and never execs the payload | `forced_pdeathsig_race_never_execs_payload` (cfg(test)-only pause hook; release builds cannot enable it) | verified P1 |
| Concurrent sandboxes with long-lived payloads cannot deadlock on inherited pipe fds: stage-1 closes every descriptor except its result pipe before proxying | `redteam.rs::rt_concurrent_long_running_sandboxes_do_not_deadlock` (4 infinite payloads, 1 s timeout, 30 s watchdog; deadlocked before the fix, passes in ~1 s) | verified P1 |
| `cara doctor` detects AppArmor/sysctl/user-max userns blockers, cgroup v1/hybrid, missing delegation or controllers, non-merged /usr, missing Landlock/seccomp/pidfd/close_range; each remedy is exact, print-only, and cites upstream docs | doctor pure `classify()` + 17 simulated-environment tests; real doctor still READY on the reference env | verified P1 |
| The README "What Carapace stops" table cannot silently drift from the escape catalog | `table::tests::readme_table_matches_the_catalog` (found and fixed 9 already-drifted rows) | verified P1 |
| Go and JVM complete in strict mode with **zero new syscalls**; the six syscalls they attempt but the profile lacks (socket, connect, getpeername, statfs, fadvise64, fallocate) stay denied, each with an attack-surface review | scripts/runtime-matrix.py go-build-run + jvm-compile-run (17/17 strict); CARA_SECCOMP_LOG=1 run: 20 audit records, 6 distinct syscalls; ADR-0008 | verified P2 |
| Debian/Ubuntu OpenJDK starts because exactly the canonical `security` directory referenced by an in-tree JVM is bind-mounted read-only; foreign targets, regular files and dangling links are dropped | supervisor `security_planner_exposes_only_referenced_etc_security_dirs` + runtime matrix `jvm-compile-run`; ADR-0007 section 8 | verified P2 |
