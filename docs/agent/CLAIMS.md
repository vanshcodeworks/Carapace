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
| Kernel config: CONFIG_SECURITY_LANDLOCK=y, CONFIG_SECCOMP_FILTER=y, CONFIG_LSM includes landlock (dev machine) | /proc/config.gz read in ENV.md (manual, cycle 1); doctor probes the features themselves (Landlock ABI, seccomp action availability) | ✅ manual + runtime probes |
| Isolation claims (fs, network, caps, limits) | escape suite (21 payloads, 23 tests) + hardening.rs + limits.rs | ✅ verified C6/P2 (see docs/threat-model.md §8) |
| Performance claims (cold start; warm pool deferred) | examples/bench.rs; ADR-0005 defers the zygote pool by measurement | ✅ cold measured C8; warm pool not built |
| "What Carapace stops" README table | generated from cara-escape-tests; pinned by table::tests::readme_table_matches_the_catalog | ✅ verified C6/P1 |

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
| network mode full permits sockets end to end (loopback round-trip); none denies them | hardening.rs::network_full_mode_permits_loopback_sockets + seccomp_blocks_socket_creation | ✅ verified cycle 15 |
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
| All 21 escape payloads exhibit their documented safe outcome through the real sandbox | tests/suite.rs 23 tests green (bridged run ~4.1s) | verified C6/P1 |
| No host env var leaks into the sandbox (PATH shared by design) | suite.rs env_leak (asserts against live host env) | verified C6 |
| setuid bits are inert: CapEff=0, NoNewPrivs=1, uid changes EPERM | suite.rs setuid_escalation | verified C6 |
| Red-team: chroot/mknod/sethostname//proc/sys/cross-hierarchy-rename denied; zombie hoards + dual floods + slow-drip contained; new mount API, cross-hierarchy link/exchange, tmpfs isolation, thread/exec inheritance, info-leak syscalls and memfd/mmap exec closed | tests/redteam.rs 31 tests green | verified C6/P1, extended cycle 16 |
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
| cara-vm fails closed both with and without KVM; VmPlan mapping clamps and rejects zero budgets | cara-vm 9 unit tests | verified C10 |
| Release runbook: topological publish order core -> sys -> native -> {mcp,wasm,vm} -> cli; audit/deny/SBOM commands real | docs/release.md (agent verified against Cargo.tomls) | verified C12 (docs); musl build verified cycle 15 |
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
| Executing a binary the payload wrote into a read-write bind works only when the policy opts in (`preset = "dev"` or `filesystem.exec_on_write = true`); strict denies it | runtime matrix gcc-compile-run + rust-binary (dev preset); escape suite write_then_exec (strict); red-team `rt_mmap_exec_of_written_file_denied` | verified P2/P1, extended cycle 16 |

## P1 hardening claims (added cycle 14)
| Claim | Basis | Status |
|---|---|---|
| Strict denies execution of files written to `/work`, `/tmp`, `/dev/shm` and read-write binds — `execve`, `mmap(PROT_EXEC)` and `dlopen` — via Landlock `RW_ALL_NO_EXEC` plus `noexec` mounts; `dev` and explicit `filesystem.exec_on_write = true` opt in | escape suite `write_then_exec` (denied, rc=126) + `write_then_exec_allowed_when_spec_opts_in` (positive control); red-team `rt_mmap_exec_of_written_file_denied` (EPERM mapping; anonymous exec mappings still allowed; opt-in maps successfully); landlock `RW_ALL_NO_EXEC` unit test | verified P1/cycle 16 |
| `/etc/alternatives` is recreated as symlinks only when the host link resolves under `/usr`; host regular files and out-of-/usr targets are never exposed | supervisor planner unit test + rootfs `etc_alternatives_work_when_host_has_them` (asserts README invisible) | verified P1 |
| The fork->PDEATHSIG interleaving is forced deterministically: when the supervisor dies inside the window, stage-2 sees stage-1 dead and never execs the payload | `forced_pdeathsig_race_never_execs_payload` (cfg(test)-only pause hook; release builds cannot enable it) | verified P1 |
| Concurrent sandboxes with long-lived payloads cannot deadlock on inherited pipe fds: stage-1 closes every descriptor except its result pipe before proxying | `redteam.rs::rt_concurrent_long_running_sandboxes_do_not_deadlock` (4 infinite payloads, 1 s timeout, 30 s watchdog; deadlocked before the fix, passes in ~1 s) | verified P1 |
| `cara doctor` detects AppArmor/sysctl/user-max userns blockers, cgroup v1/hybrid, missing delegation or controllers, non-merged /usr, missing Landlock/seccomp/pidfd/close_range; each remedy is exact, print-only, and cites upstream docs | doctor pure `classify()` + 21 doctor tests (17 simulated-environment blockers); real doctor READY on the reference env and on the Debian bookworm userland (cycle 15) | verified P1/P2 |
| The README "What Carapace stops" table cannot silently drift from the escape catalog | `table::tests::readme_table_matches_the_catalog` (found and fixed 9 already-drifted rows) | verified P1 |
| Go and JVM complete in strict mode with **zero new syscalls**; the six syscalls they attempt but the profile lacks (socket, connect, getpeername, statfs, fadvise64, fallocate) stay denied, each with an attack-surface review | scripts/runtime-matrix.py go-build-run + jvm-compile-run (17/17 strict); CARA_SECCOMP_LOG=1 run: 20 audit records, 6 distinct syscalls; ADR-0008 | verified P2 |
| Debian/Ubuntu OpenJDK starts because exactly the canonical `security` directory referenced by an in-tree JVM is bind-mounted read-only; foreign targets, regular files and dangling links are dropped | supervisor `security_planner_exposes_only_referenced_etc_security_dirs` + runtime matrix `jvm-compile-run`; ADR-0007 section 8 | verified P2 |
| A static musl build of `carapace-cli` compiles and runs: `static-pie linked`, `cara doctor` READY, and sandboxed `/bin/sh` + `python3` payloads on a Debian 12 (bookworm) userland under the same WSL kernel | `cargo build -p carapace-cli --target x86_64-unknown-linux-musl`; Debian pivot_root harness (ENV.md); fixed signedness of `statfs.f_type` | measured cycle 15 (userland-only; not a support claim) |
| Debian bookworm passes the host-layout gate: it ships an empty `/usr/lib64` with `/lib64 -> usr/lib64` | `cara doctor` READY inside the Debian pivot_root harness (ENV.md) | measured cycle 15 |

## P3 claims (added cycle 17)
| Claim | Basis | Status |
|---|---|---|
| A session keeps `/work` across separate `cara session exec` host processes and across the CLI's exit; later execs read earlier files | `cara-cli/tests/session.rs::files_persist_across_execs_and_survive_the_cli_exit`; `cara-mcp/tests/mcp_e2e.rs::mcp_sessions_persist_files_and_close` | ✅ verified P3 |
| Upload/download is byte-exact in both directions | `session.rs::upload_download_roundtrip_is_byte_exact` (all 256 byte values + 1 MiB payload); MCP e2e upload/download | ✅ verified P3 |
| Session paths are relative and normalized; `..`, absolute paths, empty/double components and symlink traversal are refused | `session.rs::traversal_absolute_paths_and_symlinks_are_refused`; `carapace-native::session::tests::relative_paths_are_strict` | ✅ verified P3 |
| A per-exec timeout kills the payload tree and leaves the session usable | `session.rs::timeout_kills_the_payload_tree_and_the_session_survives` (background `sleep 30` + foreground `sleep 30`, 1 s timeout) | ✅ verified P3 |
| The session tmpfs is a real disk quota: a 2 MiB session gets ENOSPC on the second 1.5 MiB write and stays usable | `session.rs::disk_quota_is_enforced_inside_the_session` | ✅ verified P3 |
| Session `/work` is `MS_NOEXEC` by default: `execve` fails and `mmap(PROT_EXEC)` returns EPERM (1); `preset = "dev"` / `exec_on_write = true` runs and maps the same file | `session.rs::noexec_is_the_default_and_exec_on_write_opts_in` | ✅ verified P3 |
| `session close` removes the control socket, work dir and metadata | `session.rs::close_removes_the_socket_work_dir_and_meta` | ✅ verified P3 |
| A session exec hides host paths and, under `network = "none"`, `socket(2)` itself fails with EPERM before any connect | `session.rs::host_paths_and_network_stay_hidden` | ✅ verified P3 |
| Concurrent execs against one session serialize (one connection at a time) and all complete | `session.rs::concurrent_execs_are_serialized_not_rejected` (3 parallel `cara session exec`) | ✅ verified P3 |
| Closing a session while a payload is running kills the payload and returns | `session.rs::close_while_busy_kills_the_payload_and_returns` (bounded wait) | ✅ verified P3 |
| Killing the keeper kills the running payload; `session prune` reclaims the dead session's directory | `session.rs::keeper_death_takes_the_payload_and_prune_reclaims_the_state` | ✅ verified P3 |
| Unknown/malformed session ids exit 3; `session start` requires an absolute program path | `session.rs::unknown_and_malformed_ids_are_rejected`, `session_start_requires_an_absolute_program` | ✅ verified P3 |
| Session policy is validated on the host and again in the keeper; `network = "allowlist"` is refused; memory < 64 MiB is refused; the policy round-trips through JSON | `carapace-native::session::tests::session_policy_rejects_allowlist_and_tiny_memory`, `session_policy_round_trips_through_json` | ✅ verified P3 |
| MCP exposes exactly 8 tools including 6 session tools; session ids are server-owned, and foreign ids are refused before any filesystem/socket access | `cara-mcp` unit tests `tools_list_has_exactly_eight_tools`, `session_tools_validate_before_touching_a_sandbox`; e2e foreign-id refusal | ✅ verified P3 |
