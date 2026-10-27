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
2. **Seccomp allowlist completeness for Go and JVM runtimes is unproven.**
   The P2 runtime matrix now covers bash/coreutils, Python (stdlib,
   threads, multiprocessing), Node (JSON + worker_threads), gcc
   compile-and-run, and host-built Rust binaries — 15/15 on the reference
   env. Still untested: Go (thread creation via clone with larger flag
   sets; `clone3` with fallback) and JVM-style runtimes. Risk: one of them
   hits an unexpected EPERM and agent users see failures. Verify by:
   adding Go/JVM cases to `scripts/runtime-matrix.py` (CARA_SECCOMP_LOG
   profiling for any denial).
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
7. **musl static build** — documented as a recipe (docs/release.md) with
   explicit TODO(verify); wasmtime/masa deps may not compile for musl.
   Never attempted.
8. **Non-merged-/usr and non-systemd hosts**: doctor requires /usr/bin/sh,
   /usr/lib, /usr/lib64 and a systemd user slice for delegation. Debian
   with separate /usr, Alpine (musl + OpenRC), and sysvinit hosts are
   undetected-and-untested; doctor would fail with the merged-usr message,
   which is fail-closed but possibly misleading on those layouts. Verify
   by: P1 compat matrix in VMs/containers.
9. **cgroup v1 / hybrid hosts**: doctor checks `is_cgroup2_mount` and
   fails closed, but the *remedy text* for a v1 host ("systemd defaults
   to it") is untested and may not cover e.g. Debian 10-era hosts.
   Verify by: P1 (VM with hybrid hierarchy).
10. **PDEATHSIG across the two-stage fork under every exec path**: stage-1
    sets PR_SET_PDEATHSIG before parking. `fork(2)` clears the attribute
    for the child, so stage-2 re-arms SIGKILL immediately after the fork
    and checks that stage-1 still exists via the host `/proc` (the fresh
    sandbox procfs is not mounted yet). RT16 covers the main path: a
    SIGKILLed supervisor leaves no orphan payload. What is NOT tested: a
    targeted "kill in the microsecond window" loop between the fork and
    stage-2's prctl — the liveness check closes it in code, but no test
    forces that interleaving. Verify by: P5 loop test (spawn + instant
    kill, 1000 iterations).

## R3 — Low risk (docs/ergonomics, unproven)

11. **docs/mcp.md client config JSON** was written from the MCP spec shape,
    not validated against current Claude Desktop / Cursor docs. Verify by:
    reading both products' current documentation (P3).
12. **Benchmark comparability** (bubblewrap/nsjail/Docker) — never run;
    docs make no comparative claims (correct). Verify by: P4 on the same
    machine with installable tools.
13. **SBOM tooling output** (`cargo cyclonedx`) — command documented, never
    run. Verify by: P8 release dry run.
14. **`cara policy explain` wording quality** — tested for required
    substrings, never reviewed by a human new to the project. Verify by:
    P6 new-user simulation.
15. **Large-tree builds on DrvFs**: all builds here used the ext4 cache
    (CARGO_TARGET_DIR); a naive `cargo build` directly on /mnt/p has never
    been timed (documented in ENV.md as the reason for the cache).

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
