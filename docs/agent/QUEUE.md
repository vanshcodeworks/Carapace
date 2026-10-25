# QUEUE — prioritized backlog (agent-maintained)

Legend: [C#] milestone, [RT] red-team, [A] audit, [H] hardening, [D] docs.

## Next up (C0 finish)
1. [C0] Run scripts/check.sh; fix compile/clippy/test failures until green.
2. [C0] Replace stub Readme.md with honest README.md; delete Readme.md.
3. [C0] Commit C0 (workspace + doctor + threat model + env docs).

## C1 — namespaces core
- [C1] cara-core: SandboxSpec/ExitReport/KillReason types + Backend trait
  (sync-first; streams via iterator; async facade later — ADR if needed).
- [C1] child: clone(CLONE_NEWUSER|NEWPID|NEWNS|NEWNET|NEWIPC|NEWUTS|NEWCGROUP)
  via raw clone in cara-sys; parent/child sync pipe (fail closed on any step).
- [C1] uid/gid maps + setgroups deny.
- [C1] supervisor: subreaper (PR_SET_CHILD_SUBREAPER), wall-time timeout,
  pidfd + process-group + cgroup.kill tree kill, cleanup on all paths.
- [C1] tests: timeout kills spinning payload; forked grandchildren die;
  supervisor survives hostile output; cleanup verified (no leftover procs).

## C2 — rootfs
- [C2] tmpfs root, minimal layout, pivot_root with old-root detach.
- [C2] runtime bind mounts (python3 read-only), size-capped scratch
  (mount -o size=… or fsize rlimit; ADR), /proc minimal remount, no /sys,
  no devices.
- [C2] child-side post-pivot verification of the mount table (TOCTOU guard).
- [C2] runtimes/: python recipe builder script (apt-free, host-python bind).

## C3 — cgroups
- [C3] delegated-subtree resolver (from doctor), leaf cgroup per run,
  memory.max/swap.max=0, cpu.max, pids.max, io.max when available.
- [C3] resource report from cgroup files; always-cleanup tests (crash paths).

## C4 — syscall/fs hardening
- [C4] capability drop + no_new_privs + rlimits (core=0, nofile, fsize).
- [C4] Landlock ruleset application (ABI-aware; fail closed on needed-but-
  missing features).
- [C4] seccomp allowlist compiler (raw BPF in cara-sys; per-runtime
  profiles; logging mode for profile development).
- [C4] fd sanitization (close_range) + env allowlist; child self-checks.

## C5 — network + policy
- [C5] empty netns default; full mode (shared netns) opt-in; allowlist ADR
  (veth+nftables vs userspace proxy vs slirp-style).
- [C5] policy TOML parsing/validation, presets strict/dev/network-light,
  limits parsing (bytes/percent/durations), `cara policy check|explain`,
  JSON schema via `cara schema`.

## C6 — escape suite v1 (catalog in cara-escape-tests) + generated README
   table + first red-team cycle.

## C7 — MCP server (stdio), library API examples, docs (policy reference,
   MCP guide, troubleshooting, FAQ, SECURITY.md, CONTRIBUTING.md).

## C8 — zygote/pool + honest cold/warm benchmarks + cargo-fuzz targets
   (policy parser, mount planner, seccomp compiler, MCP parser, output
   limits) + cargo audit/deny + Miri on pure logic.

## C9 — Wasm tier behind Backend trait; parity tests vs Tier 1 policy.

## C10 — microVM ADR (Firecracker vs libkrun) + design + skip-clean tests
   (no KVM on dev env).

## C11 — hardening cycles 2+3 (red-team), fuzz-found fixes, profile audits.

## C12 — release readiness: static musl build recipe, SBOM, install script
   walkthrough, demo script, benchmark report, comparison table, launch docs.

## Standing tasks (never closed)
- [A] Every 5th cycle: audit cycle (re-verify CLAIMS.md, rerun escape suite,
  grep docs for unqualified "secure", check unsafe blocks have comments).
- [RT] Every 10th cycle: red-team cycle.
- [D] Keep README claims generated-from-tests only.

## Cycle 6 additions
- [C6] redteam.rs probes (rename REFER cross-hierarchy, TIOCSTI, sethostname,
  clock_settime, chroot, mknod, /proc/sys write, huge-argv E2BIG, zombie
  hoard, dual-stream flood, invalid-UTF8 args) — running now.
- [C8] bench.rs exists; warm numbers after zygote pool.
