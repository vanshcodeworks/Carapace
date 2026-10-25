# STATE — agent working state (overwritten every cycle)

Last updated: cycle 4 done (C3 complete @ 5e23c89), C4 in progress.

## Done (all green via scripts/check.sh — which self-bridges via
systemd-run on WSL; see ADR-0003)
- C0 (bcecc3a/75226dd), C1 (9714750), C2 (745dc0a), C3 (5e23c89).
- C3: rootless cgroup v2 limits (memory.max+swap0, pids.max, cpu.max),
  two-stage child (plain-fork stage-1 attaches to leaf then unshares;
  stage-2 = pidns init), doctor attach-capability check + WSL remedy,
  resource report (cpu/peak-mem/peak-pids/OOM->MemoryLimit), overflow
  self-pipe (ms-kill), no waitpid(-1) sweeps. 24 integration tests.

## In progress (C4 — syscall/fs hardening)
- seccomp-bpf allowlist compiler (raw BPF in cara-sys; per-runtime
  profiles; default-deny; ERRATADATA; log-mode for profile development).
- Landlock ruleset: RW /work, R /usr + /proc + /dev nodes; ABI-aware.
- Capability drop (capset all=0) + PR_SET_NO_NEW_PRIVS in stage-2 before
  exec; rlimits (fsize=scratch, nofile cap); close_range fd sanitization
  before exec (keep 0/1/2 only).
- Fail-closed tests: blocked syscall kills with report; Landlock denies
  /usr write despite mount RW... (already RO); fd leak scan from inside
  (/proc/self/fd count == 3); no_new_privs observable (setuid binary
  cannot elevate — /usr has none mounted, verify bit is set via
  /proc/self/status NoNewPrivs).

## Known bugs / risks
- none open; leftover cgroup leaves from debugging purged (218 dirs,
  .wsl/purge-leaves.sh).
- io.max not set (io controller delegated but per-device needed) —
  TODO(C5+) document as optional.

## How to run checks
wsl -d Ubuntu-24.04 -u dev -- bash /mnt/p/Carapace/scripts/check.sh
Per-suite: .wsl/run-{tests,rootfs,limits,full}.sh (all self-bridge).

## Last verified commit
5e23c89
