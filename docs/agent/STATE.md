# STATE — agent working state (overwritten every cycle)

Last updated: cycle 3 done (C2 complete @ 745dc0a), C3 in progress.

## Done (all verified green via scripts/check.sh)
- C0: workspace + doctor + threat model + docs (bcecc3a, 75226dd)
- C1: rootless namespaces + supervisor (9714750): clone w/ 7 ns flags,
  CLONE_PIDFD, maps, timeout, output caps, pidns-init tree kill, fail-closed
  pre-exec handshake. 9 integration tests.
- C2: rootfs + pivot_root (745dc0a): private tmpfs over /tmp (zero host
  artifacts), ro /usr bind, safe /dev binds, minimal /etc (marker), capped
  /work, fresh proc, pivot+detach, post-pivot self-verify. 10 rootfs tests
  incl. python3 hello-world. Full sandbox spawn+run measured ~8ms wall.

## In progress (C3 — cgroups)
- Limits growth in core: memory_bytes, cpu_percent, max_processes.
- Supervisor: resolve delegated root (reuse doctor logic), create leaf
  cara-run-<id> under it in the go-pipe window, write memory.max +
  memory.swap.max=0 + pids.max + cpu.max, move child pid in via
  leaf/cgroup.procs, enable controllers in subtree_control as needed.
- ExitReport: cpu usage (cpu.stat), peak memory (memory.peak), oom_kill
  (memory.events), pids peak.
- Cleanup: rmdir leaf on every teardown path; cgroup.kill kill switch.
- Tests: memory hog OOM-killed at limit; fork bomb stopped by pids.max;
  cpu quota shapes usage; report numbers sane; leaf always gone.

## Known bugs / risks
- One supervisor-suite test consumes a full 10s (assertions pass) —
  profile and fix. QUEUED.
- /usr bind includes host full /usr: v1 recipe; narrower runtimes later.
- No seccomp/Landlock until C4: payload has fs isolation but full syscall
  access. Escape suite only after C4.

## How to run checks
wsl -d Ubuntu-24.04 -u dev -- bash /mnt/p/Carapace/scripts/check.sh
(.wsl/run-tests.sh = supervisor suite only; examples/probe.rs dev tool)

## Last verified commit
745dc0a
