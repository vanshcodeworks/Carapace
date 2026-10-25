# STATE — agent working state (overwritten every cycle)

Last updated: cycle 2 done (C1 complete), C2 in progress.

## Done
- C0 @ 75226dd, C1 @ 9714750 — all green (fmt/clippy/test incl. 9
  supervisor integration tests, no leftover processes).
- C1 delivers: rootless namespaces (user/pid/mount/net/ipc/uts/cgroup),
  pidfd kill of pidns-init (kernel kills whole ns), wall timeout, output
  caps, subreaper, fail-closed pre-exec handshake (Setup error, never a
  silent run). Empirical gotchas solved: uid_map needs parent-recorded
  uid (getuid is overflow inside ns); parent must close pipe write-end
  copies after clone or EOF never arrives.

## In progress (C2)
- Child mounts: private-propagation, tmpfs root (size-capped), ro-bind
  /usr, /dev/{null,zero,urandom,random} binds, minimal /etc, scratch tmpfs
  /work, pivot_root + MNT_DETACH old root, fresh /proc (own pidns view).
- Post-pivot self-verification (mount table as expected, no old root).
- Tests: /etc/passwd is ours; /usr write fails; host paths ENOENT;
  /proc shows only own tree; python3 hello-world runs.

## Known bugs / risks
- C1 sandbox has no fs isolation until C2 lands (benign payloads only).
- After C2: no seccomp/Landlock until C4; /proc mount leaks little but
  is fresh pidns proc; host /usr bind includes host binaries — acceptable
  for tier-1 v1 (runtime recipes narrow it later).

## How to run checks
wsl -d Ubuntu-24.04 -u dev -- bash /mnt/p/Carapace/scripts/check.sh
(bounded with timeout 300 in practice; kill stuck test pids via root if
a hang reappears — check .wsl/probe-stuck.sh)

## Last verified commit
9714750
