# STATE — agent working state (overwritten every cycle)

Last updated: cycle 1 (2026-10-25), milestone C0 in progress.

## Current milestone
C0: environment + threat model + workspace + CI + `cara doctor`.

## Done
- WSL2 Ubuntu 24.04.5 dev env set up (see ENV.md): userns ✅, cgroup v2
  delegation (cpu/io/memory/pids) ✅, Landlock ABI 7 ✅, seccomp ✅, no KVM.
- Branch `agent/work` created. Workspace scaffolded: cara-core, cara-sys,
  cara-native, cara-wasm, cara-vm, cara-cli (bin `cara`), cara-mcp,
  cara-escape-tests. CI workflow committed (fmt/clippy/test).
- `cara doctor` implemented (10 checks, JSON + human output, exit 0/4),
  fail-closed gate = DoctorReport::ready().
- docs/threat-model.md v1 written. All agent files created.

## In progress
- First full check run (fmt/clippy/test) — not yet executed; expect first
  compile errors (unverified libc constant availability: SYS_landlock_*).

## Known bugs / risks
- `libc::SYS_landlock_create_ruleset` availability unverified — fallback:
  local consts (444/445/446 verified empirically, ENV.md).
- `statfs.f_type` type match against libc unverified.

## How to run checks
`wsl -d Ubuntu-24.04 -u dev -- bash /mnt/p/Carapace/scripts/check.sh`
(from Windows Git Bash). Inside WSL: `bash scripts/check.sh`.
Never commit with red checks. Commit = green only.

## Last verified commit
(none yet — workspace not yet compiled)
