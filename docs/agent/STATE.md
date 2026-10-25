# STATE — agent working state (overwritten every cycle)

Last updated: cycle 10 — ALL MILESTONES C0-C12 COMPLETE @ 02044f0. See FINAL_REPORT.md.

## Done (all green via scripts/check.sh)
- C0-C5 COMPLETE. eae8a2b = policy TOML (deny_unknown_fields, presets,
  unit parsing), filesystem binds (rw + ro) via staging-dir design,
  network modes none/full + honest allowlist refusal (ADR-0004),
  `cara run` / `cara policy check|explain` CLI with JSON reports.
- Test suites: supervisor (9), rootfs (10), limits (5), hardening (10),
  cli_run (6), doctor (8+), core policy (9). Full workspace green.

## Done since C5
- C6 escape suite (20 payloads, 21 tests) + redteam.rs (11 probes) +
  generated README table (3ae2e4d, b3501b7). C7 MCP server via cara mcp
  (335b8bb) + full docs set (9c56935). C9 Wasm tier with parity tests
  (0dbb190) — wasmtime 50, fuel/epoch/limiter, state-based kill
  classification. ADR-0005 pool deferred by measurement (bbc0493).

## In progress (parallel subagents)
- SUBAGENT: C10 microVM ADR + cara-vm KVM-free logic (ADR-0006).
- SUBAGENT: C12 release runbook + demo script + release-dry-run workflow.
- ME (main thread): C8 fuzz runs, integration, commits.

## Known bugs / risks
- mkdir_p lesson encoded: never hardcode prefix lengths; keep join
  separators (bind ENOENT debugging).
- Stale staging dirs from debugging sessions may exist under
  /run/user/1000/cara-staging.* — .wsl/purge-leaves.sh pattern applies.

## How to run checks
wsl -d Ubuntu-24.04 -u dev -- bash /mnt/p/Carapace/scripts/check.sh
(.wsl/run-full.sh = tests only, self-bridging; per-suite runners exist)

## Last verified commit
eae8a2b
