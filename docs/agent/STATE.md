# STATE — agent working state (overwritten every cycle)

Last updated: cycle 6 done (C5 complete @ eae8a2b), C6/C7 in progress
via parallel subagents.

## Done (all green via scripts/check.sh)
- C0-C5 COMPLETE. eae8a2b = policy TOML (deny_unknown_fields, presets,
  unit parsing), filesystem binds (rw + ro) via staging-dir design,
  network modes none/full + honest allowlist refusal (ADR-0004),
  `cara run` / `cara policy check|explain` CLI with JSON reports.
- Test suites: supervisor (9), rootfs (10), limits (5), hardening (10),
  cli_run (6), doctor (8+), core policy (9). Full workspace green.

## In progress (parallel subagents)
- SUBAGENT A: cara-escape-tests catalog (20 payloads) + suite + README
  table generator. Files: crates/cara-escape-tests/** + one workspace dep line.
- SUBAGENT B: carapace-mcp stdio JSON-RPC server (initialize/tools/list/
  tools/call run_code+explain_result, hostile input validation, e2e test).
  Files: crates/cara-mcp/** + one workspace dep line.
- ME (main thread): library examples, C8 prep (fuzz scaffold, zygote ADR),
  integration of agent output, commits.

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
