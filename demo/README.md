# Carapace demo — an agent's destructive script meets the sandbox

This is the primary product demo (the README's "Why" story, executed).
An "agent-written" script tries to recon your host, fork-bomb the
machine, flood output, exhaust memory, and plant a file in `/etc`.
Carapace runs it anyway, blocks the damage, and reports exactly what was
stopped and why — `kill_reason` in the machine-readable JSON report.

The payloads are the same attacks the escape-suite catalog tests
(`crates/cara-escape-tests/src/lib.rs`); here they run through the real
`cara run` CLI instead of the library API, so what you watch is what an
agent (or you) gets from the `cara` binary. The README's "What Carapace
stops" table is generated from that same catalog, so the demo, the docs,
and the tests cannot drift apart.

## Running it

Needs a Tier-1-ready Linux host (kernel ≥ 5.10; the script runs
`cara doctor` first and refuses to run if it fails — the sandbox must
fail closed). On WSL2 see docs/troubleshooting.md if doctor reports
missing delegation.

```sh
# from the repository root, inside the Linux environment
cargo build -p carapace-cli
CARA=./target/debug/cara demo/demo.sh
```

Preview what the demo executes without executing anything (e.g. on a
CI runner without user namespaces) — prints the commands and exits 0:

```sh
DEMO_DRY_RUN=1 demo/demo.sh
```

Any binary works via `CARA=...` (release builds included —
`CARA=./target/release/cara demo/demo.sh`).

Demo exit codes: `0` every scenario passed · `1` at least one FAIL ·
`2` preconditions not met (nothing was executed).

Safety: hostile payloads only ever execute **inside the sandbox**
(CONTRIBUTING rule 2). The host is only read: file-existence checks and
`pgrep` scans after each scenario.

## The scenarios and what each one proves

| # | Payload (inside the sandbox) | Proves | Escape-suite catalog id |
|---|---|---|---|
| a | `/bin/sh -c 'echo hello from sandbox'` | The sandbox is not a broken toy: normal programs run and their output comes back untouched (exit 0, stdout intact). Baseline for "nothing above breaks normal code" — cf. the suite's `normal_python_still_works`. | *(baseline — not an escape)* |
| b | `/bin/sh -c 'ls /home'` | Host filesystem invisibility: `/home` does not exist inside the sandbox — "No such file or directory", not a listing of your users' home dirs. | `read_home` |
| c | `/bin/sh -c 'echo pwned > /etc/cara-demo-pwned'` | Writes outside the granted paths are denied (Landlock / read-only `/usr`), the payload exits nonzero, **and the host file does not exist afterwards** — checked after every scenario via the canary path `/etc/cara-demo-pwned`. | `write_outside` |
| d | `/bin/sh -c 'while :; do sleep 60 & done'` with `--timeout 3s --json` | Fork bombs are bounded twice: `pids.max` caps process creation and the supervisor kills the whole tree at the wall-clock deadline (`kill_reason: timeout`). One second later a host `pgrep -f 'sleep 60'` finds no stragglers — the tree is dead, not merely reaped. | `fork_bomb` |
| e | `/bin/sh -c 'while :; do echo x; done'` with a policy `[limits] max_output = "64KB"` | Output floods die at the byte cap: `kill_reason: output_overflow`, captured output stays capped. Policies are real TOML files (fail-closed parsing — the script validates each with `cara policy check` before running). | `output_flood` |
| f | `/usr/bin/python3 -c 'a = bytearray(10**12)'` with a policy `[limits] memory = "128MB"` | Memory hogs are OOM-killed by the cgroup at the configured limit (`kill_reason: memory_limit`); the host is unaffected. Skipped automatically when `/usr/bin/python3` is absent. (Suite verifies the same mechanism at a 64 MiB limit vs a 256 MiB request.) | `memory_hog` |

The JSON scenarios (d, e, f) assert on the stable `--json` report schema
(`crates/cara-cli/src/run_ui.rs`): `kill_reason` is one of `timeout`,
`output_overflow`, `memory_limit`, `cpu_limit`, or an internal-error
string. Plain-English versions of the same outcomes come from the MCP
tool `explain_result` (docs/mcp.md).

## Where the proof lives

- **Escape suite (the authoritative tests):** `crates/cara-escape-tests`
  — the catalog `src/lib.rs` (20 payloads, each with its documented
  expected outcome) and `tests/suite.rs` (every payload executed through
  the real sandbox, plus a host `/proc` scan asserting no straggler
  processes survive).
- **Mechanism docs:** docs/architecture.md (how a run works),
  docs/threat-model.md (what is defended, what is not — Tier 1 does not
  promise protection against kernel exploits), docs/policy.md (policy
  file reference and the stable exit codes).
- **Claims ledger:** docs/agent/CLAIMS.md — every claim above maps to a
  named test; a claim without a test is a bug in the claim.

## Interpreting a failure

A `FAIL` line means a documented sandbox property did not hold on this
machine (or the demo's assumptions broke — e.g. an unrelated host
process coincidentally matches a `pgrep` needle; check the reported
command line). Either way: do not ignore it. Reproduce with
`CARA=... demo/demo.sh`, capture `cara doctor --json`, and see
SECURITY.md if it looks like an escape.
