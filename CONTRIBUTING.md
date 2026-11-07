# Contributing to Carapace

Carapace is a sandbox for hostile code. That shapes the contribution rules:
security claims must be proven, test payloads must never touch the host,
and the public docs must match what is measured.

## Development setup

- **Linux**, or **WSL2** with a systemd-enabled distro (the reference dev
  environment is Ubuntu 24.04 on WSL2 — see docs/agent/ENV.md).
- Rust ≥ 1.85 (`rustup`, stable), `build-essential`, `pkg-config`,
  `libseccomp-dev` on Debian/Ubuntu.
- Kernel ≥ 5.10 with cgroup v2, Landlock (≥ 5.13), seccomp-bpf, unprivileged
  user namespaces. Run `cara doctor` first — it measures all of this and
  prints remedies (docs/troubleshooting.md).

Build and full verification, from the repository root **inside the Linux
environment**:

```sh
cargo build -p carapace-cli
./target/debug/cara doctor
bash scripts/check.sh
```

`scripts/check.sh` runs the whole loop: `cargo fmt --all -- --check`,
`cargo clippy --all-targets --all-features -- -D warnings`, and
`cargo test --workspace` (with `CARA_STRICT_ENV_TESTS=1`). It also sets
`CARGO_TARGET_DIR` off the source tree and **self-bridges the cgroup
context**: if it detects the process sits outside its systemd user slice
(typical for WSL `wsl.exe` commands), it re-executes itself under
`systemd-run --user --scope --quiet` (~13 ms) so the cgroup tests can run.
Normal Linux logins need none of this.

## Repository layout

```
crates/
  cara-core          types: SandboxSpec, Policy (TOML), ExitReport, DoctorReport
  cara-sys           raw syscalls — ALL unsafe code is confined here
  cara-native        Tier 1 backend: doctor, supervisor, child, rootfs,
                     cgroups, seccomp profiles
  cara-cli           the `cara` binary (doctor / run / policy / session / mcp)
  cara-escape-tests  hostile payload catalog + generated README table
  cara-mcp           MCP server with 8 tools
  cara-wasm          Tier 2 library backend
  cara-vm            Tier 3 design and fail-closed plan
docs/
  threat-model.md    what is defended, what is not — read this first
  policy.md          policy file reference        architecture.md: how a run works
  runtime-guide.md   running languages            troubleshooting.md: doctor remedies
  mcp.md             MCP contract                 agents.md: agent workflows
  decisions/         ADRs
  agent/             working state: STATE, LOG, CLAIMS, ENV, QUEUE, NEEDS_HUMAN
AGENT_SETUP.md       setup file to hand to a user's agent
scripts/check.sh     the verification loop
scripts/install.sh   build and install cara + cara-mcp
scripts/mcp-smoke.py real MCP handshake + run_code smoke test
examples/            library API examples
benches/ · fuzz/     C8 benchmark and fuzz targets
runtimes/            minimal rootfs recipes (future; v1 uses the host /usr)
```

## Workflow

- Work happens on the `agent/work` branch (or your own feature branch);
  `main` is the integration target.
- **Conventional commits**, with the milestone in the scope:
  `feat(c7): ...`, `test(c6): ...`, `fix(c4): ...`, `docs: ...`,
  `chore(c8-prep): ...`.
- Before opening a PR: `bash scripts/check.sh` must be fully green on your
  machine, and `cara doctor` must have been green in the same session.

## Rules (the important part)

1. **Every security claim maps to a named test.** If a commit message, doc
   line, or README cell says "Carapace stops X", there must be a test that
   proves it, referenced in docs/agent/CLAIMS.md. A claim without a test
   is a bug in the claim. Measured numbers state the machine; unproven
   things are marked `TODO(test)`.
2. **Payloads only ever run inside the sandbox.** Hostile test payloads
   (cara-escape-tests, red-team suites) execute exclusively through the
   real sandbox under test — never via a plain `Command`, never on the
   host, never "just this once" to debug. Debug by adding assertions
   inside the sandboxed script.
3. **Release with the runbook.** The GitHub repository is public, but there
   is no tagged release and no prebuilt binary yet. Do not publish crates,
   upload packages, or distribute binaries without following
   [docs/release.md](docs/release.md) and its human decision points.
4. **Fail closed, always.** New configuration surface (policy fields,
   flags, MCP request fields) must reject unknown values, must have a
   deny-by-default posture, and must never add a "degraded mode" that runs
   with less isolation without an ADR.
5. **Keep the docs honest.** If you change behavior, update the doc that
   describes it (docs/policy.md for policy semantics, docs/architecture.md
   for the run pipeline, docs/troubleshooting.md for doctor remedies) and
   the agent journals below. Never use unqualified "secure" in prose — say
   what is enforced, by which mechanism, with which residual risk
   (docs/threat-model.md is the style reference).

## Agent journals

The project's working memory lives in docs/agent/ and must be kept current
with your change:

- `docs/agent/STATE.md` — what exists today, what is in progress
  (overwritten every cycle).
- `docs/agent/LOG.md` — append a short entry per work cycle.
- `docs/agent/CLAIMS.md` — add/verify the claim rows for any behavior your
  change affects; measured numbers must state the reference machine
  (docs/agent/ENV.md).

## Reporting security issues

Not here — see SECURITY.md (private disclosure, 90-day goal).
