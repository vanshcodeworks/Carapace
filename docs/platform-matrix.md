# Platform matrix

This page states what has actually been built and measured. "Verified" means
a named test or measurement in this repository demonstrates the claim.
"Unverified" means no measurement exists yet. Unverified is not the same as
false, but it is also not support. Do not read a build artifact as a support
claim.

Reference environment for every current measurement: WSL2, kernel
6.18.54.1-microsoft-standard-WSL2, Ubuntu 24.04.5, x86_64, systemd user
slice with cgroup v2 delegation.

## Build and test status

| Target or environment | Built | Sandbox runtime tested | Full `scripts/check.sh` | Status |
|---|---|---|---|---|
| `x86_64-unknown-linux-gnu` on WSL2 Ubuntu 24.04, kernel 6.18 | Yes, debug and release | Yes, Tier 1 sandbox and 8-tool MCP server | Yes, all green | Verified reference |
| `x86_64-unknown-linux-musl` (`cara` CLI) | Yes, static-pie | Yes, `cara doctor` READY and sh/Python payloads on Debian 12 bookworm under the same WSL kernel | No | Partial: one userland data point |
| `x86_64-unknown-linux-musl` (`cara-mcp` server) | Planned in release workflow | No | No | Unverified |
| `aarch64-unknown-linux-gnu` | Cross-build attempted in release workflow only | No | No | Not supported |
| Debian 12 bookworm userland under the same WSL kernel | musl CLI only | sh and Python payloads, userland only | No | Unverified as a platform |
| Fedora, Arch, Alpine, other distros | No | No | No | Unverified |
| cgroup v1 or hybrid hosts | No | No | No | Unverified (fail-closed diagnosis only) |
| Non-systemd or non-merged-`/usr` hosts | No | No | No | Unverified (fail-closed diagnosis only) |
| Hosted GitHub Actions runners | Yes | No, isolation tests self-skip | No | Compile and unit checks only |
| Tier 2 Wasm backend | Workspace crate compiles | Not exposed in the CLI | No | Unverified |
| Tier 3 microVM | Workspace crate compiles | Never booted, no `/dev/kvm` | No | Not usable |

## Why aarch64 is not supported

The BPF seccomp allowlist is compiled for x86_64 only. On aarch64 the filter
kills the process by design so the failure is fail closed, not a silent
bypass. There is no aarch64 seccomp table and no aarch64 native or QEMU
runtime measurement (UNVERIFIED R1.4). The release workflow only cross-builds
that target to prove the source compiles. A produced aarch64 binary is not a
statement that the sandbox works there.

## Why hosted CI is not the isolation gate

The hosted workflow runs docs, formatting, clippy, `cargo deny`, and unit
tests. It cannot create user namespaces or delegate cgroups, so
`CARA_STRICT_ENV_TESTS` is unset there and the environment-dependent tests
self-skip. A green badge proves compile and unit behavior only. The weekly
`.github/workflows/self-hosted-check.yml` runs `bash scripts/check.sh` on a
cgroup-delegated self-hosted runner and is the authoritative gate.

## Release artifacts

`.github/workflows/release.yml` runs only on manual `workflow_dispatch`. It
builds the three targets above, attaches SHA256 checksums, and creates a draft
GitHub release. It does not publish a release and does not publish to
crates.io. Publishing remains a human decision.

## How to verify a new platform

1. Boot or enter the target with delegated cgroups and unprivileged user
   namespaces available.
2. Confirm `systemd-run --user --scope true` works as the unprivileged user.
3. Run `cara doctor` and record the result.
4. Run `bash scripts/check.sh` and record the full output.
5. Add a row to this table with the exact kernel, distro, and architecture.
   Only then may the row say Verified.

Related open items are recorded in `docs/agent/UNVERIFIED.md`, especially
R1.4, R2.11, and AUDIT-19.
