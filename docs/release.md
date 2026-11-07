# Release Runbook (docs/release.md)

> **Audience: a human.** The GitHub repository is public, but there is no
> tagged release and no prebuilt binary yet. Per
> [CONTRIBUTING.md](../CONTRIBUTING.md) rule 3, every step that
> *distributes* something — tagging, publishing, uploading assets — is
> performed by a human, deliberately, and only after this checklist passes.
> Nothing in this runbook is fully automated; the only CI support is
> [`.github/workflows/release-dry-run.yml`](../.github/workflows/release-dry-run.yml),
> which builds, tests, packages, and uploads **artifacts for inspection
> only** — it publishes nothing.

Every command below is verbatim for this repository as of cycle 18.
Unverified steps are marked `TODO(verify)` — do not skip them on release
day; resolve them first.

## 0. Environment

- The Linux dev environment (bare metal or WSL2) per
  [docs/agent/ENV.md](agent/ENV.md): Rust ≥ 1.85 stable via rustup,
  `build-essential`, `pkg-config`, `libseccomp-dev`.
- A Tier-1-ready host: `cara doctor` must exit 0 in the same session you
  build and test in (fail closed — no release from a machine the doctor
  refuses).

## 1. Prerelease checklist

Work through in order; do not batch.

- [ ] **Full verification loop green**, from the repository root inside
      the Linux environment:

  ```sh
  bash scripts/check.sh
  ```

  This runs `cargo fmt --all -- --check`,
  `cargo clippy --all-targets --all-features -- -D warnings`, and
  `cargo test --workspace` (with `CARA_STRICT_ENV_TESTS=1`), and
  self-bridges the cgroup context on WSL (see
  [docs/troubleshooting.md](troubleshooting.md)).

- [ ] **Doctor green in the same session:**

  ```sh
  cargo build -p carapace-cli
  ./target/debug/cara doctor
  ```

- [ ] **Security audit** — dependency advisories. `cargo deny check`
      runs in CI (the `deny` job in `.github/workflows/ci.yml`).
      `cargo audit` is not in CI, so run it manually. Install once, then
      audit:

  ```sh
  cargo install cargo-audit cargo-deny
  cargo audit
  cargo deny check
  ```

  Every RUSTSEC finding must be either fixed (bump the dependency in
  `Cargo.lock`) or explicitly waived with a written reason in this
  runbook's release notes. Silent waivers are bugs.

- [ ] **License / ban policy check** — `cargo deny check` runs in CI.
      `deny.toml` is committed at the repo root (generated once, then
      reviewed), so runs are reproducible:

  ```sh
  cargo deny check
  ```

  Verified cycle 18: all four sections pass with a permissive-only
  license allow list (each entry justified; copyleft fails by default).
  The wasmtime dependency was updated to 50.0.1 for RUSTSEC-2026-0420.
  Re-run both commands per release.

- [ ] **Product demo green against a release build** (built in step 2):

  ```sh
  CARA=./target/release/cara demo/demo.sh
  ```

- [ ] **Claims current:** every security claim reachable from the release
      has a row in [docs/agent/CLAIMS.md](agent/CLAIMS.md) pointing at a
      test. If a claim is marked `TODO(test)`, it is not a release
      claim — say so in the release notes.

## 2. Build the release artifact

```sh
cargo build --release -p carapace-cli
```

The binary is `target/release/cara`.

> **Path caveat (dev environment):** `scripts/check.sh` exports
> `CARGO_TARGET_DIR=$HOME/.cache/carapace-target`. If you build in a
> shell that inherited that variable, the binary lands at
> `$HOME/.cache/carapace-target/release/cara` instead. Either unset
> `CARGO_TARGET_DIR` for the release build or use the path cargo prints.

Smoke-test the artifact before anything else:

```sh
./target/release/cara doctor
./target/release/cara run -- /bin/sh -c 'echo hello from sandbox'
```

### 2a. Static musl build (optional)

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release -p carapace-cli --target x86_64-unknown-linux-musl
```

Verified cycle 15 (2026-10-27): this command builds successfully from a
clean target dir on the reference env. The result is a static-pie binary
(`file`: "static-pie linked"; `ldd`: "not a dynamic executable"). That
binary then ran `cara doctor` (READY) and sandboxed `/bin/sh` and
`python3` payloads on a Debian 12 (bookworm) userland under the same WSL2
kernel (see docs/agent/ENV.md). The build required one portability fix:
`statfs.f_type` is signed on glibc and unsigned on musl, so the cgroup2
magic comparison now normalizes to u64.

Still unverified: running the glibc build on hosts with older glibc,
musl builds of Tier 2 (`carapace-wasm`), and non-x86_64 musl targets.

Honest expectations: the `cara` dependency tree (carapace-core,
carapace-sys, carapace-native, carapace-mcp, clap, serde/serde_json,
toml, libc) is pure Rust with no C build scripts, which keeps a static
musl link plausible. The genuinely finicky combination — wasmtime + musl
— is **not** in this tree: `wasmtime` is a dependency of `carapace-wasm`
only, and `carapace-cli` does not depend on `carapace-wasm` (verified
from the workspace `Cargo.toml` files). Building `carapace-wasm` (Tier 2)
for musl is a different project. Even so, musl static builds have their
own classic failure modes (allocator behavior, backtraces, DNS); if the
build fights back, use the glibc fallback below instead of shipping a
fragile binary.

Confirm it is actually static before calling it static:

```sh
ldd target/x86_64-unknown-linux-musl/release/cara   # expect: not a dynamic executable
```

### 2b. glibc fallback

If musl fails, ship the ordinary release
build:

```sh
cargo build --release -p carapace-cli
ldd target/release/cara
```

This binary dynamically links glibc. Consequences to document in the
release notes:

- It runs on distros with a glibc **at least as new as the build
  machine's** — build on the *oldest* distro you intend to serve, not
  the newest.
- Runtime kernel requirement is unchanged: Linux ≥ 5.10, and the target
  machine must pass `cara doctor` (cgroup v2 delegation, Landlock,
  seccomp-bpf, unprivileged user namespaces).

## 3. SBOM

```sh
cargo install cargo-cyclonedx
cargo cyclonedx --workspace
```

This emits CycloneDX documents for every workspace crate next to the
build artifacts. TODO(verify): confirm the exact output paths and
format options on first run (`cargo cyclonedx --help`) and decide
whether to pin them via `[workspace.metadata.cyclonedx]` in
`Cargo.toml`.

## 4. Checksums

```sh
sha256sum target/release/cara
```

Record the output in the release notes, and produce a checksums file
for the release assets:

```sh
sha256sum target/release/cara > cara-vX.Y.Z-x86_64-linux.sha256
# plus the musl binary if built:
sha256sum target/x86_64-unknown-linux-musl/release/cara >> cara-vX.Y.Z-x86_64-linux.sha256
```

Verify a downloaded artifact with `sha256sum -c
cara-vX.Y.Z-x86_64-linux.sha256` on the receiving machine.

## 5. Version bump, tagging

- The workspace has a **single version** for all crates
  (`[workspace.package] version = "0.1.0"` in the root `Cargo.toml`;
  every crate inherits via `version.workspace = true`). Bump it once.
- Commits are **conventional commits** with the milestone scope (see
  CONTRIBUTING.md): `feat(c12): ...`, `fix(c4): ...`, `docs: ...`,
  `chore: ...`.
- Update the README status banner and `docs/agent/STATE.md` as part of
  the release commit.
- Tag and push (this triggers the release-dry-run workflow):

  ```sh
  git tag -a vX.Y.Z -m "Carapace vX.Y.Z"
  git push origin vX.Y.Z
  ```

The tag push runs `.github/workflows/release-dry-run.yml` on GitHub:
release build of `carapace-cli`, `cargo test --workspace`,
`cargo publish --dry-run -p carapace-core`, and a `sha256sum` of
`target/release/cara`, uploaded as workflow artifacts. **It publishes
nothing** — it is the last mechanical gate; inspect its artifacts and
the green run before continuing.

## 6. crates.io publishing (human; decision-gated)

> This section only applies after the release checklist passes and a human
> decides to publish. Until then: do not run `cargo publish` without
> `--dry-run`.

For every crate, dry-run first, then publish for real:

```sh
cargo publish --dry-run -p <crate>
cargo publish -p <crate>
```

### Publish order (derived from the verified dependency graph)

`cargo publish` refuses a crate whose *path* dependencies are not
already on crates.io (it resolves them to the registry version named in
`Cargo.toml` — every intra-workspace dependency here is declared as
`{ version = "0.1.0", path = ... }`, so this works — but the version
must exist on the registry first). The order therefore follows the
dependency closure, verified from the workspace `Cargo.toml` files:

| Order | Crate | Depends on (path) | Registry-only deps |
|---|---|---|---|
| 1 | `carapace-core` | — | toml, serde, serde_json, thiserror |
| 2 | `carapace-sys` | — | libc |
| 3 | `carapace-native` | core, sys | libc |
| 4 | `carapace-mcp` | core, native | serde, serde_json |
| 4 | `carapace-wasm` | core, native | wasmtime, wasmtime-wasi, wat, libc |
| 4 | `carapace-vm` | core | — |
| 5 | `carapace-cli` | core, native, mcp | clap, serde_json |

`carapace-core` is first (as it must be — everything depends on it);
`carapace-cli` is last. Within row 4 the three crates are independent of
each other. Note that `carapace-cli` **cannot** precede `carapace-mcp`,
and neither can precede `carapace-native` — the path-dep graph, not
preference, dictates the order.

### DECISION POINT: publish or keep path-only the internal crates

`carapace-sys` and `carapace-native` are internals (raw syscalls; the
Tier 1 backend). This decision is load-bearing and **unresolved**:

- **Option A — publish them.** Required if `carapace-mcp` and
  `carapace-cli` are ever to be on crates.io (see the table above).
  Upside: `carapace-sys` is the audited boundary where *all* unsafe
  syscall code lives — having it public, versioned, and diffable is an
  audit feature, and the README already advertises it as such.
- **Option B — keep them path-only.** Then `carapace-mcp` and
  `carapace-cli` also cannot be published (they depend on
  `carapace-native`), and crates.io distribution is off the table:
  releases are GitHub binary artifacts only. To *enforce* path-only
  status, add `publish = false` to those crates' `[package]` tables
  (nothing currently sets it — verified).

Also unpublished regardless: `carapace-escape-tests` (the hostile
payload catalog — test-support, not a library product) and
`carapace-vm` (Tier 3 stub; milestone C10 not implemented). If Option B
is chosen, mark these `publish = false` too.

TODO(human decision): pick A or B before the first release; record the
decision as an ADR in `docs/decisions/`.

TODO(verify) before publishing anything:

- `cargo package --list -p <crate>` for each published crate — confirm
  no unwanted files ship (e.g. scratch, local scripts).
- The crates declare `version/edition/license/repository` via workspace
  inheritance but do **not** declare `rust-version` per crate (the root
  workspace sets `rust-version = "1.85"`; the member crates do not
  inherit it — verified). Consider adding
  `rust-version.workspace = true` to each `[package]` so crates.io
  shows the MSRV.
- One crates.io account with the maintainer rights for the
  `carapace-*` names; token via `CARGO_TOKEN` or `cargo login`.

## 7. GitHub release (human)

- Create the release from the tag `vX.Y.Z`.
- Attach: the release binary (`cara`), the checksums file from step 4,
  the SBOM documents from step 3, and the musl binary if step 2a was
  verified.
- Release notes: the "What Carapace stops" table (generated from the
  escape-test catalog — never hand-edited), any measured numbers **with
  the machine they were measured on** (CLAIMS.md discipline), and the
  audit/deny waiver list from step 1 if any.

## 8. Explicitly NOT automated — the human actions list

The release-dry-run workflow builds, tests, packages, and uploads
artifacts for inspection. It deliberately does **not**:

1. Run or approve `cargo audit` / `cargo deny` (step 1 — human
   judgment on findings and waivers).
2. Create or push the git tag (step 5).
3. Publish anything to crates.io — not even the real `cargo publish`;
   only the `carapace-core` *dry run* runs in CI (step 6).
4. Create the GitHub release or upload its assets (step 7).
5. Update the README status banner, `docs/agent/STATE.md`, and
   `docs/agent/CLAIMS.md` for the release.
6. Provision/announce the security contact (still `TODO(verify)` in
   [SECURITY.md](../SECURITY.md)).
7. Make the release GO/NO-GO decision.

## 9. Post-release verification (human)

On a machine that is not the build machine:

```sh
sha256sum -c cara-vX.Y.Z-x86_64-linux.sha256
./cara doctor
CARA=./cara demo/demo.sh
```

Record the results (machine, kernel, `cara doctor --json` summary) in
[docs/agent/CLAIMS.md](agent/CLAIMS.md) as the release verification row.
