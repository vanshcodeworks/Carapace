# Development Environment (docs/agent/ENV.md)

The reference dev environment for this repository. Everything below was
measured or performed by the agent on 2026-10-24/25 (and 2026-10-27 for
the Debian userland measurement and musl build) and is the basis for
`cara doctor`'s checks and the strict tests (`CARA_STRICT_ENV_TESTS=1`).

## Host

| Item | Value |
|---|---|
| Windows | 10.0.26200 (Windows 11) |
| WSL | 3.0.3.0 |
| WSL kernel | 6.18.54.1-1 (6.18.54.1-microsoft-standard-WSL2 inside the distro) |
| Linux distro | Ubuntu 24.04.5 LTS (installed via `wsl --install Ubuntu-24.04 --no-launch`) |
| init | systemd 255 (255.4-1ubuntu8.17) as PID 1 |
| Dev user | `dev` (uid 1000), created manually; passwordless sudo via /etc/sudoers.d/dev |
| Rust | 1.99.1 stable (rustup, minimal profile + clippy + rustfmt) |
| Go | 1.22.2 (`golang-go`, Ubuntu package) |
| OpenJDK | 21.0.12.1 (`openjdk-21-jdk-headless`, Ubuntu package) |

The repository lives on the Windows mount (`/mnt/p/Carapace` in WSL). Builds
run inside WSL with `CARGO_TARGET_DIR=$HOME/.cache/carapace-target` (ext4) so
artifacts never touch the slow DrvFs mount — see `scripts/check.sh`.

## Measured capabilities

| Capability | Status | How measured |
|---|---|---|
| Unprivileged user namespaces | ✅ works | forked child `unshare(CLONE_NEWUSER)` as uid 1000 → success |
| cgroup v2 | ✅ unified hierarchy at /sys/fs/cgroup (`nsdelegate`) | `statfs` magic 0x63677270 |
| cgroup delegation for `dev` | ✅ cpu, io, memory, pids | writable probe at `user.slice/user-1000.slice/user@1000.service` |
| Landlock | ✅ ABI v7 | `landlock_create_ruleset(NULL,0,VERSION)` → 7 |
| Landlock in kernel config | ✅ CONFIG_SECURITY_LANDLOCK=y, first in CONFIG_LSM | /proc/config.gz |
| seccomp-bpf | ✅ | `seccomp(SECCOMP_GET_ACTION_AVAIL, 0, &KILL_PROCESS)` → 0 |
| pidfd_open | ✅ (kernel ≥ 5.3) | `pidfd_open(getpid(),0)` → fd |
| close_range | ✅ (kernel ≥ 5.9) | `close_range(4,3,0)` → EINVAL |
| io_uring | ✅ compiled in (CONFIG_IO_URING=y) | /proc/config.gz — seccomp stance: **deny by default** (see ADR when written) |
| KVM | ❌ no /dev/kvm | Tier 3 (microVM) not implementable here; remedy below |
| AppArmor | off (`/sys/module/apparmor/parameters/enabled` = N) | informational |

## System changes made by the agent (all inside the disposable WSL distro)

1. `wsl --install Ubuntu-24.04 --no-launch` — the distro itself.
2. rustup nightly (profile minimal, for cargo-fuzz); `cargo install
   cargo-fuzz --locked`; `cargo install cargo-audit cargo-deny --locked`
   (P0, cycle 12).
3. apt: `nodejs npm` (P2 runtime matrix, cycle 13); `golang-go
   openjdk-21-jdk-headless` (P2 Go/JVM columns, cycle 14).
4. apt: `build-essential curl git pkg-config libseccomp-dev libseccomp2
   ca-certificates uidmap fuse3`.
5. rustup for user `dev` (stable toolchain).
6. `/etc/sudoers.d/dev` — `dev ALL=(ALL) NOPASSWD:ALL` (dev convenience only).
7. `/etc/systemd/system/user@.service.d/delegate.conf` — `Delegate=cpu memory pids io`
   (adds io delegation; default user slices delegate cpu memory pids only).
8. `loginctl enable-linger dev` — keeps `user@1000.service` (and its delegated
   cgroup subtree) alive across WSL session churn.

Nothing outside the WSL distro and the repository directory was modified.
The `.wsl/` scratch directory in the repo root holds probe scripts and is
gitignored.

## Verified syscall constants (x86_64, from Ubuntu 6.8 linux-libc-dev headers + empirical C probes on this kernel)

| Constant | Value |
|---|---|
| SYS_landlock_create_ruleset | 444 |
| SYS_seccomp / SECCOMP_GET_ACTION_AVAIL / SECCOMP_RET_KILL_PROCESS | 317 / 2 / 0x80000000 |
| SYS_pidfd_open | 434 |
| SYS_close_range / CLOSE_RANGE_UNSHARE | 436 / 2 |
| LANDLOCK_CREATE_RULESET_VERSION | 1 (1U << 0) |
| CGROUP2_SUPER_MAGIC | 0x63677270 |

## Remedies for missing capabilities (what `cara doctor` prints)

- **KVM absent (Tier 3)**: on Windows 11, `%UserProfile%\.wslconfig` with
  `[wsl2]` section and `nestedVirtualization=true`, then `wsl --shutdown`.
  TODO(verify): whether this host/BIOS supports it. Tier 1/2 unaffected.
- **No cgroup delegation** (typical WSL/SSH): `sudo loginctl enable-linger $USER`
  plus the `user@.service` drop-in above, then re-login. Exact copy-paste
  remedy lives in `cara-native` `check_delegation`.
- **Unprivileged userns denied** (typical CI containers, hardened distros):
  `sysctl kernel.unprivileged_userns_clone=1` (Debian/Ubuntu),
  `kernel.apparmor_restrict_unprivileged_userns=0` (Ubuntu 23.10+), or run
  inside a userns-capable environment. Carapace fails closed without it.

## Build/check entry point

From the repository root **inside WSL**:

```sh
bash scripts/check.sh   # fmt --check + clippy -D warnings + test --workspace + runtime matrix
```

From the Windows side, a quick single command:

```
wsl -d Ubuntu-24.04 -u dev -- bash -lc "bash /mnt/p/Carapace/scripts/check.sh"
```

## Quirks learned

- Git-Bash → wsl.exe mangles shell variables containing `=` + paths; scripts
  are written to files and executed instead (probe scripts in `.wsl/`).
- WSL sessions are not systemd logind sessions by default; without lingering,
  `user@1000.service` and its delegated cgroup subtree may not exist when
  tests run — lingering fixes this.
- `/proc/config.gz` is available on the WSL kernel — doctor and docs use it
  for kernel-config claims.

## Alternate-userland measurement (cycle 15 — not a support claim)

A Debian 12.15 (bookworm) `minbase` userland was bootstrapped with
`debootstrap` at `/srv/debian-bookworm` and exercised under the **same**
WSL2 kernel (6.18.54.1). This tests the runtime recipe against a different
libc/userland; it is not a different-kernel test and not a claim that
Debian is supported.

- The sandbox binary was the static musl build of `carapace-cli` from this
  tree (`x86_64-unknown-linux-musl`), because the glibc build needs
  glibc 2.39 and bookworm ships 2.36.
- A plain `chroot` cannot be used: `unshare(2)` returns `EPERM` when the
  caller's root directory is not the mount namespace's root (documented in
  `unshare(2)`), so `CLONE_NEWUSER` fails inside any chroot — even an empty
  one. The test therefore enters a private mount namespace as root,
  `--rbind`s the Debian tree (recursive bind so `/proc`, `/sys`, `/dev`
  keep their nested mounts), `pivot_root`s into it, and drops to uid 1000
  with `setpriv`. Script: `.wsl/debian-pivot-test.sh`.
- Result: `cara doctor` → **READY** (userns, cgroup v2 + delegation,
  Landlock ABI 7, seccomp, merged-usr layout, systemd init). `cara run`
  executed `/bin/sh` (dash) and `/usr/bin/python3` successfully
  (`42`); `/etc/debian_version` is correctly absent inside the sandbox
  (sandbox-owned `/etc`).
- Debian bookworm ships an **empty** `/usr/lib64` (with `/lib64 ->
  usr/lib64`), so the host-layout gate accepts it; the earlier suspicion
  that Debian lacks this path was wrong.
- Caveats: `debootstrap` could not verify Release signatures (the host
  keyring package was absent), so this chroot is not a trusted artifact;
  only one Debian release was tested; Fedora/Arch/Alpine, other kernels,
  aarch64, non-systemd and real non-merged-/usr hosts remain unmeasured.
- `systemd-run --user --scope` returned 0 even when `cara doctor` exited
  nonzero in this harness; readiness above was read from the printed
  verdict. The CLI exit-code contract is covered by `tests/doctor_cli.rs`.
