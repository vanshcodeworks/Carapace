# Troubleshooting

**Always start with `cara doctor`.** Every check measures the actual
capability at run time and prints a remedy for what it finds. Remedies are
**printed, never applied**: Carapace does not edit sysctls, kernel parameters
or host policy. The exit code tells you the verdict: 0 = Tier 1 can run,
4 = something required is missing. Use `cara doctor --json` for
machine-readable output. The sections below expand each remedy and cite the
upstream documentation.

```sh
cara doctor
```

---

## cgroup delegation: "cannot move a child process into a delegated cgroup leaf"

**Applies to:** `cara doctor` check `cgroup-delegation`, or
`cara run` failing with a "cgroup limits" error.

Carapace needs to create a cgroup v2 leaf and **move a child process into
it**. Two things break this:

1. WSL2 places `wsl.exe`-launched commands in a root-owned
   `/non-systemd` cgroup *outside* your `user@<uid>.service` slice, and
   `nsdelegate` forbids moving tasks into a delegated subtree from outside
   it.
2. Normal Linux logins (pam_systemd) are already inside the user slice and
   work out of the box.

### Remedy A (no system changes): bridge through the user manager

```sh
systemd-run --user --scope --quiet cara doctor
systemd-run --user --scope --quiet cara run -- /bin/sh -c 'echo hello'
```

This runs `cara` inside `user@<uid>.service`, where the delegated subtree
is writable. Measured overhead of the bridge: **~13 ms** on the reference
environment. The repository's `scripts/check.sh` performs exactly this
bridge automatically when it detects it is outside the user slice.

On WSL2 the equivalent from Windows:

```
wsl -d Ubuntu-24.04 -u dev -- systemd-run --user --scope --quiet bash -lc "cara doctor"
```

### Remedy B (persistent): make sure the user slice exists and is delegated

WSL sessions are not systemd logind sessions by default, so
`user@<uid>.service` (which owns the delegated cgroup subtree) may not
exist or may not stay alive across session churn:

```sh
# keep user@<uid>.service alive
sudo loginctl enable-linger $USER

# delegate all four controllers (default is cpu memory pids; io is optional
# and only unlocks disk I/O limits)
sudo systemctl edit user@.service
```

with the drop-in content:

```ini
[Service]
Delegate=cpu io memory pids
```

then re-login (or `wsl --shutdown` and reopen the distro). `cara doctor`
should now report `cgroup-delegation` OK with controllers
`cpu io memory pids`. Without `io` delegated, everything else still works —
doctor prints a warning and disk I/O limits are simply unavailable.

If controllers are missing entirely, the doctor fails with "delegated
controllers lack: …". Carapace fails closed rather than run without
memory/cpu/pids limits. Upstream: [Control Group APIs and
Delegation](https://systemd.io/CGROUP_DELEGATION/).

## Unprivileged user namespaces denied

**Applies to:** `cara doctor` check `userns` failing.

Rootless sandboxing is impossible without user namespaces; Carapace fails
closed. The doctor identifies which layer denied it and prints the matching
exact remedy. Typical causes:

### AppArmor restriction (Ubuntu 23.10+)

`kernel.apparmor_restrict_unprivileged_userns=1` denies unprivileged user
namespaces to unconfined programs.

```sh
# immediate, system-wide
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

# persistent (per upstream AppArmor wiki)
printf 'kernel.apparmor_restrict_unprivileged_userns=0\n' \
  | sudo tee /etc/sysctl.d/60-apparmor-namespace.conf
sudo sysctl --system        # or reboot
```

Trade-off: this weakens host hardening for **every** unconfined
application. The scoped alternative is an AppArmor profile granting
`allow userns create,` to the `cara` binary only; see the upstream wiki.
Upstream:
[AppArmor unprivileged userns restriction](https://gitlab.com/apparmor/apparmor/-/wikis/unprivileged_userns_restriction).

### Distro sysctl (Debian kernels)

`kernel.unprivileged_userns_clone=0`:

```sh
sudo sysctl -w kernel.unprivileged_userns_clone=1
# persist in /etc/sysctl.d/60-cara-userns.conf, then sudo sysctl --system
```

### Global limit

`user.max_user_namespaces=0` disables user namespaces for the user:

```sh
sudo sysctl -w user.max_user_namespaces=10000
# persist the same line in /etc/sysctl.d/60-cara-userns.conf
```

Upstream for the global limit:
[user namespaces sysctls](https://docs.kernel.org/admin-guide/sysctl/user.html).

In containers, run with a user-namespace-capable runtime (`--security-opt`
equivalents) or the equivalent privileges. There is no fallback mode that
runs without userns.

## cgroup v1 / hybrid, or cgroup v2 not mounted

**Applies to:** `cara doctor` check `cgroup2` failing
("/sys/fs/cgroup is not a cgroup2 mount" or a hybrid hierarchy where v1 owns
required controllers).

Carapace requires the unified (v2) hierarchy for memory/cpu/pids limits.
systemd defaults to it. Check `mount | grep cgroup`.

- Pure v1 or no cgroup2: boot with `systemd.unified_cgroup_hierarchy=1`
  (systemd hosts; edit `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, then
  `sudo update-grub` and reboot) or `cgroup_no_v1=all` (kernel parameter for
  non-systemd hosts).
- Hybrid where cgroup2 has `memory cpu pids`: doctor warns but Tier 1 works;
  the v1 mounts are simply unused by Carapace.
- Hybrid where v1 keeps a required controller out of cgroup2: doctor fails
  and prints the same boot-parameter remedy.

If `/sys/fs/cgroup` is masked in a container, unmask it. No workaround exists
inside Carapace — limits would be unenforceable. Upstream: [Control Group v2
— Linux kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).

## No /dev/kvm — Tier 3 unavailable

`cara doctor` reports KVM as an informational check; Tier 1 and Tier 2 are
unaffected. Tier 3 (microVM, milestone C10) needs hardware virtualization:

- On Windows 11 + WSL2: add to `%UserProfile%\.wslconfig`:
  ```ini
  [wsl2]
  nestedVirtualization=true
  ```
  then `wsl --shutdown`. TODO(verify): whether your host/BIOS exposes
  VT-x/AMD-V to WSL at all.
- On Linux: load `kvm_intel`/`kvm_amd` and ensure your user can open
  `/dev/kvm` (a `kvm` group member).

Tier 3 is not implemented yet regardless; this only matters later.

## Landlock unavailable

**Applies to:** `cara doctor` check `landlock` failing.

Landlock is the second filesystem layer (blocks writes outside grants even
on writable mounts). It needs Linux ≥ 5.13 with
`CONFIG_SECURITY_LANDLOCK=y` and landlock in the LSM list. Check:

```sh
zgrep -E 'CONFIG_(SECURITY_LANDLOCK|LSM)=' /proc/config.gz
# or: cat /sys/kernel/security/lsm
```

The doctor reports the ABI version it measured (reference environment: ABI
v7). Remedy: enable the config / add `landlock` to the `lsm=` boot parameter
and reboot, or use a newer kernel. Carapace fails closed without it.
Upstream: [Landlock: unprivileged access
control](https://docs.kernel.org/userspace-api/landlock.html).

## seccomp-bpf unavailable

**Applies to:** `cara doctor` check `seccomp` failing.

The kernel must be built with `CONFIG_SECCOMP=y` and
`CONFIG_SECCOMP_FILTER=y`; check
`zgrep -E 'CONFIG_SECCOMP(_FILTER)?=' /proc/config.gz`. Boot a kernel with
both enabled. Carapace fails closed without syscall filtering. Upstream:
[Seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html).

## Old kernel: pidfd / close_range missing

Checks `pidfd` (kernel < 5.3) and `close-range` (< 5.9) degrade to
warnings, with documented fallbacks (process-group kill; `/proc/self/fd`
enumeration for fd sanitization) — but the baseline for Tier 1 is
**kernel ≥ 5.10** (development and measurement happened on 6.18), and the
remedy text for both tells you to upgrade. On old kernels expect weaker
supervision guarantees; Landlock (≥ 5.13) is required and has no fallback.
Upstream: [pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html),
[close_range(2)](https://man7.org/linux/man-pages/man2/close_range.2.html).

## "host runtime layout unsupported: /usr/bin/sh missing" (or /usr/lib, /usr/lib64)

Tier 1's runtime recipe bind-mounts the host `/usr` read-only and expects a
**merged-usr** layout. Split-usr systems (separate `/bin`) are rejected
before forking — fail closed, nothing ran.

```sh
# Debian/Ubuntu
sudo apt install usrmerge
sudo reboot
# verify: ls -ld /bin /lib /lib64  (all symlinks into usr/)
```

Other current major distros are already merged. Upstream: [The Case for the
/usr Merge](https://systemd.io/THE_CASE_FOR_THE_USR_MERGE/).

## Leftover `cara-run-*` cgroup leaves

Leaves are removed on every teardown path (asynchronously, with bounded
retries; test: `limits.rs::cgroup_leaves_are_always_removed`). A crash of
the whole supervisor process can, in principle, leave one behind. Inspect
and purge:

```sh
# where am I delegated?
cat /proc/self/cgroup

# list leftover leaves under your user slice
ls /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/ \
   | grep '^cara-run-'

# purge empty leftovers (rmdir only works when the leaf is empty —
# a leaf with live processes means a sandbox is still running)
rmdir /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cara-run-*
```

Stale staging dirs from crashed debug sessions may similarly accumulate
under `$XDG_RUNTIME_DIR` (or `/tmp`): they are created as
`cara-staging.XXXXXX` by `mkdtemp`. They are plain empty directories and
safe to remove when no run is active.

## WSL2 build quirk: slow builds on /mnt/*

The repository may live on a Windows mount (`/mnt/p/...`); building there
is dominated by DrvFs I/O. `scripts/check.sh` points
`CARGO_TARGET_DIR` at `$HOME/.cache/carapace-target` (ext4) automatically.

## JVM: "Error loading java.security file"

**Applies to:** `java`/`javac` inside the sandbox on Debian/Ubuntu.

OpenJDK packages its master security config outside `/usr`:
`/usr/lib/jvm/java-21-openjdk-amd64/conf/security/java.security` is a
symlink to `/etc/java-21-openjdk/security/java.security`. Carapace
recreates the alternatives chain but does not expose host `/etc`; it
therefore binds **only** the canonical `security` directory that an
in-tree JVM references, read-only (ADR-0007 section 8). This is automatic;
no policy setting enables it.

If the JVM still cannot find the file, the host layout differs from the
tested Debian/Ubuntu one (for example a JDK installed under `/opt`, or a
vendor that keeps the config somewhere other than `/etc` or the JVM's
`conf/security`). Check:

```sh
readlink -f /usr/lib/jvm/*/conf/security/java.security
```

- Target under `/usr`: no bind is needed; the file is already in the
  read-only `/usr` mount. If it still fails, the failure is elsewhere.
- Target under `/etc/.../security`: the planner should expose it. Include
  the `readlink` output in a bug report.
- Target elsewhere (`/opt`, a home directory): the sandbox deliberately
  does not expose it. Move the JDK into `/usr` or file an issue with the
  layout; do not add a broad `/etc` bind.

Only Ubuntu 24.04 OpenJDK 21 has been measured (UNVERIFIED R2.12).

## Where to look next

- Exit codes: docs/policy.md (stable table).
- What each isolation layer does: docs/architecture.md.
- Environment the reference numbers come from: docs/agent/ENV.md.
- Still stuck: run `cara doctor --json` and include its output in your
  issue.
