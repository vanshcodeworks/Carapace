# Troubleshooting

**Always start with `cara doctor`.** Every check measures the actual
capability at run time and prints a remedy for what it finds. The exit code
tells you the verdict: 0 = Tier 1 can run, 4 = something required is
missing. Use `cara doctor --json` for machine-readable output. The sections
below expand each remedy.

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
memory/cpu/pids limits.

## Unprivileged user namespaces denied

**Applies to:** `cara doctor` check `userns` failing.

Rootless sandboxing is impossible without user namespaces; Carapace fails
closed. Typical on hardened distros and CI containers.

```sh
# Debian/Ubuntu (legacy toggle)
sudo sysctl kernel.unprivileged_userns_clone=1

# Ubuntu 23.10+ (AppArmor restriction)
sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0
```

To make either persistent, write it to `/etc/sysctl.d/`. In containers, run
with a user-namespace-capable runtime (`--security-opt` equivalents) or the
equivalent privileges. There is no fallback mode that runs without userns.

## cgroup v2 not mounted

**Applies to:** `cara doctor` check `cgroup2` failing
("/sys/fs/cgroup is not a cgroup2 mount").

Carapace requires the unified (v2) hierarchy for memory/cpu/pids limits.
systemd defaults to it. Check `mount | grep cgroup`; if you see cgroup v1
controllers, boot with `systemd.unified_cgroup_hierarchy=1`. If `/sys/fs/cgroup`
is masked in a container, unmask it. No workaround exists inside Carapace —
limits would be unenforceable.

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
`CONFIG_SECURITY_LANDLOCK=y` and landlock in the LSM list. The doctor
reports the ABI version it measured (reference environment: ABI v7).
Remedy: a newer kernel. Carapace fails closed without it.

## Old kernel: pidfd / close_range missing

Checks `pidfd` (kernel < 5.3) and `close-range` (< 5.9) degrade to
warnings, with documented fallbacks (process-group kill; `/proc/self/fd`
enumeration for fd sanitization) — but the baseline for Tier 1 is
**kernel ≥ 5.10** (development and measurement happened on 6.18), and the
remedy text for both tells you to upgrade. On old kernels expect weaker
supervision guarantees; Landlock (≥ 5.13) is required and has no fallback.
Remedy: upgrade.

## "host runtime layout unsupported: /usr/bin/sh missing" (or /usr/lib, /usr/lib64)

Tier 1's runtime recipe bind-mounts the host `/usr` read-only and expects a
**merged-usr** layout. Split-usr systems (separate `/bin`) are rejected
before forking — fail closed, nothing ran. Remedy: use a merged-usr distro
(all current major distros are).

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

## Where to look next

- Exit codes: docs/policy.md (stable table).
- What each isolation layer does: docs/architecture.md.
- Environment the reference numbers come from: docs/agent/ENV.md.
- Still stuck: run `cara doctor --json` and include its output in your
  issue.
