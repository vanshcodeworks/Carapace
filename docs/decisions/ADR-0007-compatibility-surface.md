# ADR-0007: Compatibility surface audit — every concession, its risk, its test

Date: 2026-10-27 · Status: accepted · Milestone: P1 (hardening) · Supersedes nothing

## Context

The P2 runtime matrix (15/15 on the reference env) forced a series of
compatibility changes: each one made a real runtime work, and each one
widened the sandbox by some amount. "It made Python work" is not a security
argument. This ADR audits every such change from the last cycle, states the
capability actually gained, the risk if left unrestricted, and the decision
(keep with a narrowing, keep as-is with justification, or remove). It also
records the new `exec_on_write` policy field, which turns the last cycle's
blanket `EXECUTE` grant on writable areas into an explicit opt-in that is
off by default and off in `strict`.

Rules applied throughout:

1. A concession must buy a capability that ordinary payloads need, not one
   that only an attacker wants.
2. A concession must be the narrowest form that works: prefer read-only
   over read-write, symlinks over binds, argument-free syscalls over
   general ones.
3. Every concession keeps at least one independent enforcement layer
   (namespace, Landlock, seccomp, rlimit, cgroup) intact.
4. Every claim below names the test that proves it.

## Audit table

| # | Surface | Capability gained | Risk if unrestricted | Decision | Proof |
|---|---|---|---|---|---|
| 1 | `/etc/alternatives` | Debian/Ubuntu alternatives resolve (`awk → gawk`, etc.) | Host directory content (regular files, symlinks out of `/usr`) exposed read-only | **Narrowed**: recreate only symlinks whose canonical target is under `/usr`; no bind mount | `alternatives_planner_exposes_only_usr_symlinks`, `etc_alternatives_work_when_host_has_them` |
| 2 | `/dev/shm` tmpfs | POSIX shm + named semaphores; Python `multiprocessing` | Shared memory as an intra-sandbox channel; memory/disk consumption | **Keep**, size-capped, fresh per mount namespace, never the host's | `dev_shm_is_writable`, `python_multiprocessing_semaphores` |
| 3 | `getpgrp(2)` | bash job-control setup at pidns init | None identified: no arguments, reads caller's own pgid | **Keep** (allowlisted) | runtime matrix `bash-*`; `seccomp_profile` unit tests |
| 4 | read-only xattr family | `ls -l` POSIX-ACL queries; coreutils works | Metadata disclosure on files already visible; no mutation | **Keep read-only**; all `setxattr`/`removexattr` stay denied | `base_profile_compiles_and_is_sized_sanely`; runtime matrix `bash-find-grep` |
| 5 | `PATH`/`HOME` defaults | runtimes find helpers; `$HOME` is writable | Predictable env, not host-inherited; no host paths | **Keep**, documented defaults, overridable by policy only | `run_provides_default_path_and_home`, `to_spec_maps_everything` |
| 6 | `clone3 → ENOSYS` | glibc/musl fall back to filtered `clone(2)`; threads work | None: `clone3` never executes; fallback keeps `CLONE_NEW*` filtering | **Keep**, documented as an ABI contract | `filter_semantics_interpreted`, `seccomp_blocks_clone_with_namespace_flags` |
| 7 | `exec_on_write` | Compile-and-run workflows (`gcc`, `rustc`) | Payload can execute code it just wrote; write-then-exec staging | **New explicit field, default `false`, `false` in `strict`**; `dev`/explicit opt-in only | `write_then_exec`, `write_then_exec_allowed_when_spec_opts_in` |
| 8 | OpenJDK `/etc/.../security` | JVM starts on Debian/Ubuntu (config is packaged outside `/usr`) | Read-only exposure of world-readable crypto policy; no secrets, no mutation | **Narrowed**: bind only the canonical `security` directory that an in-tree JVM links to; never `/etc/java-*` as a whole | `security_planner_exposes_only_referenced_etc_security_dirs`, matrix `jvm-compile-run` |

## 1. `/etc/alternatives`: bind mount → recreated symlinks

**Before (P2):** the whole host `/etc/alternatives` directory was
bind-mounted read-only. That directory is not just symlinks: Ubuntu 24.04
ships `/etc/alternatives/README` as a regular file, and the bind exposed it
verbatim inside the sandbox. Any future regular file or symlink pointing
outside `/usr` would be exposed the same way.

**Capability that matters:** `/usr/bin/awk` on Debian/Ubuntu is a symlink to
`/etc/alternatives/awk`, which points to `/usr/bin/gawk` (or `mawk`). Without
the middle link, `awk` is broken even though `/usr` is mounted.

**Now:** the parent planner (`plan_alternatives`) reads the host directory
once, keeps only entries whose `canonicalize` result is a real path under
`/usr`, and recreates each as a symlink with that canonical target. Regular
files, dangling links, and links resolving outside `/usr` are dropped. The
child creates them inside the sandbox's own `/etc/alternatives`; nothing is
bind-mounted, so the host inode never enters the sandbox.

**Residual risk:** a `/usr`-resident binary is exposed read-only, but `/usr`
is already mounted read-only, so no new object is reachable. The planner runs
on the supervisor side (trusted), not in the sandbox. Non-Debian hosts yield
an empty list, which is not an error (there is nothing to reproduce).

**Test evidence:** the planner unit test creates symlinks to `/usr/bin/sh`,
a relative `../../usr/bin/sh`, `/etc/passwd`, a dangling target, and a
regular file. Only the two `/usr`-resolving symlinks survive, and every
retained target starts with `/usr/`. The rootfs integration test proves
`awk` still runs and that a host `README` is not visible when present.

## 2. `/dev/shm`: fresh, size-capped tmpfs

**Capability gained:** POSIX shared memory and named semaphores. Python's
`multiprocessing` (Pool/Lock/Queue) calls `sem_open(3)`, which lives in
`/dev/shm`; without it the matrix failed with `FileNotFoundError`.

**Narrowing already applied:** the mount is a new tmpfs in the sandbox's
private mount namespace (`MS_NOSUID | MS_NODEV`), with `size=` equal to
`limits.disk` (`scratch_bytes`). It is never the host's `/dev/shm`; it
disappears with the namespace; it cannot be reached from another sandbox.

**Residual risk, stated honestly:** `/work` and `/dev/shm` are each capped
at `limits.disk`, and `/tmp` lives on the 8 MiB root tmpfs. The *aggregate*
writable budget can therefore reach roughly `2 × limits.disk + 8 MiB`, not
`limits.disk`. This was already true before the ADR; it is now documented
rather than implied. A global budget needs a shared tmpfs or cgroup-level
accounting; that is a follow-up, not a reason to break `multiprocessing`.

**Test evidence:** byte round-trip (`dev_shm_is_writable`) and a real
`multiprocessing` run with semaphores (`python_multiprocessing_semaphores`).
Disk-filler behavior is capped by the tmpfs size and the `RLIMIT_FSIZE`
per-file limit.

## 3. `getpgrp(2)`: allowed

`bash` as pidns init calls `getpgrp` during job-control setup. The syscall
takes no arguments and returns the caller's own process-group ID; it creates,
modifies, or discloses nothing outside the process. There is no meaningful
attack surface to narrow. It is allowlisted next to `getpid`/`getppid`/
`gettid`. The general syscall allowlist remains default-deny and
`dangerous_syscalls_are_not_allowed` still rejects namespace, ptrace, bpf,
mount, keyring, and socket families.

## 4. Read-only xattr family: allowed, mutation stays denied

**Capability gained:** `ls -l` asks for `system.posix_acl_access` on every
file argument; denying `getxattr` made coreutils report `EPERM` even though
`stat` succeeded.

**Exactly what is allowed:** `getxattr`, `lgetxattr`, `fgetxattr`,
`listxattr`, `llistxattr`, `flistxattr`. **Not allowed:** `setxattr`,
`lsetxattr`, `fsetxattr`, `removexattr`, `lremovexattr`, `fremovexattr`.

**Risk:** read-only metadata disclosure on paths the payload can already
read (`/usr`, `/proc`, `/etc`, `/work`). The kernel enforces its normal
permission and user-namespace rules; `security.*` and `trusted.*` remain
governed by the kernel's xattr policy. Mutation would be a persistence and
integrity surface, which is why every setter/remover stays denied.

## 5. `PATH` and `HOME` defaults

When a policy does not set these, `Policy::to_spec` materializes
`PATH=/usr/local/sbin:...:/bin` and `HOME=/work`. Nothing is inherited from
the supervisor's environment; the child env is still an allowlist by
construction.

- `PATH` only names directories inside the read-only `/usr` bind. A binary
  there was already reachable by absolute path; the default changes
  convenience, not reachability. It does mean `/usr/local/*` is preferred if
  the host has it — the same trust decision as mounting the host `/usr`.
- `HOME=/work` points at writable scratch, so tools that write dotfiles do
  not fail. It deliberately does **not** expose the host home directory.

Both are overridable by an explicit `[environment]` entry; an explicit value
wins. Tests: `run_provides_default_path_and_home` (real sandbox) and
`to_spec_maps_everything` (policy mapping).

## 6. `clone3 → ENOSYS`

The classic-BPF filter cannot dereference `clone3`'s flags pointer, so the
only sound choices are "deny" or "deny in a way libc understands." Returning
`EPERM` broke every thread-creating runtime: glibc and musl fall back to
`clone(2)` **only on `ENOSYS`**. The filter now returns `ENOSYS` before the
allowlist chain; the fallback `clone(2)` path is still inspected for
`CLONE_NEW*` flags and returns `EPERM` when any are present.

**Security argument:** the syscall never executes; no kernel code path for
`clone3` is reachable from the payload. A program that calls `clone3`
directly receives "not implemented" and cannot use it to create a
namespace. The alternative — allowing `clone3` — would hand the kernel a
pointer to flags the filter cannot inspect. This is strictly safer than
allowing it and strictly more compatible than `EPERM`.

**Test evidence:** the BPF mini-interpreter asserts the exact `ENOSYS`
return for `clone3`, the arch check kill, and every prior branch
(`filter_semantics_interpreted`); the real sandbox test proves
`clone(CLONE_NEWUSER|...)` is still denied
(`seccomp_blocks_clone_with_namespace_flags`); the matrix proves Python and
Node threads work.

## 7. `exec_on_write`: the one genuinely new policy decision

**What changed:** Landlock's writable grants (`/work`, `/tmp`, `/dev/shm`,
and every read-write bind) previously included `EXECUTE`. That was added
during P2 so `gcc`/`rustc` could run the binary they had just written. It
also meant every payload could stage an executable in scratch and run it.

**Why that matters:** the sandbox's own controls still apply to the staged
binary (`no_new_privs`, zero capabilities, seccomp, Landlock, cgroups), so
this is not a privilege boundary by itself. But it removes a defense-in-depth
layer: write-then-exec is the standard shape of dropper/persistence
behavior, and code written by the payload should not become runnable merely
because the payload asked for scratch space. The default posture should not
concede it to every run.

**Decision:**

- `SandboxSpec::exec_on_write: bool`, default `false`.
- `Policy::exec_on_write`, TOML `[filesystem] exec_on_write`, default
  `false`; `strict` keeps `false`; `dev` sets `true` (compile-and-run is the
  documented dev workflow); `network-light` inherits `dev`.
- Landlock uses `RW_ALL` when true and `RW_ALL_NO_EXEC` when false. The
  no-exec mask is exactly `RW_ALL & !EXECUTE`.
- `cara policy explain` prints which posture is in force in both directions,
  so a reader cannot miss the denial or the grant.

**Tests:** the catalog entry `write_then_exec` writes and `chmod +x`es a
script in `/work`, runs it, and asserts the marker never appears and
`execve` fails with `EACCES`/`rc=126`. The positive control
`write_then_exec_allowed_when_spec_opts_in` runs the same payload with
`exec_on_write(true)` and asserts the marker appears — proving the denial is
the policy field, not an unrelated failure. The runtime matrix uses
`preset = "dev"` so `gcc-compile-run` and `rust-binary` keep passing.

## 8. OpenJDK `security` config: one referenced directory, read-only

**Before:** the runtime matrix had no JVM column. When one was added,
OpenJDK 21 failed immediately with `InternalError: Error loading
java.security file`: Debian/Ubuntu packages
`/usr/lib/jvm/java-21-openjdk-amd64/conf/security/java.security` as a
symlink to `/etc/java-21-openjdk/security/java.security`, and the sandbox
does not expose host `/etc`.

**Capability gained:** the JVM can start at all. This is not an optional
convenience: every Java program loads the master security properties file.

**Narrowing:** `plan_security_configs` scans the JVM tree that is already
mounted read-only (`/usr/lib/jvm/*/conf/security/java.security`), resolves
each link, and keeps it only if the canonical target is under `/etc` and its
parent is a directory named `security`. Only that canonical directory is
bind-mounted read-only. Consequences:

- No `/etc/java-*` directory is exposed wholesale; `jvm-amd64.cfg`,
  `net.properties`, `management/*`, `logging.properties` and the rest stay
  invisible.
- A host with no JVM links gets an empty list; a JVM whose config lives
  under `/usr` (the Fedora/Arch layout) needs no bind at all.
- Regular files, dangling links and links resolving outside `/etc` are
  dropped by the planner (unit-tested).
- The mount is read-only and Landlock grants only read access; the payload
  cannot modify the host files. The exposed files are world-readable crypto
  policy, not credentials.

**Test evidence:**
`security_planner_exposes_only_referenced_etc_security_dirs` covers the
positive case plus a `/usr` target, a regular file and a dangling link;
`jvm-compile-run` compiles and runs a threaded Java program through the
real sandbox on the reference env.

## Consequences

- The strict posture is now strictly stronger than the P2 posture: no
  execute from writable locations, no host `/etc/alternatives` inode, and
  the same read-only xattr/`getpgrp` surface with mutation still denied.
- The only host `/etc` content besides recreated alternatives symlinks is
  the OpenJDK `security` directory that an in-tree JVM actually references;
  it is mounted read-only and nothing else under `/etc/java-*` is visible.
- Compile-and-run is a one-line opt-in (`preset = "dev"` or
  `[filesystem] exec_on_write = true`); the docs state the trade-off next to
  the setting.
- The aggregate scratch budget (`2 × limits.disk + 8 MiB`) is documented;
  a single global cap remains a follow-up.
- Re-trigger: if a runtime needed by the matrix cannot work without a
  broader xattr, alternatives or `/etc` concession, this ADR must be amended
  with a new row and a test — not silently widened in code.
