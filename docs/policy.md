# Policy Reference

A policy is a TOML file that says what one run may do. The parser is strict
by construction (see `crates/cara-core/src/policy.rs`):

- **Unknown fields are errors**, at the top level and inside every section.
  Nothing is silently ignored; a typo can never widen permissions.
- **Unknown units and malformed values are errors.** There is no implicit
  fallback to a permissive default.
- Omitted fields inherit from the selected `preset` (`strict` if none).

Status note: policy files, `cara policy check|explain`, filesystem binds and
network modes `none`/`full` are implemented and tested (milestone C5). The
`allowlist` network mode **validates but refuses to run** — see
[Network modes](#network-modes) and ADR-0004.

---

## Using policies from the CLI

```sh
cara policy check policy.toml     # validate; exit 0 = valid, 3 = invalid
cara policy explain policy.toml   # plain-English summary of what it allows
cara run --policy policy.toml -- /usr/bin/python3 script.py
```

`cara run` without `--policy` uses the `strict` preset. `--timeout 30s`
overrides the policy's timeout (explicit flags beat file values).

## Stable exit codes (`cara policy check`, `cara run`)

| Code | Meaning | Source |
|---|---|---|
| 0 | Success (`cara run`: the payload exited on its own with code 0; `policy check`: policy is valid) | `exit_codes::OK` |
| 1 | `cara run`: the run was killed by the supervisor (timeout / output / memory / internal), the payload died by signal, or it exited with code 1 — check the report | `run_ui` |
| 2 | CLI usage error (clap's convention) | `exit_codes::USAGE` |
| 3 | Policy file invalid, or requested configuration impossible (e.g. program path not absolute, bad `--timeout`) | `exit_codes::INVALID_POLICY` |
| 4 | Environment cannot run the requested tier safely (`cara doctor` gate refused the spawn) | `exit_codes::ENV_NOT_READY` |

A payload's own exit code (0–255) is passed through verbatim by `cara run`
when it exits on its own without supervisor intervention. `cara run --json`
prints the full report as JSON on stdout regardless of exit code.

---

## Top level

```toml
preset = "dev"        # optional: "strict" | "dev" | "network-light"
                      # any other string is an error

[limits]     # resource caps
[filesystem] # extra host paths
[network]    # network posture
[runtime]    # informational runtime hint
```

Only these four tables and `preset` exist. `[wombat]`, `limits.memry = ...`
etc. are rejected (fail closed).

## `preset`

Selects the base posture; per-field settings below override it.

| Preset | timeout | memory | cpu | max_processes | disk (/work) | max_output | exec on write | network |
|---|---|---|---|---|---|---|---|---|
| `strict` (default) | 10s | 256 MiB | 100% | 32 | 64 MiB | 1 MiB | no | `none` |
| `dev` | 60s | 1 GiB | 200% | 128 | 512 MiB | 8 MiB | yes | `none` |
| `network-light` | 60s | 1 GiB | 200% | 128 | 512 MiB | 8 MiB | yes | `allowlist` (unimplemented — refuses at run time) |

Preset numbers are computed as 1024-based (MiB/GiB). Note the distinction
with string values below: in a file, `256MB` means 256,000,000 bytes
(decimal), while `256M` means 268,435,456 bytes (binary).

For reference, the library-level default (`SandboxSpec::new` without any
policy) is: timeout 10s, max_output 8 MiB, scratch 64 MiB, memory 256 MiB,
cpu 100%, max_processes 64. The CLI never uses it — `cara run` starts from
the `strict` preset (32 processes, 1 MiB output).

## `[limits]`

| Field | Type | Enforced by |
|---|---|---|
| `memory` | size string | cgroup v2 `memory.max`; `memory.swap.max` forced to 0 (no swap escape). Exceeding it is a kernel OOM kill, reported as `kill_reason = "memory_limit"` |
| `cpu` | percent string | cgroup v2 `cpu.max` — quota per 100 ms period. `100%` = one full core, `200%` = two cores |
| `timeout` | duration string | supervisor wall clock; at the deadline the whole tree is SIGKILLed |
| `max_processes` | integer >= 1 | cgroup v2 `pids.max` — the fork-bomb cap |
| `disk` | size string | size of the writable `/work` (and `/tmp`) tmpfs inside the sandbox; also sets `RLIMIT_FSIZE` (max size of any single file) to the same value |
| `max_output` | size string | byte cap on **captured stdout and stderr, each** (a stream flood is killed as soon as the cap is crossed, via the overflow self-pipe) |

### Size strings

`<number><unit>`, case-insensitive, e.g. `512`, `64K`, `8MiB`, `1GB`.

| Unit | Multiplier |
|---|---|
| *(none)*, `B` | 1 byte |
| `K`, `KiB` | 1024 (binary) |
| `M`, `MiB` | 1024² |
| `G`, `GiB` | 1024³ |
| `KB` | 1000 (decimal) |
| `MB` | 1000² |
| `GB` | 1000³ |

K/M/G are 1024-based like systemd; KB/MB/GB are 1000-based. Anything else
(`8X`, `128QWERTY`) is an error. Negative sizes and overflow are errors.

### Duration strings

Units `ms`, `s`, `m`, `h`; sums are allowed. Bare numbers are errors; zero
is an error.

```
500ms   10s   2m   1h   1m30s (= 90s)
```

### Percent strings

Required `%` suffix, integer 1–10000 (`50%`, `100%`, `200%`). `0%` and
`>10000%` are errors.

## `[filesystem]`

```toml
[filesystem]
read_only     = ["/opt/data"]            # optional
read_write    = ["/home/dev/project"]    # optional
exec_on_write = false                    # optional; default false
```

`exec_on_write` controls whether the payload may `execve` files it wrote into
the writable areas (`/work`, `/tmp`, `/dev/shm`, and every `read_write` bind).
The default is **false**, and it stays false in the `strict` preset: a
payload can create and run *nothing it wrote*, which blocks the classic
write-then-exec staging move (escape test `write_then_exec`). `dev` sets it
to `true` because compile-and-run workflows (`gcc`, `rustc`) need to execute
their own output; `network-light` inherits `dev`.

Set it explicitly when a policy needs it:

```toml
[filesystem]
exec_on_write = true
```

Landlock's writable grant then includes `EXECUTE`; everything else (seccomp,
`no_new_privs`, zero capabilities, cgroups) still applies to the new binary.
See ADR-0007 for the audit trail.

Every listed host path is bind-mounted **at the same absolute path inside
the sandbox**. Validation rules (violations are parse errors):

- Must be **absolute** (`relative/path` is rejected).
- Must be normalized: **no `..` components** (`/home/../etc` is rejected).
- Must not start with `/proc`, `/sys`, `/dev` or `/etc` — those are sandbox
  internals and may not be shadowed.
- `read_write` paths **must already exist on the host** (read-only paths are
  not existence-checked at parse time — a missing read-only path fails the
  run at mount time instead, also fail closed).
- At most **16** extra bind paths are applied per run (excess is silently
  truncated today — keep your list short; this limit is an implementation
  detail of the child's fixed buffers).

What the sandbox always contains, regardless of policy:

| Path | Content | Writable? |
|---|---|---|
| `/usr` | bind of the host `/usr` (read-only remount) — the runtime | no (EROFS) |
| `/bin`, `/lib`, `/lib64` | symlinks into `/usr` (merged-usr layout) | no |
| `/proc` | fresh procfs for the sandbox's own PID namespace | no |
| `/etc` | **minimal sandbox-owned** `/etc/passwd` + `/etc/group` (`root`, `nobody`) — *not* the host's | no (Landlock) |
| `/etc/alternatives` | symlinks recreated from the host **only** when they resolve under `/usr` (e.g. `awk`); regular files are never exposed | no |
| `/etc/java-*-openjdk/security` | read-only bind **only** when an in-tree JVM links to that canonical directory (Debian/Ubuntu OpenJDK layout); the rest of `/etc/java-*` is invisible | no |
| `/dev` | exactly `null`, `zero`, `urandom`, `random`, bind-mounted from the host | device nodes only |
| `/dev/shm` | fresh tmpfs, size = `limits.disk`, for POSIX shm/named semaphores | yes |
| `/work` | fresh tmpfs, size = `limits.disk` — the payload's cwd | yes |
| `/tmp` | directory on the 8 MiB root tmpfs | yes |

Writes are allowed but **execution of written files is denied by default**
(Landlock `RW_ALL_NO_EXEC`); see `exec_on_write` above. The scratch budget is
per mount: `/work` and `/dev/shm` are each capped at `limits.disk`, so the
aggregate writable space can reach roughly `2 × limits.disk + 8 MiB`.

Nothing else from the host is visible: no `/home`, `/root`, `/var`, and no
host `/etc` beyond the two narrow, read-only runtime directories above.
Writes outside the granted paths are denied by Landlock even where a
mount happens to be writable (test: `hardening.rs::landlock_denies_writes_outside_grants`).

## `[network]`

```toml
[network]
mode = "none"              # "none" (default) | "full" | "allowlist"
allow = ["pypi.org"]       # ONLY valid together with mode = "allowlist"
```

| Mode | What happens |
|---|---|
| `none` (default) | The child unshares `CLONE_NEWNET`: an empty network namespace with only a down `lo`. Nothing to dial, nothing to resolve, no host-shared abstract UNIX sockets. seccomp additionally denies `socket`/`connect`/... — two independent layers (ADR-0004) |
| `full` | The payload **shares the host's network namespace** (no `CLONE_NEWNET`) and seccomp allows the socket-family syscalls. The loud opt-in for tools that legitimately need the network. All other isolation is unchanged |
| `allowlist` | Designed in ADR-0004, **not implemented**. Parsing and `policy check` succeed; `cara run` fails closed with an explicit "not implemented" error rather than pretending (test: `cli_run.rs::run_fails_closed_on_unknown_network_mode_in_policy`) |

`allow` given without `mode = "allowlist"` is an error. `mode = "allowlist"`
with an empty `allow` list is what the `network-light` preset produces.

Interim guidance: `none` for anything untrusted; `full` only when you would
have run the code bare anyway.

## `[runtime]`

```toml
[runtime]
language = "python3.12"
```

`language` is informational in v1 — it is carried on the policy and shown in
tooling, but does not change enforcement. The actual runtime is whatever
interpreter you exec (see docs/runtime-guide.md).

---

## Examples

Minimal (equivalent to no policy at all):

```toml
# strict is the default; everything below is also the default
[limits]
memory = "256M"
cpu = "100%"
timeout = "10s"
max_processes = 32
disk = "64M"
max_output = "1M"

[network]
mode = "none"
```

A build task with a writable source directory (note: `M` is binary here —
`1G` = 1 GiB):

```toml
preset = "dev"

[limits]
timeout = "5m"
disk = "1G"

[filesystem]
read_write = ["/home/dev/project"]

[network]
mode = "none"
```

A loud, trusted-network run:

```toml
preset = "dev"

[network]
mode = "full"
```

## Verifying a policy

`cara policy explain` prints exactly what a policy allows — every limit, the
filesystem grants, and the network posture — and ends with the denial rule:

```
Everything not listed here is denied. Unlisted host paths are
invisible; unlisted syscalls return EPERM; unlisted network
destinations are unreachable.
```

When in doubt, explain before you run. It cannot read minds: a policy that
grants read-write on a directory containing secrets grants the payload
access to those secrets (see the threat model's residual risks, §7).
