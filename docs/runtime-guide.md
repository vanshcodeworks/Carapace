# Runtime Guide

How to run any language in the sandbox today. There is no per-language
setup, no image, no recipe directory to maintain: **v1 mounts the host's
`/usr` read-only into every sandbox**, so every interpreter your distro
ships is already inside.

## What the sandbox filesystem gives you

| Path | Content | Writable |
|---|---|---|
| `/usr` | bind of the host `/usr` (read-only) — all interpreters, compilers, libraries | no |
| `/bin`, `/lib`, `/lib64` | symlinks into `/usr` (merged-usr layout; the host must be merged-usr or spawn refuses) | no |
| `/work` | fresh size-capped tmpfs; the payload's working directory | yes |
| `/tmp` | fresh tmpfs, same cap | yes |
| `/etc` | minimal sandbox-owned `passwd`/`group` (`root`, `nobody`) — not the host's | no |
| `/dev` | exactly `null`, `zero`, `urandom`, `random` | device files only |
| `/proc` | fresh procfs for the sandbox's own PID namespace | no |

`/sys` is not mounted at all. No host paths outside `/usr` (and your policy
binds) are visible. Tests that prove this table:
`rootfs.rs::usr_is_read_only`, `work_is_writable_and_capped`,
`etc_is_sandbox_owned_not_host`, `dev_has_only_safe_devices`,
`sys_is_not_mounted`, `host_paths_are_absent`.

## Requirements for a runtime

1. **Absolute path.** Carapace performs no PATH search: `cara run -- python3`
   is rejected by the CLI, `cara run -- /usr/bin/python3` works. Library
   callers should pass absolute paths too — the payload execs from `/work`,
   so a bare name will not find your host interpreter. The seccomp allowlist
   is built for
   "a plain interpreter runtime" — anything that runs as an ordinary user
   process (python, node, perl, ruby, shell, compiled binaries) fits; it is
   not a userspace-emulation environment.
2. **No network unless the policy says so.** Default (`mode = "none"`) is
   an empty network namespace plus a seccomp deny on `socket(2)` — both
   layers tested (`hardening.rs::seccomp_blocks_socket_creation`,
   `supervisor.rs::child_runs_in_fresh_namespaces`). `mode = "full"` shares
   the host network (loud opt-in). `allowlist` fails closed today
   (ADR-0004).
3. **Environment is allowlist-only.** Nothing is inherited: the payload
   sees exactly the variables the caller sets on the spec (or none). In
   practice set at least `PATH` (`/usr/bin:/bin`), and `HOME=/work` for
   interpreters that want a home (Python writes caches there).
4. **The runtime's writable state must fit the scratch.** `/work` + `/tmp`
   tmpfs size = `limits.disk`; caches, `__pycache__`, venvs, build outputs
   all land there (or in a policy-granted read-write host directory).

## Working examples

These are the exact shapes the test suites run.

**POSIX shell** (`supervisor.rs`, `rootfs.rs`, `redteam.rs`):

```sh
cara run -- /bin/sh -c 'echo hello; ls /usr/bin | head'
```

**Python 3** (`rootfs.rs::python3_hello_world`):

```sh
cara run --json -- /usr/bin/python3 -c 'import platform; print(6*7); print(platform.machine())'
```

Library form (what the tests build):

```rust
let spec = SandboxSpec::new("/usr/bin/python3")
    .args(["-c", "import platform; print(6*7)"])
    .env("PATH", "/usr/bin:/bin")
    .env("HOME", "/work")
    .timeout(Duration::from_secs(30));
let mut handle = NativeBackend::new().spawn(&spec)?;
let report = handle.wait()?;   // ExitReport: exit code, output, cpu, peak mem
```

**A build with dependencies on disk** — grant a project directory
read-write (it must exist; paths are absolute; see docs/policy.md for all
validation rules):

```toml
# build.toml
preset = "dev"

[limits]
timeout = "5m"
disk = "1G"

[filesystem]
read_write = ["/home/dev/project"]

[network]
mode = "none"
```

```sh
cara run --policy build.toml -- /usr/bin/python3 /home/dev/project/setup.py build
```

A read-write bind is visible inside the sandbox at the same absolute path,
backed by the real host directory (test:
`cli_run.rs::run_with_read_write_bind_sees_host_dir`).

**Extra read-only data** — for big assets you don't want copied into the
scratch:

```toml
[filesystem]
read_only = ["/opt/models", "/srv/datasets"]
```

Both land at the same paths inside the sandbox, read-only, and Landlock
grants exactly that access. At most 16 extra bind paths are applied per
run (a current implementation limit of the child's fixed buffers).

## Adding a *new* runtime (the general recipe)

You almost never need one — if the interpreter is under `/usr`, it already
works. When something is genuinely missing:

1. Install it under `/usr` (distro package or a `/usr/local` prefix — note
   `/usr/local` lives inside `/usr` on merged-usr systems, so it is
   mounted too).
2. If it needs host data, add a `read_only`/`read_write` policy entry.
3. If it needs specific environment variables, set them explicitly in the
   spec/policy — the allowlist-only env means defaults you take for
   granted (`HOME`, `LC_ALL`, `PYTHONPATH`) do not exist.
4. If a syscall is denied (`EPERM` from an unusual runtime), that is the
   seccomp allowlist doing its job. For *development*, set `CARA_SECCOMP_LOG=1`
   in the parent environment to log-and-allow and read what the runtime
   needs from dmesg; production keeps the strict default. Do not ask for
   the allowlist to be widened for one runtime without a threat-model
   argument — file an issue instead.

Interpreter *zero-days* are a real residual risk (threat model §7): a
malicious `import` chain can do whatever the interpreter can. Prefer
read-only grants, keep `network = "none"` for untrusted code, and treat a
writable `site-packages` as a policy decision, not a convenience.

## What about the `runtimes/` directory and custom rootfs recipes?

The README's `runtimes/` (minimal rootfs recipes per language) is a future
convenience for *minimal* images — not needed for v1, where the host
`/usr` is the runtime. Nothing in the current enforcement path reads it.
