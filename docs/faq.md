# FAQ

## Is this safe?

Carapace is **defense in depth**, not an impenetrable boundary. Tier 1 runs
untrusted code inside user/pid/mount/net/ipc/uts/cgroup namespaces with
cgroup v2 limits, a default-deny seccomp allowlist, Landlock filesystem
grants, zero capabilities and `no_new_privs` — each mechanism verified by a
named test (see docs/agent/CLAIMS.md for the full claim → test ledger).

What Tier 1 explicitly does **not** promise: protection against a Linux
kernel 0-day/1-day exploit. All namespaces share the host kernel; a payload
that exploits the kernel from inside can escape. seccomp and Landlock
reduce the attack surface (the payload cannot simply invoke the interesting
syscalls), but that is mitigation, not a boundary. That is what Tier 2
(Wasm, no shared kernel syscalls) and Tier 3 (microVM, separate kernel) are
for. The honest, complete picture is docs/threat-model.md.

## Does it need root?

No. Carapace is rootless end to end: the sandbox runs in a user namespace
where the payload maps to "root" only over namespaced resources, all
capabilities are dropped before exec, and cgroup limits are written into
the systemd-delegated user slice. The payload's "root" cannot reach the
host (tests: `hardening.rs::no_new_privs_and_zero_capabilities`,
`supervisor.rs::child_runs_in_fresh_namespaces`). Some *environments* need
one-time admin setup (cgroup delegation drop-in, sysctls) — see
docs/troubleshooting.md — but `cara` itself never runs as root.

## Does it need Docker or a daemon?

No. Carapace is a single binary. There is no daemon, no container runtime,
no image store: each run builds a private root filesystem from the host's
own `/usr` inside namespaces and tears it down with the run. The only
system service involved is systemd's user manager, which owns the cgroup
subtree your limits are written into (standard on any Linux login).

## Does it work on WSL2?

Yes — that is the primary development environment (Ubuntu 24.04 on WSL2,
kernel 6.18). The one WSL-specific quirk: `wsl.exe`-launched commands sit
outside the systemd user slice, where cgroup attachment is denied.
`scripts/check.sh` bridges automatically via
`systemd-run --user --scope --quiet` (~13 ms overhead); for your own
commands, see docs/troubleshooting.md (Remedy A/B).

## Why isn't allowlist networking implemented?

Because a half-working allowlist is worse than none. The policy format
accepts `mode = "allowlist"` (and validates it), but running it **fails
closed** with an explicit "not implemented" error (ADR-0004). The candidate
designs — veth + nftables (needs CAP_NET_ADMIN, conflicts with
"no daemon, no root") and a userspace proxy (interception of arbitrary
programs is the hard part; `SECCOMP_RET_USER_NOTIF` is the most promising
hook) — are to be decided by measurement in a later milestone. DNS-level
filtering alone was rejected: it is bypassed by direct IPs. Until then:
`none` for anything untrusted, `full` only when you would run the code bare
anyway.

## Which kernels work?

Baseline **Linux ≥ 5.10**; developed and measured on 6.18 (WSL2). The
mechanisms and their minimums: pidfd (5.3), close_range (5.9), Landlock
(5.13, ABI-probed at run time — the reference environment has ABI v7),
cgroup v2 unified hierarchy, seccomp-bpf. `cara doctor` measures every one
of these on your actual kernel and refuses to run code when a required
piece is missing. Side channels (Spectre-class) and hardware attacks are
out of scope for v1.

## What languages can it run?

Anything whose interpreter lives under `/usr`: the sandbox bind-mounts the
host `/usr` read-only, so `/bin/sh`, `/usr/bin/python3`, `/usr/bin/perl`,
`node`, `gcc`-built binaries — whatever your distro ships — work without
any per-language setup (docs/runtime-guide.md). Requirements: the program
path must be absolute (Carapace does no PATH search), the environment is
allowlist-only, and network access requires an explicit policy. The test
suites exercise POSIX shell and Python 3 end to end
(`rootfs.rs::python3_hello_world`, `hardening.rs::normal_python_still_works`).

## What does the payload see?

A minimal root: read-only `/usr` (the runtime), fresh `/proc` showing only
its own process tree, a sandbox-owned minimal `/etc`, four safe device
nodes in `/dev` (`null`, `zero`, `urandom`, `random`), a writable
size-capped `/work` (its cwd) and `/tmp`. No host `/home`, `/root`, `/var`,
no host users, no `/sys`. Host paths appear only if the policy lists them
(read-only or read-write). Verified by the rootfs suite, e.g.
`rootfs.rs::host_paths_are_absent`, `etc_is_sandbox_owned_not_host`,
`dev_has_only_safe_devices`.

## What happens when a limit is hit?

The tree is killed and the reason is reported: `timeout` (wall clock),
`output_overflow` (stdout or stderr exceeded its cap — detected in
milliseconds via an overflow self-pipe, not at the deadline),
`memory_limit` (kernel OOM kill at `memory.max`, swap disabled). Process
count is capped by `pids.max`, so fork bombs die at the cap instead of
taking the machine down. See docs/policy.md for the exact fields and
`cara run --json` for the machine-readable report.

## How fast is it?

Cold start (full stack: 7 namespaces, rootfs + pivot_root, cgroup attach,
Landlock, seccomp, exec) measured on the reference dev machine (WSL2,
kernel 6.18.54.1, cycle 6, n=100): `/bin/true` median 6.7 ms (p95 9.3 ms),
`/bin/sh` median 6.4 ms, `python3 -c pass` median 24.9 ms. A zygote pool
for warm starts is designed (ADR-0005) and lands with milestone C8 — not
built yet.

## How do I know a security claim is real?

Every public claim maps to a named test in docs/agent/CLAIMS.md; the rule
in this repository is that a claim without a test is a bug. The hostile
payload catalog (cara-escape-tests) grows with every red-team cycle, and
the "What Carapace stops" table is generated from those tests so the docs
cannot drift from reality. Anything not yet proven is marked `TODO(test)`
and named as such.

## Where do I report a security issue?

See SECURITY.md — privately, please, not as a GitHub issue.
