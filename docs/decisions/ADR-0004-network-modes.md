# ADR-0004: Network modes

Date: 2026-10-25 · Status: accepted (all three modes implemented and tested) · Milestone: C5

## Context
Policies name three network postures: `none` (default), `full`, and
`allowlist`. The sandbox must make each posture mean exactly what it says,
rootless, without a daemon.

## Decision

### `mode = "none"` (default; always the fallback)
The child unshares `CLONE_NEWNET`: an empty network namespace with only a
down `lo`. There is nothing to dial, nothing to resolve, no abstract
UNIX-socket namespace shared with the host (abstract sockets are
per-netns). seccomp additionally denies the socket family — a second,
independent layer.

### `mode = "full"`
Stage-1's `unshare` simply omits `CLONE_NEWNET`, so the payload shares the
host's network namespace, and the seccomp profile adds the socket-family
allowlist (connect/bind/listen/send/recv/…). This is the loud opt-in for
tools that legitimately need network access. Everything else (mounts,
Landlock, cgroups, no namespace creation) stays enforced.

### `mode = "allowlist"` - shipped via seccomp user notification
This mode uses the seccomp user-notification hook (option 2 below). The
filter allows the normal socket syscalls and returns
`SECCOMP_RET_USER_NOTIF` for `connect(2)` only. Stage-2 installs the
listener with `SECCOMP_FILTER_FLAG_NEW_LISTENER` and passes the fd to
stage-1 over a CLOEXEC `AF_UNIX` socketpair before exec. Stage-1 is a
parent of the payload and therefore has the ptrace permission needed to
call `process_vm_readv` on the target's `sockaddr`: it copies at most 128
bytes, accepts only `AF_INET`/`AF_INET6`, and matches family, address
and port against the parsed list. Allowed calls get
`SECCOMP_USER_NOTIF_FLAG_CONTINUE`; denied calls get a synchronous
`ECONNREFUSED` (or `EACCES` for malformed input). A denial never kills
the payload. Stale ids are checked with `SECCOMP_IOCTL_NOTIF_ID_VALID`
before responding, and only one notification is handled at a time.

The namespace choice is the host netns (same `unshare` flags as `full`),
not a veth/netns with loopback. This is the simplest design that lets
ordinary clients create sockets rootlessly: no `CAP_NET_ADMIN` and no
daemon are needed. The trade-off is explicit: **inbound listeners are not
filtered**. A private netns with a proxy would need a privileged helper
or a preload shim, neither of which fits the no-root/no-daemon model.

Hostnames are refused at parse time. Resolving them in the broker would
depend on resolver state and add attack surface. The list holds literal
IPs, CIDR ranges and ports only (see docs/policy.md).

Alternatives considered and rejected:

1. **veth pair + nftables on the host** (kernel L3 filter): needs
   CAP_NET_ADMIN in the initial namespace, i.e. a setuid helper or a
   service, which conflicts with "no daemon, no root".
2. **DNS-scoped approximation**: trivially bypassed by direct IPs.
3. **LD_PRELOAD shim**: arbitrary binaries (static or non-glibc) need not
   honour it; seccomp is mandatory for every syscall.

Interim guidance for policy authors: `none` for anything untrusted;
`full` only when you would have run the code bare anyway; `allowlist`
when an untrusted payload needs to reach a small set of known IPs and
its inbound surface is acceptable.

## Consequences
- `none`, `full` and `allowlist` are complete, tested behaviors today.
- `allowlist` enforces outbound `connect(2)` at the syscall boundary. It
  does not filter inbound listeners, UDP traffic via `sendto`, or DNS
  if a resolver is granted; those require either `none` or a broader
  design with a privileged helper (out of scope).
- `network-light` means "dev limits, no destinations allowed" until the
  policy adds `allow` entries.
