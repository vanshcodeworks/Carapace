# ADR-0004: Network modes

Date: 2026-10-25 · Status: accepted (none/full now; allowlist designed, deferred) · Milestone: C5

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

### `mode = "allowlist"` — designed, deliberately not shipped yet
Parsing and validating the mode exists; **running** it fails closed with
an explicit "not implemented" error, because a half-working allowlist is
worse than none. The two candidate designs, to be decided by measurement
in a later milestone:

1. **veth pair + nftables on the host** (kernel L3 filter): the sandbox
   gets `cara0` (inside), the host `cara-p<id>`; an nftables chain allows
   only the listed domains' resolved IPs (refreshed periodically).
   Problem rootless: creating veth/nft rules needs CAP_NET_ADMIN in the
   *initial* namespace — requires a privileged setuid/helper component or
   a systemd service, which conflicts with "no daemon, no root".
2. **Userspace proxy** (like slirp4netns/bubblewrap's --bind*
   equivalents): a helper process in the HOST netns proxies TCP
   connections for the sandbox (sandbox has no interfaces; outbound
   connections are proxied via a UNIX socket + a preloaded shim or a
   seccomp-notif socket(2) interceptor). Rootless-friendly, but the
   interception story for arbitrary programs (no LD_PRELOAD guarantees)
   is the hard part; seccomp user-notification (SECCOMP_RET_USER_NOTIF)
   is the most promising hook.
3. **DNS-scoped approximation** (weak; rejected as the only mechanism):
   filtering at the resolver level is trivially bypassed by direct IPs.

Interim guidance for policy authors: `none` for anything untrusted;
`full` only when you would have run the code bare anyway.

## Consequences
- `none` and `full` are complete, tested behaviors today.
- The `network-light` preset validates and explains, and refuses at run
  time — an honest position that keeps docs truthful.
- When the allowlist lands (likely via seccomp user-notification + a
  userspace proxy), it slots behind the same `NetworkMode` enum with no
  policy-format change.
