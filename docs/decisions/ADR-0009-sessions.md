# ADR-0009: Persistent sessions (keeper process, shared tmpfs, one cgroup)

Date: 2026-10-27 · Status: accepted · Milestone: P3

## Context
`cara run` is one-shot by design: a fresh mount namespace, a fresh tmpfs at
`/work`, a fresh PID namespace, and a fresh cgroup leaf per run. That is the
right default for untrusted code, but it makes iterative work (compile, run,
edit, run again) impossible without re-uploading state, and it forces agents
driving `cara-mcp` to pass every artifact through the host on each call.

A session must keep `/work` between calls while preserving every isolation
property the one-shot path already has. Two constraints dominate:

1. **Limits must survive the host process.** If the session were a child of
   the `cara` CLI process, the limits would be attached to a cgroup leaf
   owned by a process that exits immediately after `session start`. A
   long-lived owner is required, and it must be attached to the leaf *before*
   it unshares (ADR-0003: cgroup v2 `nsdelegate` forbids moving a task into a
   delegated subtree from outside it, and forbids moving a task in another
   user namespace at all).
2. **No daemon.** A root-owned/system daemon would add a privileged attack
   surface, a second configuration source, and a socket that outlives the
   user's login. The session must be a plain user process in the user's own
   delegated cgroup subtree.

## Decision

1. **One keeper process per session, spawned from the same binary.**
   `cara session start` forks `<current_exe> __session-keeper <spec.json>`
   (both `cara` and `cara-mcp` understand the hidden argument). The keeper is
   a *fresh exec*, not a fork of a possibly multi-threaded parent, so it may
   allocate and serve after the fork. It parks on a go-pipe; the manager
   creates the session cgroup leaf and writes the keeper's pid into
   `cgroup.procs` while the keeper is still a plain same-uid process — the
   only moment delegation permits the move.
2. **One user namespace and one tmpfs for the whole session.** After the go
   byte the keeper `unshare(CLONE_NEWUSER|CLONE_NEWNS)`, writes
   `uid_map`/`gid_map` (single mapping to the invoking uid/gid), makes `/`
   `MS_REC|MS_PRIVATE`, and mounts a tmpfs at the session's `work` directory
   with `size=<scratch_bytes>,mode=0700,MS_NOSUID|MS_NODEV`, plus
   `MS_NOEXEC` unless `exec_on_write` is set. The tmpfs is the kernel-enforced
   disk quota; the cgroup leaf is the memory/CPU/process quota. Both die with
   the keeper (tmpfs: namespace teardown; cgroup: keeper exit plus the
   sweeper).
3. **Every exec is a fresh sandbox, minus the user namespace.**
   `session exec` sends `program`, `argv`, and an optional timeout. The keeper
   calls the existing `spawn_with` path with `skip_userns = true`,
   `work_bind = <session tmpfs>`, and `cgroup = false`: the payload gets a new
   mount, PID, IPC, UTS (and net, unless `network = "full"`) namespace, its
   own rootfs tmpfs, the usual rlimits/Landlock/seccomp stack, and the
   session tmpfs bind-mounted at `/work`. It inherits the keeper's user
   namespace and the keeper's cgroup leaf, so the session-wide limits apply
   to every exec and to the keeper itself.
4. **PDEATHSIG chain covers the whole tree.** `stage-1` and `stage-2` already
   re-arm `PR_SET_PDEATHSIG`; the keeper is a subreaper and sets
   `PR_SET_CHILD_SUBREAPER`, so a killed keeper takes the running payload's
   PID namespace init with it and stray descendants are reaped instead of
   accumulating. For MCP, the keeper is additionally armed with PDEATHSIG
   against the server process (`parent_pid`), so a crashed agent server
   cannot leave a live sandbox behind.
5. **Control socket with a length-prefixed JSON protocol.** The keeper binds
   a UNIX socket (mode 0600) inside the session directory
   (`$XDG_RUNTIME_DIR/carapace/sessions/<id>`, fallback
   `/tmp/cara-sessions-<uid>`, both mode 0700). Frames are a 4-byte
   big-endian length plus JSON; `put`/`get` stream raw bytes after the
   header. One connection may carry several requests (needed because
   `session_exec` stages the program with `put` and then runs it). The keeper
   serves one connection at a time, so concurrent uploads and execs
   serialize instead of racing.
6. **File transfer is path-validated, not string-sanitized.** Every path is
   relative to the session tmpfs, must be normalized (no `.`, `..`, empty
   components), and is resolved component-by-component with
   `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)`;
   uploads write a random temp file and `renameat(2)` it into place, so a
   partially uploaded file is never visible under its final name. Symlinks
   are listed but never followed, and a symlinked directory cannot be
   traversed. Transfers are capped at 64 MiB (`MAX_TRANSFER_BYTES`); larger
   files stay inside the session and are manipulated by `session exec`.
7. **Session policy is the same policy, validated twice.** `SessionPolicy`
   is a serializable mirror of the validated `Policy` (environment, limits,
   network mode, binds, `exec_on_write`). It is validated on the host before
   the keeper starts and again by the keeper before it creates anything, so a
   corrupted `spec.json` fails closed. Sessions add two floor checks that
   one-shot runs do not need: memory ≥ 64 MiB and `max_processes` ≥ 8 (the
   keeper and both sandbox stages live in the same cgroup), and
   `4 * max_output + 32 MiB < memory` so output buffering in the keeper
   cannot OOM the payload. `network = "allowlist"` is refused (ADR-0004:
   not implemented).
8. **MCP sessions are server-owned.** The MCP tools (`session_create`,
   `session_exec`, `session_upload`, `session_download`, `session_list`,
   `session_close`) keep a per-server allowlist of created ids and refuse any
   other id without touching the filesystem or the socket, so an agent can
   never reach the user's CLI sessions. `session_exec` stages the program at
   `.__cara/code` inside the session and runs `sh FILE` (not `sh -c FILE`),
   because `/work` is `MS_NOEXEC` by default.

## Consequences
- Iterative and multi-step work keeps its artifacts without weakening the
  per-exec isolation boundary: processes never survive an exec, only files
  do, and `/work` is `MS_NOEXEC` unless the policy explicitly opts in
  (ADR-0007 §7).
- A session costs one long-lived keeper (a few MiB) plus one cgroup leaf; the
  memory cap covers the keeper *and* the payload, so the documented
  `memory` limit is the session's real budget, not a per-exec one.
- `peak_memory_bytes`/`peak_processes` in an exec report are the cgroup's
  high-water marks (cumulative over the session), while `cpu_time_usec` is
  the per-exec delta. Reports say so; they are not per-exec peaks.
- Stale state is reclaimable in two independent ways: `session prune`
  removes directories whose keeper is gone, and the cgroup sweeper removes
  leaves whose owner pid is dead (`cara-sess-<pid>-…`).
- `exec_on_write = true` in a session is a deliberate risk (ADR-0007 §7):
  the tmpfs is executable, so a payload can write a binary and run it later.
  It stays off in `strict`.
