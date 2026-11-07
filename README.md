<p align="center">
  <img src="docs/assets/hero.svg" alt="An animated terminal shows agent code being blocked by Carapace while the host machine stays safe." width="100%">
</p>

<h1 align="center">Carapace</h1>

<p align="center">
  <strong>Run code written by AI agents. Keep your machine.</strong><br>
  A small, local sandbox. No daemon. No Docker. No root.
</p>

<p align="center">
  <a href="https://github.com/vanshcodeworks/Carapace/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/vanshcodeworks/Carapace/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <img alt="Status" src="https://img.shields.io/badge/status-alpha-orange">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20x86__64-blue">
  <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-green">
</p>

## What is Carapace?

Carapace is a local sandbox for untrusted code. It is built for code that an AI agent writes and wants to run.

You give it a program and a policy. It runs the program in a locked-down box. It returns the output, the exit code, and the reason the program stopped. Your files, your network, and your processes stay outside the box.

It is one binary. It starts in milliseconds. It does not need a daemon, Docker, or root.

## Why it exists

AI agents are good at writing code. They are not always good at knowing what is safe to run.

A normal agent needs a shell to test its work. A shell on your laptop can read your keys, change your files, and open a network connection. Carapace gives the agent a smaller door:

- run this program
- with these limits
- with this policy
- and return the result

That is the whole product.

## What works today

| Feature | Status |
|---|---|
| `cara run` | One-shot sandbox. Runs a program with limits and returns a report. |
| `cara session` | Persistent `/work` across execs. Every exec is a fresh sandbox. |
| `cara mcp` | MCP server with 8 tools for agent clients. |
| `cara doctor` | Measures the host. Refuses to run when the host cannot isolate. |
| `cara policy` | Strict TOML policy. `check` and `explain`. |
| Tier 1 native | Linux namespaces, cgroups v2, Landlock, seccomp, capability drop. This is the supported path. |
| Tier 2 Wasm | Library backend with parity tests. Not exposed by the CLI yet. |
| Tier 3 microVM | Design and fail-closed plan. Not usable yet. |

### One run

```sh
cara run -- /bin/sh -c 'echo hello from the sandbox'
cara run --json -- /usr/bin/python3 -c 'print(6 * 7)'
```

### One session

```sh
id=$(cara session start --policy dev.toml)
cara session exec "$id" -- /bin/sh -c 'echo data > /work/input.txt'
cara session exec "$id" -- /bin/sh -c 'cat /work/input.txt'
cara session close "$id"
```

The file survives. The process does not. Each `session exec` gets a new PID namespace and a new root.

### One agent connection

```json
{
  "mcpServers": {
    "carapace": {
      "command": "/home/YOU/.local/bin/cara-mcp",
      "args": []
    }
  }
}
```

The agent gets these tools:

`run_code`, `explain_result`, `session_create`, `session_exec`, `session_upload`, `session_download`, `session_list`, `session_close`.

## Try it

You need Linux x86_64. WSL2 works. You need Rust 1.85 or newer and git.

```sh
git clone https://github.com/vanshcodeworks/Carapace.git
cd Carapace
bash scripts/install.sh
```

The installer builds `cara` and `cara-mcp`, installs them in `~/.local/bin`, and runs `cara doctor`. If doctor fails, Carapace will not run code. Fix the host first. The installer prints the exact remedy.

If you do not want the installer:

```sh
cargo build --release -p carapace-cli -p carapace-mcp
./target/release/cara doctor
./target/release/cara run -- /bin/sh -c 'echo hello from the sandbox'
```

## Give this repo to your agent

Hand your agent [AGENT_SETUP.md](AGENT_SETUP.md). It is a step-by-step file for an AI agent. It covers:

- checking the host
- cloning and building
- installing the two binaries
- running the doctor gate
- connecting an MCP client
- running a safe smoke test
- what to do when the host is not ready

The short version:

> Read AGENT_SETUP.md in https://github.com/vanshcodeworks/Carapace and set up Carapace on this machine. Stop if `cara doctor` fails. Do not disable the sandbox.

For the full agent guide, see [docs/agents.md](docs/agents.md).

## What it stops

Every row is a test in the escape suite (crate `carapace-escape-tests`): the payload runs through the real sandbox and the suite asserts the documented result. The table is generated from the test catalog, so it cannot drift from what is actually tested.

| Test | Attack | Result |
|---|---|---|
| `fork_bomb` | Fork bomb | Capped by pids.max and killed at the timeout; peak process count stays near the cap and no stragglers survive on the host |
| `memory_hog` | Memory hog | OOM-killed at the memory limit (KillReason::MemoryLimit) with peak memory near the cap; the host is unaffected |
| `cpu_spin` | CPU spin | Killed at the wall timeout with cpu_time close to the cpu.max quota (100 percent of one core) |
| `disk_filler` | Disk filler | Writes fail with ENOSPC (8 MiB root tmpfs) or the RLIMIT_FSIZE / scratch-size cap; the host filesystem is untouched |
| `output_flood` | Output flood | Killed with KillReason::OutputOverflow at the output cap; captured output stays capped |
| `read_etc_passwd` | Read /etc/passwd | Succeeds but shows the sandbox's own passwd (carapace-sandbox-marker), never host users |
| `read_shadow` | Read /etc/shadow | The file does not exist inside the sandbox; cat fails |
| `read_home` | Read /home and /root | Neither exists inside the sandbox (No such file or directory) |
| `write_outside` | Write outside the sandbox | Both writes denied: /usr is read-only (EROFS), /etc is denied by Landlock; no host file appears |
| `write_then_exec` | Write then execute | The file is created but Landlock denies execve on writable locations: the written program never runs (Permission denied, rc=126) |
| `symlink_escape` | Symlink escape | The link resolves to the sandbox's own /etc/passwd within the Landlock scope; the host file is untouched |
| `proc_escape` | /proc inspection | /proc/1 is the sandbox's own shell and the pid space is fresh (max pid <= 10); host processes are invisible |
| `ptrace_attempt` | ptrace injection | Denied with EPERM: ptrace is not in the seccomp allowlist |
| `mount_attempt` | mount(2) attempt | Denied with EPERM: mount(2) is not in the seccomp allowlist |
| `unshare_attempt` | unshare(2) escape | Denied with EPERM: unshare(2) is not in the seccomp allowlist |
| `socket_egress` | Network egress | Denied with EPERM on socket(2): no sockets exist (empty netns plus seccomp); the connection is never made |
| `abstract_unix_escape` | Abstract Unix socket | Denied with EPERM: socket(2) itself is denied, so the abstract namespace is unreachable |
| `setuid_escalation` | setuid escalation | Every uid change fails with EPERM (no CAP_SETUID); setuid bits in the read-only /usr bind are inert: CapEff=0000000000000000 and NoNewPrivs=1 |
| `keyring_abuse` | Keyring abuse | Denied with EPERM: keyring syscalls are not in the seccomp allowlist |
| `fd_leak_scan` | FD leak scan | Exactly 0, 1, 2 plus the scanner's own transient directory fd; nothing else leaks in |
| `env_leak` | Environment leak | The child sees exactly the allowlisted variables the spec set; nothing is inherited from the host |

Additional red-team probes (tests/redteam.rs) cover chroot, mknod, sethostname, /proc/sys writes, cross-hierarchy rename, zombie hoards, dual-stream floods, slow-drip output, hostile argv, the new mount API, memfd, mmap exec, and more. All are denied or contained.

## What it does not do yet

- **Network allowlist.** `network = "allowlist"` is refused. Use `none` or `full`.
- **Windows and macOS native.** Linux only. WSL2 works.
- **aarch64.** The native tier is x86_64 only.
- **SDKs.** There is no Python or TypeScript SDK yet. Use MCP or the CLI.
- **Prebuilt binaries.** There is no release download yet. Build from source.
- **Kernel exploits.** Tier 1 shares the host kernel. A kernel exploit can escape. Tier 2 and Tier 3 exist to change that, but Tier 2 is not in the CLI yet and Tier 3 is not usable.
- **Other distros.** The measured environment is WSL2 Ubuntu 24.04, kernel 6.18, x86_64. Other distros are not supported until they are measured. `cara doctor` is the gate.

## How it works

1. `cara doctor` measures user namespaces, cgroup v2, Landlock, seccomp, and the host layout. If a required piece is missing, it stops.
2. `cara run` creates new user, PID, mount, network, IPC, UTS, and cgroup namespaces. It builds a small root filesystem, drops capabilities, sets `no_new_privs`, installs a seccomp allowlist, and applies Landlock rules.
3. The payload runs with CPU, memory, process, disk, output, and wall-clock limits.
4. The supervisor kills the whole tree and returns a report. A normal run removes its cgroup leaf and staging directory.

Read [docs/architecture.md](docs/architecture.md) for the full path.

## Where it fits

Carapace is an execution primitive for agent platforms. If your product lets a user ask an agent to write and run code, Carapace is the part that runs the code without giving the agent the machine.

It is deliberately small. It is not an IDE, a browser, a container platform, or a cloud service. It is the narrow step between model output and a real result.

## Documentation

- [Agent setup](AGENT_SETUP.md) - the file to hand to an agent
- [Agent guide](docs/agents.md) - MCP, sessions, policy recipes
- [Threat model](docs/threat-model.md) - what is defended and what is not
- [Policy reference](docs/policy.md) - every policy field
- [MCP guide](docs/mcp.md) - tools, caps, client config
- [Runtime guide](docs/runtime-guide.md) - Python, Node, Go, JVM, compilers
- [Troubleshooting](docs/troubleshooting.md) - doctor remedies
- [Architecture](docs/architecture.md) - how a run works
- [FAQ](docs/faq.md)
- [Claims ledger](docs/agent/CLAIMS.md) - every claim and its test
- [Unverified list](docs/agent/UNVERIFIED.md) - what is not proven yet

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). The short rules:

- every security claim needs a named test
- hostile code runs only inside the sandbox
- new configuration fails closed
- docs must match measured behavior

## Security

Report vulnerabilities privately. See [SECURITY.md](SECURITY.md). Do not open a public issue for a security report.

## License

Apache-2.0 OR MIT. See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).

---

<p align="center"><sub>Built for people who run code they did not write.</sub></p>
