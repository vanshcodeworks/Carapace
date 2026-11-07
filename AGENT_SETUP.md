# Agent setup: Carapace

This file is for an AI agent. A human can hand this file to an agent and say:
"Set up Carapace for me."

Read the whole file first. Then follow the steps in order.

## What you are setting up

Carapace is a local sandbox for untrusted code. It is built for code that an
AI agent writes and wants to run.

You give it a program and a policy. It runs the program in a locked-down
box. It returns the output, the exit code, and the reason the program
stopped. The host files, host network, and host processes stay outside the
box.

Carapace is one binary. It does not need a daemon, Docker, or root.

## Stop conditions

Stop and report to the human if any of these is true:

- the host is not Linux or WSL2
- the host is not x86_64
- Rust 1.85 or newer is missing and the human does not want it installed
- `cara doctor` exits non-zero after the printed remedy is applied
- the MCP smoke test fails
- a step asks for `sudo` and the human has not approved it

Do not bypass the doctor gate. Do not patch the source to make the doctor
pass. Do not run Carapace as root. Do not add `network = "full"` for
untrusted code. Do not claim support for a platform that has not been
measured.

## Step 0: check the host

Run these commands and keep the output:

```sh
uname -s
uname -m
. /etc/os-release && echo "$PRETTY_NAME"
command -v cargo && cargo --version
```

Expected:

- `Linux`
- `x86_64`
- Rust 1.85 or newer

WSL2 is Linux, so it is fine. The installer detects the WSL cgroup case and
bridges through the systemd user manager.

If `cargo` is missing, ask the human before installing Rust. The official
installer is https://rustup.rs. Do not install Rust with `sudo`.

## Step 1: get the code

Use a normal user account. Do not use `sudo`.

```sh
mkdir -p "$HOME/src"
git clone https://github.com/vanshcodeworks/Carapace.git "$HOME/src/Carapace"
cd "$HOME/src/Carapace"
git log -1 --oneline
```

If the directory already exists, do not delete it. Ask the human whether to
update it with `git pull --ff-only` or use it as is.

## Step 2: build and install

```sh
bash scripts/install.sh
```

This does four things:

1. builds `cara` and `cara-mcp` in release mode
2. installs them in `~/.local/bin`
3. prints the versions
4. runs `cara doctor`

If `~/.local` is not writable, choose another prefix:

```sh
bash scripts/install.sh --prefix "$HOME/.carapace"
```

Then use `$HOME/.carapace/bin/cara` and
`$HOME/.carapace/bin/cara-mcp` in every later step.

Do not use `sudo`. The binaries are owned by the user who will run them.

For a faster development build, use `bash scripts/install.sh --debug`. The
release build is the normal choice.

## Step 3: pass the doctor gate

If the installer already ran `cara doctor` and exited 0, skip to step 4.

If it exited non-zero, run the doctor again and capture both forms:

```sh
cara doctor
cara doctor --json
```

Exit code 0 means the host is ready. Exit code 4 means a required capability
is missing. Carapace will refuse to run code until it is fixed. This is the
fail-closed rule, not a bug to work around.

Read `docs/troubleshooting.md` and apply only the remedy printed for the
failing check. If the remedy needs `sudo`, ask the human before running it.
Then run `cara doctor` again.

Stop if it still fails. Report the exact failing check and the remedy text.

## Step 4: run a smoke test

```sh
cara run -- /bin/sh -c 'echo hello from carapace'
cara run --json -- /bin/sh -c 'echo json-ok'
```

Expected: exit code 0, the text `hello from carapace`, and a JSON report for
the second command.

If the sandbox refuses to start, go back to step 3. Do not run the command
on the host to "check whether the command works".

## Step 5: connect the MCP client

Find the absolute path of the server:

```sh
command -v cara-mcp
```

Use that path in the client configuration. The server speaks JSON-RPC 2.0
over stdio. It is a local process, not a network service.

Claude Desktop: open `Settings -> Developer -> Edit Config` and add:

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

Cursor: use `~/.cursor/mcp.json` or a project-level `.cursor/mcp.json`:

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

Replace `/home/YOU/.local/bin/cara-mcp` with the real absolute path. Keep the
server on the same machine as the sandbox. There is no remote mode.

If the client was already open, restart it so it reloads the configuration.

## Step 6: verify the MCP server

Run the smoke client from the repository:

```sh
python3 scripts/mcp-smoke.py "$(command -v cara-mcp)"
```

Expected:

```text
mcp smoke: ok
  server: carapace 0.1.0
  tools: 8
  run_code: returned the marker
```

This starts the real server, performs the MCP handshake, lists all 8 tools,
and runs one harmless shell command through the sandbox.

If it fails with "the sandbox environment is not ready", go back to step 3.
If it fails for another reason, capture the full output and the server's
stderr. Do not work around the sandbox.

## Step 7: report back

Report these facts to the human:

- repository path and commit (`git log -1 --oneline`)
- `cara --version` and `cara-mcp --version`
- install prefix
- doctor verdict (exit code and the summary line)
- smoke test result
- the exact MCP config file you edited
- any warning that remains

Do not paste API keys, tokens, SSH keys, or other secrets into the report.

## Safety rules for the agent

1. Run untrusted code only through Carapace. Never run a hostile payload on
   the host "just to debug it".
2. Keep `network = "none"` for untrusted code. `network = "full"` shares the
   host network and is a deliberate, loud choice.
3. Keep `exec_on_write` off unless the human explicitly needs compile and
   run. The `strict` preset keeps it off.
4. Do not edit the policy parser, the seccomp allowlist, the Landlock rules,
   or the doctor gate to make a task pass.
5. Do not run Carapace or its MCP server as root.
6. Do not use `session` to hide a long-running process. Sessions keep files.
   Each exec gets a new PID namespace, so background processes do not
   survive.
7. Treat MCP input as hostile. Size caps, field allowlists, and absolute
   program paths are part of the security model, not suggestions.

## Useful commands

```sh
# Host check
cara doctor
cara doctor --json

# One run
cara run -- /usr/bin/python3 -c 'print(6 * 7)'
cara run --json -- /bin/sh -c 'echo report'

# Policy check
cara policy check policy.toml
cara policy explain policy.toml

# Session workflow
id=$(cara session start --policy policy.toml)
cara session exec "$id" -- /bin/sh -c 'echo data > /work/input.txt'
cara session exec "$id" -- /bin/sh -c 'cat /work/input.txt'
cara session close "$id"

# MCP smoke test
python3 scripts/mcp-smoke.py "$(command -v cara-mcp)"
```

## If something is missing

- `cargo` missing: ask the human before installing Rust.
- `cara doctor` fails: read `docs/troubleshooting.md`, apply the printed
  remedy, rerun. Stop if it still fails.
- MCP client does not see the server: check the absolute path, restart the
  client, and run `python3 scripts/mcp-smoke.py` first.
- `cara run` says the environment is not ready: the doctor gate is working.
  Fix the host. Do not bypass it.
- The host is not x86_64: stop. The native tier is x86_64 only today.
- The host is not Linux: stop. WSL2 is the supported path on Windows.

## What not to claim

Do not tell the human that Carapace:

- supports Windows or macOS natively
- supports aarch64
- has a network allowlist
- has a Python or TypeScript SDK
- ships prebuilt binaries
- protects against Linux kernel exploits
- is supported on a distro that has not been measured

The measured environment is WSL2 Ubuntu 24.04, kernel 6.18, x86_64. Other
environments are unverified until they are tested. The full list is in
`docs/agent/UNVERIFIED.md`.
