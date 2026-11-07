#!/usr/bin/env python3
"""Small MCP smoke test for cara-mcp.

This is a real client, not a mock: it starts the server, performs the MCP
handshake, lists the tools, and runs one harmless shell command through the
sandbox.

Usage:
    python3 scripts/mcp-smoke.py [path-to-cara-mcp]

The default path is target/debug/cara-mcp. You can also set CARA_MCP.

On WSL2, the test automatically bridges through systemd-run --user --scope
when the current process sits outside the user cgroup slice, because
cgroup delegation only works from inside the user slice.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import select
import subprocess
import sys

EXPECTED_TOOLS = {
    "run_code",
    "explain_result",
    "session_create",
    "session_exec",
    "session_upload",
    "session_download",
    "session_list",
    "session_close",
}


def send(proc: subprocess.Popen[str], message: dict) -> None:
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()


def receive(proc: subprocess.Popen[str], timeout: float = 60.0) -> dict:
    assert proc.stdout is not None
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    if not ready:
        raise TimeoutError(f"no response from cara-mcp after {timeout:.0f}s")
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("cara-mcp closed stdout before responding")
    return json.loads(line)


def in_user_slice() -> bool:
    """Return True if the current process is inside the systemd user slice."""
    try:
        with open("/proc/self/cgroup", "r") as f:
            return f"user.slice/user-{os.getuid()}.slice" in f.read()
    except Exception:
        return False


def can_systemd_run() -> bool:
    """Return True if systemd-run --user works."""
    try:
        subprocess.run(
            ["systemd-run", "--user", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return True
    except Exception:
        return False


def make_server_command(binary: Path) -> list[str]:
    """Build the command to start the MCP server, bridging via systemd-run on WSL if needed."""
    if in_user_slice():
        return [str(binary)]
    if can_systemd_run():
        return ["systemd-run", "--user", "--scope", "--quiet", str(binary)]
    # Fallback: run directly; cara doctor will fail if cgroup delegation is missing.
    return [str(binary)]


def main() -> int:
    default = Path("target/debug/cara-mcp")
    raw = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CARA_MCP", str(default))
    binary = Path(raw).resolve()
    if not binary.exists():
        print(f"mcp smoke: binary not found: {binary}", file=sys.stderr)
        print("Build it with: cargo build -p carapace-mcp", file=sys.stderr)
        return 2

    cmd = make_server_command(binary)
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    failure: str | None = None
    try:
        send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "carapace-smoke", "version": "1.0"},
                },
            },
        )
        init = receive(proc)
        server = init.get("result", {}).get("serverInfo", {})
        if server.get("name") != "carapace":
            raise RuntimeError(f"unexpected server info: {server}")

        send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        listed = receive(proc)
        names = {tool.get("name") for tool in listed.get("result", {}).get("tools", [])}
        if names != EXPECTED_TOOLS:
            raise RuntimeError(f"unexpected tools: {sorted(names)}")

        send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "run_code",
                    "arguments": {
                        "code": "echo carapace-smoke",
                        "language": "sh",
                        "policy": {"timeout_ms": 10000},
                    },
                },
            },
        )
        called = receive(proc)
        result = called.get("result", {})
        if result.get("isError"):
            text = result.get("content", [{}])[0].get("text", "unknown error")
            raise RuntimeError(f"run_code failed: {text}")
        text = result.get("content", [{}])[0].get("text", "")
        if "carapace-smoke" not in text:
            raise RuntimeError(f"run_code output did not contain the marker: {text!r}")

        print(f"mcp smoke: ok")
        print(f"  server: carapace {server.get('version', '?')}")
        print(f"  tools: {len(names)}")
        print(f"  run_code: returned the marker")
        return 0
    except Exception as exc:  # noqa: BLE001 - this is a CLI smoke test
        failure = str(exc)
        print(f"mcp smoke: failed: {failure}", file=sys.stderr)
        return 1
    finally:
        if proc.stdin is not None:
            proc.stdin.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        if failure and proc.stderr is not None:
            stderr = proc.stderr.read().strip()
            if stderr:
                print(f"cara-mcp stderr:\n{stderr}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
