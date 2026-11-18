"""End-to-end tests for the Python SDK against a real cara-mcp binary.

Run with:

    python3 -m unittest discover sdk/python/tests

Point the tests at a binary with CARA_MCP=/abs/path/to/cara-mcp or with
``--cara-mcp=/abs/path/to/cara-mcp`` on the command line. The default is
``target/debug/cara-mcp`` relative to the working directory.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest

SDK_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SDK_ROOT))

from carapace import Client, RpcError  # noqa: E402  (path set above)

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
MARKER = "carapace-sdk-python"


def binary_path() -> Path:
    """Find the server binary from the environment or the command line."""
    raw = os.environ.get("CARA_MCP")
    if not raw:
        for arg in sys.argv[1:]:
            if arg.startswith("--cara-mcp="):
                raw = arg.split("=", 1)[1]
                break
    if not raw:
        raw = "target/debug/cara-mcp"
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    return path


def in_user_slice() -> bool:
    """True when this process sits inside the systemd user cgroup slice."""
    try:
        uid = os.getuid()
        with open("/proc/self/cgroup", "r") as handle:
            return f"user.slice/user-{uid}.slice" in handle.read()
    except (AttributeError, OSError):
        return False


def can_systemd_run() -> bool:
    """True when systemd-run --user can create a scope here."""
    try:
        subprocess.run(
            ["systemd-run", "--user", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def server_command(binary: Path) -> list[str]:
    """Bridge through the user slice on WSL2 so cgroup delegation works."""
    if in_user_slice():
        return [str(binary)]
    if can_systemd_run():
        return ["systemd-run", "--user", "--scope", "--quiet", str(binary)]
    return [str(binary)]


class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.binary = binary_path()
        if not cls.binary.exists():
            raise unittest.SkipTest(
                f"cara-mcp not found at {cls.binary}; set CARA_MCP to a built binary"
            )

    def setUp(self) -> None:
        self.client = Client(server_command(self.binary), timeout=90.0)
        self.client.start()

    def tearDown(self) -> None:
        self.client.close()

    def test_initialize_reports_carapace(self) -> None:
        self.assertEqual(self.client.server_info.get("name"), "carapace")

    def test_tools_list_has_eight_tools(self) -> None:
        names = {tool["name"] for tool in self.client.list_tools()}
        self.assertEqual(names, EXPECTED_TOOLS)
        self.assertEqual(len(names), 8)

    def test_run_code_returns_marker(self) -> None:
        result = self.client.run_code(
            f"echo {MARKER}", policy={"timeout_ms": 10000}
        )
        self.assertFalse(result.is_error)
        report = result.json
        self.assertIsInstance(report, dict)
        self.assertIn(MARKER, report["stdout"])
        self.assertEqual(report["exit_code"], 0)

    def test_unknown_tool_raises_rpc_error(self) -> None:
        with self.assertRaises(RpcError):
            self.client.call_tool("no_such_tool", {})


if __name__ == "__main__":
    unittest.main()
