"""Stdlib-only MCP client for the Carapace sandbox server.

Wire protocol: line-delimited JSON-RPC 2.0 over the child process stdin and
stdout. One request is in flight at a time. The server is synchronous, so a
tools/call response arrives only after the sandbox run has finished.

This SDK is Linux-only, like Carapace itself. The request timeout uses
``select.select`` on the process stdout pipe.
"""

from __future__ import annotations

import base64
import json
import select
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence, Union

PROTOCOL_VERSION = "2024-11-05"
DEFAULT_TIMEOUT_S = 60.0
DEFAULT_CLIENT_NAME = "carapace-python"
DEFAULT_CLIENT_VERSION = "0.1.0"

Command = Union[str, Sequence[str]]


class CarapaceError(Exception):
    """Base class for every error raised by this SDK."""


class ConnectionClosedError(CarapaceError):
    """The server closed stdout or exited before replying."""


class CarapaceTimeoutError(CarapaceError):
    """The server did not reply within the allotted time."""


class RpcError(CarapaceError):
    """A JSON-RPC error response (bad method, bad params, and so on)."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"JSON-RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class ToolError(CarapaceError):
    """A tool result flagged ``isError`` by the server.

    This is a normal JSON-RPC response. The payload was refused or killed;
    it was never run unsandboxed.
    """

    def __init__(self, text: str, result: "ToolResult") -> None:
        super().__init__(text or "tool returned an error")
        self.text = text
        self.result = result


@dataclass
class ToolResult:
    """The text content of one tools/call response.

    ``text`` is the first content block's text. Carapace writes JSON into it
    for most tools, so ``json`` parses it on demand and returns ``None`` when
    the text is not JSON.
    """

    text: str = ""
    is_error: bool = False
    raw: dict = field(default_factory=dict)

    @property
    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except (TypeError, ValueError):
            return None


class Client:
    """A synchronous MCP client bound to one ``cara-mcp`` process.

    Use it as a context manager or call :meth:`start` and :meth:`close`
    yourself. Sessions created through this client are owned by that server
    process; a different process refuses their ids.
    """

    def __init__(
        self,
        command: Command,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        cwd: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        client_name: str = DEFAULT_CLIENT_NAME,
        client_version: str = DEFAULT_CLIENT_VERSION,
    ) -> None:
        if isinstance(command, str):
            argv = [command]
        else:
            argv = list(command)
        if not argv or not argv[0]:
            raise ValueError("command must name a cara-mcp binary")
        if timeout <= 0:
            raise ValueError("timeout must be positive")

        self.command = argv
        self.timeout = timeout
        self.cwd = cwd
        self.env = dict(env) if env is not None else None
        self.client_name = client_name
        self.client_version = client_version
        self.server_info: dict = {}
        self.protocol_version: Optional[str] = None

        self._proc: Optional[subprocess.Popen] = None
        self._stderr: list[str] = []
        self._next_id = 0

    # -------------------------------------------------------------- lifecycle

    def start(self) -> "Client":
        """Spawn the server and perform the MCP initialize handshake."""
        if self._proc is not None:
            return self
        try:
            self._proc = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.cwd,
                env=self.env,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            raise CarapaceError(f"could not start cara-mcp: {exc}") from exc
        try:
            self.initialize()
        except BaseException:
            self.close()
            raise
        return self

    def __enter__(self) -> "Client":
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        """Stop the server. Safe to call more than once."""
        proc = self._proc
        if proc is None:
            return
        self._proc = None
        if proc.stdin is not None:
            try:
                proc.stdin.close()
            except OSError:
                pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        if proc.stderr is not None:
            try:
                chunk = proc.stderr.read()
                if chunk:
                    self._stderr.append(chunk)
            except OSError:
                pass
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    @property
    def process(self) -> Optional[subprocess.Popen]:
        """The underlying process, exposed for diagnostics."""
        return self._proc

    def stderr(self) -> str:
        """Server stderr collected when the process is stopped."""
        return "".join(self._stderr)

    # --------------------------------------------------------------- protocol

    def _require_proc(self) -> subprocess.Popen:
        if self._proc is None:
            raise CarapaceError("client is not started; call start() or use a with block")
        return self._proc

    def _send(self, message: dict) -> None:
        proc = self._require_proc()
        if proc.stdin is None:
            raise CarapaceError("cara-mcp stdin is not a pipe")
        try:
            proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
            proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise ConnectionClosedError(f"could not write to cara-mcp: {exc}") from exc

    def _read_line(self, timeout: float) -> str:
        proc = self._require_proc()
        if proc.stdout is None:
            raise CarapaceError("cara-mcp stdout is not a pipe")
        ready, _, _ = select.select([proc.stdout], [], [], timeout)
        if not ready:
            raise CarapaceTimeoutError(
                f"no response from cara-mcp after {timeout:.1f}s"
            )
        line = proc.stdout.readline()
        if not line:
            raise ConnectionClosedError("cara-mcp closed stdout before responding")
        return line

    def _request(
        self,
        method: str,
        params: Optional[dict] = None,
        *,
        timeout: Optional[float] = None,
    ) -> Any:
        self._require_proc()
        self._next_id += 1
        request_id = self._next_id
        message: dict = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

        limit = self.timeout if timeout is None else timeout
        if limit <= 0:
            raise ValueError("timeout must be positive")
        deadline = time.monotonic() + limit
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CarapaceTimeoutError(
                    f"no response to {method} after {limit:.1f}s"
                )
            line = self._read_line(remaining)
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                # The server writes JSON-RPC to stdout only. Ignore stray
                # non-JSON lines rather than desynchronising the channel.
                continue
            if not isinstance(response, dict) or response.get("id") != request_id:
                continue
            if "error" in response:
                error = response["error"] or {}
                raise RpcError(
                    int(error.get("code", -1)),
                    str(error.get("message", "unknown error")),
                    error.get("data"),
                )
            return response.get("result")

    def _notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def initialize(self) -> dict:
        """Perform the MCP handshake. Called by :meth:`start`."""
        result = self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": self.client_name,
                    "version": self.client_version,
                },
            },
        )
        if not isinstance(result, dict):
            raise CarapaceError("initialize returned a malformed result")
        self.server_info = result.get("serverInfo") or {}
        self.protocol_version = result.get("protocolVersion")
        self._notify("notifications/initialized")
        return self.server_info

    def list_tools(self) -> list[dict]:
        """Return the tools advertised by the server."""
        result = self._request("tools/list", {})
        if not isinstance(result, dict):
            raise CarapaceError("tools/list returned a malformed result")
        return list(result.get("tools") or [])

    def call_tool(
        self,
        name: str,
        arguments: Optional[dict] = None,
        *,
        timeout: Optional[float] = None,
    ) -> ToolResult:
        """Call a tool by name. A flagged result raises :class:`ToolError`."""
        result = self._request(
            "tools/call",
            {"name": name, "arguments": arguments or {}},
            timeout=timeout,
        )
        if not isinstance(result, dict):
            raise CarapaceError(f"{name} returned a malformed result")
        content = result.get("content") or []
        text = "".join(
            part.get("text", "")
            for part in content
            if isinstance(part, dict) and isinstance(part.get("text", ""), str)
        )
        tool_result = ToolResult(
            text=text,
            is_error=bool(result.get("isError")),
            raw=result,
        )
        if tool_result.is_error:
            raise ToolError(text, tool_result)
        return tool_result

    # ------------------------------------------------------------------ tools

    def run_code(
        self,
        code: str,
        *,
        language: str = "sh",
        policy: Optional[dict] = None,
        timeout: Optional[float] = None,
    ) -> ToolResult:
        """Run code once in a fresh sandbox. ``result.json`` is the report."""
        arguments: dict = {"code": code, "language": language}
        if policy is not None:
            arguments["policy"] = policy
        return self.call_tool("run_code", arguments, timeout=timeout)

    def explain_result(
        self,
        report: dict,
        *,
        timeout: Optional[float] = None,
    ) -> ToolResult:
        """Turn a run report into a plain-English explanation."""
        return self.call_tool("explain_result", {"report": report}, timeout=timeout)

    def session_create(self, *, policy: Optional[dict] = None) -> str:
        """Create a server-owned session and return its id."""
        arguments: dict = {}
        if policy is not None:
            arguments["policy"] = policy
        result = self.call_tool("session_create", arguments)
        data = result.json
        session_id = data.get("session_id") if isinstance(data, dict) else None
        if not isinstance(session_id, str):
            raise CarapaceError("session_create did not return a session_id")
        return session_id

    def session_exec(
        self,
        session_id: str,
        code: str,
        *,
        language: str = "sh",
        timeout_ms: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> ToolResult:
        """Run code in a fresh sandbox with the session's /work mounted."""
        arguments: dict = {
            "session_id": session_id,
            "code": code,
            "language": language,
        }
        if timeout_ms is not None:
            arguments["timeout_ms"] = timeout_ms
        return self.call_tool("session_exec", arguments, timeout=timeout)

    def session_upload(
        self,
        session_id: str,
        path: str,
        content_base64: str,
    ) -> ToolResult:
        """Write standard base64 content to a relative path in the session."""
        return self.call_tool(
            "session_upload",
            {
                "session_id": session_id,
                "path": path,
                "content_base64": content_base64,
            },
        )

    def upload_bytes(self, session_id: str, path: str, data: bytes) -> ToolResult:
        """Convenience wrapper around :meth:`session_upload` for raw bytes."""
        return self.session_upload(
            session_id, path, base64.b64encode(data).decode("ascii")
        )

    def session_download(self, session_id: str, path: str) -> bytes:
        """Read a session file and return its decoded bytes."""
        result = self.call_tool(
            "session_download", {"session_id": session_id, "path": path}
        )
        data = result.json
        encoded = data.get("content_base64") if isinstance(data, dict) else None
        if not isinstance(encoded, str):
            raise CarapaceError("session_download did not return content_base64")
        return base64.b64decode(encoded)

    def session_list(self) -> ToolResult:
        """List sessions owned by this server process."""
        return self.call_tool("session_list", {})

    def session_close(self, session_id: str) -> ToolResult:
        """Stop a session and remove its work directory."""
        return self.call_tool("session_close", {"session_id": session_id})
