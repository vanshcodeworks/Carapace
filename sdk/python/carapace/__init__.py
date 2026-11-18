"""Python SDK for the Carapace MCP server.

The SDK is a small JSON-RPC 2.0 client over stdio. It speaks to the real
``cara-mcp`` binary and uses only the Python standard library.

Example::

    from carapace import Client

    with Client(["/abs/path/to/cara-mcp"]) as c:
        result = c.run_code("echo hello")
        print(result.json["stdout"])
"""

from .client import (
    PROTOCOL_VERSION,
    CarapaceError,
    CarapaceTimeoutError,
    Client,
    ConnectionClosedError,
    RpcError,
    ToolError,
    ToolResult,
)

__all__ = [
    "PROTOCOL_VERSION",
    "CarapaceError",
    "CarapaceTimeoutError",
    "Client",
    "ConnectionClosedError",
    "RpcError",
    "ToolError",
    "ToolResult",
]
