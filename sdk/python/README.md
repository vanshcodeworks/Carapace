# Carapace Python SDK

A small MCP client for the Carapace sandbox server. It speaks JSON-RPC 2.0
over stdio to a real `cara-mcp` process and uses only the Python standard
library. There are no pip dependencies.

Carapace itself is Linux only. The request timeout uses `select.select` on
the process stdout pipe, so this SDK does not run on Windows. It does run in
WSL2.

## Build the server first

```sh
cargo build --release -p carapace-mcp
```

## Use

```python
from carapace import Client

with Client(["/absolute/path/to/cara-mcp"]) as c:
    print(c.server_info)          # initialize handshake already done
    print(len(c.list_tools()))    # 8 tools

    result = c.run_code("echo hello", policy={"timeout_ms": 10000})
    print(result.json["stdout"])  # report is JSON text

    sid = c.session_create()
    c.upload_bytes(sid, "input.txt", b"data")
    c.session_exec(sid, "cat input.txt")
    data = c.session_download(sid, "input.txt")
    print(c.session_list().json)
    c.session_close(sid)
```

`Client` accepts a path string or an argument list, so you can wrap the
server with `systemd-run` when cgroup delegation needs it:

```python
c = Client(["systemd-run", "--user", "--scope", "--quiet", "/abs/cara-mcp"])
c.start()
```

Errors are deliberately narrow:

- `RpcError` is a JSON-RPC error response, for example an unknown tool.
- `ToolError` is a normal response flagged `isError` by the server. The
  payload was refused or killed. It was never run unsandboxed.
- `CarapaceTimeoutError` means the server did not reply in time.
- `ConnectionClosedError` means the server exited or closed stdout.

All of these derive from `CarapaceError`.

## Test

The tests start a real server. They check the handshake, that `tools/list`
has exactly the eight Carapace tools, that `run_code` returns the expected
marker, and that an unknown tool is an error.

```sh
python3 -m unittest discover sdk/python/tests
```

Set `CARA_MCP` when the binary is not at `target/debug/cara-mcp`:

```sh
CARA_MCP=/abs/path/to/cara-mcp python3 -m unittest discover sdk/python/tests
```

You can also pass `--cara-mcp=/abs/path/to/cara-mcp` to the test runner. On
WSL2 the test bridges through `systemd-run --user --scope` automatically
when the caller sits outside the user cgroup slice, the same as
`scripts/mcp-smoke.py`.
