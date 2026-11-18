# Carapace TypeScript SDK

A small MCP client for the Carapace sandbox server. It speaks JSON-RPC 2.0
over stdio to a real `cara-mcp` process and imports only Node builtins
(`child_process`, `readline`, `buffer`). There are no runtime npm packages.

Carapace is Linux only. This SDK runs on Node 18 or newer, including WSL2.

## Build the server first

```sh
cargo build --release -p carapace-mcp
```

## Build and test the SDK

```sh
npm run build
npm test
```

`npm test` builds first, then runs `node --test test/client.test.mjs` against
a real server. `tsc` is the only development dependency. The compiled output
is in `dist/`. If you do not have a local TypeScript install, run `tsc` from
your global install or `npx tsc -p tsconfig.json`.

Point the tests at a binary with `CARA_MCP=/abs/path/to/cara-mcp npm test`
or `npm test -- --cara-mcp=/abs/path/to/cara-mcp`. The default is
`target/debug/cara-mcp`. On WSL2 the test bridges through
`systemd-run --user --scope` when the caller sits outside the user cgroup
slice, the same as `scripts/mcp-smoke.py`.

## Use

```ts
import { Client } from "./dist/index.js";

const c = await Client.create({ command: ["/absolute/path/to/cara-mcp"] });
try {
  console.log(c.serverInfo);            // handshake already done
  console.log((await c.listTools()).length); // 8 tools

  const result = await c.runCode("echo hello", { language: "sh" });
  console.log((result.json as { stdout: string }).stdout);

  const sid = await c.sessionCreate();
  await c.uploadBytes(sid, "input.txt", new TextEncoder().encode("data"));
  await c.sessionExec(sid, "cat input.txt");
  const bytes = await c.sessionDownload(sid, "input.txt");
  console.log(await c.sessionList());
  await c.sessionClose(sid);
} finally {
  await c.close();
}
```

`Client` accepts a path string or an argument list, so the server can be
wrapped when cgroup delegation needs it:

```ts
const c = await Client.create({
  command: ["systemd-run", "--user", "--scope", "--quiet", "/abs/cara-mcp"],
});
```

Errors:

- `RpcError`: a JSON-RPC error response, for example an unknown tool.
- `ToolError`: a normal response flagged `isError`. The payload was refused
  or killed. It was never run unsandboxed.
- `CarapaceTimeoutError`: the server did not reply in time.
- `ConnectionClosedError`: the server exited or closed stdout.

All derive from `CarapaceError`.
