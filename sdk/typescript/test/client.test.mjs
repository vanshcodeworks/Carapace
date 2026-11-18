// End-to-end tests for the TypeScript SDK against a real cara-mcp binary.
// Run with: npm test   (builds first, then node --test)
// Or:       node --test test/client.test.mjs   (after a build)

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import test from "node:test";

import { Client, RpcError } from "../dist/index.js";

const EXPECTED_TOOLS = [
  "run_code",
  "explain_result",
  "session_create",
  "session_exec",
  "session_upload",
  "session_download",
  "session_list",
  "session_close",
];
const MARKER = "carapace-sdk-typescript";

function findBinary() {
  let raw = process.env.CARA_MCP;
  if (!raw) {
    const flag = process.argv.find((arg) => arg.startsWith("--cara-mcp="));
    if (flag) raw = flag.slice("--cara-mcp=".length);
  }
  if (!raw) raw = "target/debug/cara-mcp";
  return path.isAbsolute(raw) ? raw : path.resolve(process.cwd(), raw);
}

function inUserSlice() {
  try {
    const uid = typeof process.getuid === "function" ? process.getuid() : -1;
    return readFileSync("/proc/self/cgroup", "utf8").includes(
      `user.slice/user-${uid}.slice`,
    );
  } catch {
    return false;
  }
}

function canSystemdRun() {
  try {
    execFileSync("systemd-run", ["--user", "true"], {
      stdio: "ignore",
      timeout: 5000,
    });
    return true;
  } catch {
    return false;
  }
}

function serverCommand(binary) {
  if (inUserSlice()) return [binary];
  if (canSystemdRun()) {
    return ["systemd-run", "--user", "--scope", "--quiet", binary];
  }
  return [binary];
}

const binary = findBinary();

async function withClient(fn) {
  const client = await Client.create({
    command: serverCommand(binary),
    timeoutMs: 90000,
  });
  try {
    await fn(client);
  } finally {
    await client.close();
  }
}

if (!existsSync(binary)) {
  test("cara-mcp binary is available", { skip: `set CARA_MCP; not found: ${binary}` }, () => {});
} else {
  test("initialize reports carapace", async () => {
    await withClient((client) => {
      assert.equal(client.serverInfo.name, "carapace");
    });
  });

  test("tools/list has eight tools", async () => {
    await withClient(async (client) => {
      const names = (await client.listTools()).map((tool) => tool.name).sort();
      assert.deepEqual(names, [...EXPECTED_TOOLS].sort());
      assert.equal(names.length, 8);
    });
  });

  test("run_code returns the marker", async () => {
    await withClient(async (client) => {
      const result = await client.runCode(`echo ${MARKER}`, {
        policy: { timeout_ms: 10000 },
      });
      assert.equal(result.isError, false);
      const report = result.json;
      assert.ok(report && typeof report === "object");
      assert.ok(report.stdout.includes(MARKER), `stdout was: ${report.stdout}`);
      assert.equal(report.exit_code, 0);
    });
  });

  test("unknown tool raises RpcError", async () => {
    await withClient(async (client) => {
      await assert.rejects(() => client.callTool("no_such_tool", {}), RpcError);
    });
  });
}
