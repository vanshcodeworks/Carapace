// Carapace TypeScript SDK: a stdio JSON-RPC 2.0 client for cara-mcp.
// Zero runtime dependencies: only Node builtins are imported.

import { spawn, type ChildProcess } from "node:child_process";
import { createInterface, type Interface } from "node:readline";
import { Buffer } from "node:buffer";

export const PROTOCOL_VERSION = "2024-11-05";
const DEFAULT_TIMEOUT_MS = 60_000;

export type Command = string | string[];

export interface ClientOptions {
  /** Path to cara-mcp, or an argument list to wrap it (systemd-run, and so on). */
  command: Command;
  timeoutMs?: number;
  cwd?: string;
  env?: Record<string, string | undefined>;
  clientName?: string;
  clientVersion?: string;
}

export interface RunOptions {
  language?: "sh" | "python3";
  policy?: Record<string, unknown>;
  timeoutMs?: number;
}

/** Base class for every error raised by this SDK. */
export class CarapaceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The server closed stdout or exited before replying. */
export class ConnectionClosedError extends CarapaceError {}

/** The server did not reply within the allotted time. */
export class CarapaceTimeoutError extends CarapaceError {}

/** A JSON-RPC error response, for example an unknown tool. */
export class RpcError extends CarapaceError {
  readonly code: number;
  readonly data: unknown;
  constructor(code: number, message: string, data?: unknown) {
    super(`JSON-RPC error ${code}: ${message}`);
    this.code = code;
    this.data = data;
  }
}

/** The text content of one tools/call response. */
export class ToolResult {
  constructor(
    readonly text: string,
    readonly isError: boolean,
    readonly raw: Record<string, unknown>,
  ) {}

  /** Parse the text as JSON, or return null when it is not JSON. */
  get json(): unknown {
    try {
      return JSON.parse(this.text);
    } catch {
      return null;
    }
  }
}

/** A normal response flagged isError by the server. No payload ran unsandboxed. */
export class ToolError extends CarapaceError {
  readonly result: ToolResult;
  constructor(text: string, result: ToolResult) {
    super(text || "tool returned an error");
    this.result = result;
  }
}

interface Pending {
  resolve: (value: Record<string, unknown>) => void;
  reject: (error: Error) => void;
  timer: unknown;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/** A synchronous-style MCP client bound to one cara-mcp process. */
export class Client {
  private readonly command: string[];
  private readonly timeoutMs: number;
  private readonly cwd?: string;
  private readonly env?: Record<string, string | undefined>;
  private readonly clientName: string;
  private readonly clientVersion: string;

  private proc: ChildProcess | null = null;
  private reader: Interface | null = null;
  private nextId = 0;
  private readonly pending = new Map<number, Pending>();
  private readonly stderrChunks: string[] = [];

  /** The initialize result. Empty until connect()/initialize() resolves. */
  serverInfo: Record<string, unknown> = {};
  /** The protocol version reported by the server. */
  protocolVersion: string | undefined;

  constructor(options: ClientOptions) {
    const argv = typeof options.command === "string"
      ? [options.command]
      : [...options.command];
    if (argv.length === 0 || !argv[0]) {
      throw new Error("command must name a cara-mcp binary");
    }
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (timeoutMs <= 0) {
      throw new Error("timeoutMs must be positive");
    }
    this.command = argv;
    this.timeoutMs = timeoutMs;
    this.cwd = options.cwd;
    this.env = options.env;
    this.clientName = options.clientName ?? "carapace-typescript";
    this.clientVersion = options.clientVersion ?? "0.1.0";
  }

  /** Create a client, spawn the server, and complete the handshake. */
  static async create(options: ClientOptions): Promise<Client> {
    const client = new Client(options);
    try {
      await client.initialize();
      return client;
    } catch (error) {
      await client.close();
      throw error;
    }
  }

  /** Server stderr collected so far. Useful when a connection dies. */
  stderr(): string {
    return this.stderrChunks.join("");
  }

  // ------------------------------------------------------------- lifecycle

  private spawnIfNeeded(): void {
    if (this.proc) return;
    const [command, ...args] = this.command;
    let proc: ChildProcess;
    try {
      proc = spawn(command, args, {
        stdio: ["pipe", "pipe", "pipe"],
        cwd: this.cwd,
        env: this.env,
      });
    } catch (error) {
      throw new CarapaceError(`could not start cara-mcp: ${String(error)}`);
    }
    this.proc = proc;

    const stdout = proc.stdout;
    if (!stdout) {
      throw new CarapaceError("cara-mcp stdout is not a pipe");
    }
    this.reader = createInterface({ input: stdout, crlfDelay: Infinity });
    this.reader.on("line", (line) => this.onLine(line));

    if (proc.stderr) {
      proc.stderr.on("data", (chunk: unknown) => {
        this.stderrChunks.push(String(chunk));
      });
    }
    proc.on("error", (error: unknown) => {
      this.failAll(new ConnectionClosedError(`cara-mcp error: ${String(error)}`));
    });
    proc.on("close", () => {
      this.failAll(new ConnectionClosedError("cara-mcp exited before replying"));
    });
  }

  async close(): Promise<void> {
    const proc = this.proc;
    if (!proc) return;
    this.proc = null;
    this.failAll(new ConnectionClosedError("client closed"));
    if (this.reader) {
      this.reader.close();
      this.reader = null;
    }
    if (proc.stdin) {
      try {
        proc.stdin.end();
      } catch {
        // Already closed.
      }
    }
    if (proc.exitCode === null) {
      try {
        proc.kill();
      } catch {
        // Already exited.
      }
    }
  }

  private failAll(error: Error): void {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }

  // -------------------------------------------------------------- protocol

  private onLine(line: string): void {
    if (!line.trim()) return;
    let message: Record<string, any>;
    try {
      message = JSON.parse(line) as Record<string, any>;
    } catch {
      return;
    }
    if (message === null || typeof message !== "object") return;
    const id = message.id;
    if (typeof id !== "number") return;
    const pending = this.pending.get(id);
    if (!pending) return;
    this.pending.delete(id);
    clearTimeout(pending.timer);
    if (message.error) {
      const error = asRecord(message.error);
      pending.reject(
        new RpcError(Number(error.code ?? -1), String(error.message ?? "unknown error"), error.data),
      );
    } else {
      pending.resolve(asRecord(message.result));
    }
  }

  private send(message: Record<string, unknown>): void {
    const proc = this.proc;
    if (!proc || !proc.stdin) {
      throw new ConnectionClosedError("cara-mcp stdin is not a pipe");
    }
    proc.stdin.write(`${JSON.stringify(message)}\n`);
  }

  private request(
    method: string,
    params?: Record<string, unknown>,
    timeoutMs: number = this.timeoutMs,
  ): Promise<Record<string, unknown>> {
    this.spawnIfNeeded();
    const id = ++this.nextId;
    const message: Record<string, unknown> = { jsonrpc: "2.0", id, method };
    if (params !== undefined) message.params = params;

    return new Promise<Record<string, unknown>>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(
          new CarapaceTimeoutError(`no response to ${method} after ${timeoutMs} ms`),
        );
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.send(message);
      } catch (error) {
        this.pending.delete(id);
        clearTimeout(timer);
        reject(error instanceof Error ? error : new CarapaceError(String(error)));
      }
    });
  }

  private notify(method: string): void {
    this.spawnIfNeeded();
    this.send({ jsonrpc: "2.0", method });
  }

  /** Perform the MCP handshake. Called by create(). */
  async initialize(): Promise<Record<string, unknown>> {
    const result = await this.request("initialize", {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: {
        name: this.clientName,
        version: this.clientVersion,
      },
    });
    this.serverInfo = asRecord(result.serverInfo);
    this.protocolVersion = typeof result.protocolVersion === "string"
      ? result.protocolVersion
      : undefined;
    this.notify("notifications/initialized");
    return this.serverInfo;
  }

  /** Tools advertised by the server. There should be eight. */
  async listTools(): Promise<Array<Record<string, unknown>>> {
    const result = await this.request("tools/list", {});
    return Array.isArray(result.tools) ? (result.tools as Array<Record<string, unknown>>) : [];
  }

  /** Call a tool by name. A flagged result throws ToolError. */
  async callTool(
    name: string,
    arguments_: Record<string, unknown> = {},
    timeoutMs?: number,
  ): Promise<ToolResult> {
    const result = await this.request(
      "tools/call",
      { name, arguments: arguments_ },
      timeoutMs,
    );
    const content = Array.isArray(result.content) ? result.content : [];
    const text = content
      .map((part) => {
        const block = asRecord(part);
        return typeof block.text === "string" ? block.text : "";
      })
      .join("");
    const toolResult = new ToolResult(text, Boolean(result.isError), result);
    if (toolResult.isError) {
      throw new ToolError(text, toolResult);
    }
    return toolResult;
  }

  // ------------------------------------------------------------------ tools

  /** Run code once in a fresh sandbox. result.json is the run report. */
  async runCode(code: string, options: RunOptions = {}): Promise<ToolResult> {
    const args: Record<string, unknown> = { code, language: options.language ?? "sh" };
    if (options.policy) args.policy = options.policy;
    return this.callTool("run_code", args, options.timeoutMs);
  }

  /** Turn a run report into a plain-English explanation. */
  async explainResult(report: Record<string, unknown>): Promise<ToolResult> {
    return this.callTool("explain_result", { report });
  }

  /** Create a server-owned session and return its id. */
  async sessionCreate(policy?: Record<string, unknown>): Promise<string> {
    const args: Record<string, unknown> = {};
    if (policy) args.policy = policy;
    const result = await this.callTool("session_create", args);
    const id = asRecord(result.json).session_id;
    if (typeof id !== "string") {
      throw new CarapaceError("session_create did not return a session_id");
    }
    return id;
  }

  /** Run code with the session's persistent /work mounted. */
  async sessionExec(
    sessionId: string,
    code: string,
    options: { language?: "sh" | "python3"; timeoutMs?: number } = {},
  ): Promise<ToolResult> {
    const args: Record<string, unknown> = {
      session_id: sessionId,
      code,
      language: options.language ?? "sh",
    };
    if (options.timeoutMs !== undefined) args.timeout_ms = options.timeoutMs;
    return this.callTool("session_exec", args, options.timeoutMs);
  }

  /** Write standard base64 content to a relative path in the session. */
  async sessionUpload(
    sessionId: string,
    path: string,
    contentBase64: string,
  ): Promise<ToolResult> {
    return this.callTool("session_upload", {
      session_id: sessionId,
      path,
      content_base64: contentBase64,
    });
  }

  /** Convenience wrapper around sessionUpload for raw bytes. */
  async uploadBytes(sessionId: string, path: string, data: Uint8Array): Promise<ToolResult> {
    return this.sessionUpload(sessionId, path, Buffer.from(data).toString("base64"));
  }

  /** Read a session file and return its decoded bytes. */
  async sessionDownload(sessionId: string, path: string): Promise<Uint8Array> {
    const result = await this.callTool("session_download", {
      session_id: sessionId,
      path,
    });
    const encoded = asRecord(result.json).content_base64;
    if (typeof encoded !== "string") {
      throw new CarapaceError("session_download did not return content_base64");
    }
    return Buffer.from(encoded, "base64");
  }

  /** List sessions owned by this server process. */
  async sessionList(): Promise<ToolResult> {
    return this.callTool("session_list", {});
  }

  /** Stop a session and remove its work directory. */
  async sessionClose(sessionId: string): Promise<ToolResult> {
    return this.callTool("session_close", { session_id: sessionId });
  }
}
