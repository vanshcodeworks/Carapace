// Minimal ambient declarations for the Node builtins this SDK uses.
// tsconfig.json sets "types": [], so building needs no @types/node package.
// Only the calls made by client.ts are declared here.

declare module "node:child_process" {
  export interface WritableLike {
    write(chunk: string): boolean;
    end(): void;
  }
  export interface SpawnOptions {
    cwd?: string;
    env?: Record<string, string | undefined>;
    stdio?: readonly string[];
  }
  export interface ChildProcess {
    stdin: WritableLike | null;
    stdout: import("node:stream").Readable | null;
    stderr: import("node:stream").Readable | null;
    exitCode: number | null;
    on(event: string, listener: (...args: any[]) => void): ChildProcess;
    kill(signal?: string): boolean;
  }
  export function spawn(
    command: string,
    args?: readonly string[],
    options?: SpawnOptions,
  ): ChildProcess;
}

declare module "node:stream" {
  export interface Readable {
    on(event: string, listener: (...args: any[]) => void): this;
  }
}

declare module "node:readline" {
  export interface Interface {
    on(event: "line", listener: (line: string) => void): Interface;
    close(): void;
  }
  export function createInterface(options: {
    input: unknown;
    crlfDelay?: number;
  }): Interface;
}

declare module "node:buffer" {
  export class Buffer extends Uint8Array {
    static from(data: Uint8Array | string, encoding?: string): Buffer;
    toString(encoding?: string): string;
  }
}

declare function setTimeout(callback: () => void, ms: number): unknown;
declare function clearTimeout(handle: unknown): void;
