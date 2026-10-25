//! `carapace-mcp`: Model Context Protocol server exposing `run_code` and
//! `explain_result` tools (milestone C7). MCP input is treated as hostile:
//! every field is validated and size-capped before it reaches a sandbox.
//!
//! The wire protocol is line-delimited JSON-RPC 2.0 over stdio (one request
//! per line, one response per line). The server is synchronous on purpose:
//! a sandbox run blocks its `tools/call` until the run ends. The server
//! NEVER runs code unsandboxed — every `run_code` goes through
//! [`NativeBackend::spawn`], whose doctor gate fails closed.

use carapace_core::{Backend, BackendError, ExitReport, KillReason, Policy, SandboxSpec};
use carapace_native::NativeBackend;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::io::{self, BufRead, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

pub const MILESTONE: &str = "C7";

/// MCP protocol version this server speaks.
pub const PROTOCOL_VERSION: &str = "2024-11-05";
/// Server name reported in `initialize`.
pub const SERVER_NAME: &str = "carapace";

/// JSON-RPC: the line is not valid JSON.
pub const PARSE_ERROR: i64 = -32700;
/// JSON-RPC: the line is valid JSON but not a valid JSON-RPC message.
pub const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC: the method does not exist.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC: params are missing, malformed, or fail validation.
pub const INVALID_PARAMS: i64 = -32602;

/// Maximum accepted size of the `code` parameter, in bytes.
pub const MAX_CODE_BYTES: usize = 65536;
/// Maximum accepted `policy.timeout_ms`.
pub const MAX_TIMEOUT_MS: u64 = 600_000;
/// Maximum accepted `policy.memory_mb`.
pub const MAX_MEMORY_MB: u64 = 2048;
/// Maximum accepted `policy.max_processes`.
pub const MAX_PROCESSES: u32 = 512;
/// Maximum size of one incoming JSON-RPC line (the `explain_result` report
/// echoes back captured output, so this must exceed the sandbox output cap
/// with room for JSON escaping).
pub const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum serialized size of the `report` parameter of `explain_result`.
pub const MAX_REPORT_BYTES: usize = 4 * 1024 * 1024;

/// The MCP server: reads JSON-RPC lines from `input`, writes responses to
/// `output`, and runs tool payloads through the real sandbox backend.
pub struct McpServer<R: BufRead, W: Write> {
    input: R,
    output: W,
    backend: NativeBackend,
}

impl<R: BufRead, W: Write> McpServer<R, W> {
    pub fn new(input: R, output: W) -> Self {
        Self {
            input,
            output,
            backend: NativeBackend::new(),
        }
    }

    /// Serves until the input ends (`serve_once` returned `Ok(false)`).
    pub fn serve(&mut self) -> io::Result<()> {
        while self.serve_once()? {}
        Ok(())
    }

    /// Reads and handles exactly one line. `Ok(true)` = keep serving,
    /// `Ok(false)` = input ended or the session must end (an oversized line
    /// is answered once, then the connection is closed — no resync oracle
    /// for hostile input).
    pub fn serve_once(&mut self) -> io::Result<bool> {
        match self.read_line()? {
            Incoming::Eof => Ok(false),
            Incoming::Empty => Ok(true),
            Incoming::TooLong => {
                self.write_error(
                    &Value::Null,
                    INVALID_REQUEST,
                    &format!("request line exceeds the maximum of {MAX_LINE_BYTES} bytes"),
                )?;
                Ok(false)
            }
            Incoming::Text(line) => {
                self.handle_line(&line)?;
                Ok(true)
            }
        }
    }

    /// Reads one `\n`-terminated line, capping buffered bytes at
    /// [`MAX_LINE_BYTES`] so a hostile peer cannot balloon our memory.
    fn read_line(&mut self) -> io::Result<Incoming> {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let chunk = self.input.fill_buf()?;
            if chunk.is_empty() {
                // EOF: an empty buffer is a clean end; anything staged is a
                // final unterminated line (tolerated).
                return Ok(if buf.is_empty() {
                    Incoming::Eof
                } else {
                    finish_line(buf)
                });
            }
            match chunk.iter().position(|&b| b == b'\n') {
                Some(pos) => {
                    buf.extend_from_slice(&chunk[..pos]);
                    self.input.consume(pos + 1);
                    return Ok(finish_line(buf));
                }
                None => {
                    let len = chunk.len();
                    buf.extend_from_slice(chunk);
                    self.input.consume(len);
                    if buf.len() > MAX_LINE_BYTES {
                        return Ok(Incoming::TooLong);
                    }
                }
            }
        }
    }

    /// Validates one parsed line and writes at most one response.
    fn handle_line(&mut self, line: &str) -> io::Result<()> {
        let value: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return self.write_error(&Value::Null, PARSE_ERROR, &format!("parse error: {e}"));
            }
        };
        let Some(obj) = value.as_object() else {
            return self.write_error(
                &Value::Null,
                INVALID_REQUEST,
                "request must be a JSON object",
            );
        };
        // Per JSON-RPC 2.0: a message with an "id" member is a request and
        // gets a response; without one it is a notification and gets none.
        // Echo the id verbatim (string, number, or null).
        let id = obj.get("id").cloned().unwrap_or(Value::Null);
        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return self.write_error(&id, INVALID_REQUEST, "jsonrpc must be \"2.0\"");
        }
        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            return self.write_error(&id, INVALID_REQUEST, "missing method");
        };
        match (method, obj.contains_key("id")) {
            ("initialize", true) => self.write_result(&id, initialize_result()),
            ("tools/list", true) => self.write_result(&id, tools_list_result()),
            ("tools/call", true) => self.tools_call(&id, obj.get("params")),
            // notifications/initialized and any other notification: silent.
            (_, false) => Ok(()),
            _ => self.write_error(
                &id,
                METHOD_NOT_FOUND,
                &format!("method not found: {method}"),
            ),
        }
    }

    /// `tools/call`: dispatch by `params.name`.
    fn tools_call(&mut self, id: &Value, params: Option<&Value>) -> io::Result<()> {
        let Some(params) = params else {
            return self.write_error(id, INVALID_PARAMS, "tools/call requires params");
        };
        let Some(obj) = params.as_object() else {
            return self.write_error(id, INVALID_PARAMS, "tools/call params must be an object");
        };
        let Some(name) = obj.get("name").and_then(Value::as_str) else {
            return self.write_error(
                id,
                INVALID_PARAMS,
                "tools/call params.name must be a string",
            );
        };
        let no_arguments = Value::Object(Map::new());
        let arguments = obj.get("arguments").unwrap_or(&no_arguments);
        match name {
            "run_code" => self.run_code(id, arguments),
            "explain_result" => self.explain_result(id, arguments),
            other => self.write_error(id, INVALID_PARAMS, &format!("unknown tool: {other:?}")),
        }
    }

    /// Tool `run_code`: validate, stage, sandbox, report. Never runs
    /// unsandboxed: a refused spawn is a tool error, not a fallback. Bad
    /// params are JSON-RPC `-32602` errors, not tool results.
    fn run_code(&mut self, id: &Value, arguments: &Value) -> io::Result<()> {
        let params = match validate_run_code_args(arguments) {
            Ok(p) => p,
            Err(message) => return self.write_error(id, INVALID_PARAMS, &message),
        };
        let result = match execute_run_code(&self.backend, &params) {
            RunOutcome::Report(report) => json!({
                "content": [{"type": "text", "text": report_to_json(&report).to_string()}],
                "isError": report.kill_reason.is_some(),
            }),
            RunOutcome::Failed(message) => tool_error(message),
        };
        self.write_result(id, result)
    }

    /// Tool `explain_result`: plain-English reading of a run report.
    /// Pure: no I/O, no sandbox. Bad params are JSON-RPC `-32602` errors.
    fn explain_result(&mut self, id: &Value, arguments: &Value) -> io::Result<()> {
        let report = match validate_explain_args(arguments) {
            Ok(r) => r,
            Err(message) => return self.write_error(id, INVALID_PARAMS, &message),
        };
        let result = json!({
            "content": [{"type": "text", "text": explain_report(&report)}],
        });
        self.write_result(id, result)
    }

    fn write_result(&mut self, id: &Value, result: Value) -> io::Result<()> {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "result": result}))
    }

    fn write_error(&mut self, id: &Value, code: i64, message: &str) -> io::Result<()> {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": code, "message": message},
        }))
    }

    fn send(&mut self, response: &Value) -> io::Result<()> {
        let mut line = serde_json::to_string(response).expect("a JSON value always serializes");
        line.push('\n');
        self.output.write_all(line.as_bytes())?;
        self.output.flush()
    }
}

/// One line pulled off the input.
enum Incoming {
    Text(String),
    /// Whitespace only: skip without a response.
    Empty,
    /// Longer than [`MAX_LINE_BYTES`].
    TooLong,
    Eof,
}

fn finish_line(mut buf: Vec<u8>) -> Incoming {
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    if buf.iter().all(u8::is_ascii_whitespace) {
        return Incoming::Empty;
    }
    Incoming::Text(String::from_utf8_lossy(&buf).into_owned())
}

/// `initialize` result: the MCP surface this server supports.
fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools": {}},
        "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
    })
}

/// `tools/list` result: exactly two tools.
fn tools_list_result() -> Value {
    json!({
        "tools": [
            {
                "name": "run_code",
                "description": "Run a short shell or Python program inside the Carapace sandbox \
                                (Linux namespaces, cgroups, seccomp; no network, no host writes) \
                                and get its exit status and captured output back. The code is \
                                always executed strictly sandboxed, never unsandboxed.",
                "inputSchema": {
                    "type": "object",
                    "required": ["code"],
                    "properties": {
                        "code": {
                            "type": "string",
                            "maxLength": MAX_CODE_BYTES,
                            "description": "The code to execute. Must not contain NUL bytes.",
                        },
                        "language": {
                            "type": "string",
                            "enum": ["sh", "python3"],
                            "description": "Interpreter for `code`. Defaults to \"sh\".",
                        },
                        "policy": {
                            "type": "object",
                            "additionalProperties": false,
                            "description": "Optional overrides on top of the strict policy.",
                            "properties": {
                                "timeout_ms": {
                                    "type": "integer",
                                    "maximum": MAX_TIMEOUT_MS,
                                    "description": "Wall-clock limit for the run.",
                                },
                                "memory_mb": {
                                    "type": "integer",
                                    "maximum": MAX_MEMORY_MB,
                                    "description": "Memory cap in MiB (exceeding it is an OOM kill).",
                                },
                                "max_processes": {
                                    "type": "integer",
                                    "maximum": MAX_PROCESSES,
                                    "description": "Maximum processes in the sandbox.",
                                },
                            },
                        },
                    },
                },
            },
            {
                "name": "explain_result",
                "description": "Explain a Carapace sandbox run report (as returned by run_code) \
                                in plain English: how the run ended, what a kill reason means, \
                                and what to try next.",
                "inputSchema": {
                    "type": "object",
                    "required": ["report"],
                    "properties": {
                        "report": {
                            "type": "object",
                            "description": "A run report object as returned by run_code.",
                        },
                    },
                },
            },
        ],
    })
}

/// An MCP tool-level error: a normal result flagged `isError` so the client
/// shows it to the model instead of treating it as a transport failure.
fn tool_error(message: String) -> Value {
    json!({"content": [{"type": "text", "text": message}], "isError": true})
}

// ------------------------------------------------------------------ run_code

#[derive(Debug)]
struct RunCodeParams {
    code: String,
    python3: bool,
    timeout_ms: Option<u64>,
    memory_mb: Option<u64>,
    max_processes: Option<u32>,
}

/// The `policy` object: strict surface, unknown fields rejected.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyOverrides {
    timeout_ms: Option<u64>,
    memory_mb: Option<u64>,
    max_processes: Option<u32>,
}

/// Validates `run_code` arguments (a pure function: never touches the
/// sandbox). Every failure is an [`INVALID_PARAMS`] JSON-RPC error.
fn validate_run_code_args(args: &Value) -> Result<RunCodeParams, String> {
    let Some(obj) = args.as_object() else {
        return Err("run_code arguments must be an object".to_string());
    };
    let Some(code) = obj.get("code") else {
        return Err("run_code: missing required parameter \"code\"".to_string());
    };
    let Some(code) = code.as_str() else {
        return Err("run_code: \"code\" must be a string".to_string());
    };
    if code.len() > MAX_CODE_BYTES {
        return Err(format!(
            "run_code: \"code\" is {} bytes; the maximum is {MAX_CODE_BYTES}",
            code.len()
        ));
    }
    if code.as_bytes().contains(&0) {
        return Err("run_code: \"code\" must not contain NUL bytes".to_string());
    }
    let python3 = match obj.get("language") {
        None | Some(Value::Null) => false,
        Some(Value::String(s)) => match s.as_str() {
            "sh" => false,
            "python3" => true,
            other => {
                return Err(format!(
                    "run_code: unknown language {other:?} (expected \"sh\" or \"python3\")"
                ));
            }
        },
        Some(_) => return Err("run_code: \"language\" must be a string".to_string()),
    };
    let (mut timeout_ms, mut memory_mb, mut max_processes) = (None, None, None);
    if let Some(policy) = obj.get("policy").filter(|v| !v.is_null()) {
        let overrides: PolicyOverrides =
            serde_json::from_value(policy.clone()).map_err(|e| format!("run_code: policy: {e}"))?;
        if let Some(t) = overrides.timeout_ms {
            if t == 0 {
                return Err("run_code: policy.timeout_ms must be at least 1".to_string());
            }
            if t > MAX_TIMEOUT_MS {
                return Err(format!(
                    "run_code: policy.timeout_ms {t} exceeds the maximum of {MAX_TIMEOUT_MS}"
                ));
            }
            timeout_ms = Some(t);
        }
        if let Some(m) = overrides.memory_mb {
            if m == 0 {
                return Err("run_code: policy.memory_mb must be at least 1".to_string());
            }
            if m > MAX_MEMORY_MB {
                return Err(format!(
                    "run_code: policy.memory_mb {m} exceeds the maximum of {MAX_MEMORY_MB}"
                ));
            }
            memory_mb = Some(m);
        }
        if let Some(n) = overrides.max_processes {
            if n == 0 {
                return Err("run_code: policy.max_processes must be at least 1".to_string());
            }
            if n > MAX_PROCESSES {
                return Err(format!(
                    "run_code: policy.max_processes {n} exceeds the maximum of {MAX_PROCESSES}"
                ));
            }
            max_processes = Some(n);
        }
    }
    Ok(RunCodeParams {
        code: code.to_string(),
        python3,
        timeout_ms,
        memory_mb,
        max_processes,
    })
}

/// The outcome of one sandboxed run: a full report, or a tool-level error
/// (which always means the payload did not run unsandboxed).
enum RunOutcome {
    Report(ExitReport),
    Failed(String),
}

fn execute_run_code(backend: &NativeBackend, params: &RunCodeParams) -> RunOutcome {
    if params.python3 && !Path::new("/usr/bin/python3").exists() {
        return RunOutcome::Failed(
            "python3 is not available at /usr/bin/python3 on this host".to_string(),
        );
    }
    // The staged file is deleted on every path out of this function (the
    // guard's Drop runs on returns, errors, and panics alike).
    let staged = match StagedCode::create(&params.code) {
        Ok(s) => s,
        Err(e) => return RunOutcome::Failed(format!("failed to stage the code file: {e}")),
    };
    let spec = build_spec(staged.code_path(), params);
    match backend.spawn(&spec) {
        Err(BackendError::EnvironmentNotReady(details)) => RunOutcome::Failed(format!(
            "the sandbox environment is not ready, so the code was NOT run; \
             run `cara doctor` to see what is missing ({details})"
        )),
        Err(e) => RunOutcome::Failed(format!("sandbox error: {e}")),
        Ok(mut handle) => match handle.wait() {
            Ok(report) => RunOutcome::Report(report),
            Err(e) => RunOutcome::Failed(format!("sandbox supervision failed: {e}")),
        },
    }
}

/// Builds the sandbox spec for one staged run: strict policy plus the
/// caller's limit overrides, a fixed minimal environment, and a read-only
/// bind of the staged code.
fn build_spec(code_path: &Path, params: &RunCodeParams) -> SandboxSpec {
    let mut policy = Policy::strict();
    if let Some(t) = params.timeout_ms {
        policy.limits.timeout = Duration::from_millis(t);
    }
    if let Some(m) = params.memory_mb {
        policy.limits.memory_bytes = m * 1024 * 1024;
    }
    if let Some(n) = params.max_processes {
        policy.limits.max_processes = n;
    }
    let (program, args): (&str, Vec<String>) = if params.python3 {
        ("/usr/bin/python3", vec![code_path.display().to_string()])
    } else {
        (
            "/bin/sh",
            vec!["-c".to_string(), code_path.display().to_string()],
        )
    };
    let mut spec = policy.to_spec(program, &args);
    // Make the staged code visible inside the sandbox: the child's mount
    // recipe creates each bind attach-point with mkdir(2), so single files
    // cannot be bound — bind the uniquely-named parent directory instead
    // (read-only; nothing else on the host is exposed).
    let dir = code_path
        .parent()
        .expect("the staged code path always has a parent directory")
        .to_path_buf();
    spec.read_only.push(dir);
    spec.env
        .insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    spec.env.insert("HOME".to_string(), "/work".to_string());
    spec
}

/// A uniquely-named, mode-0700 directory under [`std::env::temp_dir`] holding
/// the staged `code` file (mode 0700, created with O_EXCL). Removed on drop,
/// so the host stays clean on every path: run finished, spawn refused, or
/// panic unwind. The whole directory is deleted, never just the file.
struct StagedCode {
    dir: PathBuf,
    code_path: PathBuf,
}

impl StagedCode {
    fn create(code: &str) -> io::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let base = std::env::temp_dir();
        let mut last_err: Option<io::Error> = None;
        for _ in 0..8 {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = base.join(format!("cara-mcp-{}-{n}", std::process::id()));
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            if let Err(e) = builder.create(&dir) {
                last_err = Some(e);
                continue; // name taken or base unwritable: try the next name
            }
            let code_path = dir.join("code");
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            options.mode(0o700);
            let mut file = options.open(&code_path)?;
            file.write_all(code.as_bytes())?;
            return Ok(Self { dir, code_path });
        }
        Err(last_err
            .unwrap_or_else(|| io::Error::other("could not create a unique temp directory")))
    }

    fn code_path(&self) -> &Path {
        &self.code_path
    }
}

impl Drop for StagedCode {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The tool result body for a finished run: the report as JSON text.
/// Mirrors the documented kill-reason strings of `cara run --json`.
fn report_to_json(report: &ExitReport) -> Value {
    json!({
        "exit_code": report.exit_code,
        "signal": report.signal,
        "kill_reason": match &report.kill_reason {
            None => Value::Null,
            Some(KillReason::Timeout) => json!("timeout"),
            Some(KillReason::OutputOverflow) => json!("output_overflow"),
            Some(KillReason::MemoryLimit) => json!("memory_limit"),
            Some(KillReason::CpuLimit) => json!("cpu_limit"),
            Some(KillReason::Internal(m)) => json!(format!("internal: {m}")),
        },
        "stdout": String::from_utf8_lossy(&report.stdout),
        "stderr": String::from_utf8_lossy(&report.stderr),
        "wall_time_ms": report.wall_time.as_millis() as u64,
        "cpu_time_ms": report.cpu_time.map(|d| d.as_millis() as u64),
        "peak_memory_bytes": report.peak_memory_bytes,
    })
}

// ------------------------------------------------------------ explain_result

/// Validates `explain_result` arguments. Returns a clone of the report
/// object (capped at [`MAX_REPORT_BYTES`] serialized bytes).
fn validate_explain_args(args: &Value) -> Result<Value, String> {
    let Some(obj) = args.as_object() else {
        return Err("explain_result arguments must be an object".to_string());
    };
    let Some(report) = obj.get("report") else {
        return Err("explain_result: missing required parameter \"report\"".to_string());
    };
    if !report.is_object() {
        return Err("explain_result: \"report\" must be an object".to_string());
    }
    let size = serde_json::to_string(report)
        .map_err(|e| format!("explain_result: \"report\" is not serializable: {e}"))?
        .len();
    if size > MAX_REPORT_BYTES {
        return Err(format!(
            "explain_result: \"report\" is {size} bytes; the maximum is {MAX_REPORT_BYTES}"
        ));
    }
    Ok(report.clone())
}

/// Plain-English explanation of a run report. Tolerant by design: it reads
/// the fields it knows and never panics on a partial or foreign report.
fn explain_report(report: &Value) -> String {
    let kill_reason = report.get("kill_reason").and_then(Value::as_str);
    let exit_code = report.get("exit_code").and_then(Value::as_i64);
    let signal = report.get("signal").and_then(Value::as_i64);
    let stdout_len = report
        .get("stdout")
        .and_then(Value::as_str)
        .map_or(0, str::len);
    let stderr_len = report
        .get("stderr")
        .and_then(Value::as_str)
        .map_or(0, str::len);

    let mut out = String::new();
    match kill_reason {
        Some("timeout") => out.push_str(
            "The sandbox killed the run: it exceeded its wall-clock time limit. \
             The program was probably stuck in an infinite loop or waiting on \
             something that never happened. To allow more time, raise \
             policy.timeout_ms (maximum 600000).\n",
        ),
        Some("output_overflow") => out.push_str(
            "The sandbox killed the run: it wrote more to stdout or stderr than \
             the capture cap allows. Print less, or run with a larger output \
             limit via a policy file.\n",
        ),
        Some("cpu_limit") => out.push_str(
            "The sandbox killed the run: it consumed more CPU than its fuel \
             budget allows. Do less work, or run with a larger cpu/timeout \
             policy.
",
        ),
        Some("memory_limit") => out.push_str(
            "The kernel killed the run for using more memory than its cgroup \
             allows (OOM kill). Use less memory, or raise policy.memory_mb \
             (maximum 2048).\n",
        ),
        Some(other) if other.starts_with("internal:") => {
            out.push_str(
                "Carapace itself failed while setting up or supervising the run, \
                 so the program may not have run at all. This is a sandbox or \
                 environment problem, not a property of the code: ",
            );
            out.push_str(other);
            out.push('\n');
        }
        Some(other) => {
            out.push_str("The run was terminated by the sandbox: ");
            out.push_str(other);
            out.push('\n');
        }
        None => match (exit_code, signal) {
            (Some(0), _) => out.push_str(
                "The program ran to completion and exited successfully (exit code 0). \
                 The sandbox did not intervene.\n",
            ),
            (Some(code), _) => out.push_str(&format!(
                "The program ran to completion and exited with code {code}. \
                 A non-zero exit code usually means the program failed; check \
                 its stderr for the error message.\n"
            )),
            (None, Some(s)) => out.push_str(&format!(
                "The program died from signal {s} without exiting on its own \
                 (for example after hitting a resource limit itself).\n"
            )),
            _ => out.push_str("The report does not record how the run ended.\n"),
        },
    }
    out.push_str(&format!(
        "Captured output: {stdout_len} bytes of stdout, {stderr_len} bytes of stderr.\n"
    ));
    out
}

// --------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Serves the given request lines against an in-memory server and
    /// returns every response line, parsed. No sandbox spawns here: unit
    /// tests only exercise protocol and validation paths.
    fn serve_requests(requests: &[&str]) -> Vec<Value> {
        let mut input = requests.join("\n");
        input.push('\n');
        let mut out: Vec<u8> = Vec::new();
        {
            let mut server = McpServer::new(Cursor::new(input.into_bytes()), &mut out);
            server.serve().expect("in-memory serve must not fail");
        }
        String::from_utf8_lossy(&out)
            .lines()
            .map(|l| serde_json::from_str(l).expect("every response line is valid JSON"))
            .collect()
    }

    /// One `tools/call` round-trip for the given tool and arguments.
    fn tool_call(tool: &str, arguments: &str) -> Value {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"{tool}","arguments":{arguments}}}}}"#
        );
        serve_requests(&[&line])
            .pop()
            .expect("tools/call always produces exactly one response")
    }

    #[test]
    fn initialize_round_trips() {
        let responses =
            serve_requests(&[r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#]);
        assert_eq!(responses.len(), 1);
        let r = &responses[0];
        assert_eq!(r["jsonrpc"], "2.0");
        assert_eq!(r["id"], 1);
        assert_eq!(r["result"]["protocolVersion"], "2024-11-05");
        assert!(r["result"]["capabilities"]["tools"].is_object());
        assert_eq!(r["result"]["serverInfo"]["name"], "carapace");
        assert_eq!(
            r["result"]["serverInfo"]["version"],
            env!("CARGO_PKG_VERSION")
        );
    }

    #[test]
    fn id_is_echoed_verbatim() {
        let responses = serve_requests(&[
            r#"{"jsonrpc":"2.0","id":"client-1","method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":42,"method":"tools/list"}"#,
        ]);
        assert_eq!(responses[0]["id"], "client-1");
        assert_eq!(responses[1]["id"], 42);
    }

    #[test]
    fn notifications_are_silent() {
        let responses = serve_requests(&[
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/whatever"}"#,
        ]);
        assert!(responses.is_empty());
    }

    #[test]
    fn tools_list_has_exactly_two_tools() {
        let responses = serve_requests(&[r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#]);
        let tools = responses[0]["result"]["tools"]
            .as_array()
            .expect("tools must be an array");
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "run_code");
        assert_eq!(tools[1]["name"], "explain_result");
        let schema = &tools[0]["inputSchema"];
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["required"], json!(["code"]));
        assert_eq!(
            schema["properties"]["language"]["enum"],
            json!(["sh", "python3"])
        );
        assert_eq!(
            schema["properties"]["policy"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["policy"]["properties"]["timeout_ms"]["maximum"],
            600_000
        );
        assert_eq!(tools[1]["inputSchema"]["required"], json!(["report"]));
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let responses = serve_requests(&[r#"{"jsonrpc":"2.0","id":7,"method":"resources/list"}"#]);
        assert_eq!(responses[0]["id"], 7);
        assert_eq!(responses[0]["error"]["code"], -32601);
    }

    #[test]
    fn broken_json_is_a_parse_error() {
        let responses = serve_requests(&["{definitely not json"]);
        assert_eq!(responses.len(), 1);
        assert!(responses[0]["id"].is_null());
        assert_eq!(responses[0]["error"]["code"], -32700);
    }

    #[test]
    fn malformed_requests_are_invalid() {
        for line in [
            "[1,2,3]",
            r#"{"jsonrpc":"1.0","id":2,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":3}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":5}"#,
        ] {
            let responses = serve_requests(&[line]);
            assert_eq!(responses[0]["error"]["code"], -32600, "{line}");
        }
    }

    #[test]
    fn run_code_rejects_missing_or_mistyped_code() {
        for arguments in ["{}", r#"{"code":42}"#, "null", r#""just a string""#] {
            let r = tool_call("run_code", arguments);
            assert_eq!(r["error"]["code"], -32602, "{arguments}");
        }
    }

    #[test]
    fn run_code_rejects_oversized_code() {
        let code = "x".repeat(MAX_CODE_BYTES + 1);
        let r = tool_call("run_code", &format!(r#"{{"code":"{code}"}}"#));
        assert_eq!(r["error"]["code"], -32602);
        assert!(r["error"]["message"].as_str().unwrap().contains("maximum"));
    }

    #[test]
    fn run_code_rejects_interior_nul() {
        let r = tool_call("run_code", r#"{"code":"echo a\u0000rm -rf /"}"#);
        assert_eq!(r["error"]["code"], -32602);
        assert!(r["error"]["message"].as_str().unwrap().contains("NUL"));
    }

    #[test]
    fn run_code_rejects_bad_language() {
        let r = tool_call("run_code", r#"{"code":"puts 1","language":"ruby"}"#);
        assert_eq!(r["error"]["code"], -32602);
        assert!(r["error"]["message"].as_str().unwrap().contains("ruby"));
    }

    #[test]
    fn run_code_rejects_unknown_policy_fields() {
        let r = tool_call("run_code", r#"{"code":"true","policy":{"network":"full"}}"#);
        assert_eq!(r["error"]["code"], -32602);
        assert!(
            r["error"]["message"]
                .as_str()
                .unwrap()
                .contains("unknown field")
        );
    }

    #[test]
    fn run_code_rejects_policy_caps() {
        for arguments in [
            r#"{"code":"true","policy":{"timeout_ms":600001}}"#,
            r#"{"code":"true","policy":{"memory_mb":2049}}"#,
            r#"{"code":"true","policy":{"max_processes":513}}"#,
            r#"{"code":"true","policy":{"timeout_ms":0}}"#,
            r#"{"code":"true","policy":"sneaky"}"#,
        ] {
            let r = tool_call("run_code", arguments);
            assert_eq!(r["error"]["code"], -32602, "{arguments}");
        }
    }

    #[test]
    fn run_code_accepts_valid_params_and_defaults() {
        let args: Value = serde_json::from_str(
            r#"{"code":"echo hi","language":"python3",
                "policy":{"timeout_ms":1000,"memory_mb":64,"max_processes":8}}"#,
        )
        .unwrap();
        let p = validate_run_code_args(&args).expect("valid arguments");
        assert_eq!(p.code, "echo hi");
        assert!(p.python3);
        assert_eq!(p.timeout_ms, Some(1000));
        assert_eq!(p.memory_mb, Some(64));
        assert_eq!(p.max_processes, Some(8));

        let args: Value = serde_json::from_str(r#"{"code":"echo hi"}"#).unwrap();
        let p = validate_run_code_args(&args).expect("valid arguments");
        assert!(!p.python3);
        assert!(p.timeout_ms.is_none());
        assert!(p.memory_mb.is_none());
        assert!(p.max_processes.is_none());

        // boundary values are accepted
        let args: Value = serde_json::from_str(
            r#"{"code":"","policy":{"timeout_ms":600000,"memory_mb":2048,"max_processes":512}}"#,
        )
        .unwrap();
        let p = validate_run_code_args(&args).expect("boundary values valid");
        assert_eq!(p.timeout_ms, Some(MAX_TIMEOUT_MS));
        assert_eq!(p.code, "");
    }

    #[test]
    fn build_spec_uses_strict_base_with_overrides_and_minimal_env() {
        let params = RunCodeParams {
            code: "echo hi".to_string(),
            python3: false,
            timeout_ms: Some(1234),
            memory_mb: Some(128),
            max_processes: Some(16),
        };
        let dir = std::env::temp_dir().join("cara-mcp-spec-test");
        let code_path = dir.join("code");
        let spec = build_spec(&code_path, &params);
        assert_eq!(spec.program, "/bin/sh");
        assert_eq!(
            spec.args,
            vec!["-c".to_string(), code_path.display().to_string()]
        );
        assert_eq!(spec.limits.timeout, Duration::from_millis(1234));
        assert_eq!(spec.limits.memory_bytes, 128 * 1024 * 1024);
        assert_eq!(spec.limits.max_processes, 16);
        // untouched strict fields stay strict
        assert_eq!(
            spec.limits.max_output_bytes,
            Policy::strict().limits.max_output_bytes
        );
        assert_eq!(spec.env.get("PATH").unwrap(), "/usr/bin:/bin");
        assert_eq!(spec.env.get("HOME").unwrap(), "/work");
        assert_eq!(spec.env.len(), 2);
        // the staged parent dir is bound read-only so the code is visible
        assert_eq!(spec.read_only, vec![dir]);
        assert!(spec.read_write.is_empty());

        let python = RunCodeParams {
            python3: true,
            ..params
        };
        let spec = build_spec(&code_path, &python);
        assert_eq!(spec.program, "/usr/bin/python3");
        assert_eq!(spec.args, vec![code_path.display().to_string()]);
    }

    #[test]
    fn unknown_tool_is_invalid_params() {
        let r = tool_call("rm_rf_home", "{}");
        assert_eq!(r["error"]["code"], -32602);
        assert!(
            r["error"]["message"]
                .as_str()
                .unwrap()
                .contains("rm_rf_home")
        );
    }

    #[test]
    fn tools_call_without_params_is_invalid() {
        let responses = serve_requests(&[r#"{"jsonrpc":"2.0","id":5,"method":"tools/call"}"#]);
        assert_eq!(responses[0]["error"]["code"], -32602);
    }

    #[test]
    fn explain_result_describes_success() {
        let r = tool_call(
            "explain_result",
            r#"{"report":{"exit_code":0,"signal":null,"kill_reason":null,"stdout":"hello\n","stderr":""}}"#,
        );
        let text = r["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.contains("exit code 0"), "{text}");
        assert!(text.contains("stdout"), "{text}");
    }

    #[test]
    fn explain_result_describes_kill_reasons() {
        for (reason, needle) in [
            ("timeout", "wall-clock time limit"),
            ("output_overflow", "capture cap"),
            ("memory_limit", "OOM"),
        ] {
            let r = tool_call(
                "explain_result",
                &format!(r#"{{"report":{{"kill_reason":"{reason}","exit_code":null}}}}"#),
            );
            let text = r["result"]["content"][0]["text"]
                .as_str()
                .expect("text content");
            assert!(text.contains(needle), "{reason}: {text}");
        }
        let r = tool_call(
            "explain_result",
            r#"{"report":{"kill_reason":"internal: something broke","exit_code":null}}"#,
        );
        let text = r["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.contains("something broke"), "{text}");
    }

    #[test]
    fn explain_result_describes_nonzero_exit_and_signal() {
        let r = tool_call(
            "explain_result",
            r#"{"report":{"exit_code":2,"kill_reason":null,"stderr":"boom"}}"#,
        );
        let text = r["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.contains("code 2"), "{text}");

        let r = tool_call(
            "explain_result",
            r#"{"report":{"exit_code":null,"signal":9,"kill_reason":null}}"#,
        );
        let text = r["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.contains("signal 9"), "{text}");
    }

    #[test]
    fn explain_result_rejects_bad_params() {
        for arguments in ["{}", r#"{"report":"not an object"}"#, r#"{"report":[1]}"#] {
            let r = tool_call("explain_result", arguments);
            assert_eq!(r["error"]["code"], -32602, "{arguments}");
        }
    }

    #[test]
    fn explain_result_rejects_oversized_report() {
        let oversized = "x".repeat(MAX_REPORT_BYTES + 1);
        let r = tool_call(
            "explain_result",
            &format!(r#"{{"report":{{"stdout":"{oversized}"}}}}"#),
        );
        assert_eq!(r["error"]["code"], -32602);
    }

    #[test]
    fn explain_report_tolerates_foreign_objects() {
        let text = explain_report(&json!({"something": "else"}));
        assert!(text.contains("does not record"), "{text}");
        let text = explain_report(&json!({}));
        assert!(text.contains("does not record"), "{text}");
    }

    #[test]
    fn report_to_json_matches_the_documented_shape() {
        let report = ExitReport {
            exit_code: Some(0),
            signal: None,
            kill_reason: None,
            wall_time: Duration::from_millis(7),
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
            cpu_time: Some(Duration::from_millis(3)),
            peak_memory_bytes: Some(4096),
            peak_processes: Some(2),
        };
        let v = report_to_json(&report);
        assert_eq!(v["exit_code"], 0);
        assert!(v["signal"].is_null());
        assert!(v["kill_reason"].is_null());
        assert_eq!(v["stdout"], "out");
        assert_eq!(v["stderr"], "err");
        assert_eq!(v["wall_time_ms"], 7);
        assert_eq!(v["cpu_time_ms"], 3);
        assert_eq!(v["peak_memory_bytes"], 4096);
        assert!(
            v.get("peak_processes").is_none(),
            "not part of the MCP surface"
        );
    }

    #[test]
    fn serve_ends_on_eof() {
        let mut out: Vec<u8> = Vec::new();
        let mut server = McpServer::new(Cursor::new(Vec::new()), &mut out);
        server.serve().expect("EOF is a clean end");
        assert!(out.is_empty());
    }

    #[test]
    fn blank_lines_are_skipped_without_response() {
        let responses = serve_requests(&["", "   ", "\t"]);
        assert!(responses.is_empty());
    }

    #[test]
    fn oversized_line_is_answered_once_and_ends_the_session() {
        let big = "x".repeat(MAX_LINE_BYTES + 1);
        let mut out: Vec<u8> = Vec::new();
        {
            let mut server = McpServer::new(Cursor::new(big.into_bytes()), &mut out);
            assert!(
                !server
                    .serve_once()
                    .expect("oversize handling must not error")
            );
            assert!(!server.serve_once().expect("input is exhausted"));
        }
        let responses: Vec<Value> = String::from_utf8_lossy(&out)
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["error"]["code"], -32600);
    }

    #[test]
    fn crlf_lines_are_tolerated() {
        let mut out: Vec<u8> = Vec::new();
        {
            let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\r\n";
            let mut server = McpServer::new(Cursor::new(input.to_vec()), &mut out);
            assert!(server.serve_once().expect("one line handled"));
        }
        let r: Value = serde_json::from_str(&String::from_utf8_lossy(&out)).unwrap();
        assert_eq!(r["result"]["tools"].as_array().unwrap().len(), 2);
    }
}
