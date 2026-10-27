//! Persistent sandbox sessions (P3).
//!
//! A session is a long-lived *keeper* process that owns one size-capped
//! tmpfs (`/work`) and one cgroup leaf. Each `session exec` forks a fresh
//! sandbox from the keeper (new mount/pid/ipc/uts/net namespaces, same
//! user namespace), binds the keeper's tmpfs at `/work`, and runs exactly
//! one payload under the usual Landlock + seccomp + rlimit stack. Files
//! written by one exec are visible to the next; processes are not.
//!
//! Why a keeper instead of a daemon: the keeper is spawned by the same
//! binary (`cara __session-keeper`), is rootless, lives in the caller's
//! delegated cgroup, and is attached to its leaf *before* it unshares, so
//! the kernel enforces the session limits for every exec. If the keeper
//! dies, the existing PDEATHSIG chain (keeper -> stage-1 -> pidns init)
//! kills the running payload; no orphan can outlive it.
//!
//! Host <-> keeper protocol: a UNIX socket (mode 0600) with a 4-byte
//! big-endian length + JSON frame. `put`/`get` stream raw bytes after the
//! frame. Every path is relative to the session tmpfs and resolved with
//! `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`;
//! absolute paths, `..`, and symlinks are refused.

use carapace_core::KillReason;
use carapace_core::policy::{NetworkMode, Policy};
use carapace_core::spec::{Limits, SandboxSpec};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fmt;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::supervisor::{SpawnOptions, spawn_with};

/// Hidden argv[1] understood by `cara` and `cara-mcp`.
pub const KEEPER_ARG: &str = "__session-keeper";

/// Maximum JSON request frame (the `put` header is tiny).
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
/// Maximum JSON response frame. Exec output is base64-expanded, so this
/// is larger than the raw output cap.
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
/// Upload/download cap. Larger files stay inside the session and can be
/// manipulated by `session exec`; they are not streamed over the socket.
pub const MAX_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
/// Upper bound on a single exec's wall clock.
const MAX_SESSION_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;
/// Upper bound on captured stdout/stderr per stream for a session. The
/// keeper buffers output inside the session cgroup; a larger cap would
/// let output accounting eat the payload's memory budget.
const MAX_SESSION_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// The keeper itself lives in the session cgroup, so the memory limit
/// must leave room for its runtime plus output buffering.
const MIN_SESSION_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
/// Keeper + stage-1 + stage-2 + payload at minimum.
const MIN_SESSION_PROCESSES: u32 = 8;
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_LIST_ENTRIES: usize = 10_000;

// ------------------------------------------------------------------ errors

#[derive(Debug)]
pub enum SessionError {
    Io(std::io::Error),
    Protocol(String),
    Remote(String),
    Invalid(String),
    NotFound(String),
    Environment(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Protocol(m) => write!(f, "session protocol: {m}"),
            Self::Remote(m) => write!(f, "{m}"),
            Self::Invalid(m) => write!(f, "{m}"),
            Self::NotFound(m) => write!(f, "{m}"),
            Self::Environment(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<std::io::Error> for SessionError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type SessionResult<T> = Result<T, SessionError>;

// ------------------------------------------------------------- wire types

/// The policy surface of a session. Mirrors [`Policy`] but serializable and
/// explicit about the pieces the keeper needs after the host process is
/// gone. Unknown fields are rejected: a typo in a stored spec is an error,
/// never a silent default.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPolicy {
    pub env: BTreeMap<String, String>,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    pub scratch_bytes: u64,
    pub memory_bytes: u64,
    pub cpu_percent: u32,
    pub max_processes: u32,
    /// `"none"` or `"full"`; `allowlist` fails closed (ADR-0004).
    pub network: String,
    pub exec_on_write: bool,
    pub read_only: Vec<String>,
    pub read_write: Vec<String>,
}

impl SessionPolicy {
    /// Converts a validated [`Policy`] into the keeper's wire form.
    pub fn from_policy(policy: &Policy) -> SessionResult<Self> {
        let network = match &policy.network {
            NetworkMode::None => "none".to_string(),
            NetworkMode::Full => "full".to_string(),
            NetworkMode::Allowlist(_) => {
                return Err(SessionError::Invalid(
                    "network mode \"allowlist\" is not implemented yet (ADR-0004); \
                     use mode = \"none\" or \"full\""
                        .to_string(),
                ));
            }
        };
        let env = policy.to_spec("", &[]).env;
        let out = Self {
            env,
            timeout_ms: policy.limits.timeout.as_millis() as u64,
            max_output_bytes: policy.limits.max_output_bytes as u64,
            scratch_bytes: policy.limits.scratch_bytes,
            memory_bytes: policy.limits.memory_bytes,
            cpu_percent: policy.limits.cpu_percent,
            max_processes: policy.limits.max_processes,
            network,
            exec_on_write: policy.exec_on_write,
            read_only: policy
                .read_only
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
            read_write: policy
                .read_write
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
        };
        out.validate()?;
        Ok(out)
    }

    /// Validates every field the keeper will trust. Called on session
    /// start (host side) and again in the keeper before it creates
    /// anything, so a corrupted spec fails closed.
    pub fn validate(&self) -> SessionResult<()> {
        if self.timeout_ms == 0 || self.timeout_ms > MAX_SESSION_TIMEOUT_MS {
            return Err(SessionError::Invalid(format!(
                "session timeout must be 1..={MAX_SESSION_TIMEOUT_MS} ms"
            )));
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > MAX_SESSION_OUTPUT_BYTES as u64 {
            return Err(SessionError::Invalid(format!(
                "session max_output must be 1..={MAX_SESSION_OUTPUT_BYTES} bytes"
            )));
        }
        if self.scratch_bytes < 1024 * 1024 {
            return Err(SessionError::Invalid(
                "session disk must be at least 1 MiB".to_string(),
            ));
        }
        if self.memory_bytes < MIN_SESSION_MEMORY_BYTES {
            return Err(SessionError::Invalid(format!(
                "session memory must be at least {} MiB (the keeper lives in the \
                 same cgroup)",
                MIN_SESSION_MEMORY_BYTES / (1024 * 1024)
            )));
        }
        if self.cpu_percent == 0 {
            return Err(SessionError::Invalid(
                "session cpu must be at least 1%".to_string(),
            ));
        }
        if self.max_processes < MIN_SESSION_PROCESSES {
            return Err(SessionError::Invalid(format!(
                "session max_processes must be at least {MIN_SESSION_PROCESSES} \
                 (keeper + sandbox stages)"
            )));
        }
        // The keeper buffers up to max_output per stream (plus base64).
        // Keep that comfortably below the cgroup memory cap.
        let output_budget = self
            .max_output_bytes
            .saturating_mul(4)
            .saturating_add(32 << 20);
        if output_budget >= self.memory_bytes {
            return Err(SessionError::Invalid(format!(
                "session memory ({} bytes) is too small for the output cap; \
                 need more than {output_budget} bytes",
                self.memory_bytes
            )));
        }
        match self.network.as_str() {
            "none" | "full" => {}
            other => {
                return Err(SessionError::Invalid(format!(
                    "session network mode {other:?} is not supported"
                )));
            }
        }
        let mut env_bytes = 0usize;
        for (k, v) in &self.env {
            if k.is_empty()
                || k.as_bytes().contains(&0)
                || k.as_bytes().contains(&b'=')
                || v.as_bytes().contains(&0)
            {
                return Err(SessionError::Invalid(format!(
                    "invalid environment entry {k:?}"
                )));
            }
            env_bytes = env_bytes.saturating_add(k.len() + v.len() + 2);
        }
        if env_bytes > 64 * 1024 {
            return Err(SessionError::Invalid(
                "session environment exceeds 64 KiB".to_string(),
            ));
        }
        for p in self.read_only.iter().chain(self.read_write.iter()) {
            validate_host_path(p)?;
        }
        Ok(())
    }

    fn limits(&self) -> Limits {
        Limits {
            timeout: Duration::from_millis(self.timeout_ms),
            max_output_bytes: self.max_output_bytes as usize,
            scratch_bytes: self.scratch_bytes,
            memory_bytes: self.memory_bytes,
            cpu_percent: self.cpu_percent,
            max_processes: self.max_processes,
        }
    }

    fn to_spec(
        &self,
        program: &str,
        args: &[String],
        timeout_ms: u64,
    ) -> SessionResult<SandboxSpec> {
        let network = match self.network.as_str() {
            "none" => NetworkMode::None,
            "full" => NetworkMode::Full,
            other => {
                return Err(SessionError::Invalid(format!(
                    "unsupported session network mode {other:?}"
                )));
            }
        };
        let mut spec = SandboxSpec::new(program).args(args.iter().cloned());
        spec.env = self.env.clone();
        spec.limits = Limits {
            timeout: Duration::from_millis(timeout_ms),
            ..self.limits()
        };
        spec.read_only = self.read_only.iter().map(PathBuf::from).collect();
        spec.read_write = self.read_write.iter().map(PathBuf::from).collect();
        spec.exec_on_write = self.exec_on_write;
        spec.network = network;
        Ok(spec)
    }
}

fn validate_host_path(p: &str) -> SessionResult<()> {
    let path = Path::new(p);
    if !path.is_absolute() {
        return Err(SessionError::Invalid(format!(
            "session bind path {p:?} must be absolute"
        )));
    }
    for c in path.components() {
        match c {
            std::path::Component::ParentDir | std::path::Component::CurDir => {
                return Err(SessionError::Invalid(format!(
                    "session bind path {p:?} must be normalized"
                )));
            }
            _ => {}
        }
    }
    for forbidden in ["/proc", "/sys", "/dev", "/etc", "/work", "/tmp"] {
        if path.starts_with(forbidden) {
            return Err(SessionError::Invalid(format!(
                "session bind path {p:?} may not shadow sandbox internals ({forbidden})"
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionSpec {
    id: String,
    dir: String,
    work_dir: String,
    socket: String,
    /// 0 = detached (CLI); otherwise the keeper dies with this process.
    parent_pid: u32,
    policy: SessionPolicy,
}

/// Public metadata for one session, stored at
/// `<base>/<id>/meta.json` (mode 0600).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMeta {
    pub id: String,
    pub dir: String,
    pub socket: String,
    pub keeper_pid: u32,
    pub parent_pid: u32,
    pub created_at_ms: u64,
    pub cgroup_path: Option<String>,
    pub policy: SessionPolicy,
}

/// A session as returned by `list`, with liveness measured at call time.
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    #[serde(flatten)]
    pub meta: SessionMeta,
    pub alive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    /// `"file"`, `"dir"`, `"symlink"`, or `"other"`.
    pub kind: String,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub kill_reason: Option<String>,
    pub wall_time_ms: u64,
    pub stdout_b64: String,
    pub stderr_b64: String,
    pub cpu_usec: Option<u64>,
    pub peak_memory_bytes: Option<u64>,
    pub peak_processes: Option<u64>,
}

impl ExecResult {
    pub fn stdout(&self) -> Vec<u8> {
        base64::decode(&self.stdout_b64).unwrap_or_default()
    }
    pub fn stderr(&self) -> Vec<u8> {
        base64::decode(&self.stderr_b64).unwrap_or_default()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Ping,
    Exec {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Put {
        path: String,
        size: u64,
        #[serde(default)]
        mode: Option<u32>,
    },
    Get {
        path: String,
    },
    List {
        #[serde(default = "default_list_path")]
        path: String,
    },
    Close,
}

fn default_list_path() -> String {
    ".".to_string()
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Response {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exec: Option<ExecResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    entries: Option<Vec<Entry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
}

impl Response {
    fn ok() -> Self {
        Self {
            ok: true,
            ..Self::default()
        }
    }
    fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(message.into()),
            ..Self::default()
        }
    }
}

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T, max: usize) -> SessionResult<()> {
    let data =
        serde_json::to_vec(value).map_err(|e| SessionError::Protocol(format!("encode: {e}")))?;
    if data.len() > max {
        return Err(SessionError::Protocol(format!(
            "frame too large: {} > {max}",
            data.len()
        )));
    }
    stream.write_all(&(data.len() as u32).to_be_bytes())?;
    stream.write_all(&data)?;
    Ok(())
}

fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream, max: usize) -> SessionResult<T> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(SessionError::Protocol(format!(
            "frame too large: {len} > {max}"
        )));
    }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data)?;
    serde_json::from_slice(&data).map_err(|e| SessionError::Protocol(format!("decode: {e}")))
}

// ------------------------------------------------------------------ client

/// A connection to one session keeper. Every method is synchronous; the
/// keeper serves one request at a time, which also makes concurrent
/// uploads/execs serialize instead of racing.
pub struct SessionClient {
    stream: UnixStream,
}

impl SessionClient {
    pub fn connect(socket: &Path) -> SessionResult<Self> {
        let stream = UnixStream::connect(socket)?;
        stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
        stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
        Ok(Self { stream })
    }

    /// Overrides the socket timeout (the close path uses a short one so a
    /// keeper busy in `exec` cannot block teardown).
    pub fn set_timeout(&self, timeout: Duration) -> SessionResult<()> {
        self.stream.set_read_timeout(Some(timeout))?;
        self.stream.set_write_timeout(Some(timeout))?;
        Ok(())
    }

    fn request(&mut self, req: &Request) -> SessionResult<Response> {
        write_frame(&mut self.stream, req, MAX_REQUEST_BYTES)?;
        let resp: Response = read_frame(&mut self.stream, MAX_RESPONSE_BYTES)?;
        if resp.ok {
            Ok(resp)
        } else {
            Err(SessionError::Remote(
                resp.error.unwrap_or_else(|| "unknown session error".into()),
            ))
        }
    }

    pub fn ping(&mut self) -> SessionResult<()> {
        self.request(&Request::Ping).map(|_| ())
    }

    pub fn exec(
        &mut self,
        program: &str,
        args: &[String],
        timeout_ms: Option<u64>,
    ) -> SessionResult<ExecResult> {
        let req = Request::Exec {
            program: program.to_string(),
            args: args.to_vec(),
            timeout_ms,
        };
        // The keeper answers only after the payload is reaped, so the read
        // deadline must cover the requested wall clock (plus supervisor
        // slack). Restored on every path so a later `ping` is not stuck
        // with a huge timeout.
        let wait = timeout_ms
            .map(|ms| Duration::from_millis(ms).saturating_add(Duration::from_secs(60)))
            .unwrap_or(SOCKET_TIMEOUT);
        self.stream.set_read_timeout(Some(wait))?;
        let resp = self.request(&req);
        let _ = self.stream.set_read_timeout(Some(SOCKET_TIMEOUT));
        let resp = resp?;
        resp.exec
            .ok_or_else(|| SessionError::Protocol("exec response has no result".into()))
    }

    pub fn put(&mut self, path: &str, data: &[u8], mode: u32) -> SessionResult<()> {
        if data.len() as u64 > MAX_TRANSFER_BYTES {
            return Err(SessionError::Invalid(format!(
                "upload exceeds the {MAX_TRANSFER_BYTES}-byte session transfer cap"
            )));
        }
        let req = Request::Put {
            path: path.to_string(),
            size: data.len() as u64,
            mode: Some(mode),
        };
        write_frame(&mut self.stream, &req, MAX_REQUEST_BYTES)?;
        self.stream.write_all(data)?;
        let resp: Response = read_frame(&mut self.stream, MAX_RESPONSE_BYTES)?;
        if resp.ok {
            Ok(())
        } else {
            Err(SessionError::Remote(
                resp.error.unwrap_or_else(|| "unknown session error".into()),
            ))
        }
    }

    pub fn get(&mut self, path: &str) -> SessionResult<Vec<u8>> {
        self.get_with_limit(path, MAX_TRANSFER_BYTES)
    }

    /// Like [`Self::get`] but rejects the transfer from the response header
    /// when it exceeds `limit`, so a caller with a smaller budget never
    /// allocates the full file.
    pub fn get_with_limit(&mut self, path: &str, limit: u64) -> SessionResult<Vec<u8>> {
        let resp = self.request(&Request::Get {
            path: path.to_string(),
        })?;
        let size = resp
            .size
            .ok_or_else(|| SessionError::Protocol("get response has no size".into()))?;
        if size > limit {
            return Err(SessionError::Invalid(format!(
                "{path:?} is {size} bytes; this caller's download limit is {limit} bytes"
            )));
        }
        let mut data = vec![0u8; size as usize];
        self.stream.read_exact(&mut data)?;
        Ok(data)
    }

    pub fn list(&mut self, path: &str) -> SessionResult<Vec<Entry>> {
        let resp = self.request(&Request::List {
            path: path.to_string(),
        })?;
        resp.entries
            .ok_or_else(|| SessionError::Protocol("list response has no entries".into()))
    }

    pub fn close(&mut self) -> SessionResult<()> {
        self.request(&Request::Close).map(|_| ())
    }
}

// ----------------------------------------------------------------- manager

/// Host-side session lifecycle: start, list, connect, close, prune.
pub struct SessionManager {
    base: PathBuf,
    keeper_exe: PathBuf,
}

impl SessionManager {
    /// Uses `CARA_KEEPER_EXE` when set (tests / embedders), otherwise the
    /// running binary (which must understand [`KEEPER_ARG`]).
    pub fn new() -> SessionResult<Self> {
        let keeper_exe = match std::env::var_os("CARA_KEEPER_EXE") {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => std::env::current_exe()?,
        };
        Self::with_keeper_exe(keeper_exe)
    }

    pub fn with_keeper_exe(keeper_exe: PathBuf) -> SessionResult<Self> {
        Ok(Self {
            base: session_base()?,
            keeper_exe,
        })
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Creates a session and returns once the keeper is accepting on its
    /// socket. `parent_pid = 0` detaches (CLI); otherwise the keeper is
    /// armed with PDEATHSIG against that process (MCP).
    pub fn start(&self, policy: SessionPolicy, parent_pid: u32) -> SessionResult<SessionMeta> {
        policy.validate()?;
        let report = crate::doctor::run_checks();
        if !report.ready() {
            let failed: Vec<String> = report
                .failed_required()
                .iter()
                .map(|c| format!("{} ({})", c.id, c.detail))
                .collect();
            return Err(SessionError::Environment(format!(
                "environment not ready for sessions: {}",
                failed.join("; ")
            )));
        }

        let id = random_hex(16)?;
        let dir = self.base.join(&id);
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&dir)?;
        let work_dir = dir.join("work");
        builder.create(&work_dir)?;
        let socket = dir.join("sock");
        let spec = SessionSpec {
            id: id.clone(),
            dir: dir.to_string_lossy().into_owned(),
            work_dir: work_dir.to_string_lossy().into_owned(),
            socket: socket.to_string_lossy().into_owned(),
            parent_pid,
            policy: policy.clone(),
        };
        write_json_0600(&dir.join("spec.json"), &spec)?;

        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(dir.join("keeper.log"))?;
        let mut cmd = Command::new(&self.keeper_exe);
        cmd.arg(KEEPER_ARG)
            .arg(dir.join("spec.json"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log));
        // SAFETY: pre_exec runs in the forked child before exec; setsid(2)
        // is async-signal-safe and failure (already a leader) is harmless.
        unsafe {
            cmd.pre_exec(|| {
                let _ = libc::setsid();
                Ok(())
            });
        }
        let mut child = cmd.spawn().map_err(|e| {
            let _ = std::fs::remove_dir_all(&dir);
            SessionError::Environment(format!(
                "could not spawn session keeper {}: {e}",
                self.keeper_exe.display()
            ))
        })?;
        let keeper_pid = child.id();

        // Attach the parked keeper to a session-wide leaf. It is still a
        // plain same-uid process, which is the only moment cgroup v2
        // delegation permits the move. Every exec inherits this leaf.
        let root = match crate::cgroup::delegated_root() {
            Some(root) => root,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_dir_all(&dir);
                return Err(SessionError::Environment(
                    "no delegated cgroup root found".to_string(),
                ));
            }
        };
        let leaf = match crate::cgroup::CgroupLeaf::create_session(
            &root,
            &policy.limits(),
            keeper_pid as libc::pid_t,
        ) {
            Ok(leaf) => leaf,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_dir_all(&dir);
                return Err(SessionError::Environment(format!("cgroup limits: {e}")));
            }
        };
        let cgroup_path = leaf.into_path();

        // Release the keeper and wait for READY. On any failure the cgroup
        // kill is the authoritative tree teardown (the keeper may already
        // have forked setup children).
        let mut stdin = child.stdin.take().expect("piped stdin");
        if let Err(e) = stdin.write_all(b"G") {
            cleanup_failed_start(&mut child, &cgroup_path, &dir);
            return Err(SessionError::Io(e));
        }
        drop(stdin);
        let mut stdout = child.stdout.take().expect("piped stdout");
        let ready = read_ready(&mut stdout, READY_TIMEOUT);
        drop(stdout);
        if let Err(e) = ready {
            cleanup_failed_start(&mut child, &cgroup_path, &dir);
            return Err(e);
        }
        drop(child); // detaches; the keeper is reparented when this exits

        let meta = SessionMeta {
            id,
            dir: dir.to_string_lossy().into_owned(),
            socket: socket.to_string_lossy().into_owned(),
            keeper_pid,
            parent_pid,
            created_at_ms: now_ms(),
            cgroup_path: Some(cgroup_path.to_string_lossy().into_owned()),
            policy,
        };
        if let Err(e) = write_json_0600(&dir.join("meta.json"), &meta) {
            // The keeper is running but the host cannot describe it:
            // tear it down rather than leave an unreachable session.
            kill_pid(keeper_pid as libc::pid_t);
            remove_cgroup(&root, &cgroup_path);
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
        Ok(meta)
    }

    pub fn list(&self) -> SessionResult<Vec<SessionInfo>> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.base) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(SessionError::Io(e)),
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let Ok(meta) = read_json::<SessionMeta>(&dir.join("meta.json")) else {
                continue;
            };
            let alive = pid_is_live(meta.keeper_pid) && Path::new(&meta.socket).exists();
            out.push(SessionInfo { meta, alive });
        }
        out.sort_by_key(|s| s.meta.created_at_ms);
        Ok(out)
    }

    pub fn connect(&self, id: &str) -> SessionResult<SessionClient> {
        validate_id(id)?;
        let meta = read_json::<SessionMeta>(&self.base.join(id).join("meta.json"))
            .map_err(|_| SessionError::NotFound(format!("session {id} not found")))?;
        SessionClient::connect(Path::new(&meta.socket)).map_err(|e| {
            SessionError::NotFound(format!("session {id} keeper is not reachable: {e}"))
        })
    }

    pub fn close(&self, id: &str) -> SessionResult<()> {
        validate_id(id)?;
        let dir = self.base.join(id);
        let meta = read_json::<SessionMeta>(&dir.join("meta.json"))
            .map_err(|_| SessionError::NotFound(format!("session {id} not found")))?;

        // Graceful close first. A busy keeper is blocked inside exec, so
        // fall back to signals; PDEATHSIG then kills the payload tree.
        if let Ok(mut client) = SessionClient::connect(Path::new(&meta.socket)) {
            let _ = client.set_timeout(Duration::from_secs(1));
            let _ = client.close();
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while pid_is_live(meta.keeper_pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if pid_is_live(meta.keeper_pid) {
            kill_pid(meta.keeper_pid as libc::pid_t);
            let deadline = Instant::now() + Duration::from_secs(2);
            while pid_is_live(meta.keeper_pid) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            if pid_is_live(meta.keeper_pid) {
                kill_pid_hard(meta.keeper_pid as libc::pid_t);
            }
        }
        if let Some(root) = crate::cgroup::delegated_root()
            && let Some(path) = meta.cgroup_path.as_deref()
        {
            remove_cgroup(&root, Path::new(path));
        }
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    /// Removes sessions whose keeper is gone. Live sessions are never
    /// touched. Directories with no meta.json are removed only when they
    /// are older than an hour (a crashed `start`).
    pub fn prune(&self) -> SessionResult<usize> {
        let mut removed = 0;
        let entries = match std::fs::read_dir(&self.base) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(SessionError::Io(e)),
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            match read_json::<SessionMeta>(&dir.join("meta.json")) {
                Ok(meta) => {
                    if pid_is_live(meta.keeper_pid) && Path::new(&meta.socket).exists() {
                        continue;
                    }
                    if let Some(root) = crate::cgroup::delegated_root()
                        && let Some(path) = meta.cgroup_path.as_deref()
                    {
                        remove_cgroup(&root, Path::new(path));
                    }
                    if std::fs::remove_dir_all(&dir).is_ok() {
                        removed += 1;
                    }
                }
                Err(_) => {
                    let old = entry
                        .metadata()
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age > Duration::from_secs(3600));
                    if old && std::fs::remove_dir_all(&dir).is_ok() {
                        removed += 1;
                    }
                }
            }
        }
        Ok(removed)
    }
}

fn cleanup_failed_start(child: &mut std::process::Child, cgroup: &Path, dir: &Path) {
    let _ = std::fs::write(cgroup.join("cgroup.kill"), "1");
    let _ = child.kill();
    let _ = child.wait();
    for _ in 0..100 {
        if std::fs::remove_dir(cgroup).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let _ = std::fs::remove_dir_all(dir);
}

fn read_ready(stdout: &mut std::process::ChildStdout, timeout: Duration) -> SessionResult<()> {
    let fd = stdout.as_raw_fd();
    let deadline = Instant::now() + timeout;
    let mut buf = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SessionError::Environment(
                "session keeper did not signal READY within 15s".to_string(),
            ));
        }
        let mut pfd = [libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: poll(2) over one valid pollfd; the timeout is bounded.
        let n = unsafe {
            libc::poll(
                pfd.as_mut_ptr(),
                1,
                remaining.as_millis().min(i32::MAX as u128) as i32,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SessionError::Io(e));
        }
        if n == 0 {
            return Err(SessionError::Environment(
                "session keeper did not signal READY within 15s".to_string(),
            ));
        }
        let mut chunk = [0u8; 64];
        let n = stdout.read(&mut chunk)?;
        if n == 0 {
            return Err(SessionError::Environment(
                "session keeper exited before READY (see keeper.log)".to_string(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(6).any(|w| w == b"READY\n") {
            return Ok(());
        }
        if buf.len() > 256 {
            return Err(SessionError::Protocol(
                "unexpected keeper READY message".to_string(),
            ));
        }
    }
}

// ------------------------------------------------------------- path + I/O

fn validate_rel_path(path: &str, allow_root: bool) -> SessionResult<Vec<String>> {
    if path.is_empty() {
        return Err(SessionError::Invalid("path must not be empty".into()));
    }
    if path.as_bytes().contains(&0) {
        return Err(SessionError::Invalid("path contains NUL".into()));
    }
    if path.starts_with('/') {
        return Err(SessionError::Invalid(format!(
            "path {path:?} must be relative to the session work dir"
        )));
    }
    if path == "." {
        if allow_root {
            return Ok(Vec::new());
        }
        return Err(SessionError::Invalid(
            "path must name a file, not the work dir".into(),
        ));
    }
    if path.len() > 4096 {
        return Err(SessionError::Invalid("path is too long".into()));
    }
    let mut out = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(SessionError::Invalid(format!(
                "path {path:?} must be normalized (no . or .. components)"
            )));
        }
        if part.len() > 255 {
            return Err(SessionError::Invalid("path component is too long".into()));
        }
        out.push(part.to_string());
    }
    Ok(out)
}

#[repr(C)]
#[derive(Default)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

fn openat2(dirfd: RawFd, name: &CStr, flags: u64, resolve: u64) -> SessionResult<OwnedFd> {
    let how = OpenHow {
        flags,
        mode: 0,
        resolve,
    };
    // SAFETY: openat2(2) with a valid C string, a valid open_how, and its
    // exact size; the returned fd is owned by the caller.
    let r = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if r < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOSYS) {
            return Err(SessionError::Invalid(
                "this kernel lacks openat2(2), required for session file access".into(),
            ));
        }
        return Err(SessionError::Io(e));
    }
    // SAFETY: openat2 returned a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(r as RawFd) })
}

fn open_root(root: &Path) -> SessionResult<OwnedFd> {
    let c = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| SessionError::Invalid("session work path contains NUL".into()))?;
    // SAFETY: open(2) on the keeper's own mountpoint with constant flags.
    let r = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if r < 0 {
        return Err(SessionError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: open returned a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(r) })
}

/// Root dir fd usable with `fdopendir(3)` (readable, not O_PATH).
fn open_root_readable(root: &Path) -> SessionResult<OwnedFd> {
    let c = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| SessionError::Invalid("session work path contains NUL".into()))?;
    // SAFETY: open(2) on the keeper's own mountpoint with constant flags.
    let r = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if r < 0 {
        return Err(SessionError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: open returned a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(r) })
}

fn open_dir_at(parent: RawFd, name: &str, create: bool) -> SessionResult<OwnedFd> {
    let c = CString::new(name)
        .map_err(|_| SessionError::Invalid(format!("invalid path component {name:?}")))?;
    let flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    let resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
    match openat2(parent, &c, flags, resolve) {
        Ok(fd) => Ok(fd),
        Err(SessionError::Io(e)) if create && e.raw_os_error() == Some(libc::ENOENT) => {
            // SAFETY: mkdirat(2) with a validated single component.
            let r = unsafe { libc::mkdirat(parent, c.as_ptr(), 0o700) };
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EEXIST) {
                    return Err(SessionError::Io(e));
                }
            }
            openat2(parent, &c, flags, resolve)
        }
        Err(e) => Err(e),
    }
}

fn open_parent(root: &Path, comps: &[String], create: bool) -> SessionResult<(OwnedFd, CString)> {
    let Some((name, dirs)) = comps.split_last() else {
        return Err(SessionError::Invalid("path names no file".into()));
    };
    let mut dir = open_root(root)?;
    for part in dirs {
        dir = open_dir_at(dir.as_raw_fd(), part, create)?;
    }
    let name = CString::new(name.as_str())
        .map_err(|_| SessionError::Invalid("path component contains NUL".into()))?;
    Ok((dir, name))
}

fn put_file(
    stream: &mut UnixStream,
    root: &Path,
    rel: &str,
    size: u64,
    mode: u32,
) -> SessionResult<()> {
    let comps = validate_rel_path(rel, false)?;
    if size > MAX_TRANSFER_BYTES {
        return Err(SessionError::Invalid(format!(
            "upload exceeds the {MAX_TRANSFER_BYTES}-byte session transfer cap"
        )));
    }
    let (parent, name) = open_parent(root, &comps, true)?;
    let temp = format!(".cara-upload-{}", random_hex(8)?);
    let temp_c = CString::new(temp.clone())
        .map_err(|_| SessionError::Invalid("temporary name contains NUL".into()))?;
    let mode = (mode & 0o777) as libc::mode_t;
    // SAFETY: openat(2) on a validated parent dir with a fresh random
    // single-component name; O_EXCL|O_NOFOLLOW refuses races.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            temp_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(SessionError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: openat returned a fresh owned fd.
    let mut file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });

    let mut remaining = size;
    let mut buf = [0u8; 65536];
    let mut write_err: Option<SessionError> = None;
    while remaining > 0 {
        let take = remaining.min(buf.len() as u64) as usize;
        if let Err(e) = stream.read_exact(&mut buf[..take]) {
            unlink_temp(parent.as_raw_fd(), &temp_c);
            return Err(SessionError::Io(e));
        }
        if write_err.is_none()
            && let Err(e) = file.write_all(&buf[..take])
        {
            write_err = Some(SessionError::Io(e));
        }
        remaining -= take as u64;
    }
    if let Some(e) = write_err {
        unlink_temp(parent.as_raw_fd(), &temp_c);
        return Err(e);
    }
    if let Err(e) = file.sync_all() {
        unlink_temp(parent.as_raw_fd(), &temp_c);
        return Err(SessionError::Io(e));
    }
    drop(file);
    // SAFETY: renameat(2) within the validated parent; the destination is
    // a single component. Replacing a symlink replaces the link itself.
    let r = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            temp_c.as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
        )
    };
    if r < 0 {
        let e = std::io::Error::last_os_error();
        unlink_temp(parent.as_raw_fd(), &temp_c);
        return Err(SessionError::Io(e));
    }
    Ok(())
}

fn unlink_temp(parent: RawFd, name: &CStr) {
    // SAFETY: unlinkat(2) on the temp file we created; failure is ignored
    // because the directory is about to be discarded or retried.
    unsafe {
        libc::unlinkat(parent, name.as_ptr(), 0);
    }
}

fn get_file(root: &Path, rel: &str) -> SessionResult<(std::fs::File, u64)> {
    let comps = validate_rel_path(rel, false)?;
    let (parent, name) = open_parent(root, &comps, false)?;
    let flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
    let resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
    let fd = openat2(parent.as_raw_fd(), &name, flags, resolve)?;
    let file = std::fs::File::from(fd);
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(SessionError::Invalid(format!(
            "{rel:?} is not a regular file"
        )));
    }
    if meta.len() > MAX_TRANSFER_BYTES {
        return Err(SessionError::Invalid(format!(
            "{rel:?} is larger than the {MAX_TRANSFER_BYTES}-byte transfer cap"
        )));
    }
    Ok((file, meta.len()))
}

fn list_dir(root: &Path, rel: &str) -> SessionResult<Vec<Entry>> {
    let comps = validate_rel_path(rel, true)?;
    // NOTE: `fdopendir(3)` needs a *readable* descriptor, so listing opens
    // the directory with O_RDONLY (O_PATH works as an openat2 dirfd for
    // traversal but fails fdopendir with EBADF).
    let dir = if comps.is_empty() {
        open_root_readable(root)?
    } else {
        let (parent, name) = open_parent(root, &comps, false)?;
        let flags =
            (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
        let resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
        openat2(parent.as_raw_fd(), &name, flags, resolve)?
    };
    let raw = dir.as_raw_fd();
    // SAFETY: fdopendir(2) takes ownership of a valid directory fd.
    let stream = unsafe { libc::fdopendir(raw) };
    if stream.is_null() {
        return Err(SessionError::Io(std::io::Error::last_os_error()));
    }
    // fdopendir owns the fd now; prevent OwnedFd from closing it twice.
    std::mem::forget(dir);
    let mut out = Vec::new();
    loop {
        // SAFETY: readdir(2) on a live DIR*; the returned pointer is valid
        // until the next call, and we copy the name immediately.
        let ent = unsafe { libc::readdir(stream) };
        if ent.is_null() {
            break;
        }
        // SAFETY: d_name is a NUL-terminated name within the dirent.
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        let name = name.to_string_lossy();
        if name == "." || name == ".." {
            continue;
        }
        let mut st: libc::stat = unsafe {
            // SAFETY: plain zeroed stat buffer, filled by fstatat.
            std::mem::zeroed()
        };
        // SAFETY: fstatat(2) on the directory fd with AT_SYMLINK_NOFOLLOW
        // never follows a symlink and writes into a valid stat buffer.
        let r = unsafe {
            libc::fstatat(
                libc::dirfd(stream),
                (*ent).d_name.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if r < 0 {
            continue;
        }
        let kind = match st.st_mode & libc::S_IFMT {
            libc::S_IFREG => "file",
            libc::S_IFDIR => "dir",
            libc::S_IFLNK => "symlink",
            _ => "other",
        };
        out.push(Entry {
            name: name.into_owned(),
            kind: kind.to_string(),
            size: if kind == "file" {
                Some(st.st_size as u64)
            } else {
                None
            },
        });
        if out.len() >= MAX_LIST_ENTRIES {
            break;
        }
    }
    // SAFETY: closedir(2) releases the DIR* and its fd.
    unsafe {
        libc::closedir(stream);
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

// ------------------------------------------------------------------ keeper

/// Entry point for the hidden `__session-keeper` argument. Called by both
/// `cara` and `cara-mcp`; never returns.
pub fn keeper_main(spec_path: &Path) -> ! {
    let code = match keeper_run(spec_path) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("cara session keeper: {e}");
            1
        }
    };
    std::process::exit(code);
}

/// Convenience for binaries that dispatch on argv themselves.
pub fn keeper_main_from_args() -> ! {
    let Some(path) = std::env::args_os().nth(2) else {
        eprintln!("cara session keeper: missing spec path");
        std::process::exit(2);
    };
    keeper_main(Path::new(&path));
}

fn keeper_run(spec_path: &Path) -> SessionResult<()> {
    let spec: SessionSpec = read_json(spec_path)?;
    spec.policy.validate()?;

    // SAFETY: umask(2) has no failure mode and only affects this process.
    unsafe {
        libc::umask(0o077);
    }

    if spec.parent_pid != 0 {
        // SAFETY: prctl(PR_SET_PDEATHSIG) with constant arguments.
        let r = unsafe {
            libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as u64,
                0u64,
                0u64,
                0u64,
            )
        };
        if r < 0 {
            return Err(SessionError::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: plain getter.
        if unsafe { libc::getppid() } != spec.parent_pid as libc::pid_t {
            return Err(SessionError::Invalid(
                "session parent died before the keeper started".into(),
            ));
        }
    }
    // SAFETY: prctl(PR_SET_CHILD_SUBREAPER, 1) with constant arguments.
    let r = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1u64, 0u64, 0u64, 0u64) };
    if r < 0 {
        return Err(SessionError::Io(std::io::Error::last_os_error()));
    }

    // The host attaches us to the session cgroup leaf while we park here.
    let mut go = [0u8; 1];
    // SAFETY: raw read(2) of exactly one byte from our inherited go pipe.
    let n = unsafe { libc::read(0, go.as_mut_ptr().cast(), 1) };
    if n != 1 || go[0] != b'G' {
        return Err(SessionError::Protocol(
            "expected the go byte from the session manager".into(),
        ));
    }
    // SAFETY: closing our inherited go-pipe end; nothing else uses fd 0.
    unsafe {
        libc::close(0);
    }

    // Capture the outer ids BEFORE unshare: inside a fresh user namespace
    // and before uid_map is written, getuid() returns the overflow id.
    // SAFETY: plain getters with no failure mode.
    let (outer_uid, outer_gid) = unsafe { (libc::getuid(), libc::getgid()) };

    // One user namespace for the whole session. Every exec skips
    // CLONE_NEWUSER and inherits this map; the keeper is uid 0 here, which
    // maps to the invoking user outside. Mount namespace is private so the
    // session tmpfs cannot propagate to the host.
    // SAFETY: unshare(2) with a constant flag set; no memory arguments.
    let r = unsafe { libc::unshare((libc::CLONE_NEWUSER | libc::CLONE_NEWNS) as libc::c_int) };
    if r < 0 {
        return Err(SessionError::Io(std::io::Error::last_os_error()));
    }
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/uid_map", format!("0 {outer_uid} 1\n"))?;
    std::fs::write("/proc/self/gid_map", format!("0 {outer_gid} 1\n"))?;

    // SAFETY: mount(2) with null source/fstype and a constant propagation
    // flag; makes the copied mount tree private to this namespace.
    let r = unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if r < 0 {
        return Err(SessionError::Io(std::io::Error::last_os_error()));
    }

    mount_session_work(&spec)?;

    let listener = UnixListener::bind(&spec.socket)?;
    std::fs::set_permissions(&spec.socket, std::fs::Permissions::from_mode(0o600))?;

    // READY is the last thing written to the host pipe. Close fd 1 so a
    // later accidental write cannot SIGPIPE the keeper.
    {
        let mut out = std::io::stdout();
        out.write_all(b"READY\n")?;
        out.flush()?;
    }
    // SAFETY: fd 1 is the host READY pipe; no further stdout is used.
    unsafe {
        libc::close(1);
    }

    let result = keeper_serve(listener, &spec);
    let _ = std::fs::remove_file(&spec.socket);
    result
}

fn mount_session_work(spec: &SessionSpec) -> SessionResult<()> {
    let work = Path::new(&spec.work_dir);
    let meta = std::fs::symlink_metadata(work)?;
    if !meta.is_dir() {
        return Err(SessionError::Invalid(format!(
            "session work dir {} is not a directory",
            work.display()
        )));
    }
    let target = CString::new(spec.work_dir.as_bytes())
        .map_err(|_| SessionError::Invalid("session work path contains NUL".into()))?;
    let source = c"tmpfs";
    let fstype = c"tmpfs";
    let options = CString::new(format!("size={},mode=0700", spec.policy.scratch_bytes))
        .map_err(|_| SessionError::Invalid("tmpfs options contain NUL".into()))?;
    let flags = (libc::MS_NOSUID
        | libc::MS_NODEV
        | if spec.policy.exec_on_write {
            0
        } else {
            libc::MS_NOEXEC
        }) as libc::c_ulong;
    // SAFETY: mount(2) with NUL-terminated strings and a valid options
    // buffer; the target is the keeper's private mount namespace.
    let r = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            options.as_ptr().cast(),
        )
    };
    if r < 0 {
        return Err(SessionError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn keeper_serve(listener: UnixListener, spec: &SessionSpec) -> SessionResult<()> {
    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cara session keeper: accept: {e}");
                continue;
            }
        };
        let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
        let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
        // One connection may carry several requests (`session_exec` stages
        // the program with `put` and then runs it on the same socket). A
        // clean EOF between requests just ends the connection.
        loop {
            match handle_connection(&mut stream, spec) {
                Ok(Step::Continue) => {}
                Ok(Step::CloseSession) => return Ok(()),
                Err(SessionError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(e) => {
                    eprintln!("cara session keeper: connection: {e}");
                    break;
                }
            }
        }
        reap_strays();
    }
    Ok(())
}

/// Reaps any orphaned stage-2 reparented to the keeper (we are a
/// subreaper). Never blocks.
fn reap_strays() {
    loop {
        let mut st: libc::c_int = 0;
        // SAFETY: waitpid(-1, WNOHANG) on our own children; no memory args.
        let r = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
        if r <= 0 {
            break;
        }
    }
}

/// What the keeper should do after one handled request.
enum Step {
    /// Keep this connection open for the next request.
    Continue,
    /// A Close request was handled: shut the keeper down.
    CloseSession,
}

fn handle_connection(stream: &mut UnixStream, spec: &SessionSpec) -> SessionResult<Step> {
    let req: Request = read_frame(stream, MAX_REQUEST_BYTES)?;
    match req {
        Request::Ping => {
            write_frame(stream, &Response::ok(), MAX_RESPONSE_BYTES)?;
            return Ok(Step::Continue);
        }
        Request::Exec {
            program,
            args,
            timeout_ms,
        } => {
            let result = exec_in_session(spec, &program, &args, timeout_ms);
            let response = match result {
                Ok(exec) => Response {
                    ok: true,
                    exec: Some(exec),
                    ..Response::default()
                },
                Err(e) => Response::err(e.to_string()),
            };
            write_frame(stream, &response, MAX_RESPONSE_BYTES)?;
            return Ok(Step::Continue);
        }
        Request::Put { path, size, mode } => {
            let result = put_file(
                stream,
                Path::new(&spec.work_dir),
                &path,
                size,
                mode.unwrap_or(0o644),
            );
            match result {
                Ok(()) => {
                    write_frame(
                        stream,
                        &Response {
                            ok: true,
                            size: Some(size),
                            ..Response::default()
                        },
                        MAX_RESPONSE_BYTES,
                    )?;
                }
                Err(e) => {
                    // The client may still be writing the body. Drain it
                    // (bounded by the transfer cap) so the error response
                    // is delivered instead of a broken pipe.
                    if size <= MAX_TRANSFER_BYTES {
                        let _ = drain_exact(stream, size);
                    }
                    write_frame(stream, &Response::err(e.to_string()), MAX_RESPONSE_BYTES)?;
                }
            }
            return Ok(Step::Continue);
        }
        Request::Get { path } => match get_file(Path::new(&spec.work_dir), &path) {
            Ok((mut file, size)) => {
                write_frame(
                    stream,
                    &Response {
                        ok: true,
                        size: Some(size),
                        ..Response::default()
                    },
                    MAX_RESPONSE_BYTES,
                )?;
                std::io::copy(&mut file, stream)?;
            }
            Err(e) => {
                write_frame(stream, &Response::err(e.to_string()), MAX_RESPONSE_BYTES)?;
            }
        },
        Request::List { path } => {
            let response = match list_dir(Path::new(&spec.work_dir), &path) {
                Ok(entries) => Response {
                    ok: true,
                    entries: Some(entries),
                    ..Response::default()
                },
                Err(e) => Response::err(e.to_string()),
            };
            write_frame(stream, &response, MAX_RESPONSE_BYTES)?;
        }
        Request::Close => {
            write_frame(stream, &Response::ok(), MAX_RESPONSE_BYTES)?;
            return Ok(Step::CloseSession);
        }
    }
    Ok(Step::Continue)
}

fn drain_exact(stream: &mut UnixStream, mut n: u64) -> std::io::Result<()> {
    let mut buf = [0u8; 65536];
    while n > 0 {
        let take = n.min(buf.len() as u64) as usize;
        stream.read_exact(&mut buf[..take])?;
        n -= take as u64;
    }
    Ok(())
}

fn exec_in_session(
    spec: &SessionSpec,
    program: &str,
    args: &[String],
    timeout_ms: Option<u64>,
) -> SessionResult<ExecResult> {
    if program.is_empty() || !Path::new(program).is_absolute() {
        return Err(SessionError::Invalid(
            "session exec program must be an absolute path".into(),
        ));
    }
    if program.as_bytes().contains(&0) || args.iter().any(|a| a.as_bytes().contains(&0)) {
        return Err(SessionError::Invalid("argument contains NUL".into()));
    }
    let timeout_ms = timeout_ms.unwrap_or(spec.policy.timeout_ms);
    if timeout_ms == 0 || timeout_ms > MAX_SESSION_TIMEOUT_MS {
        return Err(SessionError::Invalid(format!(
            "timeout must be 1..={MAX_SESSION_TIMEOUT_MS} ms"
        )));
    }
    let sandbox_spec = spec.policy.to_spec(program, args, timeout_ms)?;
    let work_bind = CString::new(spec.work_dir.as_bytes())
        .map_err(|_| SessionError::Invalid("session work path contains NUL".into()))?;
    let before = CgroupSnapshot::read();
    let mut sandbox = spawn_with(
        &sandbox_spec,
        SpawnOptions {
            skip_userns: true,
            work_bind: Some(work_bind),
            cgroup: false,
        },
    )
    .map_err(|e| SessionError::Remote(format!("sandbox setup: {e}")))?;
    let report = sandbox
        .wait()
        .map_err(|e| SessionError::Remote(format!("supervision: {e}")))?;
    let after = CgroupSnapshot::read();
    let (cpu_usec, oom_kill) = after.diff(&before);
    let mut kill_reason = report.kill_reason.as_ref().map(kill_reason_str);
    if kill_reason.is_none() && oom_kill > 0 && report.signal == Some(libc::SIGKILL) {
        kill_reason = Some("memory_limit".to_string());
    }
    Ok(ExecResult {
        exit_code: report.exit_code,
        signal: report.signal,
        kill_reason,
        wall_time_ms: report.wall_time.as_millis() as u64,
        stdout_b64: base64::encode(&report.stdout),
        stderr_b64: base64::encode(&report.stderr),
        cpu_usec,
        peak_memory_bytes: after.peak_memory,
        peak_processes: after.peak_pids,
    })
}

fn kill_reason_str(reason: &KillReason) -> String {
    match reason {
        KillReason::Timeout => "timeout".into(),
        KillReason::OutputOverflow => "output_overflow".into(),
        KillReason::MemoryLimit => "memory_limit".into(),
        KillReason::CpuLimit => "cpu_limit".into(),
        KillReason::Internal(m) => format!("internal: {m}"),
    }
}

#[derive(Debug, Default)]
struct CgroupSnapshot {
    cpu_usec: Option<u64>,
    oom_kill: Option<u64>,
    peak_memory: Option<u64>,
    peak_pids: Option<u64>,
}

impl CgroupSnapshot {
    fn read() -> Self {
        let Some(dir) = self_cgroup_dir() else {
            return Self::default();
        };
        let cpu_usec = read_cgroup_key(&dir.join("cpu.stat"), "usage_usec");
        let oom_kill = read_cgroup_key(&dir.join("memory.events"), "oom_kill");
        let peak_memory = read_trim_u64(&dir.join("memory.peak"));
        let peak_pids = read_trim_u64(&dir.join("pids.peak"));
        Self {
            cpu_usec,
            oom_kill,
            peak_memory,
            peak_pids,
        }
    }

    fn diff(&self, before: &Self) -> (Option<u64>, u64) {
        let cpu = match (before.cpu_usec, self.cpu_usec) {
            (Some(a), Some(b)) => Some(b.saturating_sub(a)),
            (None, Some(b)) => Some(b),
            _ => None,
        };
        let oom = self
            .oom_kill
            .unwrap_or(0)
            .saturating_sub(before.oom_kill.unwrap_or(0));
        (cpu, oom)
    }
}

fn self_cgroup_dir() -> Option<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = text
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .unwrap_or("/");
    Some(Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

fn read_cgroup_key(path: &Path, key: &str) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next()? == key)
            .then(|| it.next()?.parse().ok())
            .flatten()
    })
}

fn read_trim_u64(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

// --------------------------------------------------------------- host util

fn session_base() -> SessionResult<PathBuf> {
    let base = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("carapace/sessions"),
        _ => {
            // SAFETY: getuid(2) is a plain getter with no failure mode.
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/tmp/cara-sessions-{uid}"))
        }
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(&base)?;
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))?;
    Ok(base)
}

fn validate_id(id: &str) -> SessionResult<()> {
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SessionError::Invalid(format!(
            "invalid session id {id:?} (expected 32 hex characters)"
        )));
    }
    Ok(())
}

fn random_hex(bytes: usize) -> SessionResult<String> {
    let mut buf = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes * 2);
    for b in buf {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    Ok(out)
}

fn write_json_0600<T: Serialize>(path: &Path, value: &T) -> SessionResult<()> {
    let data =
        serde_json::to_vec(value).map_err(|e| SessionError::Protocol(format!("serialize: {e}")))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&data)?;
    file.sync_all()?;
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> SessionResult<T> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > 1024 * 1024 {
        return Err(SessionError::Protocol(format!(
            "{} is unexpectedly large",
            path.display()
        )));
    }
    let data = std::fs::read(path)?;
    serde_json::from_slice(&data)
        .map_err(|e| SessionError::Protocol(format!("{}: {e}", path.display())))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn pid_is_live(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    // Field 3 (state) follows the parenthesized comm; comm may contain
    // spaces, so split at the last ')'.
    let Some((_, rest)) = stat.rsplit_once(')') else {
        return false;
    };
    !matches!(
        rest.trim_start().chars().next(),
        Some('Z') | Some('X') | None
    )
}

fn kill_pid(pid: libc::pid_t) {
    // SAFETY: signal to a same-uid keeper we started; failure is reported
    // by the caller's liveness poll.
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
}

fn kill_pid_hard(pid: libc::pid_t) {
    // SAFETY: as above; SIGKILL is the final fallback.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}

fn remove_cgroup(root: &Path, path: &Path) {
    // Never touch a path outside the delegated subtree, even if a
    // corrupted meta.json says so.
    if !path.starts_with(root) {
        return;
    }
    let _ = std::fs::write(path.join("cgroup.kill"), "1");
    for _ in 0..200 {
        if std::fs::remove_dir(path).is_ok() {
            return;
        }
        if !path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ------------------------------------------------------------------ base64

/// Small dependency-free base64 (RFC 4648) for exec output and MCP
/// uploads. Strict on decode: invalid bytes and misplaced padding error.
pub mod base64 {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[((n >> 6) & 63) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[(n & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    pub fn decode(text: &str) -> Result<Vec<u8>, String> {
        let bytes = text.as_bytes();
        if !bytes.len().is_multiple_of(4) {
            return Err("base64 length must be a multiple of 4".into());
        }
        let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
        let chunks = bytes.len() / 4;
        for (i, chunk) in bytes.chunks(4).enumerate() {
            let last = i + 1 == chunks;
            let pad = chunk.iter().rev().take_while(|&&b| b == b'=').count();
            if pad > 2 || (pad > 0 && !last) {
                return Err("invalid base64 padding".into());
            }
            let mut n = 0u32;
            for (j, &b) in chunk.iter().enumerate() {
                let v = if b == b'=' {
                    if j < 4 - pad {
                        return Err("invalid base64 padding position".into());
                    }
                    0
                } else {
                    value(b).ok_or_else(|| format!("invalid base64 byte {b}"))?
                };
                n = (n << 6) | v;
            }
            out.push((n >> 16) as u8);
            if pad < 2 {
                out.push((n >> 8) as u8);
            }
            if pad < 1 {
                out.push(n as u8);
            }
        }
        Ok(out)
    }

    fn value(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a' + 26) as u32),
            b'0'..=b'9' => Some((b - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_every_length() {
        for len in 0..=64 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            let encoded = base64::encode(&data);
            assert_eq!(base64::decode(&encoded).unwrap(), data);
        }
    }

    #[test]
    fn base64_rejects_garbage() {
        assert!(base64::decode("a").is_err());
        assert!(base64::decode("****").is_err());
        assert!(base64::decode("a===").is_err());
        assert!(base64::decode("ab=c").is_err());
    }

    #[test]
    fn relative_paths_are_strict() {
        assert!(validate_rel_path("a/b", false).is_ok());
        assert!(validate_rel_path(".", true).is_ok());
        assert!(validate_rel_path(".", false).is_err());
        assert!(validate_rel_path("../x", false).is_err());
        assert!(validate_rel_path("a/../x", false).is_err());
        assert!(validate_rel_path("/etc/passwd", false).is_err());
        assert!(validate_rel_path("a//b", false).is_err());
        assert!(validate_rel_path("a/", false).is_err());
        assert!(validate_rel_path("", false).is_err());
    }

    #[test]
    fn session_policy_rejects_allowlist_and_tiny_memory() {
        let mut policy = Policy::strict();
        policy.network = NetworkMode::Allowlist(vec!["example.com".into()]);
        assert!(SessionPolicy::from_policy(&policy).is_err());

        let mut policy = Policy::strict();
        policy.limits.memory_bytes = 8 * 1024 * 1024;
        assert!(SessionPolicy::from_policy(&policy).is_err());
    }

    #[test]
    fn session_policy_round_trips_through_json() {
        let p = SessionPolicy::from_policy(&Policy::strict()).unwrap();
        let text = serde_json::to_string(&p).unwrap();
        let back: SessionPolicy = serde_json::from_str(&text).unwrap();
        assert_eq!(back.timeout_ms, p.timeout_ms);
        assert_eq!(back.env, p.env);
    }

    #[test]
    fn pid_liveness_treats_zombies_as_dead() {
        assert!(pid_is_live(std::process::id()));
        assert!(!pid_is_live(u32::MAX));
    }
}
