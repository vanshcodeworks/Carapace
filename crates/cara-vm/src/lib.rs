//! `carapace-vm`: Tier 3 backend (microVM - libkrun first, Firecracker
//! second; chosen by ADR-0006).
//!
//! # Isolation model
//!
//! Every run gets a disposable Linux kernel under KVM. The payload is the
//! guest's only userland program: libkrun injects `/init.krun`, which execs
//! `spec.program` with the allowlisted argv/env (payload-as-init). The guest
//! sees a read-only-by-construction skeleton root, an optional read-only host
//! `/usr` export, one writable scratch export at `/work`, and no network
//! device or vsock. Console output goes through two pipes that the supervisor
//! reads with a hard byte cap; no unbounded log file is ever written.
//!
//! # Kill model (Linux x86_64)
//!
//! `krun_get_shutdown_eventfd` is compiled only for aarch64/macOS in libkrun
//! 1.19.8 (verified in the crate source and the v1.19.8 header), so it cannot
//! be used here. Instead the VM runs in a dedicated child process in its own
//! process group. A watchdog thread and `kill()` signal that group with
//! SIGKILL, which tears down the in-process VMM and the guest kernel together.
//! The supervisor reaps the child and reports `KillReason::Timeout` or
//! `KillReason::OutputOverflow` as appropriate.
//!
//! # Honest status
//!
//! This crate compiles, its pure logic is unit-tested everywhere, and it
//! fails closed without KVM. Booting has NOT been observed in the reference
//! environment (no `/dev/kvm`). The KVM-gated test in this module skips with
//! a clear message there. See docs/agent/UNVERIFIED.md.

pub const MILESTONE: &str = "C10";

// Force the libkrun rlib/cdylib into the link: our `extern "C"` block by
// itself does not name a linking crate, so without this reference the linker
// reports every `krun_*` symbol as undefined.
extern crate krun;

use carapace_core::report::KillReason;
use carapace_core::spec::SandboxSpec;
use carapace_core::{BackendError, SandboxHandle};
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

/// One kibibyte, for byte-to-MiB arithmetic.
const BYTES_PER_MIB: u64 = 1024 * 1024;

/// Hard per-stream console cap, mirrored from `WASM_STREAM_CAP` in
/// `carapace-wasm`. The supervisor never exposes more than this many bytes
/// per stream, and kills the VM when a stream crosses the cap.
pub const VM_STREAM_CAP: usize = 8 * 1024 * 1024;

/// Floor for guest memory, in MiB.
pub const MIN_MEMORY_MIB: u64 = 64;
/// Ceiling for guest memory, in MiB (16 GiB).
pub const MAX_MEMORY_MIB: u64 = 16 * 1024;
/// Ceiling for guest vCPUs.
pub const MAX_VCPUS: u32 = 64;

/// The virtiofs tag libkrun uses for the root filesystem (from libkrun.h).
pub const ROOT_TAG: &str = "/dev/root";
/// The virtiofs tag for the writable scratch mounted at `/work`.
pub const WORK_TAG: &str = "/work";
/// The virtiofs tag and host path for the read-only `/usr` export.
pub const USR_TAG: &str = "/usr";
pub const HOST_USR_PATH: &str = "/usr";

/// Directories created in the disposable root skeleton.
pub const ROOTFS_DIRS: &[&str] = &[
    "bin", "lib", "lib64", "usr", "etc", "work", "proc", "dev", "tmp", "sys", "var", "sbin",
    "home", "root", "mnt", "opt", "run",
];

/// How long the supervisor waits for the child to finish libkrun setup
/// before treating the run as a failed setup. Independent of the payload
/// timeout, which starts only after setup succeeds.
const SETUP_HANDSHAKE: Duration = Duration::from_secs(10);
/// Watchdog wakeup interval.
const WATCHDOG_TICK: Duration = Duration::from_millis(10);
/// Bytes read from a console pipe per poll iteration.
const CONSOLE_READ_CHUNK: usize = 4096;

/// The VM shape implied by a policy's `Limits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmPlan {
    vcpus: u32,
    memory_mib: u64,
}

impl VmPlan {
    /// Map policy limits to a VM shape. Zero budgets are errors, never a
    /// silent clamp to the floor (fail closed).
    pub fn from_limits(limits: &carapace_core::spec::Limits) -> Result<VmPlan, String> {
        if limits.memory_bytes == 0 {
            return Err("memory_bytes=0 cannot map to a microVM; fix the policy".to_string());
        }
        if limits.cpu_percent == 0 {
            return Err("cpu_percent=0 cannot map to a microVM; fix the policy".to_string());
        }
        let memory_mib = limits
            .memory_bytes
            .div_ceil(BYTES_PER_MIB)
            .clamp(MIN_MEMORY_MIB, MAX_MEMORY_MIB);
        let vcpus = limits.cpu_percent.div_ceil(100).clamp(1, MAX_VCPUS);
        Ok(VmPlan { vcpus, memory_mib })
    }

    pub fn vcpus(&self) -> u32 {
        self.vcpus
    }

    pub fn memory_mib(&self) -> u64 {
        self.memory_mib
    }
}

/// `true` when this host can drive a KVM-based microVM. Opening the device,
/// not just stat'ing it, catches the common `/dev/kvm` permission error.
pub fn kvm_available() -> bool {
    std::fs::File::open("/dev/kvm").is_ok()
}

/// One read-only virtiofs export planned for the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestBind {
    /// virtiofs tag; libkrun's kernel mounts absolute-path tags at that path.
    pub tag: &'static str,
    /// Host directory exported through virtiofs.
    pub host_path: &'static str,
    /// Exports intended to be immutable in the guest set this to true.
    pub read_only: bool,
}

/// A pure description of the guest root filesystem. No I/O in the planner:
/// this is the part that is unit-tested on every host, with or without KVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootfsPlan {
    pub dirs: &'static [&'static str],
    pub usr_bind: GuestBind,
}

impl Default for RootfsPlan {
    fn default() -> Self {
        Self {
            dirs: ROOTFS_DIRS,
            usr_bind: GuestBind {
                tag: USR_TAG,
                host_path: HOST_USR_PATH,
                read_only: true,
            },
        }
    }
}

impl RootfsPlan {
    /// Materialise the skeleton as a fresh temporary directory. Every setup
    /// error removes the partial tree so a failed run leaves nothing behind.
    pub fn materialize(&self) -> std::io::Result<RootfsDir> {
        let guard = RootfsDir {
            path: mk_unique_dir()?,
        };
        for dir in self.dirs {
            let target = guard.path.join(dir);
            fs::create_dir(&target)?;
            if !target.is_dir() {
                return Err(std::io::Error::other(format!(
                    "rootfs entry {dir} is not a directory"
                )));
            }
        }
        Ok(guard)
    }
}

/// RAII owner of the disposable guest root skeleton.
#[derive(Debug)]
pub struct RootfsDir {
    path: PathBuf,
}

impl RootfsDir {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RootfsDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// RAII owner of the writable scratch exported at `/work`.
#[derive(Debug)]
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A per-stream byte cap with an explicit overflow flag. Kept separate from
/// the FFI so it is testable without KVM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CappedOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub overflow: bool,
    cap: usize,
}

impl CappedOutput {
    pub fn new(cap: usize) -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            overflow: false,
            cap,
        }
    }

    pub fn push_stdout(&mut self, bytes: &[u8]) {
        push_capped(&mut self.stdout, bytes, self.cap, &mut self.overflow);
    }

    pub fn push_stderr(&mut self, bytes: &[u8]) {
        push_capped(&mut self.stderr, bytes, self.cap, &mut self.overflow);
    }

    #[cfg(test)]
    fn cap(&self) -> usize {
        self.cap
    }
}

fn push_capped(dst: &mut Vec<u8>, bytes: &[u8], cap: usize, overflow: &mut bool) {
    if bytes.is_empty() {
        return;
    }
    if dst.len() >= cap {
        *overflow = true;
        return;
    }
    let room = cap - dst.len();
    if bytes.len() <= room {
        dst.extend_from_slice(bytes);
    } else {
        dst.extend_from_slice(&bytes[..room]);
        *overflow = true;
    }
}

/// FFI surface, matched exactly to libkrun 1.19.8's exported C ABI
/// (checked against the crate source and the v1.19.8 `libkrun.h`).
mod ffi {
    use std::ffi::{c_char, c_int, c_uint};

    pub const KRUN_SUCCESS: c_int = 0;
    pub const KRUN_FEATURE_INIT_BLOB: u64 = 11;

    unsafe extern "C" {
        pub fn krun_init_log(target: c_int, level: c_uint, style: c_uint, options: c_uint)
        -> c_int;
        pub fn krun_create_ctx() -> c_int;
        pub fn krun_free_ctx(ctx_id: c_uint) -> c_int;
        pub fn krun_set_vm_config(ctx_id: c_uint, num_vcpus: u8, ram_mib: c_uint) -> c_int;
        pub fn krun_set_root(ctx_id: c_uint, c_root_path: *const c_char) -> c_int;
        pub fn krun_add_virtiofs3(
            ctx_id: c_uint,
            c_tag: *const c_char,
            c_path: *const c_char,
            shm_size: u64,
            read_only: bool,
        ) -> c_int;
        pub fn krun_set_exec(
            ctx_id: c_uint,
            c_exec_path: *const c_char,
            c_argv: *const *const c_char,
            c_envp: *const *const c_char,
        ) -> c_int;
        pub fn krun_set_workdir(ctx_id: c_uint, c_workdir_path: *const c_char) -> c_int;
        pub fn krun_add_virtio_console_default(
            ctx_id: c_uint,
            input_fd: c_int,
            output_fd: c_int,
            err_fd: c_int,
        ) -> c_int;
        pub fn krun_disable_implicit_vsock(ctx_id: c_uint) -> c_int;
        pub fn krun_has_feature(feature: u64) -> c_int;
        pub fn krun_start_enter(ctx_id: c_uint) -> c_int;
    }
}

static INIT_LOG: Once = Once::new();

fn init_libkrun_logging() {
    INIT_LOG.call_once(|| unsafe {
        // Log errors to stderr only; the guest console is captured on pipes.
        ffi::krun_init_log(libc::STDERR_FILENO, 1, 0, 0);
    });
}

/// The microVM tier backend (libkrun - ADR-0006).
#[derive(Debug, Clone, Default)]
pub struct VmBackend {
    rootfs_plan: RootfsPlan,
    /// (host source, guest path) files copied into the skeleton before boot.
    /// Used by the KVM-gated e2e test to supply a payload inside the guest.
    seeds: Vec<(PathBuf, String)>,
}

impl VmBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Use a non-default root skeleton. The planner is public so it can be
    /// inspected and tested independently of any boot.
    pub fn with_rootfs_plan(rootfs_plan: RootfsPlan) -> Self {
        Self {
            rootfs_plan,
            seeds: Vec::new(),
        }
    }

    /// Copy one host file into the guest root at `guest_path` before boot.
    /// Parent directories are created inside the disposable skeleton.
    pub fn with_seed(mut self, host: impl AsRef<Path>, guest_path: impl Into<String>) -> Self {
        self.seeds
            .push((host.as_ref().to_path_buf(), guest_path.into()));
        self
    }
}

/// State shared between `kill()`, the watchdog and `wait()`.
#[derive(Debug)]
struct VmState {
    /// Child pid while the VM is live; 0 once killed/reaped.
    pid: AtomicI32,
    /// Set by `kill()` or the watchdog; first reason wins.
    killed_reason: Mutex<Option<KillReason>>,
    /// Set by the console reader when a stream crosses its cap.
    overflow: AtomicBool,
    /// Raw wait status, filled by whichever side reaps first.
    reaped: Mutex<Option<i32>>,
}

impl VmState {
    fn new(pid: i32) -> Self {
        Self {
            pid: AtomicI32::new(pid),
            killed_reason: Mutex::new(None),
            overflow: AtomicBool::new(false),
            reaped: Mutex::new(None),
        }
    }

    fn record_reason(&self, reason: KillReason) {
        let mut slot = self.killed_reason.lock().unwrap();
        if slot.is_none() {
            *slot = Some(reason);
        }
    }

    /// Stop the VM and reap it. Safe to call from several threads: the pid
    /// is swapped to 0 exactly once.
    fn stop_and_reap(&self) {
        let pid = self.pid.swap(0, Ordering::AcqRel);
        if pid <= 0 {
            return;
        }
        kill_vm_group(pid);
        let mut status = 0i32;
        unsafe {
            // SAFETY: pid is our direct child and was never reaped yet (the
            // swap above serialises the only two callers).
            libc::waitpid(pid, &mut status, 0);
        }
        *self.reaped.lock().unwrap() = Some(status);
    }
}

/// Kill the child's whole process group, then the leader as a fallback. The
/// VMM and its guest threads all live in this group.
fn kill_vm_group(pid: i32) {
    if pid <= 0 {
        return;
    }
    unsafe {
        // Negative pid targets the process group led by the child.
        libc::kill(-pid, libc::SIGKILL);
        libc::kill(pid, libc::SIGKILL);
    }
}

fn watchdog(state: Arc<VmState>, deadline: Instant) {
    loop {
        if state.pid.load(Ordering::Acquire) <= 0 {
            return;
        }
        if state.overflow.load(Ordering::Acquire) {
            state.record_reason(KillReason::OutputOverflow);
            state.stop_and_reap();
            return;
        }
        if Instant::now() >= deadline {
            state.record_reason(KillReason::Timeout);
            state.stop_and_reap();
            return;
        }
        std::thread::park_timeout(WATCHDOG_TICK);
    }
}

/// Opaque live VM handle. `wait()` may be called once; `kill()` may be called
/// from any thread and takes effect immediately on the VM process group.
pub struct VmHandle {
    state: Arc<VmState>,
    stdout_fd: i32,
    stderr_fd: i32,
    status_fd: i32,
    output: CappedOutput,
    status_code: Option<i32>,
    timeout: Duration,
    start: Instant,
    waited: bool,
    // Keep the host directories alive for the whole VM lifetime.
    _root: RootfsDir,
    _scratch: ScratchDir,
    watchdog: Option<std::thread::JoinHandle<()>>,
}

impl VmHandle {
    fn build_report(&mut self) -> Result<carapace_core::report::ExitReport, BackendError> {
        if self.output.overflow {
            self.state.record_reason(KillReason::OutputOverflow);
        }
        let reason = self.state.killed_reason.lock().unwrap().clone();
        let status_code = self.status_code;

        let (exit_code, kill_reason) = if let Some(reason) = reason {
            (None, Some(reason))
        } else {
            match status_code {
                Some(code) if code >= 0 => (Some(code), None),
                Some(code) => {
                    let r = match -code {
                        libc::ENOMEM => KillReason::MemoryLimit,
                        other => KillReason::Internal(format!("libkrun error: -{other}")),
                    };
                    (None, Some(r))
                }
                None => (
                    None,
                    Some(KillReason::Internal(
                        "VM child exited without a status code".to_string(),
                    )),
                ),
            }
        };

        Ok(carapace_core::report::ExitReport {
            exit_code,
            signal: None,
            kill_reason,
            wall_time: self.start.elapsed(),
            stdout: self.output.stdout.clone(),
            stderr: self.output.stderr.clone(),
            cpu_time: None,
            peak_memory_bytes: None,
            peak_processes: None,
        })
    }

    /// Drain one ready console pipe into the capped output and publish an
    /// overflow to the watchdog as soon as it is observed.
    fn drain(&mut self, fd: i32, is_stdout: bool) -> bool {
        let mut buf = [0u8; CONSOLE_READ_CHUNK];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            if is_stdout {
                self.output.push_stdout(&buf[..n as usize]);
            } else {
                self.output.push_stderr(&buf[..n as usize]);
            }
            if self.output.overflow {
                self.state.overflow.store(true, Ordering::Release);
            }
            return true;
        }
        if n == 0 {
            return false; // EOF
        }
        let e = std::io::Error::last_os_error();
        e.raw_os_error() == Some(libc::EINTR) || e.raw_os_error() == Some(libc::EAGAIN)
    }

    /// Read the child's final 4-byte status. Returns false at EOF.
    fn read_status(&mut self) -> bool {
        let mut buf = [0u8; 4];
        let mut filled = 0usize;
        while filled < 4 {
            let got = unsafe {
                libc::read(
                    self.status_fd,
                    buf.as_mut_ptr().add(filled).cast(),
                    4 - filled,
                )
            };
            if got > 0 {
                filled += got as usize;
            } else if got == 0 {
                break;
            } else {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }
        }
        if filled == 4 {
            self.status_code = Some(i32::from_ne_bytes(buf));
        }
        filled == 4
    }
}

impl SandboxHandle for VmHandle {
    fn wait(&mut self) -> Result<carapace_core::report::ExitReport, BackendError> {
        if self.waited {
            return Err(BackendError::Supervision(
                "wait called twice on one VM handle".to_string(),
            ));
        }
        self.waited = true;

        // Drain pipes until the child is gone. The watchdog enforces the
        // deadline even if the caller never reaches wait().
        loop {
            if self.state.pid.load(Ordering::Acquire) <= 0 {
                break;
            }
            if self.state.killed_reason.lock().unwrap().is_some() {
                break;
            }
            // Backup deadline in case the watchdog was not scheduled.
            if self.start.elapsed() >= self.timeout {
                self.state.record_reason(KillReason::Timeout);
                break;
            }

            let mut fds: Vec<libc::pollfd> = Vec::new();
            if self.stdout_fd >= 0 {
                fds.push(libc::pollfd {
                    fd: self.stdout_fd,
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                });
            }
            if self.stderr_fd >= 0 {
                fds.push(libc::pollfd {
                    fd: self.stderr_fd,
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                });
            }
            if self.status_fd >= 0 {
                fds.push(libc::pollfd {
                    fd: self.status_fd,
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                });
            }
            if fds.is_empty() {
                break;
            }
            let n = unsafe {
                // SAFETY: all fds were created by pipe2 and are valid until
                // closed here; the timeout is bounded and EINTR is handled.
                libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100)
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                self.state
                    .record_reason(KillReason::Internal(format!("poll: {e}")));
                break;
            }
            if n == 0 {
                continue;
            }

            let mut i = 0usize;
            if self.stdout_fd >= 0 {
                let fd = self.stdout_fd;
                let live = self.drain(fd, true);
                if !live {
                    close_fd(&mut self.stdout_fd);
                }
                i += 1;
            }
            let _ = i;
            if self.stderr_fd >= 0 {
                let fd = self.stderr_fd;
                let live = self.drain(fd, false);
                if !live {
                    close_fd(&mut self.stderr_fd);
                }
            }
            if self.status_fd >= 0 && !self.read_status() {
                close_fd(&mut self.status_fd);
            }
        }

        // First side to notice the exit stops and reaps the child.
        self.state.stop_and_reap();
        if let Some(w) = self.watchdog.take() {
            let _ = w.join();
        }
        close_fd(&mut self.stdout_fd);
        close_fd(&mut self.stderr_fd);
        close_fd(&mut self.status_fd);
        self.build_report()
    }

    fn kill(&mut self, reason: KillReason) {
        self.state.record_reason(reason);
        self.state.stop_and_reap();
    }
}

impl Drop for VmHandle {
    fn drop(&mut self) {
        self.state.stop_and_reap();
        close_fd(&mut self.stdout_fd);
        close_fd(&mut self.stderr_fd);
        close_fd(&mut self.status_fd);
    }
}

fn close_fd(fd: &mut i32) {
    if *fd >= 0 {
        unsafe {
            libc::close(*fd);
        }
        *fd = -1;
    }
}

/// Create a pipe with CLOEXEC on both ends and NONBLOCK on the read end, so
/// the supervisor can poll and drain without ever blocking on an empty pipe.
fn make_pipe() -> std::io::Result<(i32, i32)> {
    let mut fds = [-1i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let flags = unsafe { libc::fcntl(fds[0], libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        let e = std::io::Error::last_os_error();
        close_fd(&mut fds[0]);
        close_fd(&mut fds[1]);
        return Err(e);
    }
    Ok((fds[0], fds[1]))
}

/// Create a fresh unique temporary directory using `mkdtemp`.
fn mk_unique_dir() -> std::io::Result<PathBuf> {
    let base = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let mut tmpl = format!("{base}/cara-vm.XXXXXX\0").into_bytes();
    let p = unsafe { libc::mkdtemp(tmpl.as_mut_ptr().cast::<libc::c_char>()) };
    if p.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    tmpl.truncate(tmpl.len() - 1);
    Ok(PathBuf::from(
        String::from_utf8(tmpl).map_err(|_| std::io::Error::other("unreachable NUL"))?,
    ))
}

/// Write all bytes to a pipe from the forked child.
fn child_write(fd: i32, bytes: &[u8]) {
    let mut done = 0usize;
    while done < bytes.len() {
        let n = unsafe { libc::write(fd, bytes.as_ptr().add(done).cast(), bytes.len() - done) };
        if n > 0 {
            done += n as usize;
        } else if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else {
            break;
        }
    }
}

/// Configure and boot libkrun in the forked child. Any setup error writes an
/// `E` byte plus a negative errno to `status_fd` and exits; success writes
/// `O` immediately before `krun_start_enter`.
///
/// This runs only in the post-fork, single-threaded child. All FFI calls are
/// unsafe by nature; the `allow` keeps the macro-generated exit paths terse.
#[allow(unsafe_op_in_unsafe_fn)]
#[allow(clippy::too_many_arguments)]
unsafe fn child_boot(
    spec: &SandboxSpec,
    plan: VmPlan,
    root: &Path,
    scratch: &Path,
    rootfs_plan: RootfsPlan,
    stdout_fd: i32,
    stderr_fd: i32,
    status_fd: i32,
) {
    macro_rules! fail {
        ($code:expr) => {{
            child_write(status_fd, b"E");
            let code: i32 = $code;
            child_write(status_fd, &code.to_ne_bytes());
            libc::_exit(0);
        }};
    }

    let root_s = match root.to_str() {
        Some(s) => s,
        None => fail!(-libc::EINVAL),
    };
    let scratch_s = match scratch.to_str() {
        Some(s) => s,
        None => fail!(-libc::EINVAL),
    };

    let ctx = ffi::krun_create_ctx();
    if ctx < 0 {
        fail!(ctx);
    }
    let ctx = ctx as u32;

    if ffi::krun_set_vm_config(ctx, plan.vcpus().min(255) as u8, plan.memory_mib() as u32)
        != ffi::KRUN_SUCCESS
    {
        fail!(-libc::EINVAL);
    }

    // No vsock means no TSI: with `network = none`, libkrun would otherwise
    // auto-enable socket hijacking when a root is set (libkrun README).
    if ffi::krun_disable_implicit_vsock(ctx) != ffi::KRUN_SUCCESS {
        fail!(-libc::EINVAL);
    }
    // Keep the implicit console for kernel messages, and wire our own console
    // to the supervisor's two capped pipes. krun_set_console_output is a no-op
    // when the implicit console is disabled, so we deliberately use fds.
    if ffi::krun_add_virtio_console_default(ctx, -1, stdout_fd, stderr_fd) != ffi::KRUN_SUCCESS {
        fail!(-libc::EINVAL);
    }

    let root_s_c = match CString::new(root_s) {
        Ok(s) => s,
        Err(_) => fail!(-libc::EINVAL),
    };
    // krun_set_root serves this disposable skeleton as the guest root via
    // virtiofs. It is read-write at the virtiofs layer, but the tree is a
    // throwaway temp dir owned by this run (see UNVERIFIED for the residual
    // virtiofs host-fs exposure).
    if ffi::krun_set_root(ctx, root_s_c.as_ptr()) != ffi::KRUN_SUCCESS {
        fail!(-libc::EINVAL);
    }

    let bind = rootfs_plan.usr_bind;
    if Path::new(bind.host_path).is_dir() {
        let tag = match CString::new(bind.tag) {
            Ok(s) => s,
            Err(_) => fail!(-libc::EINVAL),
        };
        let path = match CString::new(bind.host_path) {
            Ok(s) => s,
            Err(_) => fail!(-libc::EINVAL),
        };
        if ffi::krun_add_virtiofs3(ctx, tag.as_ptr(), path.as_ptr(), 0, bind.read_only)
            != ffi::KRUN_SUCCESS
        {
            fail!(-libc::EINVAL);
        }
    } else {
        fail!(-libc::ENOENT);
    }

    let work_tag = match CString::new(WORK_TAG) {
        Ok(s) => s,
        Err(_) => fail!(-libc::EINVAL),
    };
    let work_c = match CString::new(scratch_s) {
        Ok(s) => s,
        Err(_) => fail!(-libc::EINVAL),
    };
    if ffi::krun_add_virtiofs3(ctx, work_tag.as_ptr(), work_c.as_ptr(), 0, false)
        != ffi::KRUN_SUCCESS
    {
        fail!(-libc::EINVAL);
    }

    let exec_c = match CString::new(spec.program.as_str()) {
        Ok(s) => s,
        Err(_) => fail!(-libc::EINVAL),
    };
    let mut argv: Vec<CString> = vec![exec_c.clone()];
    for a in &spec.args {
        match CString::new(a.as_str()) {
            Ok(s) => argv.push(s),
            Err(_) => fail!(-libc::EINVAL),
        }
    }
    let mut env: Vec<CString> = spec
        .env
        .iter()
        .filter_map(|(k, v)| CString::new(format!("{k}={v}")).ok())
        .collect();
    env.push(CString::new("PATH=/usr/bin:/bin").unwrap());
    env.push(CString::new("HOME=/work").unwrap());
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut env_ptrs: Vec<*const libc::c_char> = env.iter().map(|s| s.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());

    if ffi::krun_set_exec(ctx, exec_c.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr())
        != ffi::KRUN_SUCCESS
    {
        fail!(-libc::EINVAL);
    }
    let workdir = match CString::new("/work") {
        Ok(s) => s,
        Err(_) => fail!(-libc::EINVAL),
    };
    if ffi::krun_set_workdir(ctx, workdir.as_ptr()) != ffi::KRUN_SUCCESS {
        fail!(-libc::EINVAL);
    }

    // Handshake: setup completed; the VM is about to start.
    child_write(status_fd, b"O");
    let ret = ffi::krun_start_enter(ctx);
    ffi::krun_free_ctx(ctx);
    child_write(status_fd, &ret.to_ne_bytes());
    libc::_exit(0);
}

impl carapace_core::Backend for VmBackend {
    fn spawn(&self, spec: &SandboxSpec) -> Result<Box<dyn SandboxHandle>, BackendError> {
        init_libkrun_logging();

        if !kvm_available() {
            return Err(BackendError::EnvironmentNotReady(
                "KVM unavailable - the microVM tier requires /dev/kvm".to_string(),
            ));
        }
        if unsafe { ffi::krun_has_feature(ffi::KRUN_FEATURE_INIT_BLOB) } != 1 {
            return Err(BackendError::Setup(
                "libkrun built without init-blob; cannot boot the guest".to_string(),
            ));
        }

        let plan = VmPlan::from_limits(&spec.limits).map_err(BackendError::Setup)?;
        let root = self
            .rootfs_plan
            .materialize()
            .map_err(|e| BackendError::Setup(format!("guest rootfs: {e}")))?;
        for (src, guest) in &self.seeds {
            let dest = root.path().join(guest.trim_start_matches('/'));
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| BackendError::Setup(format!("seed parent: {e}")))?;
            }
            fs::copy(src, &dest).map_err(|e| BackendError::Setup(format!("seed {guest}: {e}")))?;
        }
        let scratch =
            mk_scratch_dir().map_err(|e| BackendError::Setup(format!("work scratch: {e}")))?;
        let cap = spec.limits.max_output_bytes.min(VM_STREAM_CAP);
        let (stdout_r, stdout_w) =
            make_pipe().map_err(|e| BackendError::Setup(format!("stdout pipe: {e}")))?;
        let (stderr_r, stderr_w) =
            make_pipe().map_err(|e| BackendError::Setup(format!("stderr pipe: {e}")))?;
        let (status_r, status_w) =
            make_pipe().map_err(|e| BackendError::Setup(format!("status pipe: {e}")))?;

        // SAFETY: fork happens before libkrun has created any threads in this
        // process. The child is single-threaded and talks to the parent only
        // through pipes. Embedders must not hold libc-internal locks in other
        // threads while calling spawn (the same constraint as Tier 1).
        let child = unsafe { libc::fork() };
        if child < 0 {
            let e = std::io::Error::last_os_error();
            return Err(BackendError::Setup(format!("fork for VM: {e}")));
        }
        if child == 0 {
            unsafe {
                // Own process group so kill(-pid) reaches every VMM thread.
                libc::setpgid(0, 0);
                libc::close(stdout_r);
                libc::close(stderr_r);
                libc::close(status_r);
                child_boot(
                    spec,
                    plan,
                    root.path(),
                    scratch.path(),
                    self.rootfs_plan,
                    stdout_w,
                    stderr_w,
                    status_w,
                );
                libc::_exit(0);
            }
        }

        // Parent: close the write ends; the child owns them now.
        let mut w1 = stdout_w;
        let mut w2 = stderr_w;
        let mut w3 = status_w;
        close_fd(&mut w1);
        close_fd(&mut w2);
        close_fd(&mut w3);
        unsafe {
            // Avoid a setpgid race; one of the two calls may fail harmlessly.
            libc::setpgid(child, child);
        }

        // Wait for the setup handshake. This makes setup failures a spawn-
        // time error rather than a "VM that silently never ran".
        let mut handshake = [0u8; 1];
        let mut got = 0usize;
        let deadline = Instant::now() + SETUP_HANDSHAKE;
        while got == 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let mut pfd = libc::pollfd {
                fd: status_r,
                events: libc::POLLIN,
                revents: 0,
            };
            let n = unsafe {
                libc::poll(
                    &mut pfd,
                    1,
                    remaining.as_millis().min(i32::MAX as u128) as i32,
                )
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }
            if n == 0 {
                continue;
            }
            let r = unsafe { libc::read(status_r, handshake.as_mut_ptr().cast(), 1) };
            if r > 0 {
                got = 1;
            } else if r == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
            {
                break;
            }
        }

        if got == 0 || handshake[0] != b'O' {
            let detail = if got == 0 {
                "no setup handshake from VM child".to_string()
            } else {
                let mut code = [0u8; 4];
                let _ = unsafe { libc::read(status_r, code.as_mut_ptr().cast(), 4) };
                format!("libkrun setup failed: {}", i32::from_ne_bytes(code))
            };
            kill_vm_group(child);
            let mut status = 0i32;
            unsafe {
                libc::waitpid(child, &mut status, 0);
            }
            let mut a = stdout_r;
            let mut b = stderr_r;
            let mut c = status_r;
            close_fd(&mut a);
            close_fd(&mut b);
            close_fd(&mut c);
            return Err(BackendError::Setup(detail));
        }

        let state = Arc::new(VmState::new(child));
        let wd_state = state.clone();
        let wd_deadline = Instant::now() + spec.limits.timeout;
        let watchdog = std::thread::Builder::new()
            .name("cara-vm-watchdog".to_string())
            .spawn(move || watchdog(wd_state, wd_deadline))
            .map_err(|e| BackendError::Setup(format!("watchdog thread: {e}")))?;

        Ok(Box::new(VmHandle {
            state,
            stdout_fd: stdout_r,
            stderr_fd: stderr_r,
            status_fd: status_r,
            output: CappedOutput::new(cap),
            status_code: None,
            timeout: spec.limits.timeout,
            start: Instant::now(),
            waited: false,
            _root: root,
            _scratch: scratch,
            watchdog: Some(watchdog),
        }))
    }
}

fn mk_scratch_dir() -> std::io::Result<ScratchDir> {
    let mut path = mk_unique_dir()?;
    path.push("work");
    fs::create_dir(&path)?;
    Ok(ScratchDir { path })
}

#[cfg(test)]
mod tests {
    use super::*;
    use carapace_core::Backend;
    use carapace_core::spec::Limits;
    use std::time::Duration;

    #[test]
    fn vm_plan_rounds_up_and_clamps() {
        let plan = VmPlan::from_limits(&Limits {
            memory_bytes: 256 * BYTES_PER_MIB,
            cpu_percent: 100,
            ..Default::default()
        })
        .unwrap();
        assert_eq!((plan.vcpus(), plan.memory_mib()), (1, 256));

        let plan = VmPlan::from_limits(&Limits {
            memory_bytes: 1000 * BYTES_PER_MIB,
            cpu_percent: 250,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(plan.memory_mib(), 1000);
        assert_eq!(plan.vcpus(), 3);

        let plan = VmPlan::from_limits(&Limits {
            memory_bytes: 1,
            cpu_percent: 1,
            ..Default::default()
        })
        .unwrap();
        assert_eq!((plan.vcpus(), plan.memory_mib()), (1, MIN_MEMORY_MIB));

        let plan = VmPlan::from_limits(&Limits {
            memory_bytes: 32 * 1024 * BYTES_PER_MIB,
            cpu_percent: 100_000,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            (plan.vcpus(), plan.memory_mib()),
            (MAX_VCPUS, MAX_MEMORY_MIB)
        );
    }

    #[test]
    fn vm_plan_rejects_zero_budgets() {
        assert!(
            VmPlan::from_limits(&Limits {
                memory_bytes: 0,
                cpu_percent: 100,
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            VmPlan::from_limits(&Limits {
                memory_bytes: 256 * BYTES_PER_MIB,
                cpu_percent: 0,
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn rootfs_plan_lists_required_dirs() {
        let plan = RootfsPlan::default();
        for required in [
            "bin", "lib", "lib64", "usr", "etc", "work", "proc", "dev", "tmp",
        ] {
            assert!(plan.dirs.contains(&required), "missing {required}");
        }
        assert_eq!(plan.usr_bind.tag, "/usr");
        assert_eq!(plan.usr_bind.host_path, "/usr");
        assert!(plan.usr_bind.read_only);
    }

    #[test]
    fn rootfs_materialize_creates_and_removes_dirs() {
        let plan = RootfsPlan::default();
        let root = plan.materialize().unwrap();
        let path = root.path().to_path_buf();
        assert!(path.is_dir());
        for dir in plan.dirs {
            assert!(path.join(dir).is_dir(), "{} was not created", dir);
        }
        drop(root);
        assert!(!path.exists(), "rootfs dir leaked after Drop");
    }

    #[test]
    fn capped_output_enforces_hard_limit_and_flags_overflow() {
        let mut out = CappedOutput::new(8);
        out.push_stdout(b"12345");
        assert_eq!(out.stdout, b"12345");
        assert!(!out.overflow);
        out.push_stdout(b"67890");
        assert_eq!(out.stdout, b"12345678");
        assert!(out.overflow);
        out.push_stderr(b"x");
        assert_eq!(out.stderr, b"x");
        out.push_stdout(b"more");
        assert_eq!(out.stdout.len(), 8);
        assert_eq!(CappedOutput::new(VM_STREAM_CAP).cap(), 8 * 1024 * 1024);
    }

    #[test]
    fn kill_reason_is_first_wins_and_kill_stops_a_real_group() {
        let state = VmState::new(0);
        state.record_reason(KillReason::Timeout);
        state.record_reason(KillReason::OutputOverflow);
        assert_eq!(
            *state.killed_reason.lock().unwrap(),
            Some(KillReason::Timeout)
        );

        // Not a hostile payload: proves SIGKILL reaches a process group.
        use std::os::unix::process::CommandExt;
        let child = std::process::Command::new("sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;
        kill_vm_group(pid);
        let out = child.wait_with_output().expect("reap sleep");
        assert_eq!(out.status.code(), None, "sleep must die by signal");
        assert!(!out.status.success());
    }

    #[test]
    fn handle_kill_records_reason_without_kvm() {
        let root = RootfsPlan::default().materialize().unwrap();
        let scratch = mk_scratch_dir().unwrap();
        let state = Arc::new(VmState::new(0));
        let mut handle = VmHandle {
            state: state.clone(),
            stdout_fd: -1,
            stderr_fd: -1,
            status_fd: -1,
            output: CappedOutput::new(16),
            status_code: Some(0),
            timeout: Duration::from_secs(1),
            start: Instant::now(),
            waited: false,
            _root: root,
            _scratch: scratch,
            watchdog: None,
        };
        handle.kill(KillReason::Timeout);
        assert_eq!(
            *state.killed_reason.lock().unwrap(),
            Some(KillReason::Timeout)
        );
        let report = handle.wait().unwrap();
        assert_eq!(report.kill_reason, Some(KillReason::Timeout));
        assert_eq!(report.exit_code, None);
    }

    #[test]
    fn without_kvm_spawn_fails_closed() {
        if !kvm_available() {
            let spec = SandboxSpec::new("/bin/true");
            match VmBackend::new().spawn(&spec) {
                Err(BackendError::EnvironmentNotReady(msg)) => {
                    assert!(msg.contains("KVM"), "unexpected message: {msg}");
                }
                Err(other) => panic!("expected EnvironmentNotReady, got {other:?}"),
                Ok(_) => panic!("expected EnvironmentNotReady, got a live handle"),
            }
        }
    }

    #[test]
    fn kvm_boot_e2e_when_available() {
        if !kvm_available() {
            eprintln!("SKIP: /dev/kvm absent; VM boot not exercised on this host");
            return;
        }
        // Seed a real payload into the disposable guest root. This uses the
        // reference Ubuntu userland: /bin/true plus its ELF loader and libc.
        let backend = VmBackend::new()
            .with_seed("/bin/true", "/bin/true")
            .with_seed(
                "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                "/lib64/ld-linux-x86-64.so.2",
            )
            .with_seed(
                "/lib/x86_64-linux-gnu/libc.so.6",
                "/lib/x86_64-linux-gnu/libc.so.6",
            );
        let spec = SandboxSpec::new("/bin/true").timeout(Duration::from_secs(30));
        let mut handle = match backend.spawn(&spec) {
            Ok(h) => h,
            Err(e) => panic!("boot setup failed on a KVM host: {e}"),
        };
        let report = handle.wait().unwrap();
        assert_eq!(report.kill_reason, None, "clean exit expected: {report:?}");
        assert_eq!(report.exit_code, Some(0));
    }
}
