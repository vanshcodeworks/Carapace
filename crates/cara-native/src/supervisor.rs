//! Parent-side supervision of one sandbox run: stdio wiring, the go/exec
//! handshake, wall-time timeout, output caps, pidfd kill, reaping.

use crate::child::{ChildConfig, ChildError, stage};
use carapace_core::BackendError;
use carapace_core::report::{ExitReport, KillReason};
use carapace_core::spec::SandboxSpec;
use carapace_sys::fork;
use std::io::Read;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Namespace flags for every Tier 1 sandbox child: fresh user, PID, mount,
/// network, IPC, UTS and cgroup namespaces (see threat-model §3 and
/// ADR-0002 for the kill story that depends on CLONE_NEWPID).
const SANDBOX_FLAGS: libc::c_int = (libc::SIGCHLD as libc::c_int)
    | libc::CLONE_NEWUSER as libc::c_int
    | libc::CLONE_NEWPID as libc::c_int
    | libc::CLONE_NEWNS as libc::c_int
    | libc::CLONE_NEWNET as libc::c_int
    | libc::CLONE_NEWIPC as libc::c_int
    | libc::CLONE_NEWUTS as libc::c_int
    | libc::CLONE_NEWCGROUP as libc::c_int;

const CHILD_STACK_SIZE: usize = 512 * 1024;

fn pipe2_cloexec() -> std::io::Result<(RawFd, RawFd)> {
    let mut fds = [0 as libc::c_int; 2];
    let r = unsafe {
        // SAFETY: pipe2 into a valid 2-int array with O_CLOEXEC: both fds
        // are close-on-exec from birth.
        libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC)
    };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok((fds[0], fds[1]))
    }
}

/// Takes a raw fd into an owned `File` (the File closes it on drop).
unsafe fn fd_owned_file(fd: RawFd) -> std::fs::File {
    unsafe {
        // SAFETY: caller guarantees the fd is valid and exclusively ours.
        std::os::unix::io::FromRawFd::from_raw_fd(fd)
    }
}

/// Reads `fd` until EOF into a Vec, keeping at most `cap` bytes and setting
/// `overflow` when more arrived (the reader keeps draining so the child
/// never blocks on a full pipe while dying).
fn read_capped(mut file: std::fs::File, cap: usize, overflow: Arc<AtomicBool>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() < cap {
                    let take = std::cmp::min(n, cap - out.len());
                    out.extend_from_slice(&buf[..take]);
                    if n > take {
                        overflow.store(true, Ordering::Relaxed);
                    }
                } else if n > 0 {
                    overflow.store(true, Ordering::Relaxed);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    out
}

/// One running sandbox. Created by [`super::backend::NativeBackend::spawn`].
pub(crate) struct NativeSandbox {
    pid: libc::pid_t,
    pidfd: libc::c_int,
    stack: (*mut u8, usize),
    config: *mut libc::c_void,
    start: Instant,
    timeout: Duration,
    max_output: usize,
    stdout_reader: Option<std::thread::JoinHandle<Vec<u8>>>,
    stderr_reader: Option<std::thread::JoinHandle<Vec<u8>>>,
    overflow: Arc<AtomicBool>,
    killed_reason: Mutex<Option<KillReason>>,
    /// Set once the child has been reaped, with its raw wait status.
    reaped: Mutex<Option<libc::c_int>>,
}

// SAFETY: NativeSandbox owns its raw pointers exclusively (the mmap'd child
// stack and the leaked ChildConfig); they are only dereferenced/freed on
// the owning thread after the child is reaped, so moving the handle across
// threads cannot race anything.
unsafe impl Send for NativeSandbox {}

/// Spawns the sandbox child. Returns the live handle, or a `Setup` error
/// when isolation could not be established (the payload never ran).
pub(crate) fn spawn(spec: &SandboxSpec) -> Result<NativeSandbox, BackendError> {
    let setup = |what: &str, e: std::io::Error| -> BackendError {
        BackendError::Setup(format!("{what}: {e}"))
    };

    // Host-layout validation for the C2 runtime recipe (fail closed BEFORE
    // cloning: merged-usr with a real /usr tree). Narrow, recipe-driven
    // rootfs builds replace this in later milestones.
    for p in ["/usr/bin/sh", "/usr/lib", "/usr/lib64"] {
        if std::fs::metadata(p).is_err() {
            return Err(BackendError::Setup(format!(
                "host runtime layout unsupported: {p} missing (v1 requires a merged-usr host)"
            )));
        }
    }

    // Pipes: all CLOEXEC. The child dup2s 0/1/2 (dup2 clears CLOEXEC on the
    // targets — exactly what the payload's stdio needs); every other
    // inherited copy vanishes at exec.
    let (status_rd, status_wr) = pipe2_cloexec().map_err(|e| setup("status pipe", e))?;
    let (go_rd, go_wr) = pipe2_cloexec().map_err(|e| setup("go pipe", e))?;
    let (stdout_rd, stdout_wr) = pipe2_cloexec().map_err(|e| setup("stdout pipe", e))?;
    let (stderr_rd, stderr_wr) = pipe2_cloexec().map_err(|e| setup("stderr pipe", e))?;
    let devnull_rd = {
        let fd = unsafe {
            // SAFETY: open(2) on a fixed path with O_CLOEXEC; checked.
            libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
        };
        if fd < 0 {
            return Err(setup("open /dev/null", std::io::Error::last_os_error()));
        }
        fd
    };
    // Reader files take exclusive ownership of these fds.
    let stdout_file = unsafe { fd_owned_file(stdout_rd) };
    let stderr_file = unsafe { fd_owned_file(stderr_rd) };
    let status_file = unsafe { fd_owned_file(status_rd) };

    // argv/env as CStrings now — the child must not allocate.
    let mk_cstring = |s: &str, what: &str| -> Result<std::ffi::CString, BackendError> {
        std::ffi::CString::new(s).map_err(|e| setup(what, std::io::Error::other(format!("{e}"))))
    };
    let mut argv = Vec::with_capacity(spec.args.len() + 1);
    argv.push(mk_cstring(&spec.program, "program path")?);
    for a in &spec.args {
        argv.push(mk_cstring(a, "argument")?);
    }
    let mut envp = Vec::with_capacity(spec.env.len());
    for (k, v) in &spec.env {
        envp.push(mk_cstring(&format!("{k}={v}"), "env entry")?);
    }

    let config = Box::new(ChildConfig {
        argv,
        envp,
        status_wr,
        go_rd,
        stdin_fd: devnull_rd,
        stdout_fd: stdout_wr,
        stderr_fd: stderr_wr,
        // Capture BEFORE clone: the child's own getuid() inside the new
        // userns reports the overflow id until the map is written.
        parent_uid: unsafe { libc::getuid() }, // SAFETY: plain getter
        parent_gid: unsafe { libc::getgid() }, // SAFETY: plain getter
        // tmpfs size options, pre-formatted here so the child never
        // formats. Root holds /etc, symlinks, empty dirs: 8 MiB is ample.
        // /work is the payload's writable scratch from the policy.
        root_size_opt: std::ffi::CString::new(format!("size={}", 8 * 1024 * 1024))
            .expect("numeric size option has no NULs"),
        work_size_opt: std::ffi::CString::new(format!("size={}", spec.limits.scratch_bytes))
            .map_err(|e| setup("scratch size", std::io::Error::other(format!("{e}"))))?,
    });
    let config_ptr = Box::into_raw(config) as *mut libc::c_void;

    let (stack_base, stack_size) =
        unsafe { fork::alloc_child_stack(CHILD_STACK_SIZE) }.map_err(|e| {
            release_config(config_ptr);
            setup("child stack", e)
        })?;
    let stack_top = unsafe { stack_base.add(stack_size) };

    let spawned = unsafe {
        fork::clone_ns(
            crate::child::child_main,
            stack_top,
            SANDBOX_FLAGS,
            config_ptr,
        )
    };
    let spawned = match spawned {
        Ok(s) => s,
        Err(e) => {
            unsafe { fork::munmap_stack(stack_base, stack_size) };
            release_config(config_ptr);
            return Err(setup("clone(namespaces)", e));
        }
    };

    // Post-clone, pre-exec cleanup for any handshake failure below: the
    // child must never be left half-configured (fail closed).
    let child_pid = spawned.pid;
    let child_pidfd = spawned.pidfd;
    let cleanup_err = move |what: &str, e: std::io::Error| -> BackendError {
        kill_and_reap(&spawned);
        unsafe { fork::munmap_stack(stack_base, stack_size) };
        release_config(config_ptr);
        setup(what, e)
    };

    // Tell the child to exec (nothing between clone and exec needs the
    // parent in C1; C3 uses this window for the cgroup attach).
    let go_buf = *b"G";
    loop {
        let n = unsafe {
            // SAFETY: raw write to our end of the go pipe.
            libc::write(go_wr, go_buf.as_ptr().cast(), 1)
        };
        if n >= 0 {
            break;
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(cleanup_err("go signal", e));
    }

    // CRITICAL: close the parent's copies of every child-facing fd NOW.
    // The child has its own duplicates; holding write-ends open here would
    // block EOF detection on the status/stdio pipes forever (observed as a
    // supervisor hang). Nothing of the child survives in our fd table.
    for fd in [status_wr, go_rd, go_wr, stdout_wr, stderr_wr, devnull_rd] {
        unsafe {
            // SAFETY: fds we created; after the clone (which duplicated
            // them into the child) and the go write, the parent has no
            // further use for any of them.
            libc::close(fd);
        }
    }
    // status_rd lives on as `status_file`; stdio read ends as reader Files.

    // exec confirmation: EOF = running; ChildError = pre-exec failure
    // (fail closed — the payload never ran).
    let mut status_file = status_file;
    let mut pre = [0u8; std::mem::size_of::<ChildError>()];
    loop {
        match status_file.read(&mut pre) {
            Ok(0) => break, // exec happened
            Ok(n) if n == std::mem::size_of::<ChildError>() => {
                let report: ChildError =
                    unsafe { std::ptr::read_unaligned(pre.as_ptr() as *const ChildError) };
                let stage_name = stage_name(report.stage);
                return Err(cleanup_err(
                    &format!("child setup at {stage_name}"),
                    std::io::Error::from_raw_os_error(report.errno),
                ));
            }
            Ok(_) => {
                return Err(cleanup_err(
                    "status pipe",
                    std::io::Error::other("short read"),
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(cleanup_err("status pipe", e));
            }
        }
    }

    // Output readers start after exec confirmation.
    let overflow = Arc::new(AtomicBool::new(false));
    let cap = spec.limits.max_output_bytes;
    let ov1 = Arc::clone(&overflow);
    let stdout_reader = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || read_capped(stdout_file, cap, ov1))
        .map_err(|e| setup("stdout reader", e))?;
    let ov2 = Arc::clone(&overflow);
    let stderr_reader = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || read_capped(stderr_file, cap, ov2))
        .map_err(|e| setup("stderr reader", e))?;

    Ok(NativeSandbox {
        pid: child_pid,
        pidfd: child_pidfd,
        stack: (stack_base, stack_size),
        config: config_ptr,
        start: Instant::now(),
        timeout: spec.limits.timeout,
        max_output: spec.limits.max_output_bytes,
        stdout_reader: Some(stdout_reader),
        stderr_reader: Some(stderr_reader),
        overflow,
        killed_reason: Mutex::new(None),
        reaped: Mutex::new(None),
    })
}

fn release_config(p: *mut libc::c_void) {
    if !p.is_null() {
        unsafe {
            // SAFETY: p came from Box::into_raw in spawn; reclaimed exactly
            // once, after the child that referenced it is dead.
            drop(Box::from_raw(p as *mut ChildConfig));
        }
    }
}

fn kill_and_reap(spawned: &fork::SpawnedChild) {
    let _ = fork::pidfd_send_signal(spawned.pidfd, libc::SIGKILL);
    let mut status: libc::c_int = 0;
    unsafe {
        // SAFETY: blocking waitpid on our direct clone child; cleanup path.
        libc::waitpid(spawned.pid, &mut status, 0);
    }
}

fn stage_name(stage: u8) -> &'static str {
    match stage {
        stage::WRITE_UID_MAP => "uid_map",
        stage::WRITE_GID_MAP => "gid_map",
        stage::DENY_SETGROUPS => "setgroups deny",
        stage::SET_RLIMIT => "rlimits",
        stage::SYNC => "stdio/sync",
        stage::EXEC => "execve",
        stage::MOUNT_PRIVATE => "mount private",
        stage::MOUNT_ROOT => "root tmpfs",
        stage::MOUNT_RUNTIME => "runtime mounts",
        stage::MOUNT_PROC => "proc mount",
        stage::PIVOT => "pivot_root",
        stage::PIVOT_CHDIR => "pivot chdir",
        stage::PIVOT_DETACH => "pivot detach",
        stage::VERIFY => "post-pivot verify",
        _ => "unknown",
    }
}

impl NativeSandbox {
    /// Implementation of `SandboxHandle::wait`.
    pub fn wait(&mut self) -> Result<ExitReport, BackendError> {
        let deadline = self.start + self.timeout;
        loop {
            // Kill conditions first: explicit kill wins, then overflow.
            let reason = self.killed_reason.lock().unwrap().clone();
            match reason {
                Some(_) => {
                    self.kill_tree();
                    break;
                }
                None => {
                    if self.overflow.load(Ordering::Relaxed) {
                        *self.killed_reason.lock().unwrap() = Some(KillReason::OutputOverflow);
                        self.kill_tree();
                        break;
                    }
                }
            }

            let now = Instant::now();
            if now >= deadline {
                *self.killed_reason.lock().unwrap() = Some(KillReason::Timeout);
                self.kill_tree();
                break;
            }

            let mut pfd = [libc::pollfd {
                fd: self.pidfd,
                events: libc::POLLIN,
                revents: 0,
            }];
            let remaining = ((deadline - now).as_millis().min(i32::MAX as u128) as i32) + 1;
            let n = unsafe {
                // SAFETY: poll(2) over one valid pollfd with a bounded
                // timeout; EINTR handled below.
                libc::poll(pfd.as_mut_ptr(), 1, remaining)
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(BackendError::Supervision(format!("poll: {e}")));
            }
            if n > 0 && (pfd[0].revents & libc::POLLIN) != 0 {
                break; // child exited
            }
            // n == 0 → timeout re-checked at loop top
        }

        let status = self.reap();
        Ok(self.finish_report(status))
    }

    /// Implementation of `SandboxHandle::kill`.
    pub fn kill(&mut self, reason: KillReason) {
        let mut kr = self.killed_reason.lock().unwrap();
        if kr.is_none() {
            *kr = Some(reason);
        }
        drop(kr);
        self.kill_tree();
    }

    fn kill_tree(&mut self) {
        // Kill the PID-namespace init; the kernel then SIGKILLs everything
        // left in that namespace (ADR-0002). No waitpid(-1) sweep here: a
        // process hosting several sandboxes concurrently (the test suite,
        // the future pool) must never reap another sandbox's children.
        // Escaped descendants are prevented by the PID namespace itself.
        let _ = fork::pidfd_send_signal(self.pidfd, libc::SIGKILL);
    }

    fn reap(&mut self) -> libc::c_int {
        let mut slot = self.reaped.lock().unwrap();
        if let Some(s) = *slot {
            return s;
        }
        loop {
            let mut status: libc::c_int = 0;
            let r = unsafe {
                // SAFETY: blocking waitpid on our direct child.
                libc::waitpid(self.pid, &mut status, 0)
            };
            if r == self.pid {
                *slot = Some(status);
                return status;
            }
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                // ECHILD despite the pidfd saying it exited: the subreaper
                // sweep already reaped it. Synthesize a SIGKILL death — the
                // only path here is supervisor-initiated kills.
                let s = 128 + libc::SIGKILL;
                *slot = Some(s);
                return s;
            }
        }
    }

    fn finish_report(&mut self, status: libc::c_int) -> ExitReport {
        let exit_code = if libc::WIFEXITED(status) {
            Some(libc::WEXITSTATUS(status))
        } else {
            None
        };
        let signal = if libc::WIFSIGNALED(status) {
            Some(libc::WTERMSIG(status))
        } else {
            None
        };

        let stdout = self
            .stdout_reader
            .take()
            .and_then(|t| t.join().ok())
            .unwrap_or_default();
        let stderr = self
            .stderr_reader
            .take()
            .and_then(|t| t.join().ok())
            .unwrap_or_default();

        ExitReport {
            exit_code,
            signal,
            kill_reason: self.killed_reason.lock().unwrap().take(),
            wall_time: self.start.elapsed(),
            stdout: truncate_cap(stdout, self.max_output),
            stderr: truncate_cap(stderr, self.max_output),
        }
    }
}

fn truncate_cap(mut v: Vec<u8>, cap: usize) -> Vec<u8> {
    v.truncate(cap);
    v
}

impl Drop for NativeSandbox {
    fn drop(&mut self) {
        // Safety net: even if wait() was never called, the tree dies and
        // nothing leaks (pipes, stack, config, zombies, staging dir).
        self.kill_tree();
        let _ = self.reap();
        if let Some(t) = self.stdout_reader.take() {
            let _ = t.join();
        }
        if let Some(t) = self.stderr_reader.take() {
            let _ = t.join();
        }
        release_config(self.config);
        let (base, size) = self.stack;
        unsafe {
            // SAFETY: from alloc_child_stack; child is reaped by now.
            fork::munmap_stack(base, size);
        }
    }
}
