//! Parent-side supervision of one sandbox run (two-stage child design —
//! see `child.rs` for why stage-1 is a plain fork that unshares later):
//! stdio wiring, the go/exec handshake, cgroup attach, wall-time timeout,
//! output caps, pidfd kill of the payload init, reaping, resource report.

use crate::child::{ChildConfig, ChildError, msg, stage};
use carapace_core::BackendError;
use carapace_core::report::{ExitReport, KillReason};
use carapace_core::spec::SandboxSpec;
use carapace_sys::fork;
use std::io::Read;
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
        FromRawFd::from_raw_fd(fd)
    }
}

fn pidfd_open(pid: libc::pid_t) -> std::io::Result<libc::c_int> {
    let r = unsafe {
        // SAFETY: pidfd_open(2) on a live same-uid pid with flags 0.
        libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0u32)
    };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(r as libc::c_int)
    }
}

/// Reads `fd` until EOF into a Vec, keeping at most `cap` bytes. On the
/// first excess byte the overflow flag is set AND one byte goes to
/// `signal_wr`, waking the supervisor's poll loop immediately (without the
/// signal, a quiet-but-over-limit payload would only be noticed when poll
/// times out). The reader keeps draining so the child never blocks on a
/// full pipe while dying.
fn read_capped(
    mut file: std::fs::File,
    cap: usize,
    overflow: Arc<AtomicBool>,
    signal_wr: RawFd,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    let mut signalled = false;
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() < cap {
                    let take = std::cmp::min(n, cap - out.len());
                    out.extend_from_slice(&buf[..take]);
                    if n > take {
                        note_overflow(&overflow, signal_wr, &mut signalled);
                    }
                } else if n > 0 {
                    note_overflow(&overflow, signal_wr, &mut signalled);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    out
}

fn note_overflow(overflow: &AtomicBool, signal_wr: RawFd, signalled: &mut bool) {
    overflow.store(true, Ordering::Relaxed);
    if !*signalled {
        *signalled = true;
        let b = b"!";
        unsafe {
            // SAFETY: one-byte write to our own pipe; EAGAIN is fine (the
            // supervisor was already woken).
            libc::write(signal_wr, b.as_ptr().cast(), 1);
        }
    }
}

/// One running sandbox. Created by [`super::backend::NativeBackend::spawn`].
pub(crate) struct NativeSandbox {
    /// Stage-1 proxy pid (plain fork; exits after forwarding status).
    pid1: libc::pid_t,
    /// pidfd of the stage-2 payload init (pid 1 of the sandbox PID
    /// namespace): primary kill target and exit poll source. None when the
    /// payload exited before the pidfd could be opened (already finished).
    pidfd2: Option<libc::c_int>,
    config: *mut libc::c_void,
    /// Result pipe read end: receives EXIT_FORWARD after the payload dies.
    result_file: Option<std::fs::File>,
    start: Instant,
    timeout: Duration,
    max_output: usize,
    stdout_reader: Option<std::thread::JoinHandle<Vec<u8>>>,
    stderr_reader: Option<std::thread::JoinHandle<Vec<u8>>>,
    overflow: Arc<AtomicBool>,
    killed_reason: Mutex<Option<KillReason>>,
    /// Forwarded raw waitpid status of the payload, once known.
    reaped: Mutex<Option<libc::c_int>>,
    /// Set by wait(); a second call is a caller bug and errors (the trait
    /// documents wait as call-once — silently re-reporting would hide it).
    waited: Mutex<bool>,
    /// The run's cgroup leaf (limits + accounting); removed on drop.
    cgroup_leaf: Option<crate::cgroup::CgroupLeaf>,
    /// Host-side staging dir; removed after the child (and its mount ns)
    /// is gone.
    staging_dir: std::ffi::CString,
    /// Self-pipe write end handed to the reader threads for overflow
    /// signals; closed on drop.
    overflow_wr: RawFd,
    /// Self-pipe read end polled alongside the pidfd; closed on drop.
    overflow_rd: RawFd,
}

// SAFETY: NativeSandbox owns its raw pointer (the leaked ChildConfig)
// exclusively; it is only dereferenced/freed on the owning thread after
// the child is reaped, so moving the handle across threads cannot race.
unsafe impl Send for NativeSandbox {}

/// Spawns the sandbox child. Returns the live handle, or a `Setup` error
/// when isolation could not be established (the payload never ran).
pub(crate) fn spawn(spec: &SandboxSpec) -> Result<NativeSandbox, BackendError> {
    // Honest wall-time origin: the very beginning of the spawn, not the
    // moment supervision begins (the payload may already be running by
    // then — the handshake overlaps the payload's first milliseconds).
    let spawn_start = Instant::now();
    let setup = |what: &str, e: std::io::Error| -> BackendError {
        BackendError::Setup(format!("{what}: {e}"))
    };

    // Network allowlist mode: designed (ADR-0004) but not implemented —
    // fail closed with a clear message rather than pretending.
    if let carapace_core::NetworkMode::Allowlist(_) = spec.network {
        return Err(BackendError::Setup(
            "network mode \"allowlist\" is not implemented yet (ADR-0004); \
             use mode = \"none\" or \"full\""
                .to_string(),
        ));
    }

    // Host-layout validation for the C2 runtime recipe (fail closed BEFORE
    // forking: merged-usr with a real /usr tree).
    for p in ["/usr/bin/sh", "/usr/lib", "/usr/lib64"] {
        if std::fs::metadata(p).is_err() {
            return Err(BackendError::Setup(format!(
                "host runtime layout unsupported: {p} missing (v1 requires a merged-usr host)"
            )));
        }
    }

    // Pipes: all CLOEXEC. Stage-2 dup2s 0/1/2 (dup2 clears CLOEXEC on the
    // targets — exactly what the payload's stdio needs); every other
    // inherited copy vanishes at exec.
    let (status_rd, status_wr) = pipe2_cloexec().map_err(|e| setup("status pipe", e))?;
    let (result_rd, result_wr) = pipe2_cloexec().map_err(|e| setup("result pipe", e))?;
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
    // SAFETY: each fd is open, exclusively ours, and not used again after
    // the File takes ownership.
    let stdout_file = unsafe { fd_owned_file(stdout_rd) };
    // SAFETY: as above.
    let stderr_file = unsafe { fd_owned_file(stderr_rd) };
    // SAFETY: as above.
    let mut status_file = unsafe { fd_owned_file(status_rd) };

    // argv/env as CStrings now — the children must not allocate.
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

    // Staging dir for the child's new-root tmpfs: mkdtemp in a
    // uid-writable filesystem. $XDG_RUNTIME_DIR (systemd user runtime,
    // dev-owned tmpfs) first; /tmp fallback (world-writable, mkdtemp is
    // 0700-unique). Removed on every teardown path.
    let staging_dir = mk_staging_dir().map_err(|e| setup("staging dir", e))?;
    let staging_cref: &std::ffi::CStr = &staging_dir;

    let config = Box::new(ChildConfig {
        argv,
        envp,
        status_wr,
        result_wr,
        go_rd,
        stdin_fd: devnull_rd,
        stdout_fd: stdout_wr,
        stderr_fd: stderr_wr,
        // Capture BEFORE fork: inside the new userns getuid() reports the
        // overflow id until the map is written.
        parent_uid: unsafe {
            // SAFETY: plain getter with no failure mode.
            libc::getuid()
        },
        parent_gid: unsafe {
            // SAFETY: plain getter with no failure mode.
            libc::getgid()
        },
        // tmpfs size options, pre-formatted here so the children never
        // format. Root holds /etc, symlinks, empty dirs: 8 MiB is ample.
        root_size_opt: std::ffi::CString::new(format!("size={}", 8 * 1024 * 1024))
            .expect("numeric size option has no NULs"),
        work_size_opt: std::ffi::CString::new(format!("size={}", spec.limits.scratch_bytes))
            .map_err(|e| setup("scratch size", std::io::Error::other(format!("{e}"))))?,
        fsize_limit: spec.limits.scratch_bytes.max(1024),
        unshare_flags: unshare_flags_for(&spec.network),
        supervisor_pid: unsafe {
            // SAFETY: plain getter with no failure mode.
            libc::getpid()
        },
        staging_dir: staging_dir.clone(),
        seccomp_filter: crate::seccomp_profile::filter_for(&spec.network)
            .as_slice()
            .to_vec(),
        binds: binds_for(spec),
        alternatives: plan_alternatives(std::path::Path::new("/etc/alternatives")),
        exec_on_write: spec.exec_on_write,
        #[cfg(test)]
        pdeathsig_hook_fd: test_pdeathsig_hook_fd(),
    });
    let config_ptr = Box::into_raw(config) as *mut libc::c_void;

    // Stage-1: a PLAIN fork (no namespaces yet) — required so the parent
    // can move it into the cgroup leaf (see child.rs design note).
    let pid1 = unsafe {
        // SAFETY: fork(2); the child branch immediately calls the
        // async-signal-safe child_main and _exits.
        libc::fork()
    };
    if pid1 < 0 {
        release_config(config_ptr);
        return Err(setup("fork", std::io::Error::last_os_error()));
    }
    if pid1 == 0 {
        let code = crate::child::child_main(config_ptr);
        unsafe {
            // SAFETY: stage-1/2 never return normally; this is the final
            // exit for unexpected returns.
            libc::_exit(code);
        }
    }

    // Fail-closed cleanup for any handshake failure below.
    // C3: create the cgroup leaf and attach the PARKED stage-1 child. It
    // has no namespaces and no descendants yet, so the limits cover every
    // process this run will ever create. Failure is fatal (fail closed).
    let cgroup_leaf = match crate::cgroup::delegated_root() {
        Some(root) => match crate::cgroup::CgroupLeaf::create(&root, &spec.limits, pid1) {
            Ok(leaf) => leaf,
            Err(e) => {
                return Err(spawn_cleanup(
                    pid1,
                    None,
                    None,
                    staging_cref,
                    config_ptr,
                    "cgroup limits",
                    e,
                ));
            }
        },
        None => {
            return Err(spawn_cleanup(
                pid1,
                None,
                None,
                staging_cref,
                config_ptr,
                "cgroup limits",
                std::io::Error::other("no delegated cgroup root found"),
            ));
        }
    };

    // Release stage-1: it unshares everything and forks the payload init.
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
        return Err(spawn_cleanup(
            pid1,
            None,
            Some(&cgroup_leaf),
            staging_cref,
            config_ptr,
            "go signal",
            e,
        ));
    }

    // CRITICAL: close the parent's copies of every child-facing fd NOW:
    // holding write-ends open here would block EOF detection on the
    // status/stdio pipes forever.
    for fd in [
        status_wr, result_wr, go_rd, go_wr, stdout_wr, stderr_wr, devnull_rd,
    ] {
        unsafe {
            // SAFETY: fds we created; the children hold their own
            // duplicates and the go byte was already written.
            libc::close(fd);
        }
    }

    // SAFETY: result_rd is open and exclusively ours.
    let mut result_file = unsafe { fd_owned_file(result_rd) };
    let (overflow_rd, overflow_wr) = pipe2_cloexec().map_err(|e| setup("overflow pipe", e))?;
    // Handshake (two pipes, unambiguous):
    //  - result pipe (stage-1): PID2_NOTICE now, EXIT_FORWARD at payload end
    //  - status pipe (stage-2): ChildError on pre-exec failure; EOF = exec
    let mut got = [0u8; std::mem::size_of::<ChildError>()];
    let mut off = 0usize;
    while off < got.len() {
        match result_file.read(&mut got[off..]) {
            Ok(0) => {
                return Err(spawn_cleanup(
                    pid1,
                    None,
                    Some(&cgroup_leaf),
                    staging_cref,
                    config_ptr,
                    "handshake",
                    std::io::Error::other("stage-1 died before forking the payload"),
                ));
            }
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(spawn_cleanup(
                    pid1,
                    None,
                    Some(&cgroup_leaf),
                    staging_cref,
                    config_ptr,
                    "result pipe",
                    e,
                ));
            }
        }
    }
    // SAFETY: `got` holds exactly size_of::<ChildError>() valid bytes.
    let notice: ChildError = unsafe { std::ptr::read_unaligned(got.as_ptr() as *const ChildError) };
    if notice.stage != msg::PID2_NOTICE {
        return Err(spawn_cleanup(
            pid1,
            None,
            Some(&cgroup_leaf),
            staging_cref,
            config_ptr,
            "handshake",
            std::io::Error::other(format!("unexpected stage-1 message {}", notice.stage)),
        ));
    }
    let pid2 = notice.errno;
    // Short-lived payloads can exit before we open the pidfd (pidfd_open
    // refuses zombies with ESRCH): that is not a setup failure — the run
    // simply already finished. wait() handles the None case by reaping
    // directly from the result pipe.
    let pidfd2 = match pidfd_open(pid2) {
        Ok(f) => Some(f),
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => None,
        Err(e) => {
            return Err(spawn_cleanup(
                pid1,
                Some(pid2),
                Some(&cgroup_leaf),
                staging_cref,
                config_ptr,
                "pidfd_open(payload)",
                std::io::Error::other(format!("{e} (pid {pid2})")),
            ));
        }
    };

    // exec confirmation on the STATUS pipe: EOF = running; ChildError =
    // pre-exec failure (fail closed — the payload never ran).
    let mut pre = [0u8; std::mem::size_of::<ChildError>()];
    loop {
        match status_file.read(&mut pre) {
            Ok(0) => break, // exec happened
            Ok(n) if n == std::mem::size_of::<ChildError>() => {
                // SAFETY: `pre` holds exactly size_of::<ChildError>() valid bytes.
                let report: ChildError =
                    unsafe { std::ptr::read_unaligned(pre.as_ptr() as *const ChildError) };
                let stage_name = stage_name(report.stage);
                return Err(spawn_cleanup(
                    pid1,
                    Some(pid2),
                    Some(&cgroup_leaf),
                    staging_cref,
                    config_ptr,
                    &format!("child setup at {stage_name}"),
                    std::io::Error::from_raw_os_error(report.errno),
                ));
            }
            Ok(_) => {
                return Err(spawn_cleanup(
                    pid1,
                    Some(pid2),
                    Some(&cgroup_leaf),
                    staging_cref,
                    config_ptr,
                    "status pipe",
                    std::io::Error::other("short read"),
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(spawn_cleanup(
                    pid1,
                    Some(pid2),
                    Some(&cgroup_leaf),
                    staging_cref,
                    config_ptr,
                    "status pipe",
                    e,
                ));
            }
        }
    }

    // Output readers start after exec confirmation.
    let overflow = Arc::new(AtomicBool::new(false));
    let cap = spec.limits.max_output_bytes;
    let ov1 = Arc::clone(&overflow);
    let stdout_reader = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || read_capped(stdout_file, cap, ov1, overflow_wr))
        .map_err(|e| setup("stdout reader", e))?;
    let ov2 = Arc::clone(&overflow);
    let stderr_reader = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || read_capped(stderr_file, cap, ov2, overflow_wr))
        .map_err(|e| setup("stderr reader", e))?;

    drop(status_file); // status pipe fully consumed; result pipe kept
    Ok(NativeSandbox {
        pid1,
        pidfd2,
        config: config_ptr,
        result_file: Some(result_file),
        start: spawn_start,
        timeout: spec.limits.timeout,
        max_output: spec.limits.max_output_bytes,
        stdout_reader: Some(stdout_reader),
        stderr_reader: Some(stderr_reader),
        overflow,
        killed_reason: Mutex::new(None),
        reaped: Mutex::new(None),
        waited: Mutex::new(false),
        cgroup_leaf: Some(cgroup_leaf),
        staging_dir,
        overflow_wr,
        overflow_rd,
    })
}

/// Namespace flags by network mode: "full" shares the host network
/// namespace (loud, opt-in); everything else gets a fresh empty one.
fn unshare_flags_for(network: &carapace_core::NetworkMode) -> libc::c_int {
    let mut flags = libc::CLONE_NEWUSER as libc::c_int
        | libc::CLONE_NEWNS as libc::c_int
        | libc::CLONE_NEWPID as libc::c_int
        | libc::CLONE_NEWIPC as libc::c_int
        | libc::CLONE_NEWUTS as libc::c_int;
    if !matches!(network, carapace_core::NetworkMode::Full) {
        flags |= libc::CLONE_NEWNET as libc::c_int;
    }
    flags
}

/// Policy bind mounts, prepared parent-side (validated paths as
/// CStrings; existence re-checked where it matters).
fn binds_for(spec: &SandboxSpec) -> Vec<crate::child::BindSpec> {
    let mut out = Vec::new();
    for (p, rw) in spec
        .read_only
        .iter()
        .map(|p| (p, false))
        .chain(spec.read_write.iter().map(|p| (p, true)))
    {
        if let Ok(c) = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()) {
            out.push(crate::child::BindSpec { path: c, rw });
        }
    }
    out.truncate(16); // child-side buffer budget
    for p in plan_security_configs(
        std::path::Path::new("/usr/lib/jvm"),
        std::path::Path::new("/etc"),
    ) {
        if let Ok(c) = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()) {
            out.push(crate::child::BindSpec { path: c, rw: false });
        }
    }
    out
}

/// Debian/Ubuntu OpenJDK keeps `conf/security/java.security` in `/usr` as a
/// symlink into `/etc/java-<v>-openjdk/security`. The sandbox does not expose
/// host `/etc`, so the JVM refuses to start ("Error loading java.security
/// file") without this one directory.
///
/// Security rule, mirroring `/etc/alternatives`: expose a directory only
/// when a JVM inside the mounted `/usr` tree actually links to it, and only
/// the canonical `security` directory itself — never `/etc/java-*` as a
/// whole. The files are world-readable crypto policy (`java.security`,
/// `java.policy`, `default.policy`, `blocked.certs`,
/// `public_suffix_list.dat`, `nss.cfg`), mounted read-only and also denied
/// for writes by Landlock. Everything else under the host's `/etc` stays
/// invisible.
fn plan_security_configs(jvm_root: &std::path::Path, etc_root: &std::path::Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let Ok(entries) = std::fs::read_dir(jvm_root) else {
        return out;
    };
    for entry in entries.flatten() {
        let link = entry.path().join("conf/security/java.security");
        let Ok(target) = std::fs::canonicalize(&link) else {
            continue;
        };
        if !target.starts_with(etc_root) {
            continue;
        }
        let Some(dir) = target.parent() else {
            continue;
        };
        if dir.file_name().and_then(|n| n.to_str()) != Some("security") {
            continue;
        }
        if !dir.join("java.security").is_file() {
            continue;
        }
        if !out.iter().any(|p| p == dir) {
            out.push(dir.to_path_buf());
        }
    }
    out.sort();
    out
}

/// `/etc/alternatives` entries to recreate, parent-side. Security rule:
/// only symlinks whose resolved target is under `/usr` are exposed, and
/// only the canonical target is recreated (never a bind mount). That drops
/// regular files in the host directory (Ubuntu ships `README`) and any
/// symlink that leaves the read-only runtime tree. Non-Debian hosts simply
/// yield an empty list.
fn plan_alternatives(base: &std::path::Path) -> Vec<crate::child::AltLink> {
    use std::os::unix::ffi::OsStrExt;
    const MAX_LINKS: usize = 256;
    const MAX_NAME: usize = 180;
    const MAX_TARGET: usize = 300;
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(base) else {
        return out;
    };
    for entry in entries.flatten() {
        if out.len() == MAX_LINKS {
            break;
        }
        if !entry.file_type().is_ok_and(|t| t.is_symlink()) {
            continue;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str.is_empty()
            || name_str == "."
            || name_str == ".."
            || name_str.contains('/')
            || name_str.len() > MAX_NAME
        {
            continue;
        }
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let resolved = if target.is_absolute() {
            target
        } else {
            base.join(target)
        };
        let Ok(canonical) = std::fs::canonicalize(resolved) else {
            continue; // dangling alternative: nothing usable to expose
        };
        if canonical == std::path::Path::new("/usr") || !canonical.starts_with("/usr") {
            continue;
        }
        let bytes = canonical.as_os_str().as_bytes();
        if bytes.len() > MAX_TARGET {
            continue;
        }
        let (Ok(name_c), Ok(target_c)) = (
            std::ffi::CString::new(name_str),
            std::ffi::CString::new(bytes),
        ) else {
            continue;
        };
        out.push(crate::child::AltLink {
            name: name_c,
            target: target_c,
        });
    }
    out.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    out
}

/// Test-only env plumbing for the forced PDEATHSIG interleaving test. The
/// release build does not read this variable at all (the field is
/// `cfg(test)`), so a user cannot enable the pause hook.
#[cfg(test)]
fn test_pdeathsig_hook_fd() -> RawFd {
    std::env::var("CARA_PDEATHSIG_FD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(-1)
}

fn release_config(p: *mut libc::c_void) {
    if !p.is_null() {
        unsafe {
            // SAFETY: p came from Box::into_raw in spawn; reclaimed exactly
            // once, after the children that referenced it are dead.
            drop(Box::from_raw(p as *mut ChildConfig));
        }
    }
}

/// Removes empty `cara-staging.*` dirs left behind by a supervisor that was
/// killed before it could clean up. Only empty dirs older than 60s are
/// considered: a live spawn may have just run mkdtemp and not mounted the
/// rootfs yet, and a mounted rootfs is never empty. Best effort.
fn sweep_stale_staging(base: &str) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("cara-staging.") {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        let old = meta
            .modified()
            .ok()
            .and_then(|m| m.elapsed().ok())
            .is_some_and(|age| age.as_secs() >= 60);
        if old {
            let _ = std::fs::remove_dir(entry.path());
        }
    }
}

/// Creates the unique staging dir (mkdtemp): $XDG_RUNTIME_DIR first,
/// /tmp fallback.
fn mk_staging_dir() -> std::io::Result<std::ffi::CString> {
    let base = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    sweep_stale_staging(&base);
    let mut tmpl = format!("{}/cara-staging.XXXXXX\0", base).into_bytes();
    let p = unsafe {
        // SAFETY: mkdtemp(3) with a mutable NUL-terminated template of the
        // documented form; returns NULL on failure.
        libc::mkdtemp(tmpl.as_mut_ptr().cast::<libc::c_char>())
    };
    if p.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    tmpl.truncate(tmpl.len() - 1); // drop the NUL for CString::new
    std::ffi::CString::new(tmpl).map_err(|_| std::io::Error::other("unreachable NUL"))
}

/// Removes the staging dir: empty (child-ns dead) it rmdirs directly;
/// retries briefly in a detached thread if kernel teardown lags.
fn rm_staging_dir(dir: &std::ffi::CStr) {
    if unsafe {
        // SAFETY: rmdir(2) on our own NUL-terminated mkdtemp dir.
        libc::rmdir(dir.as_ptr())
    } == 0
    {
        return;
    }
    let path = dir.to_owned();
    std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(move || {
            for _ in 0..100 {
                if unsafe {
                    // SAFETY: as above; detached retry path.
                    libc::rmdir(path.as_ptr())
                } == 0
                {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        })
        .ok();
}

/// Fail-closed teardown for a spawn that could not complete: kill every
/// process of the half-built run (cgroup.kill covers both stages even when
/// the payload pid is unknown), reap what we can, free the config, and
/// return the Setup error.
fn spawn_cleanup(
    pid1: libc::pid_t,
    pid2: Option<libc::pid_t>,
    leaf: Option<&crate::cgroup::CgroupLeaf>,
    staging: &std::ffi::CStr,
    config_ptr: *mut libc::c_void,
    what: &str,
    e: std::io::Error,
) -> BackendError {
    if let Some(l) = leaf {
        l.kill();
    }
    unsafe {
        // SAFETY: signaling our own children; reaping the proxy.
        libc::kill(pid1, libc::SIGKILL);
        let mut st: libc::c_int = 0;
        libc::waitpid(pid1, &mut st, 0);
        if let Some(p2) = pid2 {
            // The payload init was reparented to us when stage-1 died; it
            // is SIGKILLed already, so a blocking reap terminates quickly.
            let mut st2: libc::c_int = 0;
            libc::waitpid(p2, &mut st2, 0);
        } else {
            // pid2 unknown: bounded, non-blocking, best-effort sweep.
            for _ in 0..8 {
                let mut st2: libc::c_int = 0;
                if libc::waitpid(-1, &mut st2, libc::WNOHANG) <= 0 {
                    break;
                }
            }
        }
    }
    rm_staging_dir(staging);
    release_config(config_ptr);
    BackendError::Setup(format!("{what}: {e}"))
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
        stage::NS_SETUP => "namespace unshare",
        stage::PDEATHSIG => "parent-death signal",
        stage::BIND_OPEN => "bind open",
        stage::BIND_MKDIR => "bind mkdir",
        stage::BIND_MOUNT => "bind mount",
        stage::BIND_REMOUNT => "bind remount",
        _ => "unknown",
    }
}

impl NativeSandbox {
    /// Implementation of `SandboxHandle::wait`.
    pub fn wait(&mut self) -> Result<ExitReport, BackendError> {
        {
            let mut w = self.waited.lock().unwrap();
            if *w {
                return Err(BackendError::Supervision(
                    "wait called twice on one sandbox handle".into(),
                ));
            }
            *w = true;
        }
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

            let Some(pidfd2) = self.pidfd2 else {
                // Payload already exited before we could open a pidfd:
                // nothing to poll; reap directly.
                break;
            };
            let mut pfd = [
                libc::pollfd {
                    fd: pidfd2,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.overflow_rd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let remaining = ((deadline - now).as_millis().min(i32::MAX as u128) as i32) + 1;
            let n = unsafe {
                // SAFETY: poll(2) over two valid pollfds with a bounded
                // timeout; EINTR handled below.
                libc::poll(pfd.as_mut_ptr(), 2, remaining)
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(BackendError::Supervision(format!("poll: {e}")));
            }
            if n > 0 && (pfd[0].revents & libc::POLLIN) != 0 {
                break; // payload init exited
            }
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
        // Primary: SIGKILL the payload init via pidfd (kernel then kills
        // everything left in its PID namespace — ADR-0002).
        if let Some(fd) = self.pidfd2 {
            let _ = fork::pidfd_send_signal(fd, libc::SIGKILL);
        }
        // The proxy dies with the payload (it only waits and forwards);
        // kill it too so it can never linger.
        unsafe {
            // SAFETY: signaling our direct child; pid reuse is not a
            // concern while stage-1 is alive, and cgroup.kill covers races.
            libc::kill(self.pid1, libc::SIGKILL);
        }
        // Third switch: cgroup.kill SIGKILLs everything in the leaf.
        if let Some(leaf) = &self.cgroup_leaf {
            leaf.kill();
        }
    }

    /// Reads the forwarded payload status and reaps the proxy.
    fn reap(&mut self) -> libc::c_int {
        let mut slot = self.reaped.lock().unwrap();
        if let Some(s) = *slot {
            return s;
        }
        // Read the EXIT_FORWARD message (8 bytes) from the status pipe.
        let mut fwd = [0u8; std::mem::size_of::<ChildError>()];
        let mut got: Option<libc::c_int> = None;
        if let Some(f) = self.result_file.as_mut() {
            let mut off = 0usize;
            while off < fwd.len() {
                match f.read(&mut fwd[off..]) {
                    Ok(0) => break,
                    Ok(n) => off += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            if off == fwd.len() {
                // SAFETY: `fwd` holds exactly size_of::<ChildError>() valid bytes.
                let m: ChildError =
                    unsafe { std::ptr::read_unaligned(fwd.as_ptr() as *const ChildError) };
                if m.stage == msg::EXIT_FORWARD {
                    got = Some(m.errno);
                }
            }
        }
        // Reap the proxy regardless.
        let mut st1: libc::c_int = 0;
        loop {
            let r = unsafe {
                // SAFETY: blocking waitpid on our direct child (stage-1).
                libc::waitpid(self.pid1, &mut st1, 0)
            };
            if r == self.pid1 {
                break;
            }
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
        let status = got.unwrap_or(128 + libc::SIGKILL);
        *slot = Some(status);
        status
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

        // Accounting (leaf must still exist; it is removed below).
        let stats = self
            .cgroup_leaf
            .as_ref()
            .map(crate::cgroup::CgroupLeaf::stats)
            .unwrap_or_default();

        // Remove the leaf synchronously on the normal path. Drop's async
        // remover is a safety net, but a short-lived CLI process exits
        // before its detached thread can run — which leaked one empty
        // cgroup directory per `cara run` in the P2 cycle. Waiting here is
        // bounded (normally instant) and keeps the "always removed" claim
        // true across process exit.
        if let Some(leaf) = self.cgroup_leaf.take() {
            leaf.remove();
        }

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

        let mut kill_reason = self.killed_reason.lock().unwrap().take();
        if kill_reason.is_none() && stats.oom_kill && signal == Some(libc::SIGKILL) {
            // The kernel OOM-killed the run within its memory limit.
            kill_reason = Some(KillReason::MemoryLimit);
        }

        ExitReport {
            exit_code,
            signal,
            kill_reason,
            wall_time: self.start.elapsed(),
            stdout: truncate_cap(stdout, self.max_output),
            stderr: truncate_cap(stderr, self.max_output),
            cpu_time: stats.cpu_usec.map(Duration::from_micros),
            peak_memory_bytes: stats.peak_memory_bytes,
            peak_processes: stats.peak_processes,
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
        // nothing leaks (pipes, config, zombies, cgroup leaf, pidfd).
        self.kill_tree();
        let _ = self.reap();
        if let Some(t) = self.stdout_reader.take() {
            let _ = t.join();
        }
        if let Some(t) = self.stderr_reader.take() {
            let _ = t.join();
        }
        self.result_file.take(); // closes the result pipe
        release_config(self.config);
        if let Some(fd) = self.pidfd2 {
            unsafe {
                // SAFETY: pidfd we opened in spawn; all users are done.
                libc::close(fd);
            }
        }
        unsafe {
            // SAFETY: our overflow self-pipe; readers have been joined.
            libc::close(self.overflow_wr);
            libc::close(self.overflow_rd);
        }
        rm_staging_dir(&self.staging_dir);
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;

    #[test]
    fn alternatives_planner_exposes_only_usr_symlinks() {
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!(
            "cara-alt-plan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir(&base).expect("temp base");
        symlink("/usr/bin/sh", base.join("ok")).expect("symlink ok");
        symlink("../../usr/bin/sh", base.join("relative-ok")).expect("symlink rel");
        symlink("/etc/passwd", base.join("outside")).expect("symlink outside");
        symlink("/usr/bin/cara-definitely-missing", base.join("dangling"))
            .expect("symlink dangling");
        std::fs::write(base.join("README"), b"not a symlink").expect("regular file");

        let links = plan_alternatives(&base);
        let names: Vec<&str> = links.iter().map(|l| l.name.to_str().unwrap()).collect();
        assert_eq!(
            names,
            vec!["ok", "relative-ok"],
            "only /usr-resolving symlinks may be exposed"
        );
        for l in &links {
            let target = l.target.to_str().unwrap();
            assert!(
                target.starts_with("/usr/"),
                "target must be canonical under /usr: {target}"
            );
        }
        std::fs::remove_dir_all(&base).ok();
    }

    /// Debian/Ubuntu OpenJDK config: only the canonical `security`
    /// directory that an in-tree JVM actually links to may be exposed.
    /// Foreign targets, regular files and dangling links are dropped.
    #[test]
    fn security_planner_exposes_only_referenced_etc_security_dirs() {
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!(
            "cara-jvm-plan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let jvm = base.join("usr/lib/jvm");
        let etc = base.join("etc");
        let good = etc.join("java-21-openjdk/security");
        std::fs::create_dir_all(&good).expect("etc security dir");
        std::fs::write(good.join("java.security"), b"# policy").expect("java.security");

        let linked = jvm.join("openjdk-21/conf/security");
        std::fs::create_dir_all(&linked).expect("jvm conf dir");
        symlink(good.join("java.security"), linked.join("java.security")).expect("good link");

        // A JVM whose config resolves under /usr is not an /etc exposure.
        let share = base.join("usr/share/security");
        std::fs::create_dir_all(&share).expect("share dir");
        std::fs::write(share.join("java.security"), b"# usr").expect("share file");
        let foreign = jvm.join("openjdk-17/conf/security");
        std::fs::create_dir_all(&foreign).expect("foreign dir");
        symlink(share.join("java.security"), foreign.join("java.security")).expect("foreign link");

        // A regular file at the expected path is not a distro config link.
        let regular = jvm.join("openjdk-11/conf/security");
        std::fs::create_dir_all(&regular).expect("regular dir");
        std::fs::write(regular.join("java.security"), b"# regular").expect("regular file");

        // Dangling link must not abort the scan.
        let dangling = jvm.join("openjdk-8/conf/security");
        std::fs::create_dir_all(&dangling).expect("dangling dir");
        symlink(
            etc.join("java-8-openjdk/security/java.security"),
            dangling.join("java.security"),
        )
        .expect("dangling link");

        let got = plan_security_configs(&jvm, &etc);
        assert_eq!(
            got,
            vec![std::fs::canonicalize(&good).expect("canonical good")],
            "only the referenced /etc security dir may be exposed"
        );
        std::fs::remove_dir_all(&base).ok();
    }
}

#[cfg(test)]
mod staging_tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn stale_staging_sweep_removes_only_old_empty_dirs() {
        let base = std::env::temp_dir().join(format!(
            "cara-staging-sweep-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir(&base).expect("temp base");
        let old = base.join("cara-staging.old");
        let fresh = base.join("cara-staging.fresh");
        let nonempty = base.join("cara-staging.nonempty");
        let other = base.join("not-cara-staging");
        for d in [&old, &fresh, &nonempty, &other] {
            std::fs::create_dir(d).expect("probe dir");
        }
        std::fs::write(nonempty.join("x"), b"x").expect("probe file");
        for d in [&old, &nonempty] {
            std::fs::File::open(d)
                .expect("open dir")
                .set_modified(SystemTime::now() - Duration::from_secs(120))
                .expect("set mtime");
        }

        sweep_stale_staging(base.to_str().expect("utf-8 temp path"));

        assert!(!old.exists(), "old empty staging dir is swept");
        assert!(fresh.exists(), "fresh staging dir is kept (mkdir race)");
        assert!(nonempty.exists(), "non-empty staging dir is kept");
        assert!(other.exists(), "unrelated directory is kept");
        std::fs::remove_dir_all(&base).ok();
    }
}
