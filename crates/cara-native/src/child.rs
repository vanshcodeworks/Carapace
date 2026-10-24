//! Code that runs in the forked child between `clone` and `execve`.
//!
//! FORK SAFETY: everything here runs in a child of a multithreaded-capable
//! process, so until `execve` only async-signal-safe operations are allowed:
//! raw `write`/`read`/`close`/`execve` syscalls, no allocation, no std
//! formatting, no locks. All data it touches is prepared by the parent in
//! [`ChildConfig`] before the clone.
//!
//! C1 SCOPE WARNING: this child does NOT yet isolate the filesystem (no
//! pivot_root — that is milestone C2) and does not yet apply seccomp or
//! Landlock (C4). It exists to build and prove the namespace + supervisor
//! machinery. Only self-written benign payloads run through it in tests.

use std::ffi::CString;
use std::os::unix::io::RawFd;

/// Stage codes reported through the exec-status pipe (kept in sync with
/// the supervisor's parser; both sides assert sizes).
pub mod stage {
    pub const WRITE_UID_MAP: u8 = 1;
    pub const WRITE_GID_MAP: u8 = 2;
    pub const DENY_SETGROUPS: u8 = 3;
    pub const SET_RLIMIT: u8 = 4;
    pub const SYNC: u8 = 5;
    pub const EXEC: u8 = 6;
}

/// Fixed-size pre-exec failure report written to the exec-status pipe.
/// `#[repr(C)]` with fixed-width fields so parent and child agree exactly.
#[repr(C)]
pub struct ChildError {
    pub stage: u8,
    pub errno: i32,
}

/// Everything the child needs, fully prepared (no allocation after clone).
pub(crate) struct ChildConfig {
    /// Full argv for execve (argv[0] included).
    pub argv: Vec<CString>,
    /// Full envp for execve.
    pub envp: Vec<CString>,
    /// Write end of the exec-status pipe (CLOEXEC). exec success = the pipe
    /// closes (EOF at the parent); failure = a [`ChildError`] is written.
    pub status_wr: RawFd,
    /// Read end of the go-pipe (CLOEXEC). The child blocks until the parent
    /// says go, so the parent can finish any post-clone, pre-exec setup
    /// (cgroup attach from C3) without racing the payload.
    pub go_rd: RawFd,
    /// fds to wire up as stdin/stdout/stderr (already CLOEXEC where needed;
    /// dup2 clears CLOEXEC on the targets, which is exactly what we want).
    pub stdin_fd: RawFd,
    pub stdout_fd: RawFd,
    pub stderr_fd: RawFd,
    /// uid/gid of the parent OUTSIDE the new user namespace, recorded
    /// before clone: inside the ns, getuid() reports the overflow id
    /// (65534) until uid_map is written, so mapping "our own uid" must use
    /// the value captured here, not a runtime getuid().
    pub parent_uid: libc::uid_t,
    pub parent_gid: libc::gid_t,
}

// ---------------------------------------------------------------- raw I/O

/// write(2) until all of `buf` is written or an error occurs. Returns errno
/// style: Ok(()) or Err(errno). Only used pre-exec on tiny buffers, so a
/// partial write loop is enough; pipes are < pipe buffer size.
fn write_all(fd: RawFd, buf: &[u8]) -> Result<(), i32> {
    let mut off = 0usize;
    while off < buf.len() {
        let n = unsafe {
            // SAFETY: raw write(2) to a valid fd from a valid buffer slice.
            libc::write(
                fd,
                buf[off..].as_ptr() as *const libc::c_void,
                buf.len() - off,
            )
        };
        if n < 0 {
            let e = unsafe { *libc::__errno_location() };
            if e == libc::EINTR {
                continue;
            }
            return Err(e);
        }
        off += n as usize;
    }
    Ok(())
}

/// Opens a file read-only. Err(errno). Used for uid_map writes via
/// /proc (write side needs O_WRONLY).
fn open_proc(path: &[u8], flags: libc::c_int) -> Result<RawFd, i32> {
    // The path must be NUL-terminated; caller passes fixed literals, and we
    // build a small stack buffer without allocation.
    let mut buf = [0u8; 64];
    if path.len() + 1 > buf.len() {
        return Err(libc::ENAMETOOLONG);
    }
    buf[..path.len()].copy_from_slice(path);
    let fd = unsafe {
        // SAFETY: path is NUL-terminated in buf; openat(AT_FDCWD, ...).
        libc::open(buf.as_ptr().cast(), flags, 0)
    };
    if fd < 0 {
        Err(unsafe { *libc::__errno_location() })
    } else {
        Ok(fd)
    }
}

/// Writes `data` to a /proc file at `path`, opening and closing it.
fn write_proc_file(path: &[u8], data: &[u8]) -> Result<(), i32> {
    let fd = open_proc(path, libc::O_WRONLY)?;
    let r = write_all(fd, data);
    unsafe {
        // SAFETY: closing an fd we opened.
        libc::close(fd);
    }
    r
}

/// Formats "0 <id> 1\n" into a stack buffer (no allocation).
fn map_line(id: libc::uid_t, out: &mut [u8; 32]) -> &[u8] {
    // id is a small u32; manual digits, always fits "0 <id> 1\n".
    let mut pos = 0usize;
    out[pos] = b'0';
    pos += 1;
    out[pos] = b' ';
    pos += 1;
    let mut digits = [0u8; 10];
    let mut nd = 0;
    let mut v = id;
    if v == 0 {
        digits[0] = b'0';
        nd = 1;
    } else {
        while v > 0 {
            digits[nd] = b'0' + (v % 10) as u8;
            nd += 1;
            v /= 10;
        }
    }
    for &d in digits[..nd].iter().rev() {
        out[pos] = d;
        pos += 1;
    }
    out[pos] = b' ';
    pos += 1;
    out[pos] = b'1';
    pos += 1;
    out[pos] = b'\n';
    pos += 1;
    &out[..pos]
}

/// Reads exactly one byte from the go-pipe. Ok(()) on 'G'.
fn wait_for_go(fd: RawFd) -> Result<(), i32> {
    loop {
        let mut b = [0u8; 1];
        let n = unsafe {
            // SAFETY: raw read(2) into a valid 1-byte buffer.
            libc::read(fd, b.as_mut_ptr().cast(), 1)
        };
        if n == 1 {
            return if b[0] == b'G' { Ok(()) } else { Err(libc::EIO) };
        }
        if n == 0 {
            return Err(libc::EPIPE); // parent died or closed without go
        }
        let e = unsafe { *libc::__errno_location() };
        if e != libc::EINTR {
            return Err(e);
        }
    }
}

// ------------------------------------------------------------------ child

/// The child entry point. `arg` is a leaked `*mut Box<ChildConfig>` (the
/// Box is recovered with Box::from_raw — no allocation involved).
pub(crate) extern "C" fn child_main(arg: *mut libc::c_void) -> libc::c_int {
    let cfg: &ChildConfig = unsafe {
        // SAFETY: the parent passed a leaked Box<ChildConfig> pointer via
        // clone's arg; the child owns it exclusively until exec/exit.
        &*(arg as *const ChildConfig)
    };

    // 1. Deny setgroups, then write uid/gid maps: we are uid 0 inside the
    //    new user namespace, mapped 1:1 onto the parent's unprivileged ids.
    //    Order matters: setgroups must be denied before gid_map is accepted.
    if let Err(e) = write_proc_file(b"/proc/self/setgroups", b"deny") {
        fail(cfg, stage::DENY_SETGROUPS, e);
    }
    // The parent captured its uid/gid BEFORE the clone: inside this
    // namespace getuid() is meaningless (overflow) until the map exists.
    let ruid = cfg.parent_uid;
    let rgid = cfg.parent_gid;
    let mut line = [0u8; 32];
    if let Err(e) = write_proc_file(b"/proc/self/uid_map", map_line(ruid, &mut line)) {
        fail(cfg, stage::WRITE_UID_MAP, e);
    }
    let mut line = [0u8; 32];
    if let Err(e) = write_proc_file(b"/proc/self/gid_map", map_line(rgid, &mut line)) {
        fail(cfg, stage::WRITE_GID_MAP, e);
    }

    // 2. rlimits: no core dumps. (fsize/nofile arrive with C2/C4 policy.)
    let rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let r = unsafe {
        // SAFETY: setrlimit(RLIMIT_CORE, &rl) with a valid struct.
        libc::setrlimit(libc::RLIMIT_CORE, &rl)
    };
    if r < 0 {
        fail(cfg, stage::SET_RLIMIT, unsafe { *libc::__errno_location() });
    }

    // 3. Wire up stdio. dup2 clears FD_CLOEXEC on the targets 0/1/2 — the
    //    payload keeps its pipes across exec, and nothing else does.
    if unsafe { libc::dup2(cfg.stdin_fd, 0) } < 0
        || unsafe { libc::dup2(cfg.stdout_fd, 1) } < 0
        || unsafe { libc::dup2(cfg.stderr_fd, 2) } < 0
    {
        fail(cfg, stage::SYNC, unsafe { *libc::__errno_location() });
    }

    // 4. Wait until the parent finished any post-clone setup (from C3:
    //    cgroup attach) — never race the payload.
    if let Err(e) = wait_for_go(cfg.go_rd) {
        fail(cfg, stage::SYNC, e);
    }

    // 5. execve. C arrays built from the leaked config; on success we never
    //    return. The status pipe (CLOEXEC) closes at exec: that EOF is the
    //    parent's "running" signal.
    let mut argv_buf: [*const libc::c_char; 64] = [std::ptr::null(); 64];
    let mut envp_buf: [*const libc::c_char; 256] = [std::ptr::null(); 256];
    if cfg.argv.is_empty() || cfg.argv.len() >= argv_buf.len() {
        fail(cfg, stage::EXEC, libc::EINVAL);
    }
    for (i, a) in cfg.argv.iter().enumerate() {
        argv_buf[i] = a.as_ptr();
    }
    if cfg.envp.len() >= envp_buf.len() {
        fail(cfg, stage::EXEC, libc::E2BIG);
    }
    for (i, e2) in cfg.envp.iter().enumerate() {
        envp_buf[i] = e2.as_ptr();
    }
    let prog = argv_buf[0];
    unsafe {
        // SAFETY: execve with NUL-terminated argv/envp built above from
        // CStrings owned by the leaked config. Never returns on success.
        libc::execve(prog, argv_buf.as_ptr(), envp_buf.as_ptr());
    }
    // execve returned: total failure. Report and die; the parent returns a
    // Setup error and NO code ran unsandboxed.
    fail(cfg, stage::EXEC, unsafe { *libc::__errno_location() })
}

/// Reports a pre-exec failure to the parent and exits. Never returns.
fn fail(cfg: &ChildConfig, stage: u8, errno: i32) -> ! {
    let report = ChildError { stage, errno };
    let bytes = std::ptr::from_ref(&report).cast::<u8>();
    let _ = write_all(cfg.status_wr, unsafe {
        // SAFETY: `bytes` addresses exactly size_of::<ChildError>() valid
        // bytes of a local struct that lives through this call.
        std::slice::from_raw_parts(bytes, std::mem::size_of::<ChildError>())
    });
    unsafe {
        // SAFETY: final exit; nothing to unwind in a forked child.
        libc::_exit(127);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_error_is_eight_bytes_on_the_wire() {
        // The parent parses exactly size_of::<ChildError>() bytes; assert
        // the layout has no padding surprises across toolchains.
        assert_eq!(std::mem::size_of::<ChildError>(), 8);
        assert_eq!(std::mem::align_of::<ChildError>(), 4);
    }

    #[test]
    fn map_line_formats() {
        let mut buf = [0u8; 32];
        assert_eq!(map_line(1000, &mut buf), b"0 1000 1\n");
        let mut buf = [0u8; 32];
        assert_eq!(map_line(0, &mut buf), b"0 0 1\n");
    }
}
