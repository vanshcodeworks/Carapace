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
    pub const MOUNT_PRIVATE: u8 = 7;
    pub const MOUNT_ROOT: u8 = 8;
    pub const MOUNT_RUNTIME: u8 = 9;
    pub const MOUNT_PROC: u8 = 10;
    pub const PIVOT: u8 = 11;
    pub const PIVOT_CHDIR: u8 = 13;
    pub const PIVOT_DETACH: u8 = 14;
    pub const VERIFY: u8 = 12;
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
    /// Pre-formatted tmpfs mount options ("size=N") for the sandbox root
    /// and the /work scratch area (formatting happens in the parent; the
    /// child only passes pointers to mount(2)).
    pub root_size_opt: CString,
    pub work_size_opt: CString,
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

/// Builds the sandbox filesystem and pivots into it. Runs entirely in the
/// child's private mount namespace and touches NO host state: first a
/// private tmpfs is mounted over /tmp (child-ns only), the new root is
/// assembled inside it, and after pivot_root the old root is detached.
/// When the child exits, the kernel destroys the namespace and every
/// tmpfs in it. There is nothing to clean up on the host.
fn setup_rootfs(cfg: &ChildConfig) {
    // (a) Stop mount propagation FIRST: without this, mounts created below
    // could propagate back to the host through shared peer groups (the
    // classic sandbox leak). Applies recursively to the whole tree copy.
    if let Err(e) = mount_raw(
        b"",
        c"/".to_bytes_with_nul(),
        b"",
        (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
        std::ptr::null(),
    ) {
        fail(cfg, stage::MOUNT_PRIVATE, e);
    }

    // (b) Private tmpfs over /tmp, then the new root inside it. The mount
    // exists only in this namespace: the host's /tmp is untouched and no
    // host-side staging directory is ever created.
    if let Err(e) = mount_raw(
        c"tmpfs".to_bytes_with_nul(),
        c"/tmp".to_bytes_with_nul(),
        c"tmpfs".to_bytes_with_nul(),
        (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
        cfg.root_size_opt.as_ptr().cast(),
    ) {
        fail(cfg, stage::MOUNT_ROOT, e);
    }
    const ROOT_BASE: &[u8] = b"/tmp/cara-root";
    let mut root = [0u8; 64];
    assert!(ROOT_BASE.len() < 64);
    root[..ROOT_BASE.len()].copy_from_slice(ROOT_BASE);
    if let Err(e) = mkdir_raw(c"/tmp/cara-root".to_bytes_with_nul(), 0o700) {
        fail(cfg, stage::MOUNT_ROOT, e);
    }
    if let Err(e) = mount_raw(
        c"tmpfs".to_bytes_with_nul(),
        &root,
        c"tmpfs".to_bytes_with_nul(),
        (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
        cfg.root_size_opt.as_ptr().cast(),
    ) {
        fail(cfg, stage::MOUNT_ROOT, e);
    }

    // (c) Directory skeleton in the new root.
    for d in [
        c"/usr".to_bytes_with_nul(),
        c"/dev".to_bytes_with_nul(),
        c"/etc".to_bytes_with_nul(),
        c"/proc".to_bytes_with_nul(),
        c"/work".to_bytes_with_nul(),
        c"/tmp".to_bytes_with_nul(),
        c"/.cara-old".to_bytes_with_nul(),
    ] {
        let p = join(&root, d);
        if let Err(e) = mkdir_raw(&p, 0o755) {
            fail(cfg, stage::MOUNT_ROOT, e);
        }
    }

    // (d) Read-only bind of the host's /usr (the interpreter runtime; the
    // parent validated the merged-usr layout before clone). Two-step ro:
    // bind, then remount read-only.
    let usr_dst = join(&root, c"/usr".to_bytes_with_nul());
    if let Err(e) = mount_raw(
        c"/usr".to_bytes_with_nul(),
        &usr_dst,
        b"",
        (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
        std::ptr::null(),
    ) {
        fail(cfg, stage::MOUNT_RUNTIME, e);
    }
    if let Err(e) = mount_raw(
        c"/usr".to_bytes_with_nul(),
        &usr_dst,
        b"",
        (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC | libc::MS_NODEV)
            as libc::c_ulong,
        std::ptr::null(),
    ) {
        fail(cfg, stage::MOUNT_RUNTIME, e);
    }

    // (e) Symlinks the merged-usr layout needs (bin→usr/bin etc.). The
    // parent verified each target exists on the host before cloning.
    for (link, target) in [
        (c"/bin".to_bytes_with_nul(), c"usr/bin".to_bytes_with_nul()),
        (c"/lib".to_bytes_with_nul(), c"usr/lib".to_bytes_with_nul()),
        (
            c"/lib64".to_bytes_with_nul(),
            c"usr/lib64".to_bytes_with_nul(),
        ),
    ] {
        let l = join(&root, link);
        if let Err(e) = symlink_raw(target, &l) {
            fail(cfg, stage::MOUNT_RUNTIME, e);
        }
    }

    // (f) /dev: only the safe character devices, bind-mounted from the
    // host (mknod is impossible rootless — binding existing nodes is the
    // only sound way). Each target must exist first; use open(O_CREAT).
    for dev in [
        c"/dev/null".to_bytes_with_nul(),
        c"/dev/zero".to_bytes_with_nul(),
        c"/dev/urandom".to_bytes_with_nul(),
        c"/dev/random".to_bytes_with_nul(),
    ] {
        let dst = join(&root, dev);
        if let Err(e) = touch_raw(&dst) {
            fail(cfg, stage::MOUNT_RUNTIME, e);
        }
        if let Err(e) = mount_raw(
            dev,
            &dst,
            b"",
            libc::MS_BIND as libc::c_ulong,
            std::ptr::null(),
        ) {
            fail(cfg, stage::MOUNT_RUNTIME, e);
        }
    }

    // (g) Minimal /etc: our own passwd/group (never the host's users). The
    // "cara" entry doubles as a sandbox marker the tests assert on.
    let etc_passwd = join(&root, c"/etc/passwd".to_bytes_with_nul());
    write_new_file(
        &etc_passwd,
        b"root:x:0:0:root:/work:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/sh\n\
          cara:x:0:0:carapace-sandbox-marker:/work:/bin/sh\n",
    )
    .or_fail(cfg, stage::MOUNT_RUNTIME);
    let etc_group = join(&root, c"/etc/group".to_bytes_with_nul());
    write_new_file(&etc_group, b"root:x:0:\nnobody:x:65534:\n").or_fail(cfg, stage::MOUNT_RUNTIME);

    // (h) Size-capped scratch at /work (the only writable data area).
    let work = join(&root, c"/work".to_bytes_with_nul());
    if let Err(e) = mount_raw(
        c"tmpfs".to_bytes_with_nul(),
        &work,
        c"tmpfs".to_bytes_with_nul(),
        (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
        cfg.work_size_opt.as_ptr().cast(),
    ) {
        fail(cfg, stage::MOUNT_ROOT, e);
    }

    // (i) Fresh procfs for OUR pid namespace (mounted pre-pivot at the
    // new-root path: it shows this namespace's processes only).
    let proc_dst = join(&root, c"/proc".to_bytes_with_nul());
    if let Err(e) = mount_raw(
        c"proc".to_bytes_with_nul(),
        &proc_dst,
        c"proc".to_bytes_with_nul(),
        (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
        std::ptr::null(),
    ) {
        fail(cfg, stage::MOUNT_PROC, e);
    }

    // (j) Pivot: new root becomes /, the old root is detached and removed.
    errno_of(unsafe {
        // SAFETY: chdir into the tmpfs new root (created in (b)).
        libc::chdir(root.as_ptr().cast::<libc::c_char>())
    })
    .or_fail(cfg, stage::PIVOT_CHDIR);
    let old = join(&root, c"/.cara-old".to_bytes_with_nul());
    errno_of(unsafe {
        // SAFETY: pivot_root(2) with two NUL-terminated paths: the tmpfs
        // new root and the .cara-old directory created inside it in (c).
        // Returned as c_long via syscall(); converted to c_int check.
        let r = libc::syscall(
            libc::SYS_pivot_root,
            root.as_ptr().cast::<libc::c_char>(),
            old.as_ptr().cast::<libc::c_char>(),
        );
        if r < 0 { -1 } else { 0 }
    })
    .or_fail(cfg, stage::PIVOT);
    umount2_raw(c"/.cara-old".to_bytes_with_nul(), libc::MNT_DETACH)
        .or_fail(cfg, stage::PIVOT_DETACH);
    // Best-effort removal of the now-detached directory node.
    unsafe {
        // SAFETY: rmdir of a path that no longer has a mount over it.
        libc::rmdir(
            c"/.cara-old"
                .to_bytes_with_nul()
                .as_ptr()
                .cast::<libc::c_char>(),
        );
    }

    // (k) Fail-closed self-verification: the payload must not start unless
    // the sandbox looks exactly as designed.
    if let Err(e) = verify_rootfs() {
        fail(cfg, stage::VERIFY, e);
    }

    // Working directory for the payload: the scratch area.
    if let Err(e) = errno_of(unsafe {
        // SAFETY: chdir to /work, created in (h).
        libc::chdir(c"/work".to_bytes_with_nul().as_ptr().cast::<libc::c_char>())
    }) {
        fail(cfg, stage::VERIFY, e);
    }
}

/// Post-pivot sanity checks (all async-signal-safe: access/open/stat).
fn verify_rootfs() -> Result<(), i32> {
    // Runtime present.
    errno_of(unsafe {
        // SAFETY: access(2) with fixed literal paths.
        libc::access(
            c"/usr/bin/sh"
                .to_bytes_with_nul()
                .as_ptr()
                .cast::<libc::c_char>(),
            libc::F_OK,
        )
    })?;
    // Fresh /proc of our namespace.
    errno_of(unsafe {
        // SAFETY: stat of a fixed literal path with a zeroed struct.
        let mut st: libc::stat = std::mem::zeroed();
        libc::stat(
            c"/proc/self/status"
                .to_bytes_with_nul()
                .as_ptr()
                .cast::<libc::c_char>(),
            &mut st,
        )
    })?;
    // Old root truly gone: /.cara-old must not exist.
    if unsafe {
        // SAFETY: access(2) as above.
        libc::access(
            c"/.cara-old"
                .to_bytes_with_nul()
                .as_ptr()
                .cast::<libc::c_char>(),
            libc::F_OK,
        )
    } == 0
    {
        return Err(libc::EEXIST);
    }
    // Host paths must be invisible: /home and /root are not part of the
    // recipe, so they must not resolve.
    for p in [c"/home".to_bytes_with_nul(), c"/root".to_bytes_with_nul()] {
        if unsafe {
            // SAFETY: access(2) as above.
            libc::access(p.as_ptr().cast::<libc::c_char>(), libc::F_OK)
        } == 0
        {
            return Err(libc::EPERM);
        }
    }
    // /work writable.
    let fd = unsafe {
        // SAFETY: open(2) with O_CREAT|O_EXCL|O_RDWR on a tmpfs we own.
        libc::open(
            c"/work/.cara-verify"
                .to_bytes_with_nul()
                .as_ptr()
                .cast::<libc::c_char>(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
            0o600,
        )
    };
    if fd < 0 {
        return Err(unsafe { *libc::__errno_location() });
    }
    let un = unsafe {
        // SAFETY: unlink of the file we just created; close regardless.
        let u = libc::unlink(
            c"/work/.cara-verify"
                .to_bytes_with_nul()
                .as_ptr()
                .cast::<libc::c_char>(),
        );
        libc::close(fd);
        u
    };
    if un < 0 {
        return Err(unsafe { *libc::__errno_location() });
    }
    Ok(())
}

// ------------------------------------------------------------ mount helpers

/// A 64-byte NUL-terminated path buffer (all sandbox paths fit). Buffers
/// start zeroed, so copying without the NUL leaves one in place.
type PathBuf64 = [u8; 64];

/// staging-dir bytes (NUL-terminated within the buffer) + suffix, where
/// suffix INCLUDES its trailing NUL.
fn join(root: &PathBuf64, suffix: &[u8]) -> PathBuf64 {
    let mut b = [0u8; 64];
    let n = root
        .iter()
        .position(|&c| c == 0)
        .expect("root path buffer is NUL-terminated");
    assert!(n + suffix.len() <= 64);
    b[..n].copy_from_slice(&root[..n]);
    let m = suffix.len() - 1; // drop the NUL; the buffer already ends in NULs
    b[n..n + m].copy_from_slice(&suffix[..m]);
    b
}

/// Byte-string literals must INCLUDE their trailing NUL. An empty slice
/// means "pass NULL" (required for e.g. remount/private operations) — an
/// empty slice's `as_ptr()` would be a dangling non-NULL pointer and the
/// kernel would fail with EFAULT.
fn mount_raw(
    src: &[u8],
    dst: &[u8],
    fstype: &[u8],
    flags: libc::c_ulong,
    data: *const libc::c_void,
) -> Result<(), i32> {
    debug_assert!(src.is_empty() || src.last() == Some(&0));
    debug_assert_eq!(dst.last(), Some(&0));
    let src = if src.is_empty() {
        std::ptr::null()
    } else {
        src.as_ptr().cast::<libc::c_char>()
    };
    let fstype = if fstype.is_empty() {
        std::ptr::null()
    } else {
        fstype.as_ptr().cast::<libc::c_char>()
    };
    let r = unsafe {
        // SAFETY: mount(2) with NUL-terminated strings (or NULL where the
        // operation takes none) and a zero-or-valid data pointer.
        libc::mount(
            src,
            dst.as_ptr().cast::<libc::c_char>(),
            fstype,
            flags,
            data,
        )
    };
    errno_of(r)
}

fn mkdir_raw(path: &[u8], mode: libc::mode_t) -> Result<(), i32> {
    debug_assert_eq!(path.last(), Some(&0));
    errno_of(unsafe {
        // SAFETY: mkdir(2) with a NUL-terminated path.
        libc::mkdir(path.as_ptr().cast::<libc::c_char>(), mode)
    })
}

/// umount2(2); `flags` is e.g. MNT_DETACH (an int, NOT a mount flag).
fn umount2_raw(path: &[u8], flags: libc::c_int) -> Result<(), i32> {
    debug_assert_eq!(path.last(), Some(&0));
    errno_of(unsafe {
        // SAFETY: umount2(2) with a NUL-terminated path.
        libc::umount2(path.as_ptr().cast::<libc::c_char>(), flags)
    })
}

fn symlink_raw(target: &[u8], link: &[u8]) -> Result<(), i32> {
    errno_of(unsafe {
        // SAFETY: symlink(2) with NUL-terminated strings.
        libc::symlink(
            target.as_ptr().cast::<libc::c_char>(),
            link.as_ptr().cast::<libc::c_char>(),
        )
    })
}

fn touch_raw(path: &[u8]) -> Result<(), i32> {
    let fd = unsafe {
        // SAFETY: open(2) O_CREAT|O_RDONLY on a directory we own.
        libc::open(
            path.as_ptr().cast::<libc::c_char>(),
            libc::O_CREAT | libc::O_RDONLY,
            0o600,
        )
    };
    if fd < 0 {
        return Err(unsafe { *libc::__errno_location() });
    }
    errno_of(unsafe {
        // SAFETY: closing the fd we opened.
        libc::close(fd)
    })
}

fn write_new_file(path: &[u8], contents: &[u8]) -> Result<(), i32> {
    let fd = unsafe {
        // SAFETY: open(2) O_CREAT|O_EXCL|O_WRONLY on tmpfs we own.
        libc::open(
            path.as_ptr().cast::<libc::c_char>(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
            0o644,
        )
    };
    if fd < 0 {
        return Err(unsafe { *libc::__errno_location() });
    }
    let r = write_all(fd, contents);
    unsafe {
        // SAFETY: closing the fd we opened.
        libc::close(fd);
    }
    r
}

fn errno_of(r: libc::c_int) -> Result<(), i32> {
    if r < 0 {
        Err(unsafe { *libc::__errno_location() })
    } else {
        Ok(())
    }
}

/// Fail-closed bridge: any setup error terminates the child (and surfaces
/// as a Setup error in the parent; the payload never runs).
trait OrFail {
    fn or_fail(self, cfg: &ChildConfig, stage: u8);
}
impl OrFail for Result<(), i32> {
    fn or_fail(self, cfg: &ChildConfig, stage: u8) {
        if let Err(e) = self {
            fail(cfg, stage, e);
        }
    }
}

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

    // 2. rlimits: no core dumps. (fsize/nofile arrive with C4 policy.)
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

    // 3. Build the sandbox filesystem (milestone C2) and pivot into it.
    setup_rootfs(cfg);

    // 4. Wire up stdio. dup2 clears FD_CLOEXEC on the targets 0/1/2 — the
    //    payload keeps its pipes across exec, and nothing else does.
    if unsafe { libc::dup2(cfg.stdin_fd, 0) } < 0
        || unsafe { libc::dup2(cfg.stdout_fd, 1) } < 0
        || unsafe { libc::dup2(cfg.stderr_fd, 2) } < 0
    {
        fail(cfg, stage::SYNC, unsafe { *libc::__errno_location() });
    }

    // 5. Wait until the parent finished any post-clone setup (from C3:
    //    cgroup attach) — never race the payload.
    if let Err(e) = wait_for_go(cfg.go_rd) {
        fail(cfg, stage::SYNC, e);
    }

    // 6. execve. C arrays built from the leaked config; on success we never
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
