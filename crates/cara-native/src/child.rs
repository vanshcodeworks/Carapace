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
    pub const NS_SETUP: u8 = 15;
    pub const BIND_OPEN: u8 = 40;
    pub const BIND_MKDIR: u8 = 41;
    pub const BIND_MOUNT: u8 = 42;
    pub const BIND_REMOUNT: u8 = 43;
    pub const FD_CLOSE: u8 = 30;
    pub const CAPS_DROP: u8 = 31;
    pub const NO_NEW_PRIVS: u8 = 32;
    pub const LANDLOCK: u8 = 33;
    pub const SECCOMP: u8 = 34;
}

/// One extra bind mount requested by the policy.
#[derive(Debug, Clone)]
pub(crate) struct BindSpec {
    /// Absolute host path (also the in-sandbox path). NUL-terminated
    /// CString, prepared parent-side.
    pub path: CString,
    /// Read-write (true) or read-only (false).
    pub rw: bool,
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
    /// Write end of the exec-status pipe (CLOEXEC, STAGE-2 ONLY). exec
    /// success = the pipe closes (EOF at the parent); failure = a
    /// [`ChildError`] is written.
    pub status_wr: RawFd,
    /// Write end of the result pipe (STAGE-1 ONLY, held until exit): the
    /// payload-pid notice and, later, the forwarded wait status.
    pub result_wr: RawFd,
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
    /// RLIMIT_FSIZE for the payload (the per-file size cap).
    pub fsize_limit: u64,
    /// unshare(2) flag set for stage-1 (parent-computed: network mode
    /// "full" omits CLONE_NEWNET so the payload shares the host netns).
    pub unshare_flags: libc::c_int,
    /// Absolute staging dir (parent-created via mkdtemp in a uid-writable
    /// filesystem): the child mounts the new-root tmpfs over it. Removed
    /// by the parent after the run.
    pub staging_dir: CString,
    /// Extra bind mounts, applied like the runtime ones: same absolute
    /// path inside and outside, read-only or read-write.
    pub binds: Vec<BindSpec>,
    /// Compiled seccomp filter (parent-side compilation; installed by
    /// stage-2 as the LAST setup step before exec).
    pub seccomp_filter: Vec<libc::sock_filter>,
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
            let e = unsafe {
                // SAFETY: per-thread errno pointer, valid to read here.
                *libc::__errno_location()
            };
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
        Err(unsafe {
            // SAFETY: per-thread errno pointer, valid to read here.
            *libc::__errno_location()
        })
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
        let e = errno();
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

    // (b) The new root is a size-capped tmpfs mounted over the staging
    // dir the parent created (mkdtemp, uid-writable). Plain dir, NOT an
    // overmount of /tmp: host paths everywhere stay visible, so policy
    // binds in (c2) resolve their sources with plain path-based mounts.
    // The tmpfs (and everything on it) dies with this mount namespace;
    // only the empty staging dir remains, which the parent removes.
    let staging = cfg.staging_dir.as_bytes();
    let mut root = [0u8; 64];
    assert!(staging.len() < 64);
    root[..staging.len()].copy_from_slice(staging);
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

    // (c2) Policy-requested extra binds (paths already validated by the
    // parent: absolute, no .., not shadowing sandbox internals). Same
    // path inside the sandbox; read-only or read-write per policy. All
    // host source paths are still fully visible here.
    for b in &cfg.binds {
        let bytes = b.path.as_bytes();
        // Destination under the staging root, NUL-terminated (zero tail).
        let n_root = root
            .iter()
            .position(|&c| c == 0)
            .expect("root buffer is NUL-terminated");
        let mut inner = [0u8; 256];
        assert!(n_root + bytes.len() < 255);
        inner[..n_root].copy_from_slice(&root[..n_root]);
        inner[n_root..n_root + bytes.len()].copy_from_slice(bytes);
        let inner_ref: &[u8] = &inner;
        // mkdir -p so the attach point exists.
        if let Err(e) = mkdir_p(&root, bytes) {
            fail(cfg, stage::BIND_MKDIR, e);
        }
        let src = b.path.as_bytes_with_nul();
        if let Err(e) = mount_raw(
            src,
            inner_ref,
            b"",
            (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
            std::ptr::null(),
        ) {
            fail(cfg, stage::BIND_MOUNT, e);
        }
        if !b.rw
            && let Err(e) = mount_raw(
                src,
                inner_ref,
                b"",
                (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC)
                    as libc::c_ulong,
                std::ptr::null(),
            )
        {
            fail(cfg, stage::BIND_REMOUNT, e);
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
        return Err(errno());
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
        return Err(errno());
    }
    Ok(())
}

// ------------------------------------------------------------ mount helpers

/// A 64-byte NUL-terminated path buffer (core sandbox paths fit).
type PathBuf64 = [u8; 64];
/// mkdir -p under the new root for a full absolute guest path (bytes
/// without NUL; must start with b"/").
fn mkdir_p(root: &PathBuf64, path: &[u8]) -> Result<(), i32> {
    debug_assert_eq!(path.first(), Some(&b'/'));
    let mut buf = [0u8; 256];
    // The staging root's real length (an arbitrary mkdtemp path).
    let n = root
        .iter()
        .position(|&c| c == 0)
        .expect("root buffer is NUL-terminated");
    buf[..n].copy_from_slice(&root[..n]);
    let mut depth = n;
    // Join separator: path[0] ('/') was skipped, so restore it.
    buf[depth] = b'/';
    depth += 1;
    let mut first_err = None;
    for &b in &path[1..] {
        if b == b'/'
            && depth > n
            && let Err(e) = mkdir_raw_slice(&buf[..depth])
        {
            first_err = first_err.or(Some(e));
        }
        buf[depth] = b;
        depth += 1;
    }
    if let Err(e) = mkdir_raw_slice(&buf[..depth]) {
        first_err = first_err.or(Some(e));
    }
    match first_err {
        Some(e) if e != libc::EEXIST => Err(e),
        _ => Ok(()),
    }
}

/// mkdir(2) over a NON-NUL-terminated slice (adds the terminator).
fn mkdir_raw_slice(path: &[u8]) -> Result<(), i32> {
    let mut b = [0u8; 256];
    assert!(path.len() < 256);
    b[..path.len()].copy_from_slice(path);
    mkdir_raw(&b, 0o755)
}

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
        return Err(errno());
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
        return Err(errno());
    }
    let r = write_all(fd, contents);
    unsafe {
        // SAFETY: closing the fd we opened.
        libc::close(fd);
    }
    r
}

/// Reads the thread-local errno. Async-signal-safe (a plain memory read).
fn errno() -> i32 {
    unsafe {
        // SAFETY: __errno_location returns a valid per-thread pointer.
        *libc::__errno_location()
    }
}

fn errno_of(r: libc::c_int) -> Result<(), i32> {
    if r < 0 {
        Err(unsafe {
            // SAFETY: per-thread errno pointer, valid to read here.
            *libc::__errno_location()
        })
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

/// Stage message kinds sent through the exec-status pipe beyond error
/// reports (see the two-stage design note on [`child_main`]).
pub mod msg {
    /// stage=20: payload pid (the PID-namespace init) in `errno`.
    pub const PID2_NOTICE: u8 = 20;
    /// stage=21: forwarded raw waitpid status of the payload in `errno`.
    pub const EXIT_FORWARD: u8 = 21;
}

/// The child entry point: a TWO-STAGE design.
///
/// The supervisor forks a PLAIN (no namespaces) stage-1 process, because a
/// rootless parent may only move a plain child of its own uid into a
/// delegated cgroup leaf (crossing into the subtree from a user namespace
/// is denied by `nsdelegate`). Stage-1 then:
///
/// 1. waits for the go signal (parent attaches it to the cgroup leaf first),
/// 2. `unshare`s ALL namespaces (user/pid/mount/net/ipc/uts) in one call —
///    the unprivileged-legal combination — and writes its id maps,
/// 3. forks stage-2, which (as pid 1 of the new PID namespace, so its death
///    kills the whole tree) does rlimits → rootfs → pivot → stdio → execve,
/// 4. forwards the payload pid and later its wait status to the supervisor,
///    and exits.
///
/// Fork safety: between fork and exec, stage-1/2 only use raw syscalls
/// (no allocation, no std formatting, no locks).
pub(crate) extern "C" fn child_main(arg: *mut libc::c_void) -> libc::c_int {
    let cfg: &ChildConfig = unsafe {
        // SAFETY: the parent passed a leaked Box<ChildConfig> pointer via
        // clone's arg; the child owns it exclusively until exec/exit.
        &*(arg as *const ChildConfig)
    };

    // 1. Park until the parent has attached this process to the cgroup
    //    leaf (limits must cover every descendant we are about to create).
    if let Err(e) = wait_for_go(cfg.go_rd) {
        fail(cfg, stage::SYNC, e);
    }

    // 2. All namespaces at once (the parent-computed flag set; NEWUSER in
    //    the set is what makes this unprivileged-legal: the kernel creates
    //    the user namespace first, then the rest owned by it).
    let r = unsafe {
        // SAFETY: unshare(2) with a constant flag set; no memory args.
        libc::unshare(cfg.unshare_flags)
    };
    if r < 0 {
        fail(cfg, stage::NS_SETUP, errno());
    }

    // 3. Deny setgroups, then write uid/gid maps: we are uid 0 inside the
    //    new user namespace, mapped 1:1 onto the parent's unprivileged ids.
    //    Order matters: setgroups must be denied before gid_map is accepted.
    if let Err(e) = write_proc_file(c"/proc/self/setgroups".to_bytes_with_nul(), b"deny") {
        fail(cfg, stage::DENY_SETGROUPS, e);
    }
    // The parent captured its uid/gid BEFORE the fork: inside this
    // namespace getuid() is meaningless (overflow) until the map exists.
    let ruid = cfg.parent_uid;
    let rgid = cfg.parent_gid;
    let mut line = [0u8; 32];
    if let Err(e) = write_proc_file(
        c"/proc/self/uid_map".to_bytes_with_nul(),
        map_line(ruid, &mut line),
    ) {
        fail(cfg, stage::WRITE_UID_MAP, e);
    }
    let mut line = [0u8; 32];
    if let Err(e) = write_proc_file(
        c"/proc/self/gid_map".to_bytes_with_nul(),
        map_line(rgid, &mut line),
    ) {
        fail(cfg, stage::WRITE_GID_MAP, e);
    }

    // 4. Fork stage-2: the payload's PID-namespace init.
    let pid2 = unsafe {
        // SAFETY: fork(2); both halves below stay async-signal-safe.
        libc::fork()
    };
    if pid2 < 0 {
        fail(cfg, stage::NS_SETUP, errno());
    }
    if pid2 == 0 {
        // ---- stage-2: the actual sandbox init ----
        run_payload(cfg);
    }

    // ---- stage-1: supervisor proxy ----
    // CRITICAL: close every child-facing fd except our result pipe. We
    // never exec (so CLOEXEC never fires for us); holding the status or
    // stdio pipes open would block the parent's EOF detection forever —
    // observed as a deadlock once the payload fills its stdout pipe.
    for fd in [
        cfg.status_wr,
        cfg.go_rd,
        cfg.stdin_fd,
        cfg.stdout_fd,
        cfg.stderr_fd,
    ] {
        unsafe {
            // SAFETY: fds from the config; stage-2 owns its own copies.
            libc::close(fd);
        }
    }
    // Tell the parent which pid to watch (the payload init).
    let notice = ChildError {
        stage: msg::PID2_NOTICE,
        errno: pid2,
    };
    let bytes = std::ptr::from_ref(&notice).cast::<u8>();
    let _ = write_all(cfg.result_wr, unsafe {
        // SAFETY: `bytes` covers exactly size_of::<ChildError>() valid
        // bytes of a local struct alive across this call.
        std::slice::from_raw_parts(bytes, std::mem::size_of::<ChildError>())
    });
    // Wait for the payload init and forward its raw status, then exit.
    let mut st2: libc::c_int = 0;
    loop {
        let r = unsafe {
            // SAFETY: blocking waitpid on our direct child (stage-2).
            libc::waitpid(pid2, &mut st2, 0)
        };
        if r == pid2 {
            break;
        }
        let e = errno();
        if e != libc::EINTR {
            st2 = 128 + libc::SIGKILL; // stage-2 vanished abnormally
            break;
        }
    }
    let fwd = ChildError {
        stage: msg::EXIT_FORWARD,
        errno: st2,
    };
    let bytes = std::ptr::from_ref(&fwd).cast::<u8>();
    let _ = write_all(cfg.result_wr, unsafe {
        // SAFETY: as above.
        std::slice::from_raw_parts(bytes, std::mem::size_of::<ChildError>())
    });
    unsafe {
        // SAFETY: proxy done; nothing to unwind.
        libc::_exit(0);
    }
}

/// Stage-2 body: everything after namespaces, until execve. Never returns.
fn run_payload(cfg: &ChildConfig) -> ! {
    // rlimits: no core dumps. (fsize/nofile arrive with C4 policy.)
    let rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let r = unsafe {
        // SAFETY: setrlimit(RLIMIT_CORE, &rl) with a valid struct.
        libc::setrlimit(libc::RLIMIT_CORE, &rl)
    };
    if r < 0 {
        fail(cfg, stage::SET_RLIMIT, errno());
    }

    // Build the sandbox filesystem (milestone C2) and pivot into it.
    setup_rootfs(cfg);

    // Wire up stdio. dup2 clears FD_CLOEXEC on the targets 0/1/2 — the
    // payload keeps its pipes across exec, and nothing else does.
    // SAFETY: dup2(2) over our own pipe fds; targets 0/1/2 are free.
    let stdio_ok = unsafe {
        libc::dup2(cfg.stdin_fd, 0) >= 0
            && libc::dup2(cfg.stdout_fd, 1) >= 0
            && libc::dup2(cfg.stderr_fd, 2) >= 0
    };
    if !stdio_ok {
        fail(cfg, stage::SYNC, errno());
    }

    // ---- C4 hardening, in the order the threat model documents ----------
    harden_fds(cfg);
    harden_rlimits(cfg);
    drop_capabilities(cfg);
    set_no_new_privs(cfg);
    apply_landlock(cfg);
    install_seccomp(cfg);

    // execve. C arrays built from the leaked config; on success we never
    // return. The status pipe (CLOEXEC) closes at exec: that EOF is the
    // parent's "running" signal (stage-1's forwarding comes later, through
    // its own copy, after the payload dies).
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
    fail(cfg, stage::EXEC, errno())
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

// ------------------------------------------------------- C4 hardening

/// Closes every fd above 2 except the exec-status write end (still needed
/// to report an exec failure): two close_range calls bracketing it. The
/// payload inherits exactly {0,1,2}.
fn harden_fds(cfg: &ChildConfig) {
    let keep = cfg.status_wr;
    if keep > 3 {
        errno_of(unsafe {
            // SAFETY: close_range(3, keep-1, 0): plain closes.
            libc::syscall(libc::SYS_close_range, 3u32, (keep - 1) as u32, 0u32) as libc::c_int
        })
        .or_fail(cfg, stage::FD_CLOSE);
    }
    errno_of(unsafe {
        // SAFETY: close_range(keep+1, UINT_MAX, 0).
        libc::syscall(libc::SYS_close_range, (keep + 1) as u32, u32::MAX, 0u32) as libc::c_int
    })
    .or_fail(cfg, stage::FD_CLOSE);
}

/// RLIMIT_FSIZE caps any single file the payload writes (the /work tmpfs
/// bounds the total independently); RLIMIT_NOFILE caps descriptor use.
fn harden_rlimits(cfg: &ChildConfig) {
    let rl = libc::rlimit {
        rlim_cur: cfg.fsize_limit,
        rlim_max: cfg.fsize_limit,
    };
    let r = unsafe {
        // SAFETY: setrlimit(RLIMIT_FSIZE, &rl) with a valid struct.
        libc::setrlimit(libc::RLIMIT_FSIZE, &rl)
    };
    if r < 0 {
        fail(cfg, stage::SET_RLIMIT, errno());
    }
    let rl = libc::rlimit {
        rlim_cur: 256,
        rlim_max: 256,
    };
    let r = unsafe {
        // SAFETY: setrlimit(RLIMIT_NOFILE, &rl) with a valid struct.
        libc::setrlimit(libc::RLIMIT_NOFILE, &rl)
    };
    if r < 0 {
        fail(cfg, stage::SET_RLIMIT, errno());
    }
}

/// Drops every capability (we are uid 0 in the userns; after this the
/// payload holds none, not even namespaced ones).
fn drop_capabilities(cfg: &ChildConfig) {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut hdr = CapHeader {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3 (capability.h)
        pid: 0,
    };
    let mut data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    let r = unsafe {
        // SAFETY: capset(2) with the standard v3 header and two data
        // structs; all sets zeroed = drop everything.
        libc::syscall(
            libc::SYS_capset,
            std::ptr::from_mut(&mut hdr),
            data.as_mut_ptr(),
        )
    };
    if r < 0 {
        fail(cfg, stage::CAPS_DROP, errno());
    }
}

fn set_no_new_privs(cfg: &ChildConfig) {
    let r = unsafe {
        // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1): plain process attribute.
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64)
    };
    if r < 0 {
        fail(cfg, stage::NO_NEW_PRIVS, errno());
    }
}

/// Landlock: deny-by-default across the whole filesystem; explicit grants:
/// read-only /usr, /proc, /etc; read-write /work, /tmp, /dev (only our
/// four safe device nodes live there). ABI-aware; fails closed if the
/// kernel lacks Landlock (doctor gates this environment class, so an
/// error here is a real anomaly, not noise).
fn apply_landlock(cfg: &ChildConfig) {
    let Some(abi) = carapace_sys::landlock::abi_version() else {
        fail(cfg, stage::LANDLOCK, libc::ENOSYS);
    };
    if abi < 1 {
        fail(cfg, stage::LANDLOCK, libc::EOPNOTSUPP);
    }
    let handled = carapace_sys::landlock::handled_access_for_abi(abi);
    let rs = match carapace_sys::landlock::create_ruleset(handled) {
        Ok(fd) => fd,
        Err(e) => fail(cfg, stage::LANDLOCK, e),
    };
    use carapace_sys::landlock::access_fs as fs;
    let mut grants: Vec<(&[u8], u64)> = vec![
        (c"/usr".to_bytes_with_nul(), fs::RO),
        (c"/proc".to_bytes_with_nul(), fs::RO),
        (c"/etc".to_bytes_with_nul(), fs::RO),
        (c"/dev".to_bytes_with_nul(), fs::RW_FILES),
        (c"/work".to_bytes_with_nul(), fs::RW_ALL),
        (c"/tmp".to_bytes_with_nul(), fs::RW_ALL),
    ];
    for b in &cfg.binds {
        grants.push((
            b.path.as_bytes_with_nul(),
            if b.rw { fs::RW_ALL } else { fs::RO },
        ));
    }
    for (path, access) in grants {
        let fd = unsafe {
            // SAFETY: openat(2) O_PATH on fixed literal paths inside the
            // pivoted root.
            libc::openat(
                libc::AT_FDCWD,
                path.as_ptr().cast::<libc::c_char>(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let e = unsafe {
                // SAFETY: per-thread errno pointer, valid to read here.
                *libc::__errno_location()
            };
            unsafe {
                // SAFETY: closing the ruleset fd on the error path.
                libc::close(rs);
            }
            fail(cfg, stage::LANDLOCK, e);
        }
        let r = carapace_sys::landlock::add_path_beneath(rs, access, fd);
        unsafe {
            // SAFETY: the O_PATH fd is not needed after adding the rule.
            libc::close(fd);
        }
        if let Err(e) = r {
            unsafe {
                // SAFETY: closing the ruleset fd on the error path.
                libc::close(rs);
            }
            fail(cfg, stage::LANDLOCK, e);
        }
    }
    if let Err(e) = carapace_sys::landlock::restrict_self(rs) {
        unsafe {
            // SAFETY: closing the ruleset fd on the error path.
            libc::close(rs);
        }
        fail(cfg, stage::LANDLOCK, e);
    }
    unsafe {
        // SAFETY: the ruleset is applied; the fd is no longer needed.
        libc::close(rs);
    }
}

/// seccomp LAST: with Landlock applied and fds sanitized, the allowlist
/// filter seals the syscall surface until exec.
fn install_seccomp(cfg: &ChildConfig) {
    if let Err(e) = carapace_sys::seccomp::install(&cfg.seccomp_filter) {
        fail(cfg, stage::SECCOMP, e);
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
