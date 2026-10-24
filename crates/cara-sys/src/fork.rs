//! Process creation with namespace flags: `clone(2)` wrappers and child
//! stack management. This is the entry point of every sandbox run; policy
//! (which flags, which order) lives in `carapace-native`.

/// Allocates a child stack via `mmap` and returns a pointer to its TOP
/// (stacks grow down). Returns the base pointer for later `munmap` plus the
/// size. The memory is zero-filled, MAP_PRIVATE|MAP_ANONYMOUS.
///
/// # Safety
/// Caller must eventually pass the returned top to [`munmap_stack`] with
/// the same base/size, and must not free twice.
pub unsafe fn alloc_child_stack(size: usize) -> std::io::Result<(*mut u8, usize)> {
    let base = unsafe {
        // SAFETY: mmap of `size` bytes (caller rounds up to page size),
        // PROT_READ|PROT_WRITE, anonymous private mapping; returns
        // MAP_FAILED (-1) on error, which we check.
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    Ok((base as *mut u8, size))
}

/// Frees a stack from [`alloc_child_stack`].
///
/// # Safety
/// `base`/`size` must be exactly what [`alloc_child_stack`] returned, and
/// the child that used the stack must have exited (its COW pages are its
/// own; the parent's mapping is safe to unmap once the child is reaped).
pub unsafe fn munmap_stack(base: *mut u8, size: usize) {
    unsafe {
        // SAFETY: caller guarantees base/size came from alloc_child_stack.
        libc::munmap(base as *mut libc::c_void, size);
    }
}

/// A child created by [`clone_ns`].
pub struct SpawnedChild {
    /// The child's pid in the parent's namespace.
    pub pid: libc::pid_t,
    /// A pidfd referring to the child (from CLONE_PIDFD): pollable,
    /// killable via pidfd_send_signal, immune to pid reuse.
    pub pidfd: libc::c_int,
}

/// Creates a child that runs `child_fn(arg)` on the given stack (the
/// pointer returned by [`alloc_child_stack`] — the TOP of the mapping).
///
/// `flags` must include a termination signal (normally SIGCHLD); this
/// function adds `CLONE_PIDFD` and returns the pidfd.
///
/// # Safety
/// - `stack_top` must be the pointer returned by [`alloc_child_stack`] and
///   must not be unmapped while the child runs.
/// - `child_fn` may only perform async-signal-safe operations until it
///   execs or exits: the child is a fork of a potentially multithreaded
///   parent (only this thread survives in the child).
/// - `arg` must be valid to dereference as whatever `child_fn` expects and
///   must remain valid for the child's whole pre-exec lifetime.
pub unsafe fn clone_ns(
    child_fn: extern "C" fn(*mut libc::c_void) -> libc::c_int,
    stack_top: *mut u8,
    mut flags: libc::c_int,
    arg: *mut libc::c_void,
) -> std::io::Result<SpawnedChild> {
    flags |= libc::CLONE_PIDFD as libc::c_int;
    let mut pidfd: libc::c_int = -1;
    let ret = unsafe {
        // SAFETY: libc clone(2). stack_top points to the top of a mapping
        // of at least one page owned by the caller; parent_tid receives the
        // pidfd because CLONE_PIDFD is set; child_tid and tls are unused.
        libc::clone(
            child_fn,
            stack_top as *mut libc::c_void,
            flags,
            arg,
            &mut pidfd as *mut libc::c_int,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(SpawnedChild { pid: ret, pidfd })
    }
}

/// Sends `sig` to the process referred to by `pidfd` (immune to pid reuse).
pub fn pidfd_send_signal(pidfd: libc::c_int, sig: libc::c_int) -> std::io::Result<()> {
    let ret = unsafe {
        // SAFETY: pidfd_send_signal(2) with a valid pidfd, no siginfo
        // (NULL), no flags. Sends the signal; returns -1/EINVAL on error.
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd as libc::c_long,
            sig as libc::c_long,
            std::ptr::null::<libc::c_void>(),
            0u32,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Marks the calling process as a **child subreaper**: orphaned descendants
/// reparent to it instead of to init. Set once by the supervisor backend.
pub fn set_child_subreaper() -> std::io::Result<()> {
    let ret = unsafe {
        // SAFETY: prctl(PR_SET_CHILD_SUBREAPER, 1): plain process attribute.
        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1u64, 0u64, 0u64, 0u64)
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
